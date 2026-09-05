package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditVersion is the audit record schema version. Every record carries
// it, and the chain hash covers it, so a version downgrade/upgrade inside
// a file is detectable by verify.
const AuditVersion = 1

// Genesis is the expected Prev of the first record.
const Genesis = "genesis"

// Entry is one structured audit line. Prev chains to the previous entry's
// hash, forming a hash-chained log per task. A hash chain alone is NOT
// proof against whole-file replacement — see verify and external anchors.
type Entry struct {
	V          int    `json:"v"`
	Task       string `json:"task"`
	Seq        int64  `json:"seq"`
	Time       string `json:"time"`
	AgentKey   string `json:"agent_key,omitempty"`
	Tool       string `json:"tool"`
	ArgsHash   string `json:"args_hash"`
	Decision   string `json:"decision"` // allow | deny | expired | error | active | revoked | shutdown | requested | granted | denied
	ResultHash string `json:"result_hash,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Prev       string `json:"prev"`
	Hash       string `json:"hash"`
}

// Logger appends Entries as JSONL.
type Logger struct {
	mu sync.Mutex
	f  *os.File
	// path identifies the sink in degradation reports.
	path     string
	task     string
	agentKey string
	seq      int64
	prev     string
	// sealed, once set by LogTerminal, refuses further records: the
	// runtime can no longer emit "deny after task.stop" entries.
	sealed bool
	// writeErr is sticky: the first sink failure is retained so the
	// operator can be told the audit degraded instead of silently
	// losing records.
	writeErr error
}

// Open creates (or appends to) dir/<task>.jsonl.
func Open(dir, task, agentKey string) (*Logger, error) {
	if dir == "" {
		return &Logger{task: task, agentKey: agentKey, prev: Genesis}, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, task+".jsonl")
	//nolint:gosec // reason: path derives from the operator's --audit dir and the server-minted task id, never from agent input.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Logger{f: f, path: path, task: task, agentKey: agentKey, prev: Genesis}
	// Resume chain: read last hash if file non-empty.
	if st, _ := f.Stat(); st.Size() > 0 {
		if last, err := lastHash(path); err == nil && last != "" {
			l.prev = last
			// Resume seq too.
			if n, err := lastSeq(path); err == nil {
				l.seq = n
			}
		}
	}
	return l, nil
}

// Log appends one entry. args and result are hashed, never stored raw.
// Records refused after sealing return a zero Entry.
func (l *Logger) Log(tool string, args []byte, decision string, result []byte, dur time.Duration) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sealed {
		return Entry{}
	}
	return l.appendLocked(tool, args, decision, result, dur)
}

// LogTerminal writes the terminal lifecycle event and seals the logger:
// seal and write are atomic under the logger mutex, so no concurrent Log
// can land after the terminal record.
func (l *Logger) LogTerminal(reason string) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.appendLocked(TerminalTool, nil, reason, nil, 0)
	l.sealed = true
	return e
}

// Err reports the sticky sink failure, if the audit degraded.
func (l *Logger) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.writeErr
}

// appendLocked builds the next chain entry and, only once it is fully
// durable on disk, commits it as the new seq/prev. A write that fails or
// lands short is never allowed to advance the in-memory chain state: if it
// did, the next successful entry would chain onto a hash whose entry never
// made it to the file, permanently breaking the chain for anyone auditing
// this task later. The failure is still recorded as a sticky writeErr, so
// callers can fail the task closed instead of continuing silently degraded.
func (l *Logger) appendLocked(tool string, args []byte, decision string, result []byte, dur time.Duration) Entry {
	e := Entry{
		V:          AuditVersion,
		Task:       l.task,
		Seq:        l.seq + 1,
		Time:       time.Now().UTC().Format(time.RFC3339Nano),
		AgentKey:   shortKey(l.agentKey),
		Tool:       tool,
		ArgsHash:   hashOf(args),
		Decision:   decision,
		ResultHash: hashOf(result),
		DurationMs: dur.Milliseconds(),
		Prev:       l.prev,
	}
	e.Hash = HashEntry(e)
	if l.f == nil {
		l.seq = e.Seq
		l.prev = e.Hash
		return e
	}
	// Entry is strings/ints only and cannot fail to marshal.
	raw, _ := json.Marshal(e)
	raw = append(raw, '\n')
	n, werr := l.f.Write(raw)
	if werr == nil && n != len(raw) {
		werr = io.ErrShortWrite
	}
	if werr != nil {
		if l.writeErr == nil {
			l.writeErr = werr
		}
		return e
	}
	l.seq = e.Seq
	l.prev = e.Hash
	return e
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		f := l.f
		l.f = nil
		return f.Close()
	}
	return nil
}

// HashEntry computes the chain hash of an entry. The schema version is
// part of the preimage, so version tampering breaks the chain.
func HashEntry(e Entry) string {
	return hashOf([]byte(fmt.Sprintf("%d|%s|%d|%s|%s|%s|%s|%s|%s|%d",
		e.V, e.Task, e.Seq, e.Time, e.AgentKey, e.Tool, e.ArgsHash, e.Decision, e.ResultHash, e.DurationMs) + "|" + e.Prev))
}

func hashOf(b []byte) string {
	if len(b) == 0 {
		return "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func shortKey(k string) string {
	if len(k) <= 24 {
		return k
	}
	return k[:16] + "..." + k[len(k)-6:]
}

func lastHash(path string) (string, error) {
	data, err := readAuditFile(path)
	if err != nil || len(data) == 0 {
		return "", err
	}
	lines := splitLines(data)
	for i := len(lines) - 1; i >= 0; i-- {
		var e Entry
		if json.Unmarshal(lines[i], &e) == nil && e.Hash != "" {
			return e.Hash, nil
		}
	}
	return "", nil
}

func lastSeq(path string) (int64, error) {
	data, err := readAuditFile(path)
	if err != nil || len(data) == 0 {
		return 0, err
	}
	lines := splitLines(data)
	for i := len(lines) - 1; i >= 0; i-- {
		var e Entry
		if json.Unmarshal(lines[i], &e) == nil && e.Seq > 0 {
			return e.Seq, nil
		}
	}
	return 0, nil
}

// readAuditFile reads back this process's own audit file for chain resume.
// The path always originates from the operator's --audit dir (see Open).
func readAuditFile(path string) ([]byte, error) {
	//nolint:gosec // reason: operator-configured audit dir joined with a server-minted task id; never agent input.
	return os.ReadFile(path)
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				out = append(out, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}
