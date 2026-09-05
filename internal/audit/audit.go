package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one structured audit line. Prev chains to the previous entry's
// hash, forming a tamper-evident hash chain per task.
type Entry struct {
	Task       string `json:"task"`
	Seq        int64  `json:"seq"`
	Time       string `json:"time"`
	AgentKey   string `json:"agent_key,omitempty"`
	Tool       string `json:"tool"`
	ArgsHash   string `json:"args_hash"`
	Decision   string `json:"decision"` // allow | deny | expired | error
	ResultHash string `json:"result_hash,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Prev       string `json:"prev"`
	Hash       string `json:"hash"`
}

// Logger appends Entries as JSONL.
type Logger struct {
	mu       sync.Mutex
	f        *os.File
	task     string
	agentKey string
	seq      int64
	prev     string
}

// Open creates (or appends to) dir/<task>.jsonl.
func Open(dir, task, agentKey string) (*Logger, error) {
	if dir == "" {
		return &Logger{task: task, agentKey: agentKey, prev: "genesis"}, nil
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
	l := &Logger{f: f, task: task, agentKey: agentKey, prev: "genesis"}
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
func (l *Logger) Log(tool string, args []byte, decision string, result []byte, dur time.Duration) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e := Entry{
		Task:       l.task,
		Seq:        l.seq,
		Time:       time.Now().UTC().Format(time.RFC3339Nano),
		AgentKey:   shortKey(l.agentKey),
		Tool:       tool,
		ArgsHash:   hashOf(args),
		Decision:   decision,
		ResultHash: hashOf(result),
		DurationMs: dur.Milliseconds(),
		Prev:       l.prev,
	}
	e.Hash = hashOf([]byte(fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s|%s|%d",
		e.Task, e.Seq, e.Time, e.AgentKey, e.Tool, e.ArgsHash, e.Decision, e.ResultHash, e.DurationMs) + "|" + e.Prev))
	l.prev = e.Hash
	if l.f != nil {
		// Entry is strings/ints only and cannot fail to marshal; a
		// failure must not advance the file past the in-memory chain,
		// so skip the write rather than recording a partial entry.
		if raw, merr := json.Marshal(e); merr == nil {
			raw = append(raw, '\n')
			_, _ = l.f.Write(raw)
		}
	}
	return e
}

func (l *Logger) Close() error {
	if l.f != nil {
		return l.f.Close()
	}
	return nil
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
