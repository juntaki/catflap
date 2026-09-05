package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// TerminalTool is the lifecycle event closing a task's chain. No records
// may follow it; see Verify.
const TerminalTool = "task.stop"

// CreateTool is the lifecycle event opening a task's chain, recording the
// canonical policy snapshot hash in ArgsHash.
const CreateTool = "task.create"

// Report summarizes verification of one audit file.
type Report struct {
	File      string
	Task      string
	Entries   int64
	Head      string
	HasCreate bool
	Terminal  string // terminal decision (reason) or ""
}

// Verify checks a JSONL audit file and returns its report:
//
//   - every line parses with required fields and schema version 1;
//   - sequence runs 1..n without gaps;
//   - every Prev links to the previous hash (first is "genesis");
//   - every Hash recomputes;
//   - all records name the same task;
//   - no record follows a terminal (task.stop) event.
//
// A valid report means "internally consistent hash chain" — NOT proof
// against whole-file replacement. Pair with an external head anchor
// (see the audit anchor command) to detect truncation/rewrite.
func Verify(path string) (*Report, error) {
	//nolint:gosec // reason: operator-supplied audit file path for offline verification.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	rep := &Report{File: path}
	prev := Genesis
	var seq int64
	terminal := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytesTrimSpace(line)) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("line %d: invalid record: %w", seq+1, err)
		}
		seq++
		if e.V != AuditVersion {
			return nil, fmt.Errorf("line %d: unsupported audit version %d", seq, e.V)
		}
		if e.Task == "" || e.Tool == "" || e.Hash == "" {
			return nil, fmt.Errorf("line %d: missing required fields", seq)
		}
		if rep.Task == "" {
			rep.Task = e.Task
		} else if e.Task != rep.Task {
			return nil, fmt.Errorf("line %d: task id changed (%q was %q)", seq, e.Task, rep.Task)
		}
		if e.Seq != seq {
			return nil, fmt.Errorf("line %d: sequence break (got seq %d)", seq, e.Seq)
		}
		if e.Prev != prev {
			return nil, fmt.Errorf("line %d: prev-link break", seq)
		}
		if HashEntry(e) != e.Hash {
			return nil, fmt.Errorf("line %d: hash mismatch (record tampered)", seq)
		}
		if terminal {
			return nil, fmt.Errorf("line %d: record after terminal event", seq)
		}
		if e.Tool == CreateTool && seq == 1 {
			rep.HasCreate = true
		}
		if e.Tool == TerminalTool {
			terminal = true
			rep.Terminal = e.Decision
		}
		prev = e.Hash
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if seq == 0 {
		return nil, fmt.Errorf("empty audit file")
	}
	rep.Entries = seq
	rep.Head = prev
	return rep, nil
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
