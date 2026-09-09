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
//   - the first record is task.create (the chain always opens with the
//     policy-binding creation event; a lone task.stop is invalid);
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
	chain := chainState{prev: Genesis}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytesTrimSpace(line)) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("line %d: invalid record: %w", chain.seq+1, err)
		}
		if err := chain.step(rep, e); err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if chain.seq == 0 {
		return nil, fmt.Errorf("empty audit file")
	}
	rep.Entries = chain.seq
	rep.Head = chain.prev
	return rep, nil
}

// chainState tracks the running hash-chain position across Verify's
// line loop, so each record's checks can live in one flat method
// instead of nesting inside the scanner loop.
type chainState struct {
	prev     string
	seq      int64
	terminal bool
}

// step validates one record against the chain built so far, updating
// rep and the chain position on success.
func (c *chainState) step(rep *Report, e Entry) error {
	c.seq++
	if e.V != AuditVersion {
		return fmt.Errorf("line %d: unsupported audit version %d", c.seq, e.V)
	}
	if e.Task == "" || e.Tool == "" || e.Hash == "" {
		return fmt.Errorf("line %d: missing required fields", c.seq)
	}
	if rep.Task == "" {
		rep.Task = e.Task
	} else if e.Task != rep.Task {
		return fmt.Errorf("line %d: task id changed (%q was %q)", c.seq, e.Task, rep.Task)
	}
	if e.Seq != c.seq {
		return fmt.Errorf("line %d: sequence break (got seq %d)", c.seq, e.Seq)
	}
	if e.Prev != c.prev {
		return fmt.Errorf("line %d: prev-link break", c.seq)
	}
	if HashEntry(e) != e.Hash {
		return fmt.Errorf("line %d: hash mismatch (record tampered)", c.seq)
	}
	if c.terminal {
		return fmt.Errorf("line %d: record after terminal event", c.seq)
	}
	if c.seq == 1 {
		if e.Tool != CreateTool {
			return fmt.Errorf("line 1: chain must open with %q, got %q", CreateTool, e.Tool)
		}
		rep.HasCreate = true
	}
	if e.Tool == TerminalTool {
		c.terminal = true
		rep.Terminal = e.Decision
	}
	c.prev = e.Hash
	return nil
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
