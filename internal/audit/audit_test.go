package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeLog(t *testing.T, tools ...string) string {
	t.Helper()
	dir := "testdata/audit-verify"
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := Open(dir, "agt_verify", "nodekey:test")
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools {
		l.Log(tool, []byte("args"), "allow", []byte("result"), time.Millisecond)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "agt_verify.jsonl")
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	//nolint:gosec // reason: test-only readback of fixtures created by the same test.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func mustMarshal(t *testing.T, e Entry) string {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyHappyPath(t *testing.T) {
	rep, err := Verify(writeLog(t, "remote_exec", "remote_read", "task.stop"))
	if err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if rep.Entries != 3 || rep.Task != "agt_verify" || rep.Head == "" {
		t.Errorf("bad report: %+v", rep)
	}
	if rep.Terminal == "" {
		t.Error("expected terminal event detected")
	}
}

func TestVerifyTamperDetected(t *testing.T) {
	path := writeLog(t, "remote_exec", "remote_read")
	lines := readLines(t, path)
	var e Entry
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil {
		t.Fatal(err)
	}
	e.Decision = "allow-evil"
	lines[1] = mustMarshal(t, e)
	writeLines(t, path, lines)
	if _, err := Verify(path); err == nil {
		t.Error("tampered decision must be detected")
	}
}

func TestVerifyTruncatePassesButAnchorCatches(t *testing.T) {
	path := writeLog(t, "remote_exec", "remote_read", "task.stop")
	rep, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	head := rep.Head
	lines := readLines(t, path)
	writeLines(t, path, lines[:2]) // drop terminal: still a valid prefix
	rep2, err := Verify(path)
	if err != nil {
		t.Fatalf("valid prefix must verify (truncation needs an anchor): %v", err)
	}
	if rep2.Head == head {
		t.Fatal("truncated head must differ")
	}
}

func TestVerifySeqBreak(t *testing.T) {
	path := writeLog(t, "remote_exec", "remote_read")
	lines := readLines(t, path)
	lines[0], lines[1] = lines[1], lines[0]
	writeLines(t, path, lines)
	if _, err := Verify(path); err == nil {
		t.Error("swapped lines must break sequence/prev linkage")
	}
}

func TestVerifyAfterTerminal(t *testing.T) {
	path := writeLog(t, "task.stop", "remote_exec")
	if _, err := Verify(path); err == nil {
		t.Error("record after terminal event must be rejected")
	}
}

func TestVerifyVersionRejected(t *testing.T) {
	path := writeLog(t, "remote_exec")
	lines := readLines(t, path)
	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatal(err)
	}
	e.V = 99
	e.Hash = HashEntry(e) // re-chained, but wrong version
	writeLines(t, path, []string{mustMarshal(t, e)})
	if _, err := Verify(path); err == nil {
		t.Error("unknown audit version must be rejected")
	}
}

func TestVerifyEmptyRejected(t *testing.T) {
	dir := "testdata/audit-empty"
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(p); err == nil {
		t.Error("empty file must be rejected")
	}
}

func TestSealRefusesPostTerminal(t *testing.T) {
	l, err := Open("", "agt_seal", "")
	if err != nil {
		t.Fatal(err)
	}
	l.Log("remote_exec", nil, "allow", nil, 0)
	term := l.LogTerminal("expired")
	if term.Tool != TerminalTool || term.Decision != "expired" || term.Seq != 2 {
		t.Errorf("bad terminal event: %+v", term)
	}
	if e := l.Log("remote_exec", nil, "deny", nil, 0); e != (Entry{}) {
		t.Errorf("post-terminal Log must be refused, got %+v", e)
	}
	// Chain still verifies: seal only stops new records.
	if l.f != nil {
		t.Error("in-memory logger should have no file")
	}
}

func TestStickyWriteError(t *testing.T) {
	dir := "testdata/audit-sticky"
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := Open(dir, "agt_sticky", "")
	if err != nil {
		t.Fatal(err)
	}
	// Break the sink behind the logger's back: writes now fail.
	if err := l.f.Close(); err != nil {
		t.Fatal(err)
	}
	l.Log("remote_exec", nil, "allow", nil, 0)
	if err := l.Err(); err == nil {
		t.Error("sink failure must stick")
	}
	_ = l.Close()
}
