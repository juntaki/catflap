package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/gateway"
)

func TestSanitizeForTerminalEscapesControlBytes(t *testing.T) {
	cases := map[string]string{
		"plain text":              "plain text",
		"esc\x1b[2Jattack":        "esc\\x1b[2Jattack",
		"line1\nline2":            "line1\\x0aline2",
		"cr\rinjection":           "cr\\x0dinjection",
		"tab\ttab":                "tab\\x09tab",
		"bell\x07nul\x00del\x7fx": "bell\\x07nul\\x00del\\x7fx",
	}
	for in, want := range cases {
		if got := sanitizeForTerminal(in); got != want {
			t.Errorf("sanitizeForTerminal(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeForTerminalCannotForgeApprovalLine(t *testing.T) {
	// An argv element trying to visually forge the prompt's own answer
	// line must never render as a real newline — it must show up as an
	// escaped, inert \x0a in the operator's view.
	forged := "harmless\napprove exactly: abc123 y"
	got := sanitizeForTerminal(forged)
	if strings.Contains(got, "\n") {
		t.Fatalf("sanitized output must contain no raw newline, got %q", got)
	}
	if !strings.Contains(got, "\\x0a") {
		t.Fatalf("expected escaped newline marker, got %q", got)
	}
}

// TestParseApprovalAnswerRequiresExactToken covers a bug caught while
// fixing the round-2 collision finding: tokens are now a plain
// increasing counter (1, 2, 3, ...), so "1" is a string PREFIX of "12" —
// a naive strings.HasPrefix check would let token "1"'s answer match a
// line actually tagged for token "12". parseApprovalAnswer must compare
// the first whitespace-delimited field for exact equality instead.
func TestParseApprovalAnswerRequiresExactToken(t *testing.T) {
	if _, matched := parseApprovalAnswer("12", "1"); matched {
		t.Fatal(`token "1" must not match a line tagged for token "12"`)
	}
	approved, matched := parseApprovalAnswer("12", "12")
	if !matched || !approved {
		t.Fatalf("bare exact token must approve: approved=%v matched=%v", approved, matched)
	}
	approved, matched = parseApprovalAnswer("12 n", "12")
	if !matched || approved {
		t.Fatalf("token plus anything else must deny: approved=%v matched=%v", approved, matched)
	}
}

// syncBuf is a concurrency-safe io.Writer/fmt.Stringer for tests that
// write from the approver's goroutine while polling from the test
// goroutine.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitForToken polls out for a NEW prompt's token (the "type <token> to
// approve" line) appearing strictly after byte offset since — so a
// second call, after a previous prompt already printed the same marker
// text, cannot return stale data: it waits for output that wasn't there
// yet. Returns the token and the buffer length to pass as `since` to the
// next call.
func waitForToken(t *testing.T, out *syncBuf, since int) (token string, newSince int) {
	t.Helper()
	const marker = "type "
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s := out.String()
		if len(s) > since {
			if i := strings.LastIndex(s[since:], marker); i >= 0 {
				rest := strings.TrimSpace(s[since+i+len(marker):])
				if fields := strings.Fields(rest); len(fields) > 0 {
					return fields[0], len(s)
				}
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("timed out waiting for approval prompt/token")
	return "", since
}

func TestTerminalApproverApprovesOnMatchingToken(t *testing.T) {
	pr, pw := io.Pipe()
	out := &syncBuf{}
	a := NewTerminalApprover(pr, out)

	type result struct {
		ok  bool
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		ok, err := a.Approve(context.Background(), gateway.ApprovalRequest{
			TaskID: "agt_x", Tool: "remote_exec", Summary: "run echo hi",
		})
		resCh <- result{ok, err}
	}()

	token, _ := waitForToken(t, out, 0)
	if _, err := pw.Write([]byte(token + "\n")); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-resCh:
		if r.err != nil || !r.ok {
			t.Fatalf("Approve() = %v, %v; want true, nil", r.ok, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Approve() did not return after a bare matching token")
	}
	if !strings.Contains(out.String(), "approval required") {
		t.Errorf("prompt must be printed, got %q", out.String())
	}
}

func TestTerminalApproverDeniesOnMatchingTokenNo(t *testing.T) {
	pr, pw := io.Pipe()
	out := &syncBuf{}
	a := NewTerminalApprover(pr, out)

	resCh := make(chan bool, 1)
	errCh := make(chan error, 1)
	go func() {
		ok, err := a.Approve(context.Background(), gateway.ApprovalRequest{TaskID: "agt_x"})
		resCh <- ok
		errCh <- err
	}()

	token, _ := waitForToken(t, out, 0)
	if _, err := pw.Write([]byte(token + " n\n")); err != nil {
		t.Fatal(err)
	}

	select {
	case ok := <-resCh:
		if err := <-errCh; err != nil || ok {
			t.Fatalf("Approve() = %v, %v; want false, nil", ok, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Approve() did not return after a matching-token no")
	}
}

// TestTerminalApproverIgnoresUntaggedInput covers the core Phase C fix:
// plain "y"/"n" with no token, or a token that doesn't match the current
// prompt, must never be treated as an answer — Approve keeps waiting
// instead of resolving on it.
func TestTerminalApproverIgnoresUntaggedInput(t *testing.T) {
	pr, pw := io.Pipe()
	out := &syncBuf{}
	a := NewTerminalApprover(pr, out)

	resCh := make(chan bool, 1)
	errCh := make(chan error, 1)
	go func() {
		ok, err := a.Approve(context.Background(), gateway.ApprovalRequest{TaskID: "agt_x"})
		resCh <- ok
		errCh <- err
	}()

	token, _ := waitForToken(t, out, 0)
	// Untagged "y" and a wrong token must both be ignored.
	if _, err := pw.Write([]byte("y\nffffff y\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-resCh:
		t.Fatal("Approve() must not resolve on untagged or mismatched-token input")
	case <-time.After(200 * time.Millisecond):
	}

	// The real, correctly tagged (bare) answer still resolves it.
	if _, err := pw.Write([]byte(token + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-resCh:
		if err := <-errCh; err != nil || !ok {
			t.Fatalf("Approve() = %v, %v; want true, nil", ok, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Approve() never resolved on the correctly tagged answer")
	}
}

func TestTerminalApproverDeniesOnEOF(t *testing.T) {
	in := strings.NewReader("")
	var out bytes.Buffer
	a := NewTerminalApprover(in, &out)
	ok, err := a.Approve(context.Background(), gateway.ApprovalRequest{TaskID: "agt_x"})
	if err == nil || ok {
		t.Fatalf("Approve() on closed input = %v, %v; want false, non-nil error", ok, err)
	}
}

// TestTerminalApproverCancelledPromptNeverLeaksIntoNextAnswer is the
// codex-round-1 P1 regression: an operator's answer typed for a prompt
// that already died (task cancelled) must never be silently consumed as
// the answer to a later, unrelated prompt on the shared terminal — even
// when the stray answer arrives strictly AFTER the next prompt has
// already started waiting (the timing the original pre-drain-only
// design could not close, since the drain only ever ran once, before the
// new prompt was shown).
func TestTerminalApproverCancelledPromptNeverLeaksIntoNextAnswer(t *testing.T) {
	pr, pw := io.Pipe()
	out := &syncBuf{}
	a := NewTerminalApprover(pr, out)

	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan struct{})
	go func() {
		ok, err := a.Approve(ctx, gateway.ApprovalRequest{TaskID: "agt_first"})
		if err == nil || ok {
			t.Errorf("first Approve() = %v, %v; want false, non-nil (cancelled)", ok, err)
		}
		close(firstDone)
	}()

	firstToken, offset := waitForToken(t, out, 0)
	cancel()
	<-firstDone

	// Start the second, unrelated prompt BEFORE the stray answer for the
	// first arrives — this is exactly the ordering a pre-drain step
	// cannot handle.
	secondDone := make(chan struct{ ok bool })
	go func() {
		ok, err := a.Approve(context.Background(), gateway.ApprovalRequest{TaskID: "agt_second"})
		if err != nil {
			t.Errorf("second Approve() error: %v", err)
		}
		secondDone <- struct{ ok bool }{ok}
	}()
	secondToken, _ := waitForToken(t, out, offset)
	if secondToken == firstToken {
		t.Fatal("second prompt must mint a fresh token, not reuse the first's")
	}

	// The operator, unaware the first prompt already died, answers it
	// late using its (now stale) token — after the second prompt is
	// already visible and waiting.
	if _, err := pw.Write([]byte(firstToken + " y\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-secondDone:
		t.Fatalf("stray answer for the dead first prompt must not resolve the second, got ok=%v", r.ok)
	case <-time.After(200 * time.Millisecond):
	}

	// The real answer to the second prompt still works.
	if _, err := pw.Write([]byte(secondToken + " n\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-secondDone:
		if r.ok {
			t.Fatal("second prompt's own 'n' answer must deny")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Approve() never resolved on its own correctly tagged answer")
	}
}

func TestIsInteractiveTerminalFalseForPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	if isInteractiveTerminal(r) {
		t.Error("an os.Pipe() end must not be reported as an interactive terminal")
	}
}
