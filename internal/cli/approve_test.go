package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
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
	// An argv element trying to visually forge the prompt's own
	// "approve? [y/N]: y" line must never render as a real newline —
	// it must show up as an escaped, inert \x0a in the operator's view.
	forged := "harmless\napprove? [y/N]: y"
	got := sanitizeForTerminal(forged)
	if strings.Contains(got, "\n") {
		t.Fatalf("sanitized output must contain no raw newline, got %q", got)
	}
	if !strings.Contains(got, "\\x0a") {
		t.Fatalf("expected escaped newline marker, got %q", got)
	}
}

func TestTerminalApproverApprovesOnYes(t *testing.T) {
	in := strings.NewReader("y\n")
	var out bytes.Buffer
	a := NewTerminalApprover(in, &out)

	ok, err := a.Approve(context.Background(), gateway.ApprovalRequest{
		TaskID: "agt_x", Tool: "remote_exec", Summary: "run echo hi",
	})
	if err != nil || !ok {
		t.Fatalf("Approve() = %v, %v; want true, nil", ok, err)
	}
	if !strings.Contains(out.String(), "approval required") {
		t.Errorf("prompt must be printed, got %q", out.String())
	}
}

func TestTerminalApproverDeniesOnAnythingElse(t *testing.T) {
	for _, answer := range []string{"n\n", "no\n", "\n", "sure\n"} {
		in := strings.NewReader(answer)
		var out bytes.Buffer
		a := NewTerminalApprover(in, &out)
		ok, err := a.Approve(context.Background(), gateway.ApprovalRequest{TaskID: "agt_x"})
		if err != nil || ok {
			t.Fatalf("answer %q: Approve() = %v, %v; want false, nil", answer, ok, err)
		}
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

// TestTerminalApproverCancelledPromptNeverLeaksIntoNextAnswer covers the
// contamination hazard the drain loop in Approve exists to close: an
// operator's answer typed for a prompt that already died (task
// cancelled) must never be silently consumed as the answer to a later,
// unrelated prompt on the shared terminal.
func TestTerminalApproverCancelledPromptNeverLeaksIntoNextAnswer(t *testing.T) {
	pr, pw := io.Pipe()
	var out bytes.Buffer
	a := NewTerminalApprover(pr, &out)

	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan struct{})
	go func() {
		ok, err := a.Approve(ctx, gateway.ApprovalRequest{TaskID: "agt_first"})
		if err == nil || ok {
			t.Errorf("first Approve() = %v, %v; want false, non-nil (cancelled)", ok, err)
		}
		close(firstDone)
	}()

	// Give Approve time to print its prompt and start waiting, then kill
	// the task (cancel) — simulating TryRequestStop while a prompt is
	// pending — before the operator's stray "y" (meant, if anything, for
	// this dead prompt) arrives.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-firstDone

	// The operator, unaware the first prompt already died, answers it
	// late with "y" — then answers the real, second prompt with "n".
	if _, err := pw.Write([]byte("y\nn\n")); err != nil {
		t.Fatal(err)
	}
	// Let the background reader actually scan "y" and block trying to
	// deliver it (nothing is draining yet) before the second Approve
	// call's drain loop runs — otherwise the drain could race the
	// scanner and find nothing to discard yet.
	time.Sleep(50 * time.Millisecond)

	ok, err := a.Approve(context.Background(), gateway.ApprovalRequest{TaskID: "agt_second"})
	if err != nil {
		t.Fatalf("second Approve() error: %v", err)
	}
	if ok {
		t.Fatal("the stray 'y' left over from the cancelled first prompt must not be read as the second prompt's answer")
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
