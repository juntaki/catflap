package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/juntaki/catflap/internal/gateway"
)

// TerminalApprover is the operator-facing gateway.Approver for `serve` and
// `share`: it prints the pending operation to out and blocks on one line
// from in. One TerminalApprover is shared by every task in a process (they
// share the same terminal), so mu serializes prompts end to end — only one
// operation is ever on screen awaiting an answer at a time.
type TerminalApprover struct {
	out io.Writer
	mu  sync.Mutex
	// lines is fed by a single, permanent background reader (readLoop) —
	// never more than one goroutine ever reads `in`, so two concurrent
	// prompts can never race for the same keystroke.
	lines chan string
}

// NewTerminalApprover starts a permanent background reader over in and
// returns an Approver that prints prompts to out. Call this at most once
// per process input stream.
func NewTerminalApprover(in io.Reader, out io.Writer) *TerminalApprover {
	a := &TerminalApprover{out: out, lines: make(chan string)}
	go a.readLoop(in)
	return a
}

func (a *TerminalApprover) readLoop(in io.Reader) {
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		a.lines <- sc.Text()
	}
	close(a.lines)
}

// Approve implements gateway.Approver. It never returns until the operator
// answers, ctx is cancelled (the task died — TryRequestStop cancels the
// context checkApproval waits on), or the input stream closes.
func (a *TerminalApprover) Approve(ctx context.Context, req gateway.ApprovalRequest) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// The mutex means at most one prompt is ever outstanding, so anything
	// still sitting in `lines` right now was typed for a PREVIOUS prompt
	// that already returned (most likely: the task died and this
	// Approve call's predecessor returned on ctx.Done before the operator
	// answered). It must never be misread as the answer to THIS request —
	// drain it before showing the new prompt.
	for drained := false; !drained; {
		select {
		case _, ok := <-a.lines:
			if !ok {
				drained = true
			}
		default:
			drained = true
		}
	}

	_, _ = fmt.Fprint(a.out, formatApprovalPrompt(req))

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case line, ok := <-a.lines:
		if !ok {
			return false, errors.New("approval input closed (EOF); denying")
		}
		return parseApprovalAnswer(line), nil
	}
}

func parseApprovalAnswer(line string) bool {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func formatApprovalPrompt(req gateway.ApprovalRequest) string {
	return fmt.Sprintf(
		"\n--- approval required ---\ntask:    %s\ntool:    %s\n%s\n%s\napprove? [y/N]: ",
		sanitizeForTerminal(req.TaskID),
		sanitizeForTerminal(req.Tool),
		sanitizeForTerminal(req.Summary),
		sanitizeForTerminal(req.Detail),
	)
}

// sanitizeForTerminal makes an agent-controlled string safe to print to an
// operator's terminal. Exec argv and write paths reach here unfiltered by
// design (see normalizeExecRequest/normalizeWriteRequest in package
// gateway) precisely so this is the one place that owns display safety.
// Every C0 control byte and DEL is replaced by a visible \xNN escape —
// no exceptions for \n, \r, or \t — so an agent cannot use ANSI/terminal
// escape sequences to redraw the prompt, move the cursor, or splice in
// fake extra lines (e.g. a forged "approve? [y/N]: y"), and cannot use
// bare newlines to make one argv element masquerade as another prompt
// field. The escaped form is still fully legible for the operator's
// decision; it never feeds back into the approval hash.
func sanitizeForTerminal(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			fmt.Fprintf(&b, "\\x%02x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isInteractiveTerminal reports whether f looks like an interactive
// terminal rather than a pipe, file, or /dev/null. Used to decide whether
// `serve`/`share` may attach a TerminalApprover at all: with no operator
// on the other end, any policy rule requiring approval must fail closed
// (see gateway.Task.checkApproval's "no approver attached" path) rather
// than block forever or silently auto-approve.
func isInteractiveTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
