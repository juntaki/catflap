package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
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
//
// Each call mints its own random token and only accepts a line that starts
// with it. This is not a secrecy mechanism — it defeats a timing hazard
// specific to a shared line-based terminal: the mutex guarantees at most
// one prompt is ever outstanding, but an operator's answer for a prompt
// that already returned (because its task died mid-prompt, so Approve
// returned via ctx.Done before they typed anything) can still arrive on
// the shared reader AFTER a new, unrelated prompt has already started
// waiting — arriving late is not the same as arriving before the drain
// step would see it, so a fixed "y"/"n" grammar cannot tell that answer
// apart from a genuine one for the new prompt. Binding each prompt to its
// own token makes a stale answer simply not match, at any arrival time,
// so it is discarded and Approve keeps waiting instead of ever crediting
// it to a different request. Any line that arrives already-stale from
// before this call started is handled the exact same way, by the same
// loop — no separate pre-drain step is needed.
func (a *TerminalApprover) Approve(ctx context.Context, req gateway.ApprovalRequest) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	token, err := shortApprovalToken()
	if err != nil {
		return false, fmt.Errorf("generate approval token: %w", err)
	}
	_, _ = fmt.Fprint(a.out, formatApprovalPrompt(req, token))

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case line, ok := <-a.lines:
			if !ok {
				return false, errors.New("approval input closed (EOF); denying")
			}
			approved, matched := parseApprovalAnswer(line, token)
			if !matched {
				_, _ = fmt.Fprintf(a.out, "(ignoring unrelated input; reply exactly: %s y  or  %s n)\n", token, token)
				continue
			}
			return approved, nil
		}
	}
}

// parseApprovalAnswer reports whether line is an answer to THIS prompt
// (its token prefix matches) and, if so, whether it approves. A line
// whose token does not match is never treated as an answer at all —
// matched is false and the caller keeps waiting.
func parseApprovalAnswer(line, token string) (approved, matched bool) {
	line = strings.TrimSpace(line)
	lower := strings.ToLower(line)
	tok := strings.ToLower(token)
	if !strings.HasPrefix(lower, tok) {
		return false, false
	}
	switch strings.TrimSpace(lower[len(tok):]) {
	case "y", "yes":
		return true, true
	default:
		return false, true
	}
}

func shortApprovalToken() (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func formatApprovalPrompt(req gateway.ApprovalRequest, token string) string {
	return fmt.Sprintf(
		"\n--- approval required ---\ntask:    %s\ntool:    %s\n%s\n%s\napprove? reply exactly: %s y   (anything else, including plain y/n, denies)\n> ",
		sanitizeForTerminal(req.TaskID),
		sanitizeForTerminal(req.Tool),
		sanitizeForTerminal(req.Summary),
		sanitizeForTerminal(req.Detail),
		token,
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
