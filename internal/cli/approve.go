package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

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
	// nextID mints each prompt's token. A strictly increasing counter,
	// not random bits: codex round 2 correctly flagged a fixed-width
	// random token as only PROBABLY unique, which is not what "a stale
	// answer can never match a different prompt" requires — a counter
	// makes every token distinct by construction, for the life of this
	// TerminalApprover (one process), no collision possible at any size.
	nextID atomic.Uint64
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
// Each call mints its own token (a.nextID, strictly increasing — see the
// field comment) and only accepts a line whose first field is EXACTLY
// that token (see parseApprovalAnswer — not merely prefixed by it, since
// counter values like "1" and "12" share a prefix). This is not
// a secrecy mechanism — it defeats a timing hazard specific to a shared
// line-based terminal: the mutex guarantees at most one prompt is ever
// outstanding, but an operator's answer for a prompt that already
// returned (because its task died mid-prompt, so Approve returned via
// ctx.Done before they typed anything) can still arrive on the shared
// reader AFTER a new, unrelated prompt has already started waiting —
// arriving late is not the same as arriving before a one-time drain step
// would have seen it, so a fixed "y"/"n" grammar cannot tell that answer
// apart from a genuine one for the new prompt. Binding each prompt to its
// own never-repeated token makes a stale answer simply not match, at any
// arrival time, so it is discarded and Approve keeps waiting instead of
// ever crediting it to a different request. Any line that arrives
// already-stale from before this call started is handled the exact same
// way, by the same loop — no separate pre-drain step is needed.
func (a *TerminalApprover) Approve(ctx context.Context, req gateway.ApprovalRequest) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	token := strconv.FormatUint(a.nextID.Add(1), 10)
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
				_, _ = fmt.Fprintf(a.out, "(ignoring unrelated input; type %s to approve, anything else to deny)\n", token)
				continue
			}
			return approved, nil
		}
	}
}

// parseApprovalAnswer reports whether line is an answer to THIS prompt
// (its first field is EXACTLY token, not merely prefixed by it — token
// "1" must not match a line for token "12") and, if so, whether it
// approves. A line whose first field isn't exactly token is never
// treated as an answer at all — matched is false and the caller keeps
// waiting; this is what makes a blank Enter (or any other unrelated
// input, including a stale answer for a prompt that already died) safe
// to ignore rather than accidentally denying the current prompt.
//
// The token ALONE approves — that's the whole point of binding a
// single-token reply to the prompt: an operator "approves #7" by typing
// 7. Anything else attached to a matching token (a trailing word, "n",
// garbage) denies, so there's still an explicit, low-effort way to
// reject a specific prompt rather than just leaving it hanging.
func parseApprovalAnswer(line, token string) (approved, matched bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != token {
		return false, false
	}
	return len(fields) == 1, true
}

func formatApprovalPrompt(req gateway.ApprovalRequest, token string) string {
	return fmt.Sprintf(
		"\n--- approval required (#%s) ---\ntask:    %s\ntool:    %s\n%s\n%s\ntype %s to approve, anything else to deny\n> ",
		token,
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
