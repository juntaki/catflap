// Package sshhost is the new core of Catflap: an embedded SSH server
// bound to one ephemeral task. There is no command allowlist, no
// filesystem capability, and no approval flow here — the OS account
// `catflap share` runs as already defines what the agent can do,
// exactly like a normal SSH login. What Catflap adds is that the
// endpoint, the route to it, and the credential that authenticates
// against it all live no longer than the task itself:
//
//   - the SSH host key is generated fresh per task and exists only in
//     memory;
//   - the one client key allowed to authenticate is registered during
//     pairing and is exact-match only — no authorized_keys file, no
//     persistence;
//   - the whole task is torn down by its own TTL, an explicit revoke,
//     or process shutdown, which cancels every in-flight command's
//     context and closes the listener — the access dies with the task,
//     including anything it started.
package sshhost

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	gossh "golang.org/x/crypto/ssh"

	ssh "github.com/tailscale/gliderssh"

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/transport"
)

// Task is one live ephemeral SSH endpoint. Its context governs every
// command it runs: cancelling it (TTL, revoke, shutdown) kills every
// in-flight process tree, not just new connection attempts.
type Task struct {
	ID        string
	ExpiresAt time.Time
	Audit     *audit.Logger

	hostSigner gossh.Signer
	// sshSrv is ONE gliderssh.Server shared by every connection this
	// task ever accepts (constructed once in NewTask, not per-connection):
	// gliderssh.Server.Close "immediately closes all active listeners and
	// all active connections", which is exactly what Stop needs to sever
	// a client mid-session, not just refuse new connections — a
	// per-connection Server instance would have nothing for Stop to
	// reach back into.
	sshSrv *ssh.Server

	mu         sync.Mutex
	allowedKey gossh.PublicKey // nil until pairing registers one; no key authenticates until then

	ctx    context.Context
	cancel context.CancelCauseFunc

	stopOnce sync.Once
	stopDone chan struct{}
	// onStop releases task-external resources (the task's transport
	// server). Set by the caller before the task starts serving.
	onStop func()
}

// causeExpired/causeRevoked/causeShutdown distinguish why a task's
// context was cancelled, mirroring gateway.Task's terminationCause —
// a session killed by expiry should not be reported the same as one
// killed by an explicit revoke.
var (
	errExpired  = fmt.Errorf("task expired")
	errRevoked  = fmt.Errorf("task revoked")
	errShutdown = fmt.Errorf("task shutdown")
)

func causeFor(reason string) error {
	switch reason {
	case "revoked":
		return errRevoked
	case "shutdown":
		return errShutdown
	default:
		return errExpired
	}
}

// NewTask mints a task with a fresh ephemeral Ed25519 host key and a
// context that self-cancels at ttl. No client key is allowed until
// SetAllowedKey registers one (see pairing).
func NewTask(parent context.Context, id string, ttl time.Duration, alog *audit.Logger) (*Task, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("wrap host key: %w", err)
	}
	ctx, cancel := context.WithCancelCause(parent)
	t := &Task{
		ID: id, ExpiresAt: time.Now().Add(ttl), Audit: alog,
		hostSigner: signer, ctx: ctx, cancel: cancel,
		stopDone: make(chan struct{}),
	}
	t.sshSrv = &ssh.Server{
		HostSigners: []ssh.Signer{t.hostSigner},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session": ssh.DefaultSessionHandler,
		},
		PublicKeyHandler: func(_ ssh.Context, key ssh.PublicKey) error {
			allowed := t.getAllowedKey()
			if allowed == nil || !ssh.KeysEqual(key, allowed) {
				return fmt.Errorf("unauthorized key")
			}
			return nil
		},
		Handler: t.handleSession,
	}
	time.AfterFunc(ttl, func() { t.Stop("expired") })
	return t, nil
}

// HostKeyAuthorizedLine renders the task's host public key in
// authorized_keys/known_hosts line format, for delivery to the client
// during pairing.
func (t *Task) HostKeyAuthorizedLine() string {
	return string(gossh.MarshalAuthorizedKey(t.hostSigner.PublicKey()))
}

// SetAllowedKey registers the exact client public key pairing
// delivered. Only this key will ever authenticate against this task —
// there is no allowlist file and no way to add a second key.
func (t *Task) SetAllowedKey(k gossh.PublicKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.allowedKey = k
}

func (t *Task) getAllowedKey() gossh.PublicKey {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.allowedKey
}

// OnStopFunc sets the external-release hook (closes the task's
// transport server). Must be set before the task starts serving.
func (t *Task) OnStopFunc(f func()) { t.onStop = f }

// Stop tears the task down: cancels every in-flight command, closes
// the transport server via onStop, and closes the audit sink. Safe to
// call more than once and from multiple goroutines; only the first
// call has effect.
func (t *Task) Stop(reason string) {
	t.stopOnce.Do(func() {
		t.cancel(causeFor(reason))
		// Closing the shared gliderssh.Server severs every currently
		// open SSH connection for this task, not just future ones — a
		// revoke/expiry/shutdown must disconnect an already-paired
		// client sitting in an interactive session, not merely stop
		// admitting new ones. Cancelling t.ctx above already kills any
		// in-flight exec'd process tree; this is what kills the
		// connection carrying an idle PTY with nothing running yet.
		_ = t.sshSrv.Close()
		if t.Audit != nil {
			t.Audit.LogTerminal(reason)
		}
		if t.onStop != nil {
			t.onStop()
		}
		if t.Audit != nil {
			_ = t.Audit.Close()
		}
		close(t.stopDone)
	})
}

// Done reports when the task has been stopped.
func (t *Task) Done() <-chan struct{} { return t.stopDone }

// Handler returns the transport.Handler for this task: one gliderssh
// server, bound to the task's host key and its (initially absent, set
// by pairing) allowed client key. Every session it runs is rooted in
// the task's own context, so Stop kills every in-flight command.
func (t *Task) Handler() transport.Handler {
	return func(conn net.Conn) { t.sshSrv.HandleConn(conn) }
}

// auditExec logs one command's shape and outcome — never its output —
// so the audit trail shows what ran and how it ended without capturing
// arbitrary command output as an implicit second copy of the session.
func (t *Task) auditExec(rawCommand string, pty bool, start time.Time, exitCode int, err error) {
	if t.Audit == nil {
		return
	}
	decision := "allow"
	if err != nil && t.ctx.Err() != nil {
		decision = "terminated"
	}
	args := fmt.Sprintf(`{"command":%q,"pty":%v}`, rawCommand, pty)
	result := fmt.Sprintf(`{"exit_code":%d}`, exitCode)
	t.Audit.Log("ssh_exec", []byte(args), decision, []byte(result), time.Since(start))
}

// handleSession runs one SSH session's command (or login shell, if the
// client sent none) to completion, wired to a PTY when the client
// requested one. Every command is rooted in the task's own context:
// task expiry/revoke/shutdown kills it immediately, not just future
// sessions.
func (t *Task) handleSession(s ssh.Session) {
	start := time.Now()
	shell := loginShell()
	var cmd *exec.Cmd
	if raw := s.RawCommand(); raw != "" {
		// Match real sshd: an exec request runs "$SHELL -c <raw command
		// text>", not an argv Catflap parses and execs directly. Catflap
		// has no command allowlist to protect by avoiding a shell here —
		// the OS account is the boundary now — and the caller (an agent
		// driving builds/tests, or a human's own ssh client) expects
		// ordinary shell semantics: pipes, &&, redirection, quoting.
		//nolint:gosec // reason: this IS the SSH exec primitive; running the client's command text through the login shell is standard sshd behavior, not a shell-injection surface — there is no separate trusted argv this could be smuggled past.
		cmd = exec.CommandContext(t.ctx, shell, "-c", raw)
	} else {
		//nolint:gosec // reason: no untrusted argv here — this launches the user's own login shell for an interactive session, matching sshd with no command in the exec/session request.
		cmd = exec.CommandContext(t.ctx, shell, "-l")
	}

	ptyReq, winCh, isPty := s.Pty()
	var exitCode int
	var runErr error
	if isPty {
		cmd.Env = append(os.Environ(), "TERM="+ptyReq.Term)
		f, err := pty.Start(cmd)
		if err != nil {
			_ = s.Exit(1)
			t.auditExec(s.RawCommand(), true, start, 1, err)
			return
		}
		go func() {
			for win := range winCh {
				_ = pty.Setsize(f, &pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)}) //nolint:gosec // reason: SSH window dimensions are small terminal row/col counts, never large enough to overflow uint16 in practice; a client sending an absurd value just clamps via wraparound, no memory-safety issue.
			}
		}()
		go func() { _, _ = io.Copy(f, s) }()
		_, _ = io.Copy(s, f)
		runErr = cmd.Wait()
		_ = f.Close()
	} else {
		cmd.Stdin = s
		cmd.Stdout = s
		cmd.Stderr = s.Stderr()
		runErr = cmd.Run()
	}

	switch {
	case cmd.ProcessState != nil:
		exitCode = cmd.ProcessState.ExitCode()
	case runErr != nil:
		exitCode = 1
	}
	t.auditExec(s.RawCommand(), isPty, start, exitCode, runErr)
	_ = s.Exit(exitCode)
}

func loginShell() string {
	if sh := os.Getenv("SHELL"); sh != "" {
		return sh
	}
	return "/bin/sh"
}

// NewID mints a random task id, matching capability.NewTaskID's shape
// without importing the (soon to be retired) capability package.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "agt_" + hex.EncodeToString(b[:])[:16]
}
