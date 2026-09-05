package gateway

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/policy"
	"github.com/juntaki/catflap/internal/rpc"
	"github.com/juntaki/catflap/internal/safefs"
)

// ApprovalRequest is one operator approval prompt. Hash is the scope
// identity: approval covers exactly this normalized request, and any
// mutation produces a different hash that is not covered.
type ApprovalRequest struct {
	TaskID     string
	Tool       string
	Summary    string
	Detail     string
	Normalized string
	Hash       string
}

// Approver asks the operator to authorize one normalized request. It runs
// in the serve process, fed by the operator's terminal — never by the
// agent: the agent's only channel is MCP, which cannot answer prompts.
// A nil Approver denies everything that requires approval (headless safe
// default); headless automation uses approval:never-only policies.
type Approver interface {
	Approve(ctx context.Context, req ApprovalRequest) (bool, error)
}

// normalizeExecRequest builds the approval identity for one argv vector.
// The preimage covers the RESOLVED executable path plus exact argv, so any
// mutation — different binary, reordered flags, one changed character —
// yields a different hash that no prior approval covers.
func normalizeExecRequest(taskID, exe string, argv []string) ApprovalRequest {
	var b strings.Builder
	b.WriteString("exec\x00")
	b.WriteString(exe)
	for _, a := range argv {
		b.WriteString("\x00")
		b.WriteString(a)
	}
	normalized := b.String()
	sum := sha256.Sum256([]byte(normalized))
	display := "exec " + exe
	if len(argv) > 0 {
		display += " " + strings.Join(argv, " ")
	}
	return ApprovalRequest{
		TaskID: taskID, Tool: rpc.ToolExec,
		Summary:    truncateDisplay(display, 200),
		Detail:     "command: " + exe + "\nargv: " + strings.Join(argv, " "),
		Normalized: normalized,
		Hash:       hex.EncodeToString(sum[:]),
	}
}

// normalizeWriteRequest builds the approval identity for one file write.
// The preimage covers the absolute path plus the content hash, so rewriting
// different bytes to the same path is a different request.
func normalizeWriteRequest(taskID, absPath string, content []byte) ApprovalRequest {
	contentSum := sha256.Sum256(content)
	contentHash := hex.EncodeToString(contentSum[:])
	normalized := "write\x00" + absPath + "\x00" + contentHash
	sum := sha256.Sum256([]byte(normalized))
	preview := string(content)
	if len(preview) > 500 {
		preview = preview[:500] + "…(truncated)"
	}
	return ApprovalRequest{
		TaskID: taskID, Tool: rpc.ToolWrite,
		Summary:    fmt.Sprintf("write %s (%d bytes, sha256:%s…)", absPath, len(content), contentHash[:12]),
		Detail:     fmt.Sprintf("path: %s\nsize: %d\nsha256: %s\npreview:\n%s", absPath, len(content), contentHash, preview),
		Normalized: normalized,
		Hash:       hex.EncodeToString(sum[:]),
	}
}

func truncateDisplay(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// checkApproval enforces never/once/always for one normalized request.
// "" means authorized, else the denial message. Requested/granted/
// denied decisions are audited; static allows are audited by the caller.
// Approvers MUST respect ctx (task death aborts the prompt); the prompt
// holds one concurrency slot while waiting.
func (t *Task) checkApproval(req ApprovalRequest, mode policy.ApprovalMode) string {
	if mode == policy.ApprovalNever {
		return ""
	}
	if mode == policy.ApprovalOnce && t.isApproved(req.Hash) {
		return ""
	}
	if t.Audit != nil {
		t.Audit.Log("approval", []byte(req.Normalized), "requested", nil, 0)
	}
	approver := t.getApprover()
	if approver == nil {
		if t.Audit != nil {
			t.Audit.Log("approval", []byte(req.Normalized), "denied", nil, 0)
		}
		return "approval required by policy (no operator approver attached; run serve with --approval=terminal or use approval:never)"
	}
	ok, err := approver.Approve(t.Context(), req)
	if err != nil || !ok {
		if t.Audit != nil {
			t.Audit.Log("approval", []byte(req.Normalized), "denied", nil, 0)
		}
		if err != nil {
			return fmt.Sprintf("approval failed: %v", err)
		}
		return "approval denied by operator"
	}
	if t.Audit != nil {
		t.Audit.Log("approval", []byte(req.Normalized), "granted", nil, 0)
	}
	if mode == policy.ApprovalOnce {
		t.recordApproval(req.Hash)
	}
	return ""
}

// Task termination causes. Stop(reason) cancels the task context with the
// matching cause so in-flight operations report *why* they died — and so
// the v0.2 structured error codes can key off the same values.
var (
	ErrTaskExpired  = errors.New("task expired")
	ErrTaskRevoked  = errors.New("task revoked")
	ErrTaskShutdown = errors.New("task shutdown")
)

// causeForReason maps a Stop reason to its cancellation cause.
func causeForReason(reason string) error {
	switch reason {
	case "revoked":
		return ErrTaskRevoked
	case "shutdown":
		return ErrTaskShutdown
	default:
		return ErrTaskExpired
	}
}

// State is the task lifecycle state (§8). The zero value is StateCreating;
// a task becomes usable only after Activate, and Stop drives it through
// StateStopping to StateStopped exactly once.
type State int32

const (
	StateCreating State = iota
	StateActive
	StateStopping
	StateStopped
)

// String reports the lifecycle state for logs and diagnostics.
func (s State) String() string {
	switch s {
	case StateCreating:
		return "creating"
	case StateActive:
		return "active"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// Task is one live ephemeral grant: policy snapshot + expiry + audit chain.
// Stop tears the whole task down; expiry, revoke, and shutdown all funnel
// through it.
//
// The task owns a context: every in-flight operation derives from it, so
// termination cancels running execs instead of orphaning them past the TTL.
// "The access dies with the task" includes already-started processes.
type Task struct {
	ID        string
	Secret    string
	Policy    *policy.Policy
	ExpiresAt time.Time
	Audit     *audit.Logger
	AgentKey  string

	ctx      context.Context
	cancel   context.CancelCauseFunc
	stopOnce sync.Once
	// opMu + state + wg form the operation registry: Stop flips the state
	// (new ops fail), cancels the context (running ops die), then drains
	// in-flight ops boundedly before the terminal audit event and close.
	opMu  sync.Mutex
	state atomic.Int32 // State
	wg    sync.WaitGroup
	// sem bounds concurrent operations per task (limits.max_concurrent_calls).
	// Sized in InitContext; admission is non-blocking (fail fast on exhaustion).
	sem chan struct{}
	// approver answers operator approval prompts (nil = deny all gated
	// calls). approved records once-scoped grants by normalized request
	// hash; guarded by apMu.
	approver Approver
	apMu     sync.Mutex
	approved map[string]bool
	// onStop releases task-external resources (its Tailcat server).
	// Set by the serve loop; nil in tests.
	onStop func()
}

// SetApprover installs the operator approver for the task.
func (t *Task) SetApprover(a Approver) {
	t.apMu.Lock()
	defer t.apMu.Unlock()
	t.approver = a
	if t.approved == nil {
		t.approved = map[string]bool{}
	}
}

func (t *Task) isApproved(hash string) bool {
	t.apMu.Lock()
	defer t.apMu.Unlock()
	return t.approved[hash]
}

func (t *Task) recordApproval(hash string) {
	t.apMu.Lock()
	defer t.apMu.Unlock()
	if t.approved == nil {
		t.approved = map[string]bool{}
	}
	t.approved[hash] = true
}

func (t *Task) getApprover() Approver {
	t.apMu.Lock()
	defer t.apMu.Unlock()
	return t.approver
}

// StateOf returns the current lifecycle state.
func (t *Task) StateOf() State { return State(t.state.Load()) }

// Activate moves a created task to ACTIVE. Called once the task's server,
// handler binding, audit, and expiry are all armed — capabilities MUST NOT
// be emitted before this point (§8.1).
func (t *Task) Activate() { t.state.Store(int32(StateActive)) }

// TryActivate moves a created task to ACTIVE, but only from CREATING.
// Compare-and-swap: a task that already left Creating (stopping, stopped)
// can never be reactivated, closing the shutdown/commit race.
func (t *Task) TryActivate() bool {
	return t.state.CompareAndSwap(int32(StateCreating), int32(StateActive))
}

// InitContext arms the task's cancellation scope under a non-nil parent
// (the serve root context in production, Background in tests) and sizes
// the concurrency semaphore from the effective limits. Idempotent.
func (t *Task) InitContext(parent context.Context) {
	if t.ctx == nil {
		t.ctx, t.cancel = context.WithCancelCause(parent)
		n := t.Policy.EffectiveLimits().MaxConcurrentCalls
		if n < 1 {
			n = 1
		}
		t.sem = make(chan struct{}, n)
	}
}

// Context returns the task scope, or Background for tasks that never armed it.
func (t *Task) Context() context.Context {
	if t.ctx == nil {
		return context.Background()
	}
	return t.ctx
}

// Stop destroys the task with the given reason ("expired", "revoked",
// "shutdown"). Ordering is fixed:
//
//	stop accepting → cancel task context (kill trees) → bounded drain of
//	in-flight ops → terminal audit event → release server → close audit.
//
// It MUST be followed by Store.Delete, and every termination path (expiry,
// revoke, shutdown) funnels through it (INV-3).
func (t *Task) Stop(reason string) {
	t.stopOnce.Do(func() {
		if reason == "" {
			reason = "shutdown"
		}
		t.opMu.Lock()
		t.state.Store(int32(StateStopping))
		t.opMu.Unlock()
		if t.cancel != nil {
			t.cancel(causeForReason(reason)) // kill running trees with cause
		}
		drained := make(chan struct{})
		go func() { t.wg.Wait(); close(drained) }()
		select {
		case <-drained:
		case <-time.After(10 * time.Second):
		}
		if t.Audit != nil {
			t.Audit.LogTerminal(reason)
		}
		if t.onStop != nil {
			t.onStop()
		}
		if t.Audit != nil {
			_ = t.Audit.Close()
		}
		t.state.Store(int32(StateStopped))
	})
}

// beginOp registers an in-flight operation, enforcing the ACTIVE state and
// the per-task concurrency bound. A non-empty return is the denial reason
// ("task stopping" or "concurrency limit exceeded"); "" means admitted and
// the caller MUST defer endOp.
func (t *Task) beginOp() string {
	t.opMu.Lock()
	defer t.opMu.Unlock()
	if State(t.state.Load()) != StateActive {
		return "task stopping"
	}
	if t.sem == nil {
		return "task stopping"
	}
	select {
	case t.sem <- struct{}{}:
	default:
		return "concurrency limit exceeded"
	}
	t.wg.Add(1)
	return ""
}

func (t *Task) endOp() {
	<-t.sem
	t.wg.Done()
}

// Store holds live tasks. The zero value is ready.
type Store struct {
	mu    sync.RWMutex
	tasks map[string]*Task
}

// Add registers a task.
func (s *Store) Add(t *Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tasks == nil {
		s.tasks = map[string]*Task{}
	}
	s.tasks[t.ID] = t
}

// Delete removes a task so its id/secret can never authenticate again.
// Call t.Stop(reason) first to release its server and audit handle.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tasks, id)
}

// Lookup returns the task if its secret matches (constant-time).
func (s *Store) Lookup(id, secret string) (*Task, bool) {
	s.mu.RLock()
	t, ok := s.tasks[id]
	s.mu.RUnlock()
	if !ok || t == nil {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(t.Secret), []byte(secret)) != 1 {
		return nil, false
	}
	return t, true
}

// OnStopFunc sets the external-release hook. Used by the serve loop to bind
// each task to its own network server (1 task = 1 server).
func (t *Task) OnStopFunc(f func()) { t.onStop = f }

// TaskInfo is a lock-free snapshot for the admin API.
type TaskInfo struct {
	ID        string
	Policy    string
	ExpiresAt time.Time
	AgentKey  string
}

// List returns task snapshots for the admin API.
func (s *Store) List() []TaskInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TaskInfo, 0, len(s.tasks))
	for _, t := range s.tasks {
		name := ""
		if t.Policy != nil {
			name = t.Policy.Name
		}
		out = append(out, TaskInfo{ID: t.ID, Policy: name, ExpiresAt: t.ExpiresAt, AgentKey: t.AgentKey})
	}
	return out
}

// Expired reports whether the task is past its TTL.
func (t *Task) Expired(now time.Time) bool { return !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt) }

// Handler returns a transport.Handler dispatching JSONL RPC with per-task auth.
// The handler is unbound: any task in the store may authenticate. Prefer
// HandlerFor so a stolen secret cannot be replayed at another task's endpoint.
func (s *Store) Handler() func(net.Conn) {
	return func(conn net.Conn) { s.serveConn(conn, "") }
}

// HandlerFor returns a handler bound to one task: requests naming any other
// task are denied BEFORE secret lookup, even when the secret is valid.
// This binds network credential (which endpoint you reached) to RPC
// credential (which task secret you present): A-endpoint + B-secret = DENY.
func (s *Store) HandlerFor(taskID string) func(net.Conn) {
	return func(conn net.Conn) { s.serveConn(conn, taskID) }
}

func (s *Store) serveConn(conn net.Conn, boundTaskID string) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReaderSize(conn, 64<<10)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := rpc.ReadRequest(r)
		if err != nil {
			return
		}
		res := s.handleRPC(req, boundTaskID)
		if err := rpc.WriteResponse(conn, res); err != nil {
			return
		}
	}
}

// handleRPC authenticates then dispatches one call with auditing.
// boundTaskID, when non-empty, pins this connection to one task: a request
// for any other task is denied before its secret is even examined.
func (s *Store) handleRPC(req rpc.Request, boundTaskID string) rpc.Response {
	if boundTaskID != "" && req.Task != boundTaskID {
		// Attribute the attempt to the endpoint owner for forensics.
		s.mu.RLock()
		owner := s.tasks[boundTaskID]
		s.mu.RUnlock()
		if owner != nil && owner.Audit != nil {
			owner.Audit.Log(req.Tool, req.Args, "deny", nil, 0)
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "task does not belong to this endpoint"}
	}
	t, ok := s.Lookup(req.Task, req.Secret)
	if !ok {
		return rpc.Response{ID: req.ID, OK: false, Error: "unknown task or bad secret"}
	}
	if t.Expired(time.Now()) {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "expired", nil, 0)
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "capability expired"}
	}
	if reason := t.beginOp(); reason != "" {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "deny", nil, 0)
		}
		return rpc.Response{ID: req.ID, OK: false, Error: reason}
	}
	defer t.endOp()
	switch req.Tool {
	case rpc.ToolExec:
		return s.doExec(t, req)
	case rpc.ToolRead:
		return s.doRead(t, req)
	case rpc.ToolStat:
		return s.doStat(t, req)
	case rpc.ToolWrite:
		return s.doWrite(t, req)
	default:
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "deny", nil, 0)
		}
		return rpc.Response{ID: req.ID, OK: false, Error: fmt.Sprintf("unknown tool %q", req.Tool)}
	}
}

func (s *Store) doExec(t *Task, req rpc.Request) rpc.Response {
	start := time.Now()
	var args rpc.ExecArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return rpc.Response{ID: req.ID, OK: false, Error: "bad exec args"}
	}
	exe, ok := t.Policy.MatchExec(args.Command, args.Args)
	if !ok {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "deny", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "command not allowed by policy"}
	}
	lim := t.Policy.EffectiveLimits()
	timeout := time.Duration(args.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout > lim.MaxExecDuration {
		timeout = lim.MaxExecDuration
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	// No shell, ever: argv goes straight to the pinned executable.
	//nolint:gosec // reason: this is the allowlisted exec primitive itself — MatchExec pins a policy executable and argv shape, and no shell interprets anything.
	cmd := exec.CommandContext(ctx, exe, args.Args...)
	startDetached(cmd) // own process group: expiry kills the whole tree
	// Narrow environment: no passthrough of caller env.
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/local/bin", "LC_ALL=C"}
	stdout, stderr := boundedBuffer(lim.MaxStdoutBytes), boundedBuffer(lim.MaxStderrBytes)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	res := rpc.ExecResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		// Task death outranks every other failure: an exec killed by
		// termination must report its cause, never a normal result. The
		// group SIGKILL already landed via cmd.Cancel at cancel time.
		if t.Context().Err() != nil {
			msg, decision := "capability expired", "expired"
			switch {
			case errors.Is(context.Cause(t.Context()), ErrTaskRevoked):
				msg, decision = "task revoked", "revoked"
			case errors.Is(context.Cause(t.Context()), ErrTaskShutdown):
				msg, decision = "task shutdown", "shutdown"
			}
			if t.Audit != nil {
				t.Audit.Log(req.Tool, req.Args, decision, nil, time.Since(start))
			}
			return rpc.Response{ID: req.ID, OK: false, Error: msg}
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = 127
			if ctx.Err() == context.DeadlineExceeded {
				if t.Audit != nil {
					t.Audit.Log(req.Tool, req.Args, "error", nil, time.Since(start))
				}
				return rpc.Response{ID: req.ID, OK: false, Error: "command timed out"}
			}
		}
	}
	raw := rpc.MustRaw(res)
	if t.Audit != nil {
		t.Audit.Log(req.Tool, req.Args, "allow", raw, time.Since(start))
	}
	return rpc.Response{ID: req.ID, OK: true, Result: raw}
}

func (s *Store) doRead(t *Task, req rpc.Request) rpc.Response {
	start := time.Now()
	var args rpc.ReadArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return rpc.Response{ID: req.ID, OK: false, Error: "bad read args"}
	}
	if args.Path == "" {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "deny", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "path not allowed by policy"}
	}
	fs := t.Policy.ReadFS()
	if fs == nil {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "deny", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "file read is not allowed by policy"}
	}
	f, err := fs.OpenRead(args.Path)
	if err != nil {
		decision := "deny"
		if isStatError(err) {
			decision = "error"
		}
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, decision, nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: err.Error()}
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "error", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "stat: " + err.Error()}
	}
	data, truncated, err := safefs.ReadAllCapped(f, t.Policy.EffectiveLimits().MaxReadBytes)
	if err != nil {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "error", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "read: " + err.Error()}
	}
	res := rpc.ReadResult{Size: info.Size(), Content: string(data), Truncated: truncated}
	raw := rpc.MustRaw(res)
	if t.Audit != nil {
		t.Audit.Log(req.Tool, req.Args, "allow", raw, time.Since(start))
	}
	return rpc.Response{ID: req.ID, OK: true, Result: raw}
}

func (s *Store) doStat(t *Task, req rpc.Request) rpc.Response {
	start := time.Now()
	var args rpc.StatArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return rpc.Response{ID: req.ID, OK: false, Error: "bad stat args"}
	}
	if args.Path == "" {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "deny", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "path not allowed by policy"}
	}
	fs := t.Policy.ReadFS()
	if fs == nil {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "deny", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "file read is not allowed by policy"}
	}
	info, err := fs.Stat(args.Path)
	if err != nil {
		decision := "deny"
		if isStatError(err) {
			decision = "error"
		}
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, decision, nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: err.Error()}
	}
	res := rpc.StatResult{
		Name: info.Name(), Size: info.Size(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime().UTC().Format(time.RFC3339),
		IsDir:   info.IsDir(),
	}
	raw := rpc.MustRaw(res)
	if t.Audit != nil {
		t.Audit.Log(req.Tool, req.Args, "allow", raw, time.Since(start))
	}
	return rpc.Response{ID: req.ID, OK: true, Result: raw}
}

// doWrite implements remote_write: the ONLY write path, and only through
// SafeFS with a file.write grant. Reads and writes are separate grants;
// without file.write this tool denies everything (default deny).
func (s *Store) doWrite(t *Task, req rpc.Request) rpc.Response {
	start := time.Now()
	var args rpc.WriteArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return rpc.Response{ID: req.ID, OK: false, Error: "bad write args"}
	}
	deny := func(msg string) rpc.Response {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "deny", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: msg}
	}
	if args.Path == "" {
		return deny("path not allowed by policy")
	}
	if t.Policy.Tools.File == nil || t.Policy.Tools.File.Write == nil {
		return deny("file write is not allowed by policy")
	}
	fs := t.Policy.WriteFS()
	if fs == nil {
		return deny("file write is not allowed by policy")
	}
	created := !existsForWrite(fs, args.Path)
	if err := fs.WriteFile(args.Path, []byte(args.Content), t.Policy.Tools.File.Write.Options()); err != nil {
		if isStatError(err) || isIOError(err) {
			if t.Audit != nil {
				t.Audit.Log(req.Tool, req.Args, "error", nil, time.Since(start))
			}
			return rpc.Response{ID: req.ID, OK: false, Error: err.Error()}
		}
		return deny(err.Error())
	}
	info, err := fs.Stat(args.Path)
	if err != nil {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "error", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "stat: " + err.Error()}
	}
	raw := rpc.MustRaw(rpc.WriteResult{Size: info.Size(), Created: created})
	if t.Audit != nil {
		t.Audit.Log(req.Tool, req.Args, "allow", raw, time.Since(start))
	}
	return rpc.Response{ID: req.ID, OK: true, Result: raw}
}

// existsForWrite probes existence for the Created flag. Informational only;
// the write itself re-resolves, so races here change metadata, not access.
func existsForWrite(fs *safefs.FS, path string) bool {
	_, err := fs.Stat(path)
	return err == nil
}

func isStatError(err error) bool {
	msg := err.Error()
	return len(msg) >= 6 && msg[:6] == "stat: "
}

func isIOError(err error) bool {
	for _, prefix := range []string{"open: ", "write: ", "read: ", "rename: ", "sync: ", "temp: ", "close: "} {
		if strings.HasPrefix(err.Error(), prefix) {
			return true
		}
	}
	return false
}
