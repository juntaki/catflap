package gateway

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/policy"
	"github.com/juntaki/catflap/internal/rpc"
	"github.com/juntaki/catflap/internal/safefs"
)

// Task termination causes. Stop(reason) cancels the task context with the
// matching cause so in-flight operations report *why* they died — and so
// the v0.2 structured error codes can key off the same values.
var (
	ErrTaskExpired     = errors.New("task expired")
	ErrTaskRevoked     = errors.New("task revoked")
	ErrTaskShutdown    = errors.New("task shutdown")
	ErrTaskAuditFailed = errors.New("task audit sink failed")
)

// causeForReason maps a Stop reason to its cancellation cause.
func causeForReason(reason string) error {
	switch reason {
	case "revoked":
		return ErrTaskRevoked
	case "shutdown":
		return ErrTaskShutdown
	case "audit sink failed":
		return ErrTaskAuditFailed
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

// Task is one live ephemeral grant: policy snapshot + expiry + audit chain.
// Stop tears the whole task down; expiry, revoke, and shutdown all funnel
// through it.
//
// The task owns a context: every in-flight operation derives from it, so
// termination cancels running execs instead of orphaning them past the TTL.
// "The access dies with the task" includes already-started processes.
type Task struct {
	ID        string
	Name      string // human-readable task name, unique per serve process
	Secret    string
	Policy    *policy.Policy
	ExpiresAt time.Time
	Audit     *audit.Logger
	AgentKey  string

	ctx      context.Context
	cancel   context.CancelCauseFunc
	stopOnce sync.Once
	// stopDone closes when RequestStop's asynchronous teardown finishes.
	// Lazily created (stopDoneCh) since Task has no constructor.
	stopDone chan struct{}
	// opMu + state + wg form the operation registry: Stop flips the state
	// (new ops fail), cancels the context (running ops die), then drains
	// in-flight ops boundedly before the terminal audit event and close.
	opMu  sync.Mutex
	state atomic.Int32 // State
	wg    sync.WaitGroup
	// sem bounds concurrent operations per task (limits.max_concurrent_calls).
	// Sized in InitContext; admission is non-blocking (fail fast on exhaustion).
	sem chan struct{}
	// onStop releases task-external resources (its Tailcat server).
	// Set by the serve loop; nil in tests.
	onStop func()
}

// StateOf returns the current lifecycle state.
func (t *Task) StateOf() State { return State(t.state.Load()) }

// StateName reports the lifecycle state for operator displays.
func (t *Task) StateName() string {
	switch t.StateOf() {
	case StateCreating:
		return "creating"
	case StateActive:
		return "active"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	default:
		return "stopped"
	}
}

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

// RequestStop begins destroying the task with the given reason ("expired",
// "revoked", "shutdown", "audit sink failed") and returns immediately once
// the task can no longer be found ACTIVE — new ops and beginOp's is-ACTIVE
// check both key off the same state, set here synchronously before this
// call returns. The rest of teardown (bounded drain of in-flight ops,
// terminal audit event, onStop — server close + live/store/timer detach
// for tasks committed via serve.go, see commit — then audit close) runs
// asynchronously; the returned channel closes when it finishes.
//
// A caller that must not race a beginOp admitted between "audit failure
// observed" and "task actually stopped" needs this synchronous guarantee;
// Stop is the synchronous convenience for callers that don't care and
// just want to wait for the whole thing.
//
// Concurrent RequestStop/Stop calls are safe and share one teardown
// (stopOnce): every caller gets the same completion channel back,
// regardless of who triggers the one real run.
func (t *Task) RequestStop(reason string) <-chan struct{} {
	done := t.stopDoneCh()
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
		go func() {
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
			close(done)
		}()
	})
	return done
}

// stopDoneCh lazily creates the shared stop-completion channel. Guarded by
// opMu (already the lock used around state transitions) rather than a new
// one, since Task has no constructor to pre-allocate it in.
func (t *Task) stopDoneCh() chan struct{} {
	t.opMu.Lock()
	defer t.opMu.Unlock()
	if t.stopDone == nil {
		t.stopDone = make(chan struct{})
	}
	return t.stopDone
}

// Stop destroys the task and blocks until teardown fully completes. See
// RequestStop for the synchronous-vs-asynchronous split; every
// termination path (expiry, revoke, shutdown) funnels through one of the
// two (INV-3).
func (t *Task) Stop(reason string) {
	<-t.RequestStop(reason)
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

// beginControlOp admits a lifecycle tool (ping, revoke_self): it requires
// ACTIVE like beginOp, closing the window where a task mid-teardown (state
// STOPPING, already detached from most bookkeeping but not yet STOPPED)
// could still answer these calls successfully — a caller using ping as a
// "the task is alive and paired" signal must not observe true for a task
// that is already dying. Unlike beginOp it does not consume the
// concurrency semaphore: lifecycle calls are cheap and must never be
// denied by policy-tool concurrency pressure. The caller MUST call
// endControlOp on a "" return, and MUST do so before any Stop call it
// makes — Stop's drain waits on the same wg this adds to.
func (t *Task) beginControlOp() string {
	t.opMu.Lock()
	defer t.opMu.Unlock()
	if State(t.state.Load()) != StateActive {
		return "task stopping"
	}
	t.wg.Add(1)
	return ""
}

func (t *Task) endControlOp() {
	t.wg.Done()
}

// auditLog appends one audit record and, if the sink is now failing, stops
// the task fail-closed. Every audit write in this package — including
// handleRPC's early-return deny/expired paths, not just the tool
// handlers' own decisions — funnels through this, so a sink failure can
// never leave an ACTIVE task running with a degraded audit trail no
// matter which code path happened to hit it first.
//
// RequestStop, not Stop: the state flip to STOPPING (and thus beginOp
// refusing new ops) must happen before this returns, closing the window
// where a concurrent connection's beginOp could still observe ACTIVE
// between "audit failure detected" and "task actually stopped". The rest
// of teardown finishes asynchronously — waiting for it here (as Stop
// does) would deadlock on its wg.Wait against this very op, since we're
// called from inside an in-flight op (between beginOp and its deferred
// endOp).
func (t *Task) auditLog(tool string, args []byte, decision string, result []byte, dur time.Duration) {
	if t.Audit == nil {
		return
	}
	t.Audit.Log(tool, args, decision, result, dur)
	if t.Audit.Err() != nil {
		t.RequestStop("audit sink failed")
	}
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
	Name      string
	Policy    string
	ExpiresAt time.Time
	State     string
	AgentKey  string
}

// List returns snapshots of ACTIVE tasks for the admin API. Tasks still
// being admitted (CREATING) are invisible until commit: grant-in-flight
// tasks must neither appear in `tasks` nor be revokable before they exist.
func (s *Store) List() []TaskInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TaskInfo, 0, len(s.tasks))
	for _, t := range s.tasks {
		if t.StateOf() != StateActive {
			continue
		}
		name := ""
		if t.Policy != nil {
			name = t.Policy.Name
		}
		out = append(out, TaskInfo{ID: t.ID, Name: t.Name, Policy: name, ExpiresAt: t.ExpiresAt, State: t.StateName(), AgentKey: t.AgentKey})
	}
	return out
}

// Expired reports whether the task is past its TTL.
func (t *Task) Expired(now time.Time) bool { return !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt) }

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
		if owner != nil {
			owner.auditLog(req.Tool, req.Args, "deny", nil, 0)
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "task does not belong to this endpoint"}
	}
	t, ok := s.Lookup(req.Task, req.Secret)
	if !ok {
		return rpc.Response{ID: req.ID, OK: false, Error: "unknown task or bad secret"}
	}
	if t.Expired(time.Now()) {
		t.auditLog(req.Tool, req.Args, "expired", nil, 0)
		return rpc.Response{ID: req.ID, OK: false, Error: "capability expired"}
	}
	// Lifecycle tools bypass policy tools and the concurrency semaphore,
	// but still require ACTIVE via beginControlOp: ping proves
	// reachability/identity (and audits the pair), revoke_self lets the
	// task's own agent destroy it (agent-side disconnect).
	switch req.Tool {
	case rpc.ToolPing:
		if reason := t.beginControlOp(); reason != "" {
			t.auditLog(req.Tool, req.Args, "deny", nil, 0)
			return rpc.Response{ID: req.ID, OK: false, Error: reason}
		}
		defer t.endControlOp()
		t.auditLog(req.Tool, req.Args, "allow", rpc.MustRaw(map[string]string{"task": t.ID}), 0)
		return rpc.Response{ID: req.ID, OK: true, Result: rpc.MustRaw(rpc.PingResult{Task: t.ID})}
	case rpc.ToolRevokeSelf:
		if reason := t.beginControlOp(); reason != "" {
			t.auditLog(req.Tool, req.Args, "deny", nil, 0)
			return rpc.Response{ID: req.ID, OK: false, Error: reason}
		}
		t.endControlOp() // release before Stop: its drain waits on this wg
		t.Stop("revoked")
		s.Delete(t.ID)
		return rpc.Response{ID: req.ID, OK: true, Result: rpc.MustRaw(rpc.RevokeSelfResult{Revoked: true})}
	}
	if reason := t.beginOp(); reason != "" {
		t.auditLog(req.Tool, req.Args, "deny", nil, 0)
		return rpc.Response{ID: req.ID, OK: false, Error: reason}
	}
	defer t.endOp()
	var res rpc.Response
	switch req.Tool {
	case rpc.ToolExec:
		res = s.doExec(t, req)
	case rpc.ToolRead:
		res = s.doRead(t, req)
	case rpc.ToolStat:
		res = s.doStat(t, req)
	case rpc.ToolWrite:
		res = s.doWrite(t, req)
	default:
		// Unknown tools come from untrusted clients bypassing MCP, and
		// req.Tool is bounded/ASCII-checked by rpc.Request.validate, but
		// it is still arbitrary agent-chosen text; don't echo it into
		// the audit record verbatim.
		t.auditLog("unknown_tool", req.Args, "deny", nil, 0)
		res = rpc.Response{ID: req.ID, OK: false, Error: fmt.Sprintf("unknown tool %q", req.Tool)}
	}
	return res
}

func (s *Store) doExec(t *Task, req rpc.Request) rpc.Response {
	start := time.Now()
	var args rpc.ExecArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		t.auditLog(req.Tool, req.Args, "error", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "bad exec args"}
	}
	exe, ok := t.Policy.MatchExec(args.Command, args.Args)
	if !ok {
		t.auditLog(req.Tool, req.Args, "deny", nil, time.Since(start))
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
	res := rpc.ExecResult{
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		StdoutTruncated: stdout.truncated,
		StderrTruncated: stderr.truncated,
	}
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
			case errors.Is(context.Cause(t.Context()), ErrTaskAuditFailed):
				// Not a TTL expiry: a concurrent request's audit write
				// failed and fail-closed stopped this task mid-op. The
				// agent should see a distinct cause, not "expired".
				msg, decision = "task terminated: audit unavailable", "error"
			}
			t.auditLog(req.Tool, req.Args, decision, nil, time.Since(start))
			return rpc.Response{ID: req.ID, OK: false, Error: msg}
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = 127
			if ctx.Err() == context.DeadlineExceeded {
				t.auditLog(req.Tool, req.Args, "error", nil, time.Since(start))
				return rpc.Response{ID: req.ID, OK: false, Error: "command timed out"}
			}
		}
	}
	raw := rpc.MustRaw(res)
	t.auditLog(req.Tool, req.Args, "allow", raw, time.Since(start))
	return rpc.Response{ID: req.ID, OK: true, Result: raw}
}

func (s *Store) doRead(t *Task, req rpc.Request) rpc.Response {
	start := time.Now()
	var args rpc.ReadArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		t.auditLog(req.Tool, req.Args, "error", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "bad read args"}
	}
	if args.Path == "" {
		t.auditLog(req.Tool, req.Args, "deny", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "path not allowed by policy"}
	}
	fs := t.Policy.ReadFS()
	if fs == nil {
		t.auditLog(req.Tool, req.Args, "deny", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "file read is not allowed by policy"}
	}
	f, err := fs.OpenRead(args.Path)
	if err != nil {
		decision := "deny"
		if isStatError(err) {
			decision = "error"
		}
		t.auditLog(req.Tool, req.Args, decision, nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: err.Error()}
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.auditLog(req.Tool, req.Args, "error", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "stat: " + err.Error()}
	}
	data, truncated, err := safefs.ReadAllCapped(f, t.Policy.EffectiveLimits().MaxReadBytes)
	if err != nil {
		t.auditLog(req.Tool, req.Args, "error", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "read: " + err.Error()}
	}
	res := rpc.ReadResult{Size: info.Size(), Content: string(data), Truncated: truncated}
	raw := rpc.MustRaw(res)
	t.auditLog(req.Tool, req.Args, "allow", raw, time.Since(start))
	return rpc.Response{ID: req.ID, OK: true, Result: raw}
}

func (s *Store) doStat(t *Task, req rpc.Request) rpc.Response {
	start := time.Now()
	var args rpc.StatArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		t.auditLog(req.Tool, req.Args, "error", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "bad stat args"}
	}
	if args.Path == "" {
		t.auditLog(req.Tool, req.Args, "deny", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "path not allowed by policy"}
	}
	fs := t.Policy.ReadFS()
	if fs == nil {
		t.auditLog(req.Tool, req.Args, "deny", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "file read is not allowed by policy"}
	}
	info, err := fs.Stat(args.Path)
	if err != nil {
		decision := "deny"
		if isStatError(err) {
			decision = "error"
		}
		t.auditLog(req.Tool, req.Args, decision, nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: err.Error()}
	}
	res := rpc.StatResult{
		Name: info.Name(), Size: info.Size(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime().UTC().Format(time.RFC3339),
		IsDir:   info.IsDir(),
	}
	raw := rpc.MustRaw(res)
	t.auditLog(req.Tool, req.Args, "allow", raw, time.Since(start))
	return rpc.Response{ID: req.ID, OK: true, Result: raw}
}

// doWrite implements remote_write: the ONLY write path, and only through
// SafeFS with a file.write grant. Reads and writes are separate grants;
// without file.write this tool denies everything (default deny).
func (s *Store) doWrite(t *Task, req rpc.Request) rpc.Response {
	start := time.Now()
	var args rpc.WriteArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		t.auditLog(req.Tool, req.Args, "error", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "bad write args"}
	}
	deny := func(msg string) rpc.Response {
		t.auditLog(req.Tool, req.Args, "deny", nil, time.Since(start))
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
			t.auditLog(req.Tool, req.Args, "error", nil, time.Since(start))
			return rpc.Response{ID: req.ID, OK: false, Error: err.Error()}
		}
		return deny(err.Error())
	}
	info, err := fs.Stat(args.Path)
	if err != nil {
		t.auditLog(req.Tool, req.Args, "error", nil, time.Since(start))
		return rpc.Response{ID: req.ID, OK: false, Error: "stat: " + err.Error()}
	}
	raw := rpc.MustRaw(rpc.WriteResult{Size: info.Size(), Created: created})
	t.auditLog(req.Tool, req.Args, "allow", raw, time.Since(start))
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
