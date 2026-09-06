package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/gateway"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/policy"
	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/local"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// liveTask binds one task to its own network server: 1 task = 1 Tailcat
// server = 1 WireGuard identity + 1 PSK + 1 address. Expiry closes the
// server, so reachability itself dies with the task — not just the RPC auth.
type liveTask struct {
	task *gateway.Task
	srv  transport.Server
	// cap is the capability minted for this task, retained so
	// `share-code` (via issuePairCode) can reissue a fresh one-time
	// pairing code for a still-live task without minting a new one —
	// set once, right after mkTask builds it (see setCapability).
	cap *capability.Capability
	// pairSrv is this task's current temporary pair server, if a
	// pairing code has been issued and not yet claimed/expired. At
	// most one is ever live per task: issuePairCode closes the
	// previous one (if any) before starting a new one, and the task's
	// own teardown (see commit's OnStopFunc) closes it too — a pair
	// server must never outlive the task it delivers a capability for.
	pairSrv *pair.Server
	timer   *time.Timer
}

// setCapability records the capability minted for taskID, if the task
// is still live. A no-op if the task already died between commit and
// this call (e.g. an immediate revoke racing mkTask's return).
func (s *server) setCapability(taskID string, cap *capability.Capability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if lt, ok := s.live[taskID]; ok {
		lt.cap = cap
	}
}

// issuePairCode starts a fresh temporary pair server for taskID's
// retained capability and returns the pairing code for it — this is
// the ONE mechanism behind both the initial `share` announce and
// `share-code`'s reissue, so both get the same liveness/TTL-clamping
// guarantees automatically.
//
// taskID must be genuinely live: present in s.live, ACTIVE (not
// STOPPING — audit-fail-closed and other paths flip state
// synchronously before the async teardown that removes it from
// s.live actually runs, so s.live alone lags reality briefly), and not
// yet past its own TTL. requestedTTL is clamped to the task's own
// remaining TTL: a pairing code must never outlive the task it
// delivers a capability for. Any previous still-open pair server for
// this task is closed before the new one starts — at most one
// claimable code per task at a time.
func (s *server) issuePairCode(taskID string, requestedTTL time.Duration) (code string, actualTTL time.Duration, err error) {
	s.mu.Lock()
	lt, ok := s.live[taskID]
	s.mu.Unlock()
	if !ok || lt.cap == nil {
		return "", 0, fmt.Errorf("unknown or not-yet-live task")
	}
	if lt.task.StateOf() != gateway.StateActive || lt.task.Expired(time.Now()) {
		return "", 0, fmt.Errorf("task is not active")
	}
	remaining := time.Until(lt.task.ExpiresAt)
	if remaining <= 0 {
		return "", 0, fmt.Errorf("task already expired at %s", lt.task.ExpiresAt.Format(time.RFC3339))
	}
	ttl := requestedTTL
	if remaining < ttl {
		ttl = remaining
	}
	ps, serr := pair.Serve(s.transport, lt.cap, ttl, s.verbose)
	if serr != nil {
		return "", 0, fmt.Errorf("start pair server: %w", serr)
	}
	code, eerr := pair.Encode(s.transport, ps.Addr())
	if eerr != nil {
		ps.Close()
		return "", 0, fmt.Errorf("encode pairing code: %w", eerr)
	}

	s.mu.Lock()
	lt, ok = s.live[taskID]
	var old *pair.Server
	if ok {
		old, lt.pairSrv = lt.pairSrv, ps
	}
	s.mu.Unlock()
	if !ok {
		// The task died in the window between the liveness check above
		// and here (e.g. a concurrent revoke) — never hand out a code
		// for it.
		ps.Close()
		return "", 0, fmt.Errorf("task is no longer live")
	}
	if old != nil {
		old.Close()
	}
	return code, ttl, nil
}

type server struct {
	transport string
	verbose   bool
	auditDir  string
	store     *gateway.Store
	// approver is shared by every task minted by this process (they share
	// one terminal): nil when stdin isn't an interactive terminal, so a
	// policy rule requiring approval fails closed instead of blocking
	// forever or auto-approving in a headless run (see mkTask, and
	// gateway.Task.checkApproval's "no approver attached" path).
	approver gateway.Approver
	mu       sync.Mutex
	live     map[string]*liveTask
	// maxTasks bounds live tasks; exhaustion fails the grant, never an
	// unbounded allocation (§18).
	maxTasks int
	// closing flips at shutdown: reserve/commit refuse new tasks, so a
	// task can never register after the shutdown snapshot was taken.
	// pending counts reserved-but-uncommitted tasks so concurrent grants
	// cannot all observe a free slot.
	closing bool
	pending int
	// pendingNames reserves a task's name from reserve() until commit or
	// release frees it (same lock as pending/live), so two concurrent
	// grants resolving names independently can never both land on the
	// same one — the decision and the reservation are the same atomic
	// step, unlike a check against s.live alone.
	pendingNames map[string]bool
}

// GatewayOptions configures one gateway process (serve or share).
type GatewayOptions struct {
	Transport string
	AuditDir  string
	StatePath string
	AdminAddr string
	Verbose   bool
	MaxTasks  int
	TaskName  string // preferred human name for the initial task ("" = mint)
	Policy    *policy.Policy
}

// Announce carries the first live task to the caller's printer.
type Announce struct {
	State     StateFile
	Cap       *capability.Capability
	Task      *gateway.Task
	Transport string
	// IssuePairCode starts a fresh temporary pair server for THIS task
	// and returns a pairing code for it — the same mechanism
	// `share-code` uses later, bound to this specific task so callers
	// (share's announce) don't need to reach back into the server.
	IssuePairCode func(requestedTTL time.Duration) (code string, actualTTL time.Duration, err error)
}

// Serve runs the target gateway. Each task (the initial one and every
// `grant`) gets its own ephemeral network server. The process lives until
// SIGINT/SIGTERM; per-task expiry tears down that task's server alone.
func Serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "YAML policy file (default: built-in readonly-debug)")
	ttlFlag := fs.String("ttl", "", "TTL override for the initial task, e.g. 15m (default: policy ttl)")
	transportFlag := fs.String("transport", "tailcat", "transport: tailcat | local")
	auditDir := fs.String("audit", DefaultAuditDir(), "audit JSONL directory (empty disables file audit)")
	statePath := fs.String("state", DefaultStatePath(), "state file for `grant` coordination")
	adminAddr := fs.String("admin", "127.0.0.1:0", "loopback admin API listen address")
	outPath := fs.String("out", "", "write the initial capability to this file (0600) instead of stdout")
	outForce := fs.Bool("force", false, "allow --out to overwrite an existing file")
	maxTasks := fs.Int("max-tasks", 16, "maximum live tasks (grants beyond this fail)")
	verbose := fs.Bool("verbose", false, "verbose transport logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	pol, err := loadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy: %v\n", err)
		return 1
	}
	if *ttlFlag != "" {
		ttlDur, ttlErr := time.ParseDuration(*ttlFlag)
		if ttlErr != nil || ttlDur <= 0 {
			fmt.Fprintf(os.Stderr, "invalid --ttl %q\n", *ttlFlag)
			return 1
		}
		pol.TTL = ttlDur
	}
	// Policy.Validate (including the 24h TTL ceiling) and the admin-addr
	// loopback check both happen inside RunGateway, the single place every
	// gateway entry point (serve, and eventually share) must go through.

	announce := func(a Announce) error {
		if *outPath != "" {
			if err := writeCapFile(*outPath, a.Cap.Encode(), *outForce); err != nil {
				return err
			}
			fmt.Printf("Task: %s (%s)\nCapability: (written to %s)\nExpires: %s\nPolicy: %s\nTransport: %s\n",
				a.Task.ID, a.Task.Name, *outPath, a.Task.ExpiresAt.Format(time.RFC3339), pol.Name, a.Transport)
			return nil
		}
		fmt.Printf("Task: %s (%s)\nCapability:\n%s\nExpires: %s\nPolicy: %s\nTransport: %s\n",
			a.Task.ID, a.Task.Name, a.Cap.Encode(), a.Task.ExpiresAt.Format(time.RFC3339), pol.Name, a.Transport)
		return nil
	}
	return RunGateway(GatewayOptions{
		Transport: *transportFlag, AuditDir: *auditDir, StatePath: *statePath,
		AdminAddr: *adminAddr, Verbose: *verbose, MaxTasks: *maxTasks, Policy: pol,
	}, announce)
}

// RunGateway runs one gateway process around opts.Policy: first task,
// loopback admin API (/grant, /revoke, /tasks), state file, then serve
// until SIGINT/SIGTERM. announce prints the first live task; its error
// tears everything down.
//
// RunGateway owns every security invariant a gateway process must satisfy
// regardless of caller (serve, and eventually share): a policy that isn't
// Validate()'d, an admin listener that isn't loopback-only, an unknown
// transport, or a non-positive max-tasks bound must never reach a running
// admin API. CLI wrappers should only translate flags into GatewayOptions
// — they must not duplicate these checks, or a second call site that
// forgets one silently reopens the hole this closes.
func RunGateway(opts GatewayOptions, announce func(Announce) error) int {
	if opts.Policy == nil {
		fmt.Fprintf(os.Stderr, "internal error: no policy\n")
		return 1
	}
	if verr := opts.Policy.Validate(); verr != nil {
		fmt.Fprintf(os.Stderr, "policy: %v\n", verr)
		return 1
	}
	if opts.Transport != "tailcat" && opts.Transport != "local" {
		fmt.Fprintf(os.Stderr, "unknown transport %q (tailcat|local)\n", opts.Transport)
		return 1
	}
	if opts.MaxTasks < 1 {
		fmt.Fprintf(os.Stderr, "invalid max tasks %d\n", opts.MaxTasks)
		return 1
	}
	// The admin API carries a bearer token over plain HTTP: it MUST bind
	// loopback only. Remote administration rides a future Unix-socket
	// transport, not TCP.
	if rerr := requireLoopback(opts.AdminAddr); rerr != nil {
		fmt.Fprintf(os.Stderr, "admin: %v\n", rerr)
		return 1
	}

	var approver gateway.Approver
	if isInteractiveTerminal(os.Stdin) {
		// Prompts go to stderr, matching every other operator-facing
		// message in this file (e.g. the "task ... live for ..." line
		// below) — stdout stays reserved for the capability/pairing
		// output announce() prints.
		approver = NewTerminalApprover(os.Stdin, os.Stderr)
	}
	s := &server{
		transport: opts.Transport, verbose: opts.Verbose,
		auditDir: opts.AuditDir, store: &gateway.Store{}, live: map[string]*liveTask{},
		maxTasks: opts.MaxTasks, approver: approver,
	}

	// Root context for the process. Task contexts are NOT children of
	// it (mkTask wraps it in context.WithoutCancel) — this only gates
	// the <-ctx.Done() below, which triggers shutdown()'s own explicit,
	// two-pass per-task TryRequestStop("shutdown"). See mkTask and
	// shutdown for why the signal must not cancel task contexts directly.
	ctx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSig()

	firstCap, firstTask, err := s.mkTask(ctx, opts.Policy, opts.TaskName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint task: %v\n", err)
		return 1
	}

	// Admin API for `grant`.
	adminToken := randomToken()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opts.AdminAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin listen: %v\n", err)
		s.shutdown()
		return 1
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/grant", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if "Bearer "+adminToken != strings.TrimSpace(r.Header.Get("Authorization")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var greq GrantRequest
		if err := decodeAdminBody(w, r, &greq); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		p := opts.Policy // default: same policy snapshot family
		if greq.PolicyYAML != "" {
			pp, err := policy.Parse([]byte(greq.PolicyYAML))
			if err != nil {
				http.Error(w, "bad policy: "+err.Error(), http.StatusBadRequest)
				return
			}
			p = pp
		}
		if greq.TTLOverrideMs > 0 {
			cp := *p
			cp.TTL = time.Duration(greq.TTLOverrideMs) * time.Millisecond
			if err := cp.Validate(); err != nil {
				http.Error(w, "bad ttl: "+err.Error(), http.StatusBadRequest)
				return
			}
			p = &cp
		}
		cap, _, err := s.mkTask(ctx, p, "")
		if err != nil {
			if errors.Is(err, errTooManyTasks) {
				http.Error(w, err.Error(), http.StatusTooManyRequests)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		_ = json.NewEncoder(w).Encode(GrantResponse{
			Task: cap.TaskID, Capability: cap.Encode(),
			ExpiresAt: cap.ExpiresAt.Format(time.RFC3339), Policy: cap.Policy,
		})
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if "Bearer "+adminToken != strings.TrimSpace(r.Header.Get("Authorization")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var rreq RevokeRequest
		if err := decodeAdminBody(w, r, &rreq); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(rreq.Task) == "" {
			http.Error(w, "missing task", http.StatusBadRequest)
			return
		}
		// Idempotent: revoking an unknown (already gone) task succeeds
		// with status "unknown" — repeated revoke is not an error.
		status := "unknown"
		if s.stopDetached(rreq.Task, "revoked") {
			status = "revoked"
			fmt.Fprintf(os.Stderr, "catflap serve: task %s revoked — server closed, address dead\n", rreq.Task)
		}
		_ = json.NewEncoder(w).Encode(RevokeResponse{Task: rreq.Task, Status: status})
	})
	mux.HandleFunc("/pair", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if "Bearer "+adminToken != strings.TrimSpace(r.Header.Get("Authorization")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var preq PairRequest
		if err := decodeAdminBody(w, r, &preq); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		ttl := pair.DefaultCodeTTL
		if preq.TTLOverrideMs > 0 {
			ttl = time.Duration(preq.TTLOverrideMs) * time.Millisecond
		}
		//nolint:contextcheck // reason: the pair server issuePairCode starts is governed by its own TTL timer and the task's teardown (see commit's OnStopFunc), never by this HTTP request's context — the request returns as soon as the code is issued, long before the pair server itself should close.
		code, actualTTL, perr := s.issuePairCode(strings.TrimSpace(preq.Task), ttl)
		if perr != nil {
			http.Error(w, perr.Error(), http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(PairResponse{Code: code, TTLMs: actualTTL.Milliseconds()})
	})
	mux.HandleFunc("/tasks", func(w http.ResponseWriter, r *http.Request) {
		if "Bearer "+adminToken != strings.TrimSpace(r.Header.Get("Authorization")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		type item struct {
			Task    string `json:"task"`
			Name    string `json:"name"`
			Policy  string `json:"policy"`
			Expires string `json:"expires_at"`
			State   string `json:"state"`
		}
		var out []item
		for _, t := range s.store.List() {
			out = append(out, item{Task: t.ID, Name: t.Name, Policy: t.Policy, Expires: t.ExpiresAt.Format(time.RFC3339), State: t.State})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	// Timeouts on the loopback admin API: no handler should hold a
	// connection open indefinitely (G114).
	adminSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() { _ = adminSrv.Serve(ln) }()
	// Every RunGateway return path below (writeState/announce failure,
	// or the normal shutdown at the end) must close the admin listener —
	// not just the CLI's process-exit path, since share will call this
	// same function and keep running afterward.
	defer func() { _ = adminSrv.Close() }()

	st := StateFile{Transport: opts.Transport, AdminAddr: ln.Addr().String(), AdminToken: adminToken}
	if err := writeState(opts.StatePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "write state: %v\n", err)
		s.shutdown()
		return 1
	}

	announceArg := Announce{State: st, Cap: firstCap, Task: firstTask, Transport: opts.Transport}
	announceArg.IssuePairCode = func(requestedTTL time.Duration) (string, time.Duration, error) {
		return s.issuePairCode(firstTask.ID, requestedTTL)
	}
	if err := announce(announceArg); err != nil {
		fmt.Fprintf(os.Stderr, "announce: %v\n", err)
		removeOwnState(opts.StatePath, st)
		s.shutdown()
		return 1
	}
	fmt.Fprintf(os.Stderr, "catflap serve: task %s live for %s on its own address; Ctrl-C destroys all keys\n",
		firstTask.ID, opts.Policy.TTL.Round(time.Second))

	<-ctx.Done()
	fmt.Fprintf(os.Stderr, "catflap serve: shutting down, destroying all task keys\n")
	removeOwnState(opts.StatePath, st)
	s.shutdown()
	return 0
}

// errTooManyTasks fails grants beyond --max-tasks. The admin handler maps
// it to 429; anything else is a 500.
var errTooManyTasks = errors.New("too many live tasks")

// errShuttingDown fails admissions racing server shutdown.
var errShuttingDown = errors.New("server is shutting down")

// reserve holds one admission slot AND resolves+reserves the task's name,
// as one atomic step under lock: concurrent grants cannot all see a free
// slot, and cannot both resolve to the same name (the decision and the
// reservation must be the same step — deciding against s.live and
// inserting into s.live as two separate critical sections is exactly the
// race that let two concurrent grants both mint the same "unique" name).
// On success the caller MUST eventually call commit or release(name).
func (s *server) reserve(preferred string) (name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return "", errShuttingDown
	}
	if len(s.live)+s.pending >= s.maxTasks {
		return "", fmt.Errorf("%w (max %d)", errTooManyTasks, s.maxTasks)
	}
	name, err = s.resolveNameLocked(preferred)
	if err != nil {
		return "", err
	}
	s.pending++
	if s.pendingNames == nil {
		s.pendingNames = map[string]bool{}
	}
	s.pendingNames[NormalizeName(name)] = true
	return name, nil
}

func (s *server) release(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingNames, NormalizeName(name))
	if s.pending > 0 {
		s.pending--
	}
}

// mkTask creates one task with its own ephemeral network server and arms
// its expiry: timer → server.Close + audit.Close + store.Delete.
//
// Order: reserve → audit open → task.create (sink health confirmed) →
// transport start → commit (register + Activate + timer arm). The chain
// always opens with task.create, so a shutdown racing commit can only
// append task.stop after it — never seal an empty chain, and creation
// failure yields task.create + task.stop failed.
func (s *server) mkTask(ctx context.Context, p *policy.Policy, name string) (*capability.Capability, *gateway.Task, error) {
	resolvedName, err := s.reserve(name)
	if err != nil {
		return nil, nil, err
	}
	taskID := capability.NewTaskID()
	secret := capability.NewSecret()
	agentKey := ""
	var clientPriv string
	if s.transport == "tailcat" {
		priv, pub, kerr := tct.GenerateClientKey()
		if kerr != nil {
			s.release(resolvedName)
			return nil, nil, kerr
		}
		clientPriv, agentKey = priv, pub
	}
	alog, err := audit.Open(s.auditDir, taskID, agentKey)
	if err != nil {
		s.release(resolvedName)
		return nil, nil, fmt.Errorf("audit: %w", err)
	}
	t := &gateway.Task{ID: taskID, Name: resolvedName, Secret: secret, Policy: p, Audit: alog, AgentKey: agentKey}
	if s.approver != nil {
		t.SetApprover(s.approver)
	}
	// WithoutCancel: a task's own context must be cancelled ONLY through
	// TryRequestStop, with the correct cause (ErrTaskShutdown, in this
	// case) — never implicitly, by being a child of the process's
	// SIGINT/SIGTERM signal context. If ctx's cancellation propagated
	// down the tree directly, every task would cancel the instant the
	// signal fires, with context.Canceled as its cause (signal.
	// NotifyContext sets no cause of its own) — a window, however
	// narrow, before shutdown()'s explicit per-task TryRequestStop(
	// "shutdown") calls run, during which anything reading
	// context.Cause(t.Context()) would see the wrong termination
	// reason. RunGateway's shutdown() still tears every task down on
	// signal — it's the sole path that does, deliberately, with the
	// right cause — this only removes the implicit, racy second path.
	t.InitContext(context.WithoutCancel(ctx)) // in-flight execs die with the task (C7)
	s.store.Add(t)
	// Creation opens the chain and binds the canonical policy snapshot
	// into the audit trail (args = canonical policy bytes). The sink is
	// confirmed healthy before anything else is built: a task whose audit
	// cannot record must never become ACTIVE.
	t.Audit.Log("task.create", p.Canonical(), "active", nil, 0)
	if aerr := alog.Err(); aerr != nil {
		t.Stop("failed")
		s.store.Delete(taskID)
		s.release(resolvedName)
		return nil, nil, fmt.Errorf("audit sink failed: %w", aerr)
	}

	var srv transport.Server
	switch s.transport {
	case "tailcat":
		// Bound handler: only this task authenticates at this endpoint,
		// even with another task's valid secret.
		//nolint:contextcheck // reason: request context here IS the task context, derived from the serve root in InitContext; passing the serve ctx alongside would shadow task-scoped cancellation.
		srv, err = tct.Serve(s.store.HandlerFor(taskID), []string{agentKey}, s.verbose)
	case "local":
		//nolint:contextcheck // reason: see above — task context governs the request path.
		srv, err = local.Serve(s.store.HandlerFor(taskID))
	default:
		err = fmt.Errorf("unknown transport %q (tailcat|local)", s.transport)
	}
	if err != nil {
		// Creation failed: run the same teardown (terminal event + close)
		// so a half-created task never lingers. No capability is emitted.
		t.Stop("failed")
		s.store.Delete(taskID)
		s.release(resolvedName)
		return nil, nil, fmt.Errorf("start task server: %w", err)
	}
	// TTL starts at transport readiness: slow DERP startup must not eat
	// the task's lifetime, and a timer armed before registration could
	// fire-and-vanish before the task exists.
	expires := time.Now().Add(p.TTL)
	t.ExpiresAt = expires
	if err := s.commit(taskID, resolvedName, t, srv); err != nil {
		t.Stop("failed")
		s.store.Delete(taskID)
		return nil, nil, err
	}

	cap := &capability.Capability{
		Version: 1, TaskID: taskID, Name: t.Name,
		Transport: s.transport, Endpoint: srv.Addr(),
		ClientPriv: clientPriv, TaskSecret: secret,
		ExpiresAt: expires, Policy: p.Name,
		// Short prefix of the canonical policy hash: the task's exact
		// authorization semantics, independent of YAML formatting.
		PolicyHash: p.CanonicalHash()[:12],
		Tools:      toolsForPolicy(p),
		MaxExecMs:  p.EffectiveLimits().MaxExecDuration.Milliseconds(),
	}
	s.setCapability(taskID, cap)
	return cap, t, nil
}

// commit registers a reserved task: live entry, Activate, and timer arming
// happen under one lock, in that order, and refuse work racing shutdown.
// Activate is CAS (Creating→Active only): a task that already left Creating
// can never be reactivated. A task whose context already died (shutdown
// cancel won the lock race) is refused too: no capability is ever emitted
// from a cancelled parent.
func (s *server) commit(taskID, name string, t *gateway.Task, srv transport.Server) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending--
	delete(s.pendingNames, NormalizeName(name))
	if s.closing || t.Context().Err() != nil {
		_ = srv.Close()
		return errShuttingDown
	}
	lt := &liveTask{task: t, srv: srv}
	// detach is the single idempotent teardown for every termination path:
	// expiry, revoke, shutdown, and Stop calls that don't originate in
	// serve.go at all (the gateway's audit-fail-closed path stops a task
	// directly with no server-side call site to clean up after it). It
	// runs exactly once per task (Task.Stop's stopOnce guards this),
	// regardless of who called Stop, so a stopped task can never keep
	// occupying a live/store slot — and thus a max-tasks admission slot
	// — past its own termination.
	t.OnStopFunc(func() {
		_ = srv.Close()
		s.mu.Lock()
		if cur, ok := s.live[taskID]; ok && cur == lt {
			delete(s.live, taskID)
		}
		pairSrv := lt.pairSrv
		s.mu.Unlock()
		if lt.timer != nil {
			lt.timer.Stop()
		}
		// A pair server must never outlive the task it delivers a
		// capability for — revoke/expiry/shutdown kills any still-open
		// one right along with the task itself.
		if pairSrv != nil {
			pairSrv.Close()
		}
		s.store.Delete(taskID)
		reportDegraded(lt)
	})
	s.live[taskID] = lt
	if !t.TryActivate() {
		delete(s.live, taskID)
		_ = srv.Close()
		return fmt.Errorf("task %s left creating before commit", taskID)
	}
	lt.timer = time.AfterFunc(time.Until(t.ExpiresAt), func() { s.expire(taskID) })
	return nil
}

// toolsForPolicy normalizes the policy into the MCP tool list the task
// exposes. A task MUST NOT expose a tool its policy cannot authorize;
// the gateway re-enforces every call regardless (list is a hint).
func toolsForPolicy(p *policy.Policy) []string {
	// Always non-nil: an empty grant encodes as "tools":[] so it can
	// never be mistaken for a legacy (field-absent) capability.
	out := []string{}
	if p.Tools.Exec != nil && len(p.Tools.Exec.Allow) > 0 {
		out = append(out, "remote_exec")
	}
	if p.Tools.File != nil {
		if len(p.Tools.File.Read) > 0 {
			out = append(out, "remote_read", "remote_stat")
		}
		if p.Tools.File.Write.Enabled() {
			out = append(out, "remote_write")
		}
	}
	return out
}

// resolveNameLocked resolves preferred to a name reserved for the caller,
// or mints a fresh unique one. Must be called with s.mu held, and as part
// of the same critical section that records the reservation (reserve) —
// checking availability and reserving it are one atomic step, or two
// concurrent grants could both resolve to the same "unique" name.
func (s *server) resolveNameLocked(preferred string) (string, error) {
	sanitized, err := sanitizeName(preferred)
	if err != nil {
		return "", err
	}
	if sanitized != "" {
		if !s.nameTakenLocked(sanitized) {
			return sanitized, nil
		}
		// Silent fallback to a minted name, matching mint's own
		// collision behavior: a taken preferred name is a UX nudge, not
		// a hard failure, since names are display metadata only.
	}
	for i := 0; i < 100; i++ {
		name := MintName()
		if !s.nameTakenLocked(name) {
			return name, nil
		}
	}
	return capability.NewTaskID(), nil // absurd collision run; fall back to id
}

// nameTakenLocked checks both committed (live) and reserved-but-not-yet-
// committed (pendingNames) names. Must be called with s.mu held.
func (s *server) nameTakenLocked(name string) bool {
	n := NormalizeName(name)
	if s.pendingNames[n] {
		return true
	}
	for _, lt := range s.live {
		if NormalizeName(lt.task.Name) == n {
			return true
		}
	}
	return false
}

// sanitizeName validates a caller-supplied preferred task name before it
// can reach any display surface (tasks list, announce output) or the
// wire (capability.Name): an unrestricted name is a control-character/
// ANSI-escape injection vector into whatever terminal renders it later.
// Returns "" (no preference — mint one) for empty/whitespace-only input.
func sanitizeName(preferred string) (string, error) {
	s := strings.TrimSpace(preferred)
	if s == "" {
		return "", nil
	}
	if len(s) > 64 {
		return "", fmt.Errorf("task name too long (max 64 bytes)")
	}
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return "", fmt.Errorf("task name must be printable ASCII")
		}
	}
	return s, nil
}

// stopDetached is the single termination entry point for expire and
// revoke. Ownership of *why* a task stopped lives entirely in
// Task.TryRequestStop's stopOnce, not in any serve.go bookkeeping: of
// two callers racing on the same task — TTL expiry firing at the same
// moment as an admin revoke, or either racing revoke_self or an
// audit-fail-closed stop originating in the gateway package — won is
// true for exactly the caller whose reason actually took effect,
// wherever it was called from. A loser must report "did nothing", not
// silently succeed with the wrong reason or claim credit for a stop it
// didn't perform.
//
// Only after TryRequestStop returns (leaving ACTIVE synchronously) does
// a winner remove the live entry, freeing the task's name for reuse.
// The two must not be reordered: if the name became free before the old
// task actually left ACTIVE, a concurrent grant resolving names against
// s.live could pick that name while the dying task could still, for a
// brief window, answer as if it were a live ACTIVE task under it.
func (s *server) stopDetached(taskID, reason string) bool {
	s.mu.Lock()
	lt, ok := s.live[taskID]
	s.mu.Unlock()
	if !ok {
		return false
	}

	done, won := lt.task.TryRequestStop(reason)
	if won {
		s.mu.Lock()
		if cur, ok := s.live[taskID]; ok && cur == lt {
			delete(s.live, taskID)
		}
		s.mu.Unlock()
	}
	<-done
	return won
}

// expire destroys one task: network identity dies here, not just RPC
// auth. The actual resource teardown — timer stop, server close, store
// detach, degradation report — happens in Task.Stop's onStop callback
// (see commit); stopDetached only orders the ACTIVE-leave before the
// live-map/name removal and gates against a concurrent revoke.
func (s *server) expire(taskID string) {
	if !s.stopDetached(taskID, "expired") {
		return
	}
	fmt.Fprintf(os.Stderr, "catflap serve: task %s expired — server closed, address dead\n", taskID)
}

// shutdown destroys every live task. Teardown per task happens in
// Task.Stop's onStop callback (see commit).
func (s *server) shutdown() {
	s.mu.Lock()
	s.closing = true
	live := s.live
	s.live = map[string]*liveTask{}
	s.mu.Unlock()
	// Two passes, not one call+wait per task: TryRequestStop's
	// synchronous half cancels a task's context immediately, but its
	// teardown half can block up to 10s draining in-flight ops (see
	// TryRequestStop). Task contexts are no longer children of the
	// process's signal context (context.WithoutCancel in mkTask), so
	// nothing else cancels a task except this call — calling and
	// waiting one task at a time would leave every later task in the
	// iteration ACTIVE, its in-flight commands still running, for as
	// long as each earlier task's drain takes. Requesting every stop
	// first — all synchronous halves run back-to-back, uncontested,
	// before any waiting — cancels every task's context up front,
	// independent of how long any one drain takes; only then do we wait
	// for every teardown to finish.
	dones := make([]<-chan struct{}, 0, len(live))
	for _, lt := range live {
		// TryRequestStop, not Stop, purely for consistency: every
		// termination path funnels through the same primitive, so
		// "shutdown" only wins here if nothing else (a concurrent
		// revoke, say) already claimed this task first.
		done, _ := lt.task.TryRequestStop("shutdown")
		dones = append(dones, done)
	}
	for _, done := range dones {
		<-done
	}
}

// reportDegraded tells the operator when a task's audit sink failed: a
// degraded audit must never pass silently.
func reportDegraded(lt *liveTask) {
	if lt == nil || lt.task == nil || lt.task.Audit == nil {
		return
	}
	if err := lt.task.Audit.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "catflap serve: WARNING: audit degraded for task %s: %v\n", lt.task.ID, err)
	}
}

// requireLoopback rejects non-loopback admin listen addresses. An empty
// host (":port") binds all interfaces and is rejected.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("bad admin address %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return fmt.Errorf("admin address %q is not loopback (admin API carries a bearer token over plain HTTP)", addr)
		}
		return nil
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil
	}
	return fmt.Errorf("admin address %q is not loopback (use 127.0.0.1 or ::1)", addr)
}

func loadPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		return policy.Default(), nil
	}
	p, err := policy.Load(path)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// decodeAdminBody strictly decodes one JSON value from an admin request:
// bounded size (connection killed past the limit), no unknown fields, no
// trailing data. Malformed input fails closed — never a zero-value grant.
func decodeAdminBody(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	switch derr := dec.Decode(&extra); {
	case derr == nil:
		return fmt.Errorf("unexpected trailing data")
	case errors.Is(derr, io.EOF):
		return nil
	default:
		return derr
	}
}

func writeState(path string, st StateFile) error {
	raw, merr := json.MarshalIndent(st, "", "  ")
	if merr != nil {
		return merr
	}
	// The state file holds the admin bearer token: same atomic no-clobber
	// semantics as capability files. A second serve on the same --state
	// fails instead of hijacking the first one's admin API — even under
	// concurrent startup, where Lstat-then-create would race.
	if err := publishNewFile(path, raw); err != nil {
		return fmt.Errorf("state file %q: %w (another serve running?)", path, err)
	}
	return nil
}

// removeOwnState deletes the state file only if it still holds our bytes:
// a concurrent or later serve's coordination file must never be removed.
func removeOwnState(path string, st StateFile) {
	want, merr := json.MarshalIndent(st, "", "  ")
	if merr != nil {
		return
	}
	//nolint:gosec // reason: operator's own --state path, read back only to compare before deleting our own file.
	cur, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(cur, want) {
		if err == nil {
			fmt.Fprintf(os.Stderr, "catflap serve: state file changed, leaving it\n")
		}
		return
	}
	_ = os.Remove(path)
}

func randomToken() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
