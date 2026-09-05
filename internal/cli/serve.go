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

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/gateway"
	"github.com/juntaki/catflap/internal/policy"
	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/local"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// liveTask binds one task to its own network server: 1 task = 1 Tailcat
// server = 1 WireGuard identity + 1 PSK + 1 address. Expiry closes the
// server, so reachability itself dies with the task — not just the RPC auth.
type liveTask struct {
	task  *gateway.Task
	srv   transport.Server
	timer *time.Timer
}

type server struct {
	transport string
	verbose   bool
	auditDir  string
	store     *gateway.Store
	mu        sync.Mutex
	live      map[string]*liveTask
	// maxTasks bounds live tasks; exhaustion fails the grant, never an
	// unbounded allocation (§18).
	maxTasks int
	// closing flips at shutdown: reserve/commit refuse new tasks, so a
	// task can never register after the shutdown snapshot was taken.
	// pending counts reserved-but-uncommitted tasks so concurrent grants
	// cannot all observe a free slot.
	closing bool
	pending int
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
	// Same validation path as grant overrides: --ttl must not bypass the
	// 24h ceiling enforced by Policy.Validate.
	if verr := pol.Validate(); verr != nil {
		fmt.Fprintf(os.Stderr, "policy: %v\n", verr)
		return 1
	}
	// The admin API carries a bearer token over plain HTTP: it MUST bind
	// loopback only. Remote administration rides a future Unix-socket
	// transport, not TCP.
	if rerr := requireLoopback(*adminAddr); rerr != nil {
		fmt.Fprintf(os.Stderr, "admin: %v\n", rerr)
		return 1
	}

	s := &server{
		transport: *transportFlag, verbose: *verbose,
		auditDir: *auditDir, store: &gateway.Store{}, live: map[string]*liveTask{},
		maxTasks: *maxTasks,
	}
	if s.maxTasks < 1 {
		fmt.Fprintf(os.Stderr, "invalid --max-tasks %d\n", s.maxTasks)
		return 1
	}

	// Root context for the process: every task context derives from it, so
	// shutdown cancels any task that outlives its own teardown path.
	ctx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSig()

	firstCap, firstTask, err := s.mkTask(ctx, pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint task: %v\n", err)
		return 1
	}

	// Admin API for `grant`.
	adminToken := randomToken()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *adminAddr)
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
		p := pol // default: same policy snapshot family
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
		cap, _, err := s.mkTask(ctx, p)
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
		if lt := s.takeLive(rreq.Task); lt != nil {
			lt.timer.Stop()
			lt.task.Stop("revoked") // same teardown as expiry
			s.store.Delete(rreq.Task)
			reportDegraded(lt)
			status = "revoked"
			fmt.Fprintf(os.Stderr, "catflap serve: task %s revoked — server closed, address dead\n", rreq.Task)
		}
		_ = json.NewEncoder(w).Encode(RevokeResponse{Task: rreq.Task, Status: status})
	})
	mux.HandleFunc("/tasks", func(w http.ResponseWriter, r *http.Request) {
		if "Bearer "+adminToken != strings.TrimSpace(r.Header.Get("Authorization")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		type item struct {
			Task    string `json:"task"`
			Policy  string `json:"policy"`
			Expires string `json:"expires_at"`
		}
		var out []item
		for _, t := range s.store.List() {
			out = append(out, item{Task: t.ID, Policy: t.Policy, Expires: t.ExpiresAt.Format(time.RFC3339)})
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

	st := StateFile{Transport: *transportFlag, AdminAddr: ln.Addr().String(), AdminToken: adminToken}
	if err := writeState(*statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "write state: %v\n", err)
		s.shutdown()
		return 1
	}

	if *outPath != "" {
		if err := writeCapFile(*outPath, firstCap.Encode(), *outForce); err != nil {
			fmt.Fprintf(os.Stderr, "write --out: %v\n", err)
			removeOwnState(*statePath, st)
			s.shutdown()
			return 1
		}
		fmt.Printf("Task: %s\nCapability: (written to %s)\nExpires: %s\nPolicy: %s\nTransport: %s\n",
			firstTask.ID, *outPath, firstTask.ExpiresAt.Format(time.RFC3339), pol.Name, *transportFlag)
	} else {
		fmt.Printf("Task: %s\nCapability:\n%s\nExpires: %s\nPolicy: %s\nTransport: %s\n",
			firstTask.ID, firstCap.Encode(), firstTask.ExpiresAt.Format(time.RFC3339), pol.Name, *transportFlag)
	}
	fmt.Fprintf(os.Stderr, "catflap serve: task %s live for %s on its own address; Ctrl-C destroys all keys\n",
		firstTask.ID, pol.TTL.Round(time.Second))

	<-ctx.Done()
	fmt.Fprintf(os.Stderr, "catflap serve: shutting down, destroying all task keys\n")
	_ = adminSrv.Close()
	removeOwnState(*statePath, st)
	s.shutdown()
	return 0
}

// errTooManyTasks fails grants beyond --max-tasks. The admin handler maps
// it to 429; anything else is a 500.
var errTooManyTasks = errors.New("too many live tasks")

// errShuttingDown fails admissions racing server shutdown.
var errShuttingDown = errors.New("server is shutting down")

// reserve holds one admission slot. The check and the increment are one
// atomic step under lock: concurrent grants cannot all see a free slot.
func (s *server) reserve() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return errShuttingDown
	}
	if len(s.live)+s.pending >= s.maxTasks {
		return fmt.Errorf("%w (max %d)", errTooManyTasks, s.maxTasks)
	}
	s.pending++
	return nil
}

func (s *server) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
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
func (s *server) mkTask(ctx context.Context, p *policy.Policy) (*capability.Capability, *gateway.Task, error) {
	if err := s.reserve(); err != nil {
		return nil, nil, err
	}
	taskID := capability.NewTaskID()
	secret := capability.NewSecret()
	agentKey := ""
	var clientPriv string
	if s.transport == "tailcat" {
		priv, pub, err := tct.GenerateClientKey()
		if err != nil {
			s.release()
			return nil, nil, err
		}
		clientPriv, agentKey = priv, pub
	}
	alog, err := audit.Open(s.auditDir, taskID, agentKey)
	if err != nil {
		s.release()
		return nil, nil, fmt.Errorf("audit: %w", err)
	}
	t := &gateway.Task{ID: taskID, Secret: secret, Policy: p, Audit: alog, AgentKey: agentKey}
	t.InitContext(ctx) // in-flight execs die with the task (C7)
	s.store.Add(t)
	// Creation opens the chain and binds the canonical policy snapshot
	// into the audit trail (args = canonical policy bytes). The sink is
	// confirmed healthy before anything else is built: a task whose audit
	// cannot record must never become ACTIVE.
	t.Audit.Log("task.create", p.Canonical(), "active", nil, 0)
	if aerr := alog.Err(); aerr != nil {
		t.Stop("failed")
		s.store.Delete(taskID)
		s.release()
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
		s.release()
		return nil, nil, fmt.Errorf("start task server: %w", err)
	}
	// TTL starts at transport readiness: slow DERP startup must not eat
	// the task's lifetime, and a timer armed before registration could
	// fire-and-vanish before the task exists.
	expires := time.Now().Add(p.TTL)
	t.ExpiresAt = expires
	if err := s.commit(taskID, t, srv); err != nil {
		t.Stop("failed")
		s.store.Delete(taskID)
		return nil, nil, err
	}

	cap := &capability.Capability{
		Version: 1, TaskID: taskID,
		Transport: s.transport, Endpoint: srv.Addr(),
		ClientPriv: clientPriv, TaskSecret: secret,
		ExpiresAt: expires, Policy: p.Name,
		// Short prefix of the canonical policy hash: the task's exact
		// authorization semantics, independent of YAML formatting.
		PolicyHash: p.CanonicalHash()[:12],
		Tools:      toolsForPolicy(p),
		MaxExecMs:  p.EffectiveLimits().MaxExecDuration.Milliseconds(),
	}
	return cap, t, nil
}

// commit registers a reserved task: live entry, Activate, and timer arming
// happen under one lock, in that order, and refuse work racing shutdown.
// Activate is CAS (Creating→Active only): a task that already left Creating
// can never be reactivated. A task whose context already died (shutdown
// cancel won the lock race) is refused too: no capability is ever emitted
// from a cancelled parent.
func (s *server) commit(taskID string, t *gateway.Task, srv transport.Server) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending--
	if s.closing || t.Context().Err() != nil {
		_ = srv.Close()
		return errShuttingDown
	}
	lt := &liveTask{task: t, srv: srv}
	t.OnStopFunc(func() { _ = srv.Close() })
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

// takeLive removes a live task from the registry and returns it.
// Used by revoke; expiry uses its own path via expire().
func (s *server) takeLive(taskID string) *liveTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	lt, ok := s.live[taskID]
	if ok {
		delete(s.live, taskID)
	}
	return lt
}

// expire destroys one task: network identity dies here, not just RPC auth.
func (s *server) expire(taskID string) {
	s.mu.Lock()
	lt, ok := s.live[taskID]
	if ok {
		delete(s.live, taskID)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	lt.timer.Stop()
	lt.task.Stop("expired") // closes this task's server + audit
	s.store.Delete(taskID)
	reportDegraded(lt)
	fmt.Fprintf(os.Stderr, "catflap serve: task %s expired — server closed, address dead\n", taskID)
}

// shutdown destroys every live task.
func (s *server) shutdown() {
	s.mu.Lock()
	s.closing = true
	live := s.live
	s.live = map[string]*liveTask{}
	s.mu.Unlock()
	for id, lt := range live {
		lt.timer.Stop()
		lt.task.Stop("shutdown")
		s.store.Delete(id)
		reportDegraded(lt)
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
