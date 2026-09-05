package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
func RunGateway(opts GatewayOptions, announce func(Announce) error) int {
	s := &server{
		transport: opts.Transport, verbose: opts.Verbose,
		auditDir: opts.AuditDir, store: &gateway.Store{}, live: map[string]*liveTask{},
		maxTasks: opts.MaxTasks,
	}
	if s.maxTasks < 1 {
		fmt.Fprintf(os.Stderr, "invalid --max-tasks %d\n", s.maxTasks)
		return 1
	}
	// Agent-side self-revoke (disconnect) drops the serve-side timer and
	// live entry too; the gateway already Stopped and Deleted the task.
	s.store.OnRevoked = func(taskID string) {
		s.mu.Lock()
		lt, ok := s.live[taskID]
		if ok {
			delete(s.live, taskID)
		}
		s.mu.Unlock()
		if ok {
			lt.timer.Stop()
		}
	}

	// Root context for the process: every task context derives from it, so
	// shutdown cancels any task that outlives its own teardown path.
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
		body, _ := io_ReadAll(r.Body, 1<<20)
		_ = json.Unmarshal(body, &greq)
		newTaskPolicy, err := grantPolicy(opts.Policy, greq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cap, _, err := s.mkTask(ctx, newTaskPolicy, "")
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
		body, _ := io_ReadAll(r.Body, 1<<20)
		_ = json.Unmarshal(body, &rreq)
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

	st := StateFile{Transport: opts.Transport, AdminAddr: ln.Addr().String(), AdminToken: adminToken}
	if err := writeState(opts.StatePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "write state: %v\n", err)
		s.shutdown()
		_ = os.Remove(opts.StatePath)
		return 1
	}

	if err := announce(Announce{State: st, Cap: firstCap, Task: firstTask, Transport: opts.Transport}); err != nil {
		fmt.Fprintf(os.Stderr, "announce: %v\n", err)
		s.shutdown()
		_ = os.Remove(opts.StatePath)
		return 1
	}
	fmt.Fprintf(os.Stderr, "catflap serve: task %s (%s) live for %s on its own address; Ctrl-C destroys all keys\n",
		firstTask.ID, firstTask.Name, opts.Policy.TTL.Round(time.Second))

	<-ctx.Done()
	fmt.Fprintf(os.Stderr, "catflap serve: shutting down, destroying all task keys\n")
	_ = adminSrv.Close()
	_ = os.Remove(opts.StatePath)
	s.shutdown()
	return 0
}

// grantPolicy resolves a grant request against the server's default policy
// family: optional replacement YAML plus optional TTL override.
func grantPolicy(def *policy.Policy, greq GrantRequest) (*policy.Policy, error) {
	p := def // default: same policy snapshot family
	if greq.PolicyYAML != "" {
		pp, err := policy.Parse([]byte(greq.PolicyYAML))
		if err != nil {
			return nil, fmt.Errorf("bad policy: %w", err)
		}
		p = pp
	}
	if greq.TTLOverrideMs > 0 {
		cp := *p
		cp.TTL = time.Duration(greq.TTLOverrideMs) * time.Millisecond
		if err := cp.Validate(); err != nil {
			return nil, fmt.Errorf("bad ttl: %w", err)
		}
		p = &cp
	}
	return p, nil
}

// errTooManyTasks fails grants beyond --max-tasks. The admin handler maps
// it to 429; anything else is a 500.
var errTooManyTasks = errors.New("too many live tasks")

// mkTask creates one task with its own ephemeral network server and arms
// its expiry: timer → server.Close + audit.Close + store.Delete.
func (s *server) mkTask(ctx context.Context, p *policy.Policy, name string) (*capability.Capability, *gateway.Task, error) {
	s.mu.Lock()
	full := len(s.live) >= s.maxTasks
	s.mu.Unlock()
	if full {
		return nil, nil, fmt.Errorf("%w (max %d)", errTooManyTasks, s.maxTasks)
	}
	taskID := capability.NewTaskID()
	secret := capability.NewSecret()
	expires := time.Now().Add(p.TTL)
	agentKey := ""
	var clientPriv string
	if s.transport == "tailcat" {
		priv, pub, err := tct.GenerateClientKey()
		if err != nil {
			return nil, nil, err
		}
		clientPriv, agentKey = priv, pub
	}
	alog, err := audit.Open(s.auditDir, taskID, agentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: %w", err)
	}
	t := &gateway.Task{ID: taskID, Secret: secret, Policy: p, ExpiresAt: expires, Audit: alog, AgentKey: agentKey}
	t.InitContext(ctx) // in-flight execs die with the task (C7)
	t.Name = s.taskName(name)
	s.store.Add(t)

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
		return nil, nil, fmt.Errorf("start task server: %w", err)
	}
	lt := &liveTask{task: t, srv: srv}
	t.OnStopFunc(func() { _ = srv.Close() })
	lt.timer = time.AfterFunc(time.Until(expires), func() { s.expire(taskID) })
	s.mu.Lock()
	s.live[taskID] = lt
	s.mu.Unlock()
	t.Activate() // ACTIVE only now: server, binding, audit, expiry all armed
	// Creation event first in the chain, binding the canonical policy
	// snapshot hash into the audit trail (args = canonical policy bytes).
	t.Audit.Log("task.create", p.Canonical(), "active", nil, 0)

	cap := &capability.Capability{
		Version: 1, TaskID: taskID, Name: t.Name,
		Transport: s.transport, Endpoint: srv.Addr(),
		ClientPriv: clientPriv, TaskSecret: secret,
		ExpiresAt: expires, Policy: p.Name,
		// Short prefix of the canonical policy hash: the task's exact
		// authorization semantics, independent of YAML formatting.
		PolicyHash: p.CanonicalHash()[:12],
		Tools:      toolsForPolicy(p),
	}
	return cap, t, nil
}

// toolsForPolicy normalizes the policy into the MCP tool list the task
// exposes. A task MUST NOT expose a tool its policy cannot authorize;
// the gateway re-enforces every call regardless (list is a hint).
func toolsForPolicy(p *policy.Policy) []string {
	var out []string
	if p.Tools.Exec != nil && len(p.Tools.Exec.Allow) > 0 {
		out = append(out, "remote_exec")
	}
	if p.Tools.File != nil {
		if len(p.Tools.File.Read) > 0 {
			out = append(out, "remote_read", "remote_stat")
		}
		if p.Tools.File.Write != nil && len(p.Tools.File.Write.Roots) > 0 {
			out = append(out, "remote_write")
		}
	}
	return out
}

// taskName returns preferred when free, else a minted unique name.
func (s *server) taskName(preferred string) string {
	if NormalizeName(preferred) != "" {
		s.mu.Lock()
		used := false
		for _, lt := range s.live {
			if NormalizeName(lt.task.Name) == NormalizeName(preferred) {
				used = true
				break
			}
		}
		s.mu.Unlock()
		if !used {
			return strings.TrimSpace(preferred)
		}
	}
	return s.mintName()
}

// mintName returns a human-readable task name unique among live tasks.
func (s *server) mintName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	used := map[string]bool{}
	for _, lt := range s.live {
		used[NormalizeName(lt.task.Name)] = true
	}
	for i := 0; i < 100; i++ {
		name := MintName()
		if !used[NormalizeName(name)] {
			return name
		}
	}
	return capability.NewTaskID() // absurd collision run; fall back to id
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
	fmt.Fprintf(os.Stderr, "catflap serve: task %s expired — server closed, address dead\n", taskID)
}

// shutdown destroys every live task.
func (s *server) shutdown() {
	s.mu.Lock()
	live := s.live
	s.live = map[string]*liveTask{}
	s.mu.Unlock()
	for id, lt := range live {
		lt.timer.Stop()
		lt.task.Stop("shutdown")
		s.store.Delete(id)
	}
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

func writeState(path string, st StateFile) error {
	raw, merr := json.MarshalIndent(st, "", "  ")
	if merr != nil {
		return merr
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func randomToken() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
