package cli

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	verbose := fs.Bool("verbose", false, "verbose transport logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	pol, policyYAML, err := loadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy: %v\n", err)
		return 1
	}
	if *ttlFlag != "" {
		d, err := time.ParseDuration(*ttlFlag)
		if err != nil || d <= 0 {
			fmt.Fprintf(os.Stderr, "invalid --ttl %q\n", *ttlFlag)
			return 1
		}
		pol.TTL = d
	}

	s := &server{
		transport: *transportFlag, verbose: *verbose,
		auditDir: *auditDir, store: &gateway.Store{}, live: map[string]*liveTask{},
	}

	firstCap, firstTask, err := s.mkTask(pol, policyYAML)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint task: %v\n", err)
		return 1
	}

	// Admin API for `grant`.
	adminToken := randomToken()
	ln, err := net.Listen("tcp", *adminAddr)
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
		p := pol // default: same policy snapshot family
		var pYAML []byte = policyYAML
		if greq.PolicyYAML != "" {
			pp, err := policy.Parse([]byte(greq.PolicyYAML))
			if err != nil {
				http.Error(w, "bad policy: "+err.Error(), http.StatusBadRequest)
				return
			}
			p, pYAML = pp, []byte(greq.PolicyYAML)
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
		cap, _, err := s.mkTask(p, pYAML)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(GrantResponse{
			Task: cap.TaskID, Capability: cap.Encode(),
			ExpiresAt: cap.ExpiresAt.Format(time.RFC3339), Policy: cap.Policy,
		})
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
	go func() { _ = http.Serve(ln, mux) }()

	st := StateFile{Transport: *transportFlag, AdminAddr: ln.Addr().String(), AdminToken: adminToken}
	if err := writeState(*statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "write state: %v\n", err)
		s.shutdown()
		return 1
	}

	if *outPath != "" {
		if err := writeCapFile(*outPath, firstCap.Encode()); err != nil {
			fmt.Fprintf(os.Stderr, "write --out: %v\n", err)
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintf(os.Stderr, "catflap serve: shutting down, destroying all task keys\n")
	_ = ln.Close()
	_ = os.Remove(*statePath)
	s.shutdown()
	return 0
}

// mkTask creates one task with its own ephemeral network server and arms
// its expiry: timer → server.Close + audit.Close + store.Delete.
func (s *server) mkTask(p *policy.Policy, pYAML []byte) (*capability.Capability, *gateway.Task, error) {
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
	t.InitContext() // in-flight execs die with the task (C7)
	s.store.Add(t)

	var srv transport.Server
	if s.transport == "tailcat" {
		// Bound handler: only this task authenticates at this endpoint,
		// even with another task's valid secret.
		srv, err = tct.Serve(s.store.HandlerFor(taskID), []string{agentKey}, s.verbose)
	} else if s.transport == "local" {
		srv, err = local.Serve(s.store.HandlerFor(taskID))
	} else {
		err = fmt.Errorf("unknown transport %q (tailcat|local)", s.transport)
	}
	if err != nil {
		s.store.Delete(taskID)
		_ = alog.Close()
		return nil, nil, fmt.Errorf("start task server: %w", err)
	}
	lt := &liveTask{task: t, srv: srv}
	t.OnStopFunc(func() { _ = srv.Close() })
	lt.timer = time.AfterFunc(time.Until(expires), func() { s.expire(taskID) })
	s.mu.Lock()
	s.live[taskID] = lt
	s.mu.Unlock()

	cap := &capability.Capability{
		Version: 1, TaskID: taskID,
		Transport: s.transport, Endpoint: srv.Addr(),
		ClientPriv: clientPriv, TaskSecret: secret,
		ExpiresAt: expires, Policy: p.Name,
		PolicyHash: capability.PolicyHashOf(pYAML),
	}
	return cap, t, nil
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
	lt.task.Stop() // closes this task's server + audit
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
		lt.task.Stop()
		s.store.Delete(id)
	}
}

func loadPolicy(path string) (*policy.Policy, []byte, error) {
	if path == "" {
		return policy.Default(), []byte("# built-in default"), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	p, err := policy.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	return p, raw, nil
}

func writeState(path string, st StateFile) error {
	raw, _ := json.MarshalIndent(st, "", "  ")
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
