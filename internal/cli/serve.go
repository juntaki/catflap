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

// Serve runs the target gateway. It mints one initial task immediately
// (single-task demo works with serve alone) and keeps an admin API on
// loopback for `grant` to mint more tasks until SIGINT/SIGTERM.
func Serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "YAML policy file (default: built-in readonly-debug)")
	ttlFlag := fs.String("ttl", "", "TTL override, e.g. 15m (default: policy ttl)")
	transportFlag := fs.String("transport", "tailcat", "transport: tailcat | local")
	auditDir := fs.String("audit", DefaultAuditDir(), "audit JSONL directory (empty disables file audit)")
	statePath := fs.String("state", DefaultStatePath(), "state file for `grant` coordination")
	adminAddr := fs.String("admin", "127.0.0.1:0", "loopback admin API listen address")
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

	store := &gateway.Store{}
	mkTask := func(p *policy.Policy) (*gateway.Task, string, error) {
		taskID := capability.NewTaskID()
		secret := capability.NewSecret()
		expires := time.Now().Add(p.TTL)
		agentKey := ""
		var clientPriv string
		if *transportFlag == "tailcat" {
			priv, pub, err := tct.GenerateClientKey()
			if err != nil {
				return nil, "", err
			}
			clientPriv, agentKey = priv, pub
			_ = clientPriv
		}
		alog, err := audit.Open(*auditDir, taskID, agentKey)
		if err != nil {
			return nil, "", fmt.Errorf("audit: %w", err)
		}
		t := &gateway.Task{ID: taskID, Secret: secret, Policy: p, ExpiresAt: expires, Audit: alog, AgentKey: agentKey}
		store.Add(t)
		return t, clientPriv, nil
	}

	firstTask, firstPriv, err := mkTask(pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint task: %v\n", err)
		return 1
	}

	var srv transport.Server
	var firstAllowed string
	if *transportFlag == "tailcat" {
		firstAllowed = firstTask.AgentKey
		srv, err = tct.Serve(store.Handler(), []string{firstAllowed}, *verbose)
	} else if *transportFlag == "local" {
		srv, err = local.Serve(store.Handler())
	} else {
		fmt.Fprintf(os.Stderr, "unknown --transport %q (tailcat|local)\n", *transportFlag)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "start server: %v\n", err)
		return 1
	}
	defer srv.Close()

	cap := &capability.Capability{
		Version: 1, TaskID: firstTask.ID,
		Transport: *transportFlag, Endpoint: srv.Addr(),
		ClientPriv: firstPriv, TaskSecret: firstTask.Secret,
		ExpiresAt: firstTask.ExpiresAt, Policy: pol.Name,
		PolicyHash: capability.PolicyHashOf(policyYAML),
	}
	capStr := cap.Encode()

	// Admin API for `grant`.
	adminToken := randomToken()
	ln, err := net.Listen("tcp", *adminAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin listen: %v\n", err)
		return 1
	}
	defer ln.Close()
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
		t, priv, err := mkTask(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if *transportFlag == "tailcat" {
			if err := srv.AddAllowedClient(t.AgentKey); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		c := &capability.Capability{
			Version: 1, TaskID: t.ID, Transport: *transportFlag, Endpoint: srv.Addr(),
			ClientPriv: priv, TaskSecret: t.Secret,
			ExpiresAt: t.ExpiresAt, Policy: p.Name,
			PolicyHash: capability.PolicyHashOf(pYAML),
		}
		_ = json.NewEncoder(w).Encode(GrantResponse{
			Task: t.ID, Capability: c.Encode(),
			ExpiresAt: t.ExpiresAt.Format(time.RFC3339), Policy: p.Name,
		})
	})
	mux.HandleFunc("/tasks", func(w http.ResponseWriter, r *http.Request) {
		if "Bearer "+adminToken != strings.TrimSpace(r.Header.Get("Authorization")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		type item struct {
			Task string `json:"task"`
			Policy string `json:"policy"`
			Expires string `json:"expires_at"`
		}
		var out []item
		for _, t := range store.List() {
			out = append(out, item{Task: t.ID, Policy: t.Policy.Name, Expires: t.ExpiresAt.Format(time.RFC3339)})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	go func() { _ = http.Serve(ln, mux) }()

	st := StateFile{Transport: *transportFlag, Endpoint: srv.Addr(), AdminAddr: ln.Addr().String(), AdminToken: adminToken}
	if err := writeState(*statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "write state: %v\n", err)
		return 1
	}
	defer os.Remove(*statePath)

	fmt.Printf("Task: %s\nCapability:\n%s\nExpires: %s\nPolicy: %s\nTransport: %s\n",
		firstTask.ID, capStr, firstTask.ExpiresAt.Format(time.RFC3339), pol.Name, *transportFlag)
	fmt.Fprintf(os.Stderr, "catflap serve: task %s live for %s; Ctrl-C to destroy keys\n", firstTask.ID, pol.TTL.Round(time.Second))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	// Also wake at first-task expiry so single-task servers don't linger forever.
	timer := time.NewTimer(time.Until(firstTask.ExpiresAt))
	defer timer.Stop()
	select {
	case <-sig:
	case <-timer.C:
		fmt.Fprintf(os.Stderr, "catflap serve: task expired, shutting down\n")
	}
	return 0
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
