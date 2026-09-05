package gateway

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/policy"
	"github.com/juntaki/catflap/internal/rpc"
)

// Task is one live ephemeral grant: policy snapshot + expiry + audit chain.
// Stop tears the whole task down; expiry and shutdown both funnel through it.
type Task struct {
	ID        string
	Secret    string
	Policy    *policy.Policy
	ExpiresAt time.Time
	Audit     *audit.Logger
	AgentKey  string

	stopOnce sync.Once
	// onStop releases task-external resources (its Tailcat server).
	// Set by the serve loop; nil in tests.
	onStop func()
}

// Stop destroys the task: closes audit, releases the network server,
// and must be followed by Store.Delete.
func (t *Task) Stop() {
	t.stopOnce.Do(func() {
		if t.onStop != nil {
			t.onStop()
		}
		if t.Audit != nil {
			_ = t.Audit.Close()
		}
	})
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
// Call t.Stop() first to release its server and audit handle.
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
func (s *Store) Handler() func(net.Conn) {
	return func(conn net.Conn) {
		defer conn.Close()
		r := bufio.NewReaderSize(conn, 64<<10)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			req, err := rpc.ReadRequest(r)
			if err != nil {
				return
			}
			res := s.handle(req)
			if err := rpc.WriteResponse(conn, res); err != nil {
				return
			}
		}
	}
}

func (s *Store) handle(req RequestAlias) ResponseAlias {
	return s.handleRPC(req)
}

// handleRPC authenticates then dispatches one call with auditing.
func (s *Store) handleRPC(req rpc.Request) rpc.Response {
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
	switch req.Tool {
	case rpc.ToolExec:
		return s.doExec(t, req)
	case rpc.ToolRead:
		return s.doRead(t, req)
	case rpc.ToolStat:
		return s.doStat(t, req)
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
	timeout := time.Duration(args.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout > 2*time.Minute {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// No shell, ever: argv goes straight to the pinned executable.
	cmd := exec.CommandContext(ctx, exe, args.Args...)
	// Narrow environment: no passthrough of caller env.
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/local/bin", "LC_ALL=C"}
	stdout, stderr := boundedBuffer(256 << 10), boundedBuffer(64 << 10)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	res := rpc.ExecResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
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
	real, err := t.Policy.ResolveRead(args.Path)
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
	info, err := os.Stat(real)
	if err != nil {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "error", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "stat: " + err.Error()}
	}
	if info.IsDir() {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "deny", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "is a directory (use remote_stat)"}
	}
	const maxRead = 1 << 20
	// O_NOFOLLOW: the final component must not be a symlink at open time.
	f, err := os.OpenFile(real, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "deny", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "open: " + err.Error()}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRead+1))
	_ = f.Close()
	if err != nil {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "error", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "read: " + err.Error()}
	}
	res := rpc.ReadResult{Size: info.Size()}
	if len(data) > maxRead {
		res.Content, res.Truncated = string(data[:maxRead]), true
	} else {
		res.Content = string(data)
	}
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
	real, err := t.Policy.ResolveRead(args.Path)
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
	info, err := os.Stat(real)
	if err != nil {
		if t.Audit != nil {
			t.Audit.Log(req.Tool, req.Args, "error", nil, time.Since(start))
		}
		return rpc.Response{ID: req.ID, OK: false, Error: "stat: " + err.Error()}
	}
	res := rpc.StatResult{
		Name: info.Name(), Size: info.Size(),
		Mode: info.Mode().String(),
		ModTime: info.ModTime().UTC().Format(time.RFC3339),
		IsDir:   info.IsDir(),
	}
	raw := rpc.MustRaw(res)
	if t.Audit != nil {
		t.Audit.Log(req.Tool, req.Args, "allow", raw, time.Since(start))
	}
	return rpc.Response{ID: req.ID, OK: true, Result: raw}
}

func isStatError(err error) bool {
	msg := err.Error()
	return len(msg) >= 6 && msg[:6] == "stat: "
}

// RequestAlias / ResponseAlias keep the transport seam free of refactors:
// gateway speaks rpc types directly.
type RequestAlias = rpc.Request
type ResponseAlias = rpc.Response
