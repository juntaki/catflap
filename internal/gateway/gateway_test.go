package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/policy"
	"github.com/juntaki/catflap/internal/rpc"
	"github.com/juntaki/catflap/internal/transport/local"
)

func testStore(t *testing.T, ttl time.Duration) (*Store, *Task) {
	t.Helper()
	alog, err := audit.Open("", "agt_test", "nodekey:test")
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{
		ID: "agt_test", Secret: "s3cret",
		Policy:    policy.Default(),
		ExpiresAt: time.Now().Add(ttl),
		Audit:     alog,
	}
	s := &Store{}
	s.Add(task)
	return s, task
}

func testStoreWithPolicy(t *testing.T, p *policy.Policy, ttl time.Duration) (*Store, *Task) {
	t.Helper()
	alog, err := audit.Open("", "agt_test", "nodekey:test")
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{
		ID: "agt_test", Secret: "s3cret",
		Policy:    p,
		ExpiresAt: time.Now().Add(ttl),
		Audit:     alog,
	}
	s := &Store{}
	s.Add(task)
	return s, task
}

func call(t *testing.T, s *Store, tool string, args any) rpc.Response {
	t.Helper()
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	go s.Handler()(c2)
	raw := mustJSON(t, args)
	if err := rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "s3cret", ID: 1, Tool: tool, Args: raw}); err != nil {
		t.Fatal(err)
	}
	res, err := rpc.ReadResponse(bufio.NewReader(c1))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func execResult(t *testing.T, res rpc.Response) rpc.ExecResult {
	t.Helper()
	if !res.OK {
		t.Fatalf("exec denied: %s", res.Error)
	}
	var out rpc.ExecResult
	if err := json.Unmarshal(res.Result, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExecAllowDeny(t *testing.T) {
	s, _ := testStore(t, time.Minute)
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}}); !res.OK {
		t.Errorf("echo should be allowed: %s", res.Error)
	}
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "rm", Args: []string{"-rf", "/"}}); res.OK {
		t.Error("rm should be denied")
	}
	// Arity is enforced even for allowed commands.
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "pwd", Args: []string{"x"}}); res.OK {
		t.Error("pwd with args should be denied")
	}
}

// TestShellMetacharsInert is the C0 adversarial core: every classic shell
// escape must arrive as inert argv, never execute.
func TestShellMetacharsInert(t *testing.T) {
	s, _ := testStore(t, time.Minute)
	probePath := "testdata/probe-c0"
	_ = os.Remove(probePath)
	payloads := []string{
		"hi; touch " + probePath,
		"hi && touch " + probePath,
		"hi | touch " + probePath,
		"$(touch " + probePath + ")",
		"`touch " + probePath + "`",
		"hi\ntouch " + probePath,
	}
	for _, p := range payloads {
		res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{p}})
		out := execResult(t, res)
		if !strings.Contains(out.Stdout, p) {
			t.Errorf("payload should echo literally, got %q", out.Stdout)
		}
	}
	if _, err := os.Stat(probePath); !os.IsNotExist(err) {
		_ = os.Remove(probePath)
		t.Fatal("shell escape executed: payload file was created")
	}
}

// TestArgSmuggling: extra argv beyond the rule shape is denied.
func TestArgSmuggling(t *testing.T) {
	p, err := policy.Parse([]byte(`
name: strict
ttl: 15m
tools:
  exec:
    allow:
      - command: echo
        args: ["-n"]
`))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := testStoreWithPolicy(t, p, time.Minute)
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"-n"}}); !res.OK {
		t.Errorf("exact shape should be allowed: %s", res.Error)
	}
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"-n", "extra"}}); res.OK {
		t.Error("trailing extra arg should be denied")
	}
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"-e"}}); res.OK {
		t.Error("wrong flag should be denied")
	}
}

func TestBadSecretAndExpiry(t *testing.T) {
	s, task := testStore(t, time.Minute)
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	go s.Handler()(c2)
	raw := mustJSON(t, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
	_ = rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "wrong", ID: 1, Tool: rpc.ToolExec, Args: raw})
	res, err := rpc.ReadResponse(bufio.NewReader(c1))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Error("bad secret should be rejected")
	}

	task.ExpiresAt = time.Now().Add(-time.Second)
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}}); res.OK || res.Error != "capability expired" {
		t.Errorf("expired task should fail with expiry, got %+v", res)
	}
}

// TestEndpointTaskBinding is the cross-credential quadrant test: each task
// owns an endpoint, and a valid secret for task B is useless at A's endpoint.
func TestEndpointTaskBinding(t *testing.T) {
	mkTask := func(id, secret string) *Task {
		alog, err := audit.Open("", id, "nodekey:test")
		if err != nil {
			t.Fatal(err)
		}
		tk := &Task{ID: id, Secret: secret, Policy: policy.Default(),
			ExpiresAt: time.Now().Add(time.Minute), Audit: alog}
		tk.InitContext(context.Background())
		return tk
	}
	s := &Store{}
	taskA, taskB := mkTask("agt_a", "secret-a"), mkTask("agt_b", "secret-b")
	s.Add(taskA)
	s.Add(taskB)
	srvA, err := local.Serve(s.HandlerFor("agt_a"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srvA.Close() }()
	srvB, err := local.Serve(s.HandlerFor("agt_b"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srvB.Close() }()
	taskA.OnStopFunc(func() { _ = srvA.Close() })
	taskB.OnStopFunc(func() { _ = srvB.Close() })
	defer taskA.Stop("shutdown")
	defer taskB.Stop("shutdown")

	dial := func(addr string) net.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	try := func(addr, taskID, secret string) rpc.Response {
		c := dial(addr)
		defer func() { _ = c.Close() }()
		raw, merr := json.Marshal(rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
		if merr != nil {
			t.Fatal(merr)
		}
		if err := rpc.WriteRequest(c, rpc.Request{Task: taskID, Secret: secret, ID: 1, Tool: rpc.ToolExec, Args: raw}); err != nil {
			t.Fatal(err)
		}
		res, err := rpc.ReadResponse(bufio.NewReader(c))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	if res := try(srvA.Addr(), "agt_a", "secret-a"); !res.OK {
		t.Errorf("A endpoint + A secret should allow: %s", res.Error)
	}
	if res := try(srvB.Addr(), "agt_b", "secret-b"); !res.OK {
		t.Errorf("B endpoint + B secret should allow: %s", res.Error)
	}
	// Stolen-secret cross-use: valid B secret at A's endpoint must deny.
	if res := try(srvA.Addr(), "agt_b", "secret-b"); res.OK {
		t.Error("A endpoint + B secret (stolen) must be denied")
	}
	if res := try(srvB.Addr(), "agt_a", "secret-a"); res.OK {
		t.Error("B endpoint + A secret (stolen) must be denied")
	}
	// Wrong secret anywhere must deny.
	if res := try(srvA.Addr(), "agt_a", "secret-b"); res.OK {
		t.Error("A endpoint + wrong secret must be denied")
	}
}

// TestExpiryKillsInflightExec (C7): stopping the task kills a running exec
// instead of orphaning it past the TTL.
func TestExpiryKillsInflightExec(t *testing.T) {
	if _, err := os.Stat("/bin/sleep"); err != nil {
		t.Skip("no /bin/sleep on this machine")
	}
	p, err := policy.Parse([]byte(`
name: sleeper
ttl: 15m
tools:
  exec:
    allow:
      - command: /bin/sleep
        args: [{ integer: { max: 60 } }]
`))
	if err != nil {
		t.Fatal(err)
	}
	s, task := testStoreWithPolicy(t, p, time.Minute)
	task.InitContext(context.Background())

	type outcome struct {
		res rpc.Response
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		c1, c2 := net.Pipe()
		defer func() { _ = c1.Close() }()
		defer func() { _ = c2.Close() }()
		go s.Handler()(c2)
		raw := mustJSON(t, rpc.ExecArgs{Command: "/bin/sleep", Args: []string{"30"}, TimeoutMs: 60000})
		if err := rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "s3cret", ID: 1, Tool: rpc.ToolExec, Args: raw}); err != nil {
			done <- outcome{err: err}
			return
		}
		res, err := rpc.ReadResponse(bufio.NewReader(c1))
		done <- outcome{res: res, err: err}
	}()
	time.Sleep(500 * time.Millisecond) // let sleep(30) start
	start := time.Now()
	task.Stop("expired") // simulate TTL expiry
	s.Delete(task.ID)
	out := <-done
	if out.err != nil {
		t.Fatalf("rpc failed: %v", out.err)
	}
	if out.res.OK || out.res.Error != "capability expired" {
		t.Errorf("killed exec must report expiry, got %+v", out.res)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("exec survived Stop by %s (should die immediately)", elapsed)
	}
}

// TestStopCauseReporting: the kill reason reaches the in-flight caller.
// Expired → "capability expired"; revoked/shutdown carry their own message
// so future revoke cannot masquerade as expiry.
func TestStopCauseReporting(t *testing.T) {
	if _, err := os.Stat("/bin/sleep"); err != nil {
		t.Skip("no /bin/sleep on this machine")
	}
	p, err := policy.Parse([]byte(`
name: sleeper
ttl: 15m
tools:
  exec:
    allow:
      - command: /bin/sleep
        args: [{ integer: { max: 60 } }]
`))
	if err != nil {
		t.Fatal(err)
	}
	run := func(reason, wantErr string) {
		t.Helper()
		s, task := testStoreWithPolicy(t, p, time.Minute)
		task.InitContext(context.Background())
		type outcome struct {
			res rpc.Response
			err error
		}
		done := make(chan outcome, 1)
		go func() {
			c1, c2 := net.Pipe()
			defer func() { _ = c1.Close() }()
			defer func() { _ = c2.Close() }()
			go s.Handler()(c2)
			raw := mustJSON(t, rpc.ExecArgs{Command: "/bin/sleep", Args: []string{"30"}, TimeoutMs: 60000})
			if werr := rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "s3cret", ID: 1, Tool: rpc.ToolExec, Args: raw}); werr != nil {
				done <- outcome{err: werr}
				return
			}
			res, rerr := rpc.ReadResponse(bufio.NewReader(c1))
			done <- outcome{res: res, err: rerr}
		}()
		time.Sleep(500 * time.Millisecond)
		task.Stop(reason)
		s.Delete(task.ID)
		out := <-done
		if out.err != nil {
			t.Fatalf("rpc failed: %v", out.err)
		}
		if out.res.OK || out.res.Error != wantErr {
			t.Errorf("Stop(%q): got %+v, want error %q", reason, out.res, wantErr)
		}
	}
	run("expired", "capability expired")
	run("revoked", "task revoked")
	run("shutdown", "task shutdown")
}

func TestUnknownTask(t *testing.T) {
	s, task := testStore(t, time.Minute)
	task.Stop("shutdown")
	s.Delete(task.ID)
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	go s.Handler()(c2)
	raw := mustJSON(t, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
	_ = rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "s3cret", ID: 1, Tool: rpc.ToolExec, Args: raw})
	res, err := rpc.ReadResponse(bufio.NewReader(c1))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Error("deleted task should be rejected")
	}
}

func TestReadRoots(t *testing.T) {
	s, _ := testStore(t, time.Minute)
	if res := call(t, s, rpc.ToolRead, rpc.ReadArgs{Path: "/etc/passwd"}); res.OK {
		t.Error("/etc/passwd should be denied by default policy")
	}
}

// TestProcessTreeKill: stopping the task must kill grandchildren too, not
// just the direct child. Uses sh only as a test-local spawner (the product
// never grants shells); unix-only, since tree-kill needs process groups.
func TestProcessTreeKill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group kill is unix-only")
	}
	for _, bin := range []string{"/bin/sh", "/bin/sleep"} {
		if _, err := os.Stat(bin); err != nil {
			t.Skipf("missing %s on this machine", bin)
		}
	}
	p, err := policy.Parse([]byte(`
name: treekill
ttl: 15m
tools:
  exec:
    allow:
      - command: /bin/sh
        rest: any
`))
	if err != nil {
		t.Fatal(err)
	}
	s, task := testStoreWithPolicy(t, p, time.Minute)
	task.InitContext(context.Background())

	type outcome struct {
		res rpc.Response
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		c1, c2 := net.Pipe()
		defer func() { _ = c1.Close() }()
		defer func() { _ = c2.Close() }()
		go s.Handler()(c2)
		// sh spawns a grandchild sleep; both must die on Stop.
		raw := mustJSON(t, rpc.ExecArgs{
			Command: "/bin/sh", Args: []string{"-c", "sleep 45"}, TimeoutMs: 60000,
		})
		if err := rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "s3cret", ID: 1, Tool: rpc.ToolExec, Args: raw}); err != nil {
			done <- outcome{err: err}
			return
		}
		res, err := rpc.ReadResponse(bufio.NewReader(c1))
		done <- outcome{res: res, err: err}
	}()
	// Wait until the grandchild is observable, then stop the task.
	deadline := time.Now().Add(10 * time.Second)
	for !procExists("sleep 45") {
		if time.Now().After(deadline) {
			t.Fatal("grandchild sleep never appeared")
		}
		time.Sleep(100 * time.Millisecond)
	}
	task.Stop("expired")
	s.Delete(task.ID)
	out := <-done
	if out.err != nil {
		t.Fatalf("rpc failed: %v", out.err)
	}
	if out.res.OK || out.res.Error != "capability expired" {
		t.Errorf("killed tree must report expiry, got %+v", out.res)
	}
	// The grandchild must be gone: poll briefly to let SIGKILL land.
	gone := false
	for i := 0; i < 50 && !gone; i++ {
		gone = !procExists("sleep 45")
		time.Sleep(100 * time.Millisecond)
	}
	if !gone {
		t.Error("grandchild sleep survived task Stop (process-tree kill failed)")
	}
}

// procExists reports whether a process matching pattern exists, via pgrep.
// Test-only helper (unix).
func procExists(pattern string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//nolint:gosec // reason: fixed test binary with a constant pattern; no agent input reaches exec here.
	cmd := exec.CommandContext(ctx, "pgrep", "-f", pattern)
	return cmd.Run() == nil
}

// TestSymlinkEscapeGate: intermediate and final-component symlinks denied.
func TestSymlinkEscapeGate(t *testing.T) {
	base := "testdata/symlink-gw"
	_ = os.RemoveAll(base)
	if err := os.MkdirAll(base+"/root", 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.WriteFile(base+"/secret.txt", []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", base+"/root/escape"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../secret.txt", base+"/root/link"); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse([]byte(`
name: confined
ttl: 15m
tools:
  file:
    read: ["` + base + `/root"]
`))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := testStoreWithPolicy(t, p, time.Minute)
	absBase, _ := filepath.Abs(base)
	for _, path := range []string{
		absBase + "/root/escape/secret.txt",
		absBase + "/root/link",
	} {
		if res := call(t, s, rpc.ToolRead, rpc.ReadArgs{Path: path}); res.OK {
			t.Errorf("symlink escape must be denied: %s", path)
		}
		if res := call(t, s, rpc.ToolStat, rpc.StatArgs{Path: path}); res.OK {
			t.Errorf("symlink escape (stat) must be denied: %s", path)
		}
	}
}
