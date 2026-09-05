package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
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
	defer c1.Close()
	defer c2.Close()
	go s.Handler()(c2)
	raw, _ := json.Marshal(args)
	if err := rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "s3cret", ID: 1, Tool: tool, Args: raw}); err != nil {
		t.Fatal(err)
	}
	res, err := rpc.ReadResponse(bufio.NewReader(c1))
	if err != nil {
		t.Fatal(err)
	}
	return res
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
	pwnPath := "testdata/pwned-c0"
	_ = os.Remove(pwnPath)
	payloads := []string{
		"hi; touch " + pwnPath,
		"hi && touch " + pwnPath,
		"hi | touch " + pwnPath,
		"$(touch " + pwnPath + ")",
		"`touch " + pwnPath + "`",
		"hi\ntouch " + pwnPath,
	}
	for _, p := range payloads {
		res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{p}})
		out := execResult(t, res)
		if !strings.Contains(out.Stdout, p) {
			t.Errorf("payload should echo literally, got %q", out.Stdout)
		}
	}
	if _, err := os.Stat(pwnPath); !os.IsNotExist(err) {
		_ = os.Remove(pwnPath)
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
	defer c1.Close()
	defer c2.Close()
	go s.Handler()(c2)
	raw, _ := json.Marshal(rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
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
		tk.InitContext()
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
	defer srvA.Close()
	srvB, err := local.Serve(s.HandlerFor("agt_b"))
	if err != nil {
		t.Fatal(err)
	}
	defer srvB.Close()
	taskA.OnStopFunc(func() { _ = srvA.Close() })
	taskB.OnStopFunc(func() { _ = srvB.Close() })
	defer taskA.Stop()
	defer taskB.Stop()

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
		defer c.Close()
		raw, _ := json.Marshal(rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
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
	task.InitContext()

	type outcome struct {
		res rpc.Response
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		go s.Handler()(c2)
		raw, _ := json.Marshal(rpc.ExecArgs{Command: "/bin/sleep", Args: []string{"30"}, TimeoutMs: 60000})
		if err := rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "s3cret", ID: 1, Tool: rpc.ToolExec, Args: raw}); err != nil {
			done <- outcome{err: err}
			return
		}
		res, err := rpc.ReadResponse(bufio.NewReader(c1))
		done <- outcome{res: res, err: err}
	}()
	time.Sleep(500 * time.Millisecond) // let sleep(30) start
	start := time.Now()
	task.Stop() // simulate TTL expiry
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
func TestUnknownTask(t *testing.T) {
	s, task := testStore(t, time.Minute)
	task.Stop()
	s.Delete(task.ID)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go s.Handler()(c2)
	raw, _ := json.Marshal(rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
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

// TestSymlinkEscapeGate: intermediate and final-component symlinks denied.
func TestSymlinkEscapeGate(t *testing.T) {
	base := "testdata/symlink-gw"
	_ = os.RemoveAll(base)
	if err := os.MkdirAll(base+"/root", 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.WriteFile(base+"/secret.txt", []byte("secret"), 0o644); err != nil {
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
