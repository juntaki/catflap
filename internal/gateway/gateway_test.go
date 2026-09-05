package gateway

import (
	"bufio"
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

// TestUnknownTask: deleted (GC'd) tasks authenticate as unknown.
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
