package gateway

import (
	"bufio"
	"encoding/json"
	"net"
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

func TestExecAllowDeny(t *testing.T) {
	s, _ := testStore(t, time.Minute)
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo hi"}); !res.OK {
		t.Errorf("echo should be allowed: %s", res.Error)
	}
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "rm -rf /"}); res.OK {
		t.Error("rm should be denied")
	}
}

func TestBadSecretAndExpiry(t *testing.T) {
	s, task := testStore(t, time.Minute)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go s.Handler()(c2)
	raw, _ := json.Marshal(rpc.ExecArgs{Command: "echo hi"})
	_ = rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "wrong", ID: 1, Tool: rpc.ToolExec, Args: raw})
	res, err := rpc.ReadResponse(bufio.NewReader(c1))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Error("bad secret should be rejected")
	}

	task.ExpiresAt = time.Now().Add(-time.Second)
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo hi"}); res.OK || res.Error != "capability expired" {
		t.Errorf("expired task should fail with expiry, got %+v", res)
	}
}

func TestReadRoots(t *testing.T) {
	s, _ := testStore(t, time.Minute)
	if res := call(t, s, rpc.ToolRead, rpc.ReadArgs{Path: "/etc/passwd"}); res.OK {
		t.Error("/etc/passwd should be denied by default policy")
	}
}
