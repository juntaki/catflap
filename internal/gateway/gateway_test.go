package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	task.InitContext(context.Background())
	s := &Store{}
	s.Add(task)
	task.TryActivate()
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
	task.InitContext(context.Background())
	s := &Store{}
	s.Add(task)
	task.TryActivate()
	return s, task
}

func call(t *testing.T, s *Store, tool string, args any) rpc.Response {
	t.Helper()
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	go s.HandlerFor("agt_test")(c2)
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
version: 1
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
	go s.HandlerFor("agt_test")(c2)
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

// TestAuditFailureStopsTaskOnEarlyReturn covers the P1 fix: handleRPC's
// early-return deny paths (expired, endpoint mismatch, concurrency limit)
// used to audit-log without checking whether that write itself failed, so
// an audit sink outage there left the task ACTIVE. Every audit write now
// funnels through Task.auditLog, which checks Err() and stops the task
// fail-closed regardless of which code path triggered the write.
func TestAuditFailureStopsTaskOnEarlyReturn(t *testing.T) {
	dir := t.TempDir()
	alog, err := audit.Open(dir, "agt_early", "")
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{
		ID: "agt_test", Secret: "s3cret",
		Policy: policy.Default(),
		// Already expired: handleRPC's early-return "expired" branch is
		// what audits and returns, before ever reaching beginOp/dispatch.
		ExpiresAt: time.Now().Add(-time.Minute),
		Audit:     alog,
	}
	task.InitContext(context.Background())
	s := &Store{}
	s.Add(task)
	task.TryActivate()

	_ = alog.Close()

	res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
	if res.OK || res.Error != "capability expired" {
		t.Fatalf("expired task must still deny normally, got %+v", res)
	}

	deadline := time.Now().Add(2 * time.Second)
	for task.StateOf() != StateStopped && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if task.StateOf() != StateStopped {
		t.Fatalf("audit sink failure on the early-return path must stop the task fail-closed, state=%v", task.StateOf())
	}
}

// TestPingFailsClosedOnAuditFailure covers the P1 fix: ping must not
// report OK for a task whose audit write just failed and stopped it —
// pairing uses ping as an "is this task alive" liveness signal, so a
// stale OK here would let it treat a dying task as successfully paired.
func TestPingFailsClosedOnAuditFailure(t *testing.T) {
	dir := t.TempDir()
	alog, err := audit.Open(dir, "agt_test", "")
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: "agt_test", Secret: "s3cret", Policy: policy.Default(), ExpiresAt: time.Now().Add(time.Minute), Audit: alog}
	task.InitContext(context.Background())
	s := &Store{}
	s.Add(task)
	task.TryActivate()

	_ = alog.Close()

	res := call(t, s, rpc.ToolPing, struct{}{})
	if res.OK {
		t.Errorf("ping must not report OK when its own audit write just failed, got %+v", res)
	}
	if task.StateOf() == StateActive {
		t.Errorf("task must have left ACTIVE, got state=%v", task.StateOf())
	}
}

// TestRevokeVsAuditFailureOwnershipMatchesWinner covers Phase 0's
// termination-ownership unification: TryRequestStop is the single
// arbiter (Task.stopOnce) that every termination path funnels through —
// an admin/agent revoke calling TryRequestStop directly, racing an
// audit sink failure detected inside auditLog (also TryRequestStop) —
// so exactly one reason ever takes effect, and it is always the one
// whose caller is told won == true.
func TestRevokeVsAuditFailureOwnershipMatchesWinner(t *testing.T) {
	dir := t.TempDir()
	alog, err := audit.Open(dir, "agt_test", "")
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: "agt_test", Secret: "s3cret", Policy: policy.Default(), ExpiresAt: time.Now().Add(time.Minute), Audit: alog}
	task.InitContext(context.Background())
	task.TryActivate()

	_ = alog.Close() // any further audit write is now a sink failure

	var wonRevoke bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, wonRevoke = task.TryRequestStop("revoked")
	}()
	go func() {
		defer wg.Done()
		task.auditLog(rpc.ToolPing, nil, "allow", nil, 0)
	}()
	wg.Wait()

	// auditLog's own win is only observable indirectly (it discards
	// TryRequestStop's won), so cross-check against the task's actual
	// cancellation cause: exactly one of "revoked wins" / "cause is
	// ErrTaskAuditFailed" can be true.
	causeIsRevoked := errors.Is(context.Cause(task.Context()), ErrTaskRevoked)
	causeIsAuditFailed := errors.Is(context.Cause(task.Context()), ErrTaskAuditFailed)
	if causeIsRevoked == causeIsAuditFailed {
		t.Fatalf("exactly one cause must win, got revoked=%v auditFailed=%v", causeIsRevoked, causeIsAuditFailed)
	}
	if wonRevoke != causeIsRevoked {
		t.Errorf("TryRequestStop(%q)'s won=%v must match the actual cause (revoked=%v)", "revoked", wonRevoke, causeIsRevoked)
	}
}

// TestTerminationCauseMapping covers the P2 fix: ping's fail-closed check
// used to hardcode "task terminated: audit unavailable" for ANY reason a
// concurrent revoke/expiry/shutdown/audit-failure left the task
// non-ACTIVE, not just an audit failure — terminationCause is the single
// mapping doExec's in-flight-kill path and ping now both use, so neither
// can drift from the other or hardcode the wrong cause.
func TestTerminationCauseMapping(t *testing.T) {
	cases := []struct {
		reason       string
		wantMsg      string
		wantDecision string
	}{
		{"expired", "capability expired", "expired"},
		{"revoked", "task revoked", "revoked"},
		{"shutdown", "task shutdown", "shutdown"},
		{"audit sink failed", "task terminated: audit unavailable", "error"},
	}
	for _, c := range cases {
		task := &Task{ID: "agt_test", Policy: policy.Default(), ExpiresAt: time.Now().Add(time.Minute)}
		task.InitContext(context.Background())
		task.TryActivate()
		task.Stop(c.reason)
		msg, decision := task.terminationCause()
		if msg != c.wantMsg || decision != c.wantDecision {
			t.Errorf("Stop(%q): terminationCause() = (%q, %q), want (%q, %q)",
				c.reason, msg, decision, c.wantMsg, c.wantDecision)
		}
	}
}

// TestRequestStopSynchronousStateTransition covers the P1 fix: the state
// flip to StateStopping (and thus beginOp refusing new ops) must happen
// before RequestStop returns, not somewhere inside an async goroutine.
// Before this fix, auditLog scheduled `go t.Stop(...)`, leaving a window
// where a concurrent connection's beginOp could still observe ACTIVE
// between "audit failure detected" and "task actually stopped".
func TestRequestStopSynchronousStateTransition(t *testing.T) {
	task := &Task{ID: "agt_test", Secret: "s3cret", Policy: policy.Default(), ExpiresAt: time.Now().Add(time.Minute)}
	task.InitContext(context.Background())
	task.TryActivate()

	done := task.RequestStop("audit sink failed")
	// No sleep, no polling: this must already be true the instant
	// RequestStop returns, synchronously — that's the property under test.
	if task.StateOf() == StateActive {
		t.Fatal("state must leave ACTIVE synchronously within RequestStop, not asynchronously")
	}
	if reason := task.beginOp(); reason == "" {
		t.Error("beginOp must refuse immediately after RequestStop returns")
	}
	<-done // async teardown must still complete
	if task.StateOf() != StateStopped {
		t.Errorf("state = %v, want StateStopped once RequestStop's channel closes", task.StateOf())
	}
}

// TestMalformedArgsAudited covers the P2 fix: a decode failure on tool
// args used to return before any audit write, so an authenticated client
// sending malformed JSON left no trace in the audit chain — contrary to
// "every decision (allow/deny/expired/error) is audited".
func TestMalformedArgsAudited(t *testing.T) {
	dir := t.TempDir()
	alog, err := audit.Open(dir, "agt_test", "")
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: "agt_test", Secret: "s3cret", Policy: policy.Default(), ExpiresAt: time.Now().Add(time.Minute), Audit: alog}
	task.InitContext(context.Background())
	s := &Store{}
	s.Add(task)
	task.TryActivate()

	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	go s.HandlerFor("agt_test")(c2)
	// Valid JSON (so the outer Request frame itself still marshals), but
	// the wrong shape to unmarshal into rpc.ExecArgs.
	if werr := rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "s3cret", ID: 1, Tool: rpc.ToolExec, Args: []byte(`123`)}); werr != nil {
		t.Fatal(werr)
	}
	res, err := rpc.ReadResponse(bufio.NewReader(c1))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Error != "bad exec args" {
		t.Fatalf("malformed args must still be denied normally, got %+v", res)
	}

	//nolint:gosec // reason: test-owned t.TempDir() joined with a fixed literal filename; never external input.
	raw, err := os.ReadFile(filepath.Join(dir, "agt_test.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"tool":"remote_exec"`) || !strings.Contains(string(raw), `"decision":"error"`) {
		t.Errorf("malformed args must produce an audited error entry, got:\n%s", raw)
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
	taskA.TryActivate()
	taskB.TryActivate()
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
version: 1
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
		go s.HandlerFor("agt_test")(c2)
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
version: 1
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
			go s.HandlerFor("agt_test")(c2)
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
	// P2 fix: an audit-fail-closed stop is not a TTL expiry, so an
	// in-flight exec killed by it must not be told "capability expired" —
	// that would misrepresent why access ended.
	run("audit sink failed", "task terminated: audit unavailable")
}

// TestLifecycleStates walks CREATING → ACTIVE → STOPPING → STOPPED and
// checks the operation gate at each step. Stop is idempotent.
func TestLifecycleStates(t *testing.T) {
	alog, err := audit.Open("", "agt_life", "nodekey:test")
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{
		ID: "agt_life", Secret: "s3cret",
		Policy:    policy.Default(),
		ExpiresAt: time.Now().Add(time.Minute),
		Audit:     alog,
	}
	if task.StateOf() != StateCreating {
		t.Errorf("new task state = %d, want creating", task.StateOf())
	}
	if reason := task.beginOp(); reason == "" {
		t.Error("creating task must reject operations")
		task.endOp()
	}
	task.InitContext(context.Background())
	task.TryActivate()
	if task.StateOf() != StateActive {
		t.Errorf("after Activate state = %d, want active", task.StateOf())
	}
	if reason := task.beginOp(); reason != "" {
		t.Fatalf("active task must accept operations: %s", reason)
	}
	task.endOp()
	task.Stop("revoked")
	if task.StateOf() != StateStopped {
		t.Errorf("after Stop state = %d, want stopped", task.StateOf())
	}
	if reason := task.beginOp(); reason == "" {
		t.Error("stopped task must reject operations")
		task.endOp()
	}
	if task.TryActivate() {
		t.Error("a stopped task must never reactivate (CAS)")
	}
	task.Stop("revoked") // idempotent: no panic, no second terminal event
}

// TestConcurrencyLimit: the second concurrent operation fails fast with a
// limit error instead of queueing unboundedly.
func TestConcurrencyLimit(t *testing.T) {
	if _, err := os.Stat("/bin/sleep"); err != nil {
		t.Skip("no /bin/sleep on this machine")
	}
	p, err := policy.Parse([]byte(`
version: 1
name: limited
ttl: 15m
limits:
  max_concurrent_calls: 1
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
	defer task.Stop("shutdown")
	defer s.Delete(task.ID)

	first := make(chan rpc.Response, 1)
	go func() {
		c1, c2 := net.Pipe()
		defer func() { _ = c1.Close() }()
		defer func() { _ = c2.Close() }()
		go s.HandlerFor("agt_test")(c2)
		raw := mustJSON(t, rpc.ExecArgs{Command: "/bin/sleep", Args: []string{"5"}, TimeoutMs: 30000})
		if werr := rpc.WriteRequest(c1, rpc.Request{Task: "agt_test", Secret: "s3cret", ID: 1, Tool: rpc.ToolExec, Args: raw}); werr != nil {
			t.Error(werr)
			return
		}
		res, rerr := rpc.ReadResponse(bufio.NewReader(c1))
		if rerr != nil {
			t.Error(rerr)
			return
		}
		first <- res
	}()
	time.Sleep(500 * time.Millisecond) // let sleep(5) occupy the single slot
	res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "/bin/sleep", Args: []string{"1"}})
	if res.OK || res.Error != "concurrency limit exceeded" {
		t.Errorf("second concurrent op must fail fast, got %+v", res)
	}
	select {
	case out := <-first:
		if !out.OK {
			t.Errorf("first op must succeed, got %+v", out)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("first op never finished")
	}
}

func TestUnknownTask(t *testing.T) {
	s, task := testStore(t, time.Minute)
	task.Stop("shutdown")
	s.Delete(task.ID)
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	go s.HandlerFor("agt_test")(c2)
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
version: 1
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
		go s.HandlerFor("agt_test")(c2)
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
version: 1
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

// writeFixture builds testdata/write-gw/root with a docs dir, a secret
// outside the root, and an escape symlink. In-project, cleaned up after.
func writeFixture(t *testing.T) string {
	t.Helper()
	base := "testdata/write-gw"
	_ = os.RemoveAll(base)
	if err := os.MkdirAll(base+"/root/docs", 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.WriteFile(base+"/root/docs/orig.txt", []byte("orig"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+"/secret.txt", []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", base+"/root/escape"); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func writePolicy(t *testing.T, root, writeYAML string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`
version: 1
name: writer
ttl: 15m
tools:
  file:
    read: ["` + root + `"]
    write:
` + writeYAML))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writeResult(t *testing.T, res rpc.Response) rpc.WriteResult {
	t.Helper()
	if !res.OK {
		t.Fatalf("write denied: %s", res.Error)
	}
	var out rpc.WriteResult
	if err := json.Unmarshal(res.Result, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRemoteWrite(t *testing.T) {
	absBase := writeFixture(t)
	root := absBase + "/root"
	full := `
      roots: ["` + root + `"]
      max_file_size: 262144
      create: true
      overwrite: true
      atomic: true
`
	t.Run("create and read back", func(t *testing.T) {
		s, _ := testStoreWithPolicy(t, writePolicy(t, root, full), time.Minute)
		out := writeResult(t, call(t, s, rpc.ToolWrite,
			rpc.WriteArgs{Path: root + "/docs/new.txt", Content: "hello"}))
		if !out.Created || out.Size != 5 {
			t.Errorf("bad result: %+v", out)
		}
		res := call(t, s, rpc.ToolRead, rpc.ReadArgs{Path: root + "/docs/new.txt"})
		if !res.OK {
			t.Fatalf("readback denied: %s", res.Error)
		}
		var got rpc.ReadResult
		if err := json.Unmarshal(res.Result, &got); err != nil {
			t.Fatal(err)
		}
		if got.Content != "hello" {
			t.Errorf("bad roundtrip: %q", got.Content)
		}
	})

	t.Run("overwrite allowed", func(t *testing.T) {
		s, _ := testStoreWithPolicy(t, writePolicy(t, root, full), time.Minute)
		out := writeResult(t, call(t, s, rpc.ToolWrite,
			rpc.WriteArgs{Path: root + "/docs/orig.txt", Content: "v2"}))
		if out.Created {
			t.Error("existing file must report created=false")
		}
	})

	t.Run("overwrite denied", func(t *testing.T) {
		noOver := `
      roots: ["` + root + `"]
      max_file_size: 262144
      create: true
      overwrite: false
`
		s, _ := testStoreWithPolicy(t, writePolicy(t, root, noOver), time.Minute)
		if res := call(t, s, rpc.ToolWrite,
			rpc.WriteArgs{Path: root + "/docs/orig.txt", Content: "v2"}); res.OK {
			t.Error("overwrite without grant must be denied")
		}
	})

	t.Run("create denied", func(t *testing.T) {
		noCreate := `
      roots: ["` + root + `"]
      max_file_size: 262144
      create: false
      overwrite: true
`
		s, _ := testStoreWithPolicy(t, writePolicy(t, root, noCreate), time.Minute)
		if res := call(t, s, rpc.ToolWrite,
			rpc.WriteArgs{Path: root + "/docs/nope.txt", Content: "x"}); res.OK {
			t.Error("create without grant must be denied")
		}
	})

	t.Run("no write grant denies", func(t *testing.T) {
		s, _ := testStore(t, time.Minute) // Default policy: read-only
		res := call(t, s, rpc.ToolWrite,
			rpc.WriteArgs{Path: root + "/docs/nope.txt", Content: "x"})
		if res.OK || res.Error != "file write is not allowed by policy" {
			t.Errorf("expected write denial, got %+v", res)
		}
	})

	t.Run("symlink escape denied", func(t *testing.T) {
		s, _ := testStoreWithPolicy(t, writePolicy(t, root, full), time.Minute)
		if res := call(t, s, rpc.ToolWrite,
			rpc.WriteArgs{Path: root + "/escape/pwned.txt", Content: "x"}); res.OK {
			t.Error("write via symlink escape must be denied")
		}
		if _, err := os.Stat(absBase + "/pwned.txt"); !os.IsNotExist(err) {
			t.Error("escape write landed outside the root")
		}
		if _, err := os.Stat(absBase + "/secret.txt"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("outside root denied", func(t *testing.T) {
		s, _ := testStoreWithPolicy(t, writePolicy(t, root, full), time.Minute)
		if res := call(t, s, rpc.ToolWrite,
			rpc.WriteArgs{Path: absBase + "/secret.txt", Content: "x"}); res.OK {
			t.Error("write outside root must be denied")
		}
	})

	t.Run("oversize denied", func(t *testing.T) {
		tiny := `
      roots: ["` + root + `"]
      max_file_size: 4
      create: true
      overwrite: true
`
		s, _ := testStoreWithPolicy(t, writePolicy(t, root, tiny), time.Minute)
		if res := call(t, s, rpc.ToolWrite,
			rpc.WriteArgs{Path: root + "/docs/big.txt", Content: "12345"}); res.OK {
			t.Error("oversize write must be denied")
		}
	})
}
