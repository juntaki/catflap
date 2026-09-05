package gateway

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/policy"
	"github.com/juntaki/catflap/internal/rpc"
)

// fakeApprover is a scriptable Approver for tests: it records every
// request it was asked about (so tests can assert exactly how many
// times — and for which normalized operation — the operator was
// actually prompted) and answers according to decide, or blocks until
// ctx is done if block is set (to test cancellation).
type fakeApprover struct {
	decide func(req ApprovalRequest) (bool, error)
	block  bool
	calls  atomic.Int32
	seen   []ApprovalRequest
}

func (f *fakeApprover) Approve(ctx context.Context, req ApprovalRequest) (bool, error) {
	f.calls.Add(1)
	f.seen = append(f.seen, req)
	if f.block {
		<-ctx.Done()
		return false, ctx.Err()
	}
	return f.decide(req)
}

func alwaysApprove(ApprovalRequest) (bool, error) { return true, nil }
func alwaysDeny(ApprovalRequest) (bool, error)    { return false, nil }

func execAlwaysPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`
version: 1
name: gated
ttl: 15m
tools:
  exec:
    allow:
      - command: echo
        rest: any
        approval: always
`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func execOncePolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`
version: 1
name: gated
ttl: 15m
tools:
  exec:
    allow:
      - command: echo
        rest: any
        approval: once
`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestApprovalNeverDoesNotGate covers the P1 bug caught before this even
// reached review: a rule with no approval field at all (the Go zero
// value "" — e.g. policy.Default()'s struct literals, never touched by
// ParseApproval) must not require approval just because "" != "never" as
// raw string values. RequiresApproval(), not a direct ApprovalNever
// comparison, is what call sites must use.
func TestApprovalNeverDoesNotGate(t *testing.T) {
	s, _ := testStore(t, time.Minute) // policy.Default(): zero-value Approval fields throughout
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}}); !res.OK {
		t.Errorf("a rule with no approval field must not require one, got %+v", res)
	}
}

// TestApprovalNoApproverDeniesFailClosed covers the headless-safe
// default: approval:always/once with no Approver attached must deny,
// never silently allow.
func TestApprovalNoApproverDeniesFailClosed(t *testing.T) {
	s, _ := testStoreWithPolicy(t, execAlwaysPolicy(t), time.Minute)
	res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
	if res.OK {
		t.Fatal("no approver attached must deny, not allow")
	}
	if !strings.Contains(res.Error, "approval required") {
		t.Errorf("expected an approval-required message, got %q", res.Error)
	}
}

// TestApprovalAlwaysPromptsEveryTime covers approval:always: every call
// re-prompts, even for the exact same normalized operation — there is
// no once-cache for always.
func TestApprovalAlwaysPromptsEveryTime(t *testing.T) {
	s, task := testStoreWithPolicy(t, execAlwaysPolicy(t), time.Minute)
	ap := &fakeApprover{decide: alwaysApprove}
	task.SetApprover(ap)

	for i := 0; i < 3; i++ {
		if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}}); !res.OK {
			t.Fatalf("call %d: approved exec must succeed, got %+v", i, res)
		}
	}
	if got := ap.calls.Load(); got != 3 {
		t.Errorf("approval:always must prompt every call, got %d prompts for 3 calls", got)
	}
}

// TestApprovalOnceCachesExactOperation covers once's core semantics:
// approved for one normalized operation, that EXACT operation never
// prompts again — but any mutation (different argv) is a different
// operation and prompts again.
func TestApprovalOnceCachesExactOperation(t *testing.T) {
	s, task := testStoreWithPolicy(t, execOncePolicy(t), time.Minute)
	ap := &fakeApprover{decide: alwaysApprove}
	task.SetApprover(ap)

	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}}); !res.OK {
		t.Fatalf("first call must succeed: %+v", res)
	}
	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}}); !res.OK {
		t.Fatalf("identical second call must succeed: %+v", res)
	}
	if got := ap.calls.Load(); got != 1 {
		t.Errorf("identical operation must prompt exactly once, got %d prompts", got)
	}

	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"different"}}); !res.OK {
		t.Fatalf("mutated argv must still succeed once approved: %+v", res)
	}
	if got := ap.calls.Load(); got != 2 {
		t.Errorf("a different argv is a different operation and must prompt again, got %d total prompts", got)
	}
}

// TestApprovalDeniedByOperator covers the operator saying no: the call
// is denied, and (for once) nothing is cached — a denial must not be
// confused with an approval on any subsequent identical call.
func TestApprovalDeniedByOperator(t *testing.T) {
	s, task := testStoreWithPolicy(t, execOncePolicy(t), time.Minute)
	ap := &fakeApprover{decide: alwaysDeny}
	task.SetApprover(ap)

	res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
	if res.OK {
		t.Fatal("operator denial must deny the call")
	}
	if !strings.Contains(res.Error, "denied") {
		t.Errorf("expected a denial message, got %q", res.Error)
	}

	// Denial must not be cached as if it were an approval.
	res2 := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
	if res2.OK {
		t.Fatal("a prior denial must not become a cached approval")
	}
	if got := ap.calls.Load(); got != 2 {
		t.Errorf("a denied-then-retried identical operation must prompt again, got %d prompts", got)
	}
}

// TestApprovalOnceCacheScopedPerTaskNotShared covers "once" never
// crossing task boundaries: two different tasks with the same policy
// and the same operation each get their own independent approval — one
// task's approval must never authorize another task's identical call.
func TestApprovalOnceCacheScopedPerTaskNotShared(t *testing.T) {
	p := execOncePolicy(t)
	mkTask := func(id, secret string) *Task {
		alog, err := audit.Open("", id, "")
		if err != nil {
			t.Fatal(err)
		}
		tk := &Task{ID: id, Secret: secret, Policy: p, ExpiresAt: time.Now().Add(time.Minute), Audit: alog}
		tk.InitContext(context.Background())
		return tk
	}
	s := &Store{}
	taskA, taskB := mkTask("agt_a", "secret-a"), mkTask("agt_b", "secret-b")
	s.Add(taskA)
	s.Add(taskB)
	taskA.TryActivate()
	taskB.TryActivate()

	apA := &fakeApprover{decide: alwaysApprove}
	apB := &fakeApprover{decide: alwaysApprove}
	taskA.SetApprover(apA)
	taskB.SetApprover(apB)

	callAs := func(taskID, secret string) rpc.Response {
		t.Helper()
		c1, c2 := net.Pipe()
		defer func() { _ = c1.Close() }()
		defer func() { _ = c2.Close() }()
		go s.HandlerFor(taskID)(c2)
		raw := mustJSON(t, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
		if err := rpc.WriteRequest(c1, rpc.Request{Task: taskID, Secret: secret, ID: 1, Tool: rpc.ToolExec, Args: raw}); err != nil {
			t.Fatal(err)
		}
		res, err := rpc.ReadResponse(bufio.NewReader(c1))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := callAs("agt_a", "secret-a"); !res.OK {
		t.Fatalf("task A call must succeed: %+v", res)
	}
	if res := callAs("agt_b", "secret-b"); !res.OK {
		t.Fatalf("task B call must succeed: %+v", res)
	}
	if apA.calls.Load() != 1 || apB.calls.Load() != 1 {
		t.Errorf("each task must be prompted independently, got A=%d B=%d", apA.calls.Load(), apB.calls.Load())
	}
}

// TestApprovalHashBindingWrite covers write's normalization: the SAME
// path with DIFFERENT content is a different operation under once, and
// must prompt again — the approval hash binds path+content, not just
// path.
func TestApprovalHashBindingWrite(t *testing.T) {
	root := t.TempDir()
	p := writePolicy(t, root, `
      roots: ["`+root+`"]
      max_file_size: 4096
      create: true
      overwrite: true
      approval: once
`)
	s, task := testStoreWithPolicy(t, p, time.Minute)
	ap := &fakeApprover{decide: alwaysApprove}
	task.SetApprover(ap)

	path := root + "/f.txt"
	if res := call(t, s, rpc.ToolWrite, rpc.WriteArgs{Path: path, Content: "v1"}); !res.OK {
		t.Fatalf("first write must succeed: %+v", res)
	}
	if res := call(t, s, rpc.ToolWrite, rpc.WriteArgs{Path: path, Content: "v1"}); !res.OK {
		t.Fatalf("identical rewrite must succeed: %+v", res)
	}
	if got := ap.calls.Load(); got != 1 {
		t.Errorf("identical content must prompt exactly once, got %d", got)
	}
	if res := call(t, s, rpc.ToolWrite, rpc.WriteArgs{Path: path, Content: "v2"}); !res.OK {
		t.Fatalf("different content must still succeed once approved: %+v", res)
	}
	if got := ap.calls.Load(); got != 2 {
		t.Errorf("different content at the same path is a different operation, got %d total prompts", got)
	}
}

// TestApprovalCannotOverridePolicyDeny covers the non-negotiable
// ordering: approval is an ADDITIONAL restriction, never a substitute
// authorization. A command the policy doesn't allow at all must stay
// denied regardless of what any Approver would say — checkApproval must
// never even run for it.
func TestApprovalCannotOverridePolicyDeny(t *testing.T) {
	s, task := testStoreWithPolicy(t, execAlwaysPolicy(t), time.Minute)
	ap := &fakeApprover{decide: alwaysApprove} // would approve anything asked
	task.SetApprover(ap)

	res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "rm", Args: []string{"-rf", "/"}})
	if res.OK {
		t.Fatal("a policy-denied command must stay denied no matter what the approver would say")
	}
	if ap.calls.Load() != 0 {
		t.Error("the approver must never even be consulted for a policy-denied command")
	}
}

// TestApprovalRespectsTaskCancellation covers the cancellation
// requirement on Approver implementations: if the task dies (here,
// revoked) while a prompt is pending, the prompt's context must be
// cancelled — an Approver that respects ctx returns promptly instead of
// hanging, and the call must report denied, never hang or succeed.
func TestApprovalRespectsTaskCancellation(t *testing.T) {
	s, task := testStoreWithPolicy(t, execAlwaysPolicy(t), time.Minute)
	ap := &fakeApprover{block: true}
	task.SetApprover(ap)

	done := make(chan rpc.Response, 1)
	go func() {
		done <- call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}})
	}()

	// Give the call time to reach the (blocked) approver, then kill the
	// task out from under it.
	deadline := time.Now().Add(2 * time.Second)
	for ap.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ap.calls.Load() == 0 {
		t.Fatal("approver was never even reached")
	}
	task.Stop("revoked")

	select {
	case res := <-done:
		if res.OK {
			t.Error("a call whose task died mid-approval must not succeed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call never returned after the task was revoked mid-approval — the prompt held the concurrency slot forever")
	}
}

// TestApprovalAuditTrail covers the audit contract: approval decisions
// get their own "approval" audit lines (requested/granted/denied),
// distinct from the operation's own remote_exec allow/deny line.
func TestApprovalAuditTrail(t *testing.T) {
	dir := t.TempDir()
	alog, err := audit.Open(dir, "agt_test", "")
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: "agt_test", Secret: "s3cret", Policy: execAlwaysPolicy(t), ExpiresAt: time.Now().Add(time.Minute), Audit: alog}
	task.InitContext(context.Background())
	task.SetApprover(&fakeApprover{decide: alwaysApprove})
	s := &Store{}
	s.Add(task)
	task.TryActivate()

	if res := call(t, s, rpc.ToolExec, rpc.ExecArgs{Command: "echo", Args: []string{"hi"}}); !res.OK {
		t.Fatalf("approved call must succeed: %+v", res)
	}

	//nolint:gosec // reason: test-owned t.TempDir() joined with a fixed literal filename; never external input.
	raw, err := os.ReadFile(filepath.Join(dir, "agt_test.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"tool":"approval"`)) {
		t.Errorf("expected an approval-tool audit line, got:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte(`"decision":"requested"`)) || !bytes.Contains(raw, []byte(`"decision":"granted"`)) {
		t.Errorf("expected both requested and granted decisions in the audit trail, got:\n%s", raw)
	}
}
