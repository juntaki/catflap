package cli

import (
	"context"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/gateway"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/policy"
)

// TestIssuePairCodeForMintedTask covers share-code's core dependency: a
// task's capability is retained after mkTask returns, so issuePairCode
// can start a pair server for it and hand out a code without minting a
// new task — and Fetch against that code recovers the exact capability.
func TestIssuePairCodeForMintedTask(t *testing.T) {
	s := &server{
		transport: "local",
		auditDir:  t.TempDir(),
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  4,
	}
	p := policy.Default()
	p.TTL = time.Hour

	cap, task, err := s.mkTask(context.Background(), p, "")
	if err != nil {
		t.Fatal(err)
	}

	code, actualTTL, err := s.issuePairCode(task.ID, time.Minute)
	if err != nil {
		t.Fatalf("issuePairCode: %v", err)
	}
	if actualTTL != time.Minute {
		t.Errorf("actualTTL = %v, want the requested %v (task has an hour left)", actualTTL, time.Minute)
	}

	transportName, addr, err := pair.Decode(code)
	if err != nil {
		t.Fatalf("decode code: %v", err)
	}
	got, err := pair.Fetch(context.Background(), transportName, addr, false)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got.TaskID != cap.TaskID || got.TaskSecret != cap.TaskSecret {
		t.Errorf("fetched capability = %+v, want it to match the minted one", got)
	}
}

// TestIssuePairCodeFailsAfterTaskStops covers the flip side: once a
// task is torn down, it must no longer be re-pairable via
// `share-code`.
func TestIssuePairCodeFailsAfterTaskStops(t *testing.T) {
	s := &server{
		transport: "local",
		auditDir:  t.TempDir(),
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  4,
	}
	p := policy.Default()
	p.TTL = time.Hour

	_, task, err := s.mkTask(context.Background(), p, "")
	if err != nil {
		t.Fatal(err)
	}
	task.Stop("revoked")

	if _, _, err := s.issuePairCode(task.ID, time.Minute); err == nil {
		t.Fatal("issuePairCode must fail for a stopped task")
	}
}

// TestIssuePairCodeReplacesPreviousPairServer covers "at most one
// claimable code per task at a time": issuing a second code for the
// same still-live task must close the first pair server, so an old,
// unused code can never be claimed after a newer one was issued.
func TestIssuePairCodeReplacesPreviousPairServer(t *testing.T) {
	s := &server{
		transport: "local",
		auditDir:  t.TempDir(),
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  4,
	}
	p := policy.Default()
	p.TTL = time.Hour

	_, task, err := s.mkTask(context.Background(), p, "")
	if err != nil {
		t.Fatal(err)
	}

	firstCode, _, err := s.issuePairCode(task.ID, time.Minute)
	if err != nil {
		t.Fatalf("first issuePairCode: %v", err)
	}
	if _, _, secondErr := s.issuePairCode(task.ID, time.Minute); secondErr != nil {
		t.Fatalf("second issuePairCode: %v", secondErr)
	}

	transportName, addr, err := pair.Decode(firstCode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pair.Fetch(context.Background(), transportName, addr, false); err == nil {
		t.Error("the first pair server must have been closed once a second code was issued for the same task")
	}
}

// TestIssuePairCodeRejectsStoppingTask covers a real bug: audit
// fail-closed (and every other termination path) flips a task's state
// to STOPPING synchronously, but only removes it from s.live later,
// asynchronously, after up to a 10s drain — so a share-code call
// landing in that window would see the task still "present" in s.live
// and hand out a capability for a task that is already on its way out.
// issuePairCode must check StateOf(), not just s.live membership.
func TestIssuePairCodeRejectsStoppingTask(t *testing.T) {
	task := &gateway.Task{ID: "agt_stopping", Policy: policy.Default(), ExpiresAt: time.Now().Add(time.Hour)}
	task.InitContext(context.Background())
	task.TryActivate()

	blocked := make(chan struct{})
	unblock := make(chan struct{})
	task.OnStopFunc(func() {
		close(blocked)
		<-unblock // teardown (and thus removal from s.live) stalls here
	})

	s := &server{transport: "local", live: map[string]*liveTask{
		"agt_stopping": {task: task, cap: &capability.Capability{TaskID: "agt_stopping"}},
	}}

	task.TryRequestStop("revoked")
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("teardown never reached the blocking OnStopFunc")
	}

	// Task is STOPPING and still sitting in s.live right now — this is
	// exactly the window the fix must close.
	if _, _, err := s.issuePairCode("agt_stopping", time.Minute); err == nil {
		t.Fatal("issuePairCode must reject a task that is STOPPING, even while still present in s.live")
	}

	close(unblock)
}

// TestIssuePairCodeClampsToRemainingTaskTTL covers a real bug: a
// pairing code issued with a TTL longer than the task's own remaining
// TTL would let its pair server stay claimable after the task itself
// already expired — Fetch would succeed, but the capability behind it
// would immediately fail as expired. The pair server's TTL must never
// exceed the task's remaining life.
func TestIssuePairCodeClampsToRemainingTaskTTL(t *testing.T) {
	s := &server{
		transport: "local",
		auditDir:  t.TempDir(),
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  4,
	}
	p := policy.Default()
	p.TTL = 2 * time.Second

	_, task, err := s.mkTask(context.Background(), p, "")
	if err != nil {
		t.Fatal(err)
	}
	defer task.Stop("revoked")

	_, actualTTL, err := s.issuePairCode(task.ID, 5*time.Minute)
	if err != nil {
		t.Fatalf("issuePairCode: %v", err)
	}
	if actualTTL > 2*time.Second {
		t.Errorf("actualTTL = %v, want it clamped to ~2s (the task's remaining TTL), not the requested 5m", actualTTL)
	}
}

// TestIssuePairCodeRejectsAlreadyExpiredTask covers the edge of the
// same fix: a task with no time left must fail upfront, never issue a
// code for it.
func TestIssuePairCodeRejectsAlreadyExpiredTask(t *testing.T) {
	task := &gateway.Task{ID: "agt_expired", Policy: policy.Default(), ExpiresAt: time.Now().Add(-time.Second)}
	task.InitContext(context.Background())
	task.TryActivate()

	s := &server{transport: "local", live: map[string]*liveTask{
		"agt_expired": {task: task, cap: &capability.Capability{TaskID: "agt_expired"}},
	}}

	if _, _, err := s.issuePairCode("agt_expired", time.Minute); err == nil {
		t.Fatal("issuePairCode must reject an already-expired task")
	}
}

// TestShareCodeRequiresTaskArgument covers the CLI usage error path.
func TestShareCodeRequiresTaskArgument(t *testing.T) {
	if rc := ShareCode(nil); rc != 2 {
		t.Errorf("ShareCode with no args = %d, want 2 (usage error)", rc)
	}
}
