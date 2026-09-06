package cli

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/gateway"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/policy"
)

// TestGetCapabilityReturnsMintedCapability covers share-code's core
// dependency: a task's capability is retained after mkTask returns, so
// it can be re-published behind a brand new pairing code without
// minting a new task.
func TestGetCapabilityReturnsMintedCapability(t *testing.T) {
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

	got, ok := s.getCapability(task.ID)
	if !ok {
		t.Fatal("getCapability must find the just-minted task's capability")
	}
	if got.TaskID != cap.TaskID || got.TaskSecret != cap.TaskSecret {
		t.Errorf("getCapability returned %+v, want it to match the minted capability", got)
	}
}

// TestGetCapabilityGoneAfterTaskStops covers the flip side: once a task
// is torn down, its capability must no longer be servable — a dead
// task must never be re-pairable via `share-code`.
func TestGetCapabilityGoneAfterTaskStops(t *testing.T) {
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

	if _, ok := s.getCapability(task.ID); ok {
		t.Fatal("getCapability must not return a capability for a stopped task")
	}
}

// TestMintAndPublishPairingCodeRoundTrips covers the shared helper
// share-code reuses from shareAnnounce: the published envelope must
// unseal back into the exact capability handed in.
func TestMintAndPublishPairingCodeRoundTrips(t *testing.T) {
	rsrv := httptest.NewServer(pair.NewServer(100, 1000, 1000).Handler())
	defer rsrv.Close()

	cap := &capability.Capability{
		Version: 1, TaskID: "agt_test", Name: "calm-panda",
		Transport: "local", Endpoint: "127.0.0.1:1", TaskSecret: "s3cr3t",
		ExpiresAt: time.Now().Add(15 * time.Minute), Policy: "readonly-debug",
	}

	code, actualTTL, err := mintAndPublishPairingCode(rsrv.URL, time.Minute, cap)
	if err != nil {
		t.Fatalf("mintAndPublishPairingCode: %v", err)
	}
	if actualTTL != time.Minute {
		t.Errorf("actualTTL = %v, want the requested %v (task has 15m left)", actualTTL, time.Minute)
	}

	id, key, err := pair.ParseCode(code)
	if err != nil {
		t.Fatalf("parse code: %v", err)
	}
	env, err := pair.Fetch(context.Background(), rsrv.URL, id)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	pt, err := pair.Open(env, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var got capability.Capability
	if err := json.Unmarshal(pt, &got); err != nil {
		t.Fatalf("decode published capability: %v", err)
	}
	if got.TaskID != cap.TaskID || got.TaskSecret != cap.TaskSecret {
		t.Errorf("published capability = %+v, want it to match the original", got)
	}
}

// TestGetCapabilityRejectsStoppingTask covers a real bug: audit
// fail-closed (and every other termination path) flips a task's state
// to STOPPING synchronously, but only removes it from s.live later,
// asynchronously, after up to a 10s drain — so a share-code call
// landing in that window would see the task still "present" in s.live
// and hand out a capability for a task that is already on its way out.
// getCapability must check StateOf(), not just s.live membership.
func TestGetCapabilityRejectsStoppingTask(t *testing.T) {
	task := &gateway.Task{ID: "agt_stopping", Policy: policy.Default(), ExpiresAt: time.Now().Add(time.Hour)}
	task.InitContext(context.Background())
	task.TryActivate()

	blocked := make(chan struct{})
	unblock := make(chan struct{})
	task.OnStopFunc(func() {
		close(blocked)
		<-unblock // teardown (and thus removal from s.live) stalls here
	})

	s := &server{live: map[string]*liveTask{
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
	if _, ok := s.getCapability("agt_stopping"); ok {
		t.Fatal("getCapability must reject a task that is STOPPING, even while still present in s.live")
	}

	close(unblock)
}

// TestMintAndPublishPairingCodeClampsToRemainingTaskTTL covers a real
// bug: a pairing code published with a TTL longer than the task's own
// remaining TTL would still be "claimable" on the rendezvous server
// after the task itself already expired — pair.Fetch would succeed,
// but the capability behind it would immediately fail as expired. The
// published envelope TTL must never exceed the task's remaining life.
func TestMintAndPublishPairingCodeClampsToRemainingTaskTTL(t *testing.T) {
	rsrv := httptest.NewServer(pair.NewServer(100, 1000, 1000).Handler())
	defer rsrv.Close()

	cap := &capability.Capability{
		Version: 1, TaskID: "agt_test", Name: "calm-panda",
		Transport: "local", Endpoint: "127.0.0.1:1", TaskSecret: "s3cr3t",
		ExpiresAt: time.Now().Add(2 * time.Second), Policy: "readonly-debug",
	}

	_, actualTTL, err := mintAndPublishPairingCode(rsrv.URL, 5*time.Minute, cap)
	if err != nil {
		t.Fatalf("mintAndPublishPairingCode: %v", err)
	}
	if actualTTL > 2*time.Second {
		t.Errorf("actualTTL = %v, want it clamped to ~2s (the task's remaining TTL), not the requested 5m", actualTTL)
	}
}

// TestMintAndPublishPairingCodeRejectsAlreadyExpiredTask covers the
// edge of the same fix: a task with no time left must fail upfront,
// never publish a code for it.
func TestMintAndPublishPairingCodeRejectsAlreadyExpiredTask(t *testing.T) {
	rsrv := httptest.NewServer(pair.NewServer(100, 1000, 1000).Handler())
	defer rsrv.Close()

	cap := &capability.Capability{
		Version: 1, TaskID: "agt_test", Name: "calm-panda",
		Transport: "local", Endpoint: "127.0.0.1:1", TaskSecret: "s3cr3t",
		ExpiresAt: time.Now().Add(-time.Second), Policy: "readonly-debug",
	}

	if _, _, err := mintAndPublishPairingCode(rsrv.URL, time.Minute, cap); err == nil {
		t.Fatal("mintAndPublishPairingCode must reject an already-expired task")
	}
}

// TestShareCodeRequiresTaskArgument covers the CLI usage error path.
func TestShareCodeRequiresTaskArgument(t *testing.T) {
	if rc := ShareCode(nil); rc != 2 {
		t.Errorf("ShareCode with no args = %d, want 2 (usage error)", rc)
	}
}
