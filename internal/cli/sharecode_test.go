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

	code, err := mintAndPublishPairingCode(rsrv.URL, time.Minute, cap)
	if err != nil {
		t.Fatalf("mintAndPublishPairingCode: %v", err)
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

// TestShareCodeRequiresTaskArgument covers the CLI usage error path.
func TestShareCodeRequiresTaskArgument(t *testing.T) {
	if rc := ShareCode(nil); rc != 2 {
		t.Errorf("ShareCode with no args = %d, want 2 (usage error)", rc)
	}
}
