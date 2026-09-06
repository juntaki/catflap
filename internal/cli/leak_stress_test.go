package cli

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/gateway"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/policy"
)

// stressCycles is how many mint->pair->revoke cycles the leak-stress
// test runs. 300 is enough to make a linear-in-N goroutine leak
// obvious (the tolerance below would fail loudly) without making the
// race-detector-instrumented suite slow; bump locally with -run when
// hunting a specific leak.
const stressCycles = 300

// TestManyMintPairRevokeCyclesDoNotLeakGoroutines is the leak-stress
// case from the security-torture pass: mint a task, issue a pairing
// code for it, fetch and burn that code, then revoke the task — repeated
// many times on one server. Every goroutine (accept loops, timers,
// audit writers) opened for a cycle must be gone by the time that
// cycle's task is revoked, or NumGoroutine climbs roughly linearly
// with the cycle count instead of staying flat.
func TestManyMintPairRevokeCyclesDoNotLeakGoroutines(t *testing.T) {
	s := &server{
		transport: "local",
		auditDir:  "", // no file audit: isolates the leak check to network/timer goroutines, not disk I/O
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  2, // each cycle fully revokes before the next starts
	}
	p := policy.Default()
	p.TTL = time.Minute

	runtime.GC()
	baseline := runtime.NumGoroutine()

	for i := 0; i < stressCycles; i++ {
		_, task, err := s.mkTask(context.Background(), p, "")
		if err != nil {
			t.Fatalf("cycle %d: mkTask: %v", i, err)
		}
		code, _, err := s.issuePairCode(task.ID, time.Minute)
		if err != nil {
			t.Fatalf("cycle %d: issuePairCode: %v", i, err)
		}
		transportName, addr, derr := pair.Decode(code)
		if derr != nil {
			t.Fatalf("cycle %d: decode: %v", i, derr)
		}
		if _, ferr := pair.Fetch(context.Background(), transportName, addr, false); ferr != nil {
			t.Fatalf("cycle %d: fetch: %v", i, ferr)
		}
		if !s.stopDetached(task.ID, "revoked") {
			t.Fatalf("cycle %d: revoke did not win", i)
		}
	}

	// Teardown (timers, audit close, transport close) happens in
	// goroutines spawned by Stop/OnStopFunc — give them a moment to
	// actually finish before sampling, or every run would "leak" the
	// tail end of its own last cycle.
	deadline := time.Now().Add(5 * time.Second)
	var after int
	for {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= baseline+10 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Generous tolerance (not "== baseline"): background runtime/test
	// goroutines unrelated to this code can start and stop on their own
	// schedule. What this guards against is a leak that scales with
	// stressCycles — a real per-cycle leak of even one goroutine would
	// blow well past this margin at 300 iterations.
	if growth := after - baseline; growth > 20 {
		t.Errorf("goroutine count grew by %d after %d mint/pair/revoke cycles (baseline %d, after %d) — suspect a per-cycle leak",
			growth, stressCycles, baseline, after)
	}
}
