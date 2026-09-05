package cli

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/gateway"
	"github.com/juntaki/catflap/internal/policy"
	"github.com/juntaki/catflap/internal/rpc"
)

// TestAuditFailureDetachesTaskFromStore covers the P1 fix: Task.Stop only
// releases the task's own resources (server, audit) and explicitly
// documents "MUST be followed by Store.Delete" — a contract every
// serve.go termination path (expire/revoke/shutdown) upheld manually, but
// the gateway's audit-fail-closed path (added for a separate P1 fix)
// calls Stop directly with no server-side call site to do that follow-up.
// Without a shared teardown, an audit-failed task stays in s.live/s.store
// until its TTL, consuming a max-tasks admission slot for nothing.
// commit's onStop callback is now that shared, idempotent teardown.
func TestAuditFailureDetachesTaskFromStore(t *testing.T) {
	dir := t.TempDir()
	s := &server{
		transport: "local",
		auditDir:  dir,
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  1,
	}
	p := policy.Default()
	p.TTL = time.Hour

	cap, task, err := s.mkTask(context.Background(), p, "")
	if err != nil {
		t.Fatal(err)
	}

	// The single admission slot is now taken.
	if _, _, err := s.mkTask(context.Background(), p, ""); err == nil {
		t.Fatal("expected max-tasks to be exhausted")
	}

	_ = task.Audit.Close()

	// Drive one RPC through the real transport handler, same as a live
	// client would; any request path audits, so this trips fail-closed
	// regardless of whether the request itself is allowed or denied.
	c1, c2 := net.Pipe()
	go s.store.HandlerFor(cap.TaskID)(c2)
	req := rpc.Request{Task: cap.TaskID, Secret: cap.TaskSecret, ID: 1, Tool: rpc.ToolStat, Args: []byte(`{"path":""}`)}
	if err := rpc.WriteRequest(c1, req); err != nil {
		t.Fatal(err)
	}
	_, _ = rpc.ReadResponse(bufio.NewReader(c1))
	_ = c1.Close()
	_ = c2.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		_, live := s.live[cap.TaskID]
		s.mu.Unlock()
		if !live {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.mu.Lock()
	_, stillLive := s.live[cap.TaskID]
	s.mu.Unlock()
	if stillLive {
		t.Error("task must be detached from the live map after audit-fail-closed Stop")
	}
	if _, ok := s.store.Lookup(cap.TaskID, cap.TaskSecret); ok {
		t.Error("task must be detached from the store after audit-fail-closed Stop")
	}

	// The freed slot must admit a new task.
	if _, _, err := s.mkTask(context.Background(), p, ""); err != nil {
		t.Errorf("admission slot must be free after detach: %v", err)
	}
}

// TestExpireLeavesActiveBeforeNameFreed covers the P2 fix: expire/revoke
// used to remove a task from the live map (freeing its name for reuse)
// BEFORE calling Stop, so a new grant could claim that name while the old
// task — Stop not yet even started — was still fully ACTIVE. stopDetached
// now calls RequestStop (leaving ACTIVE synchronously) before removing
// the live entry, so whenever a new grant observes a name as free, the
// task that held it is provably no longer ACTIVE.
func TestExpireLeavesActiveBeforeNameFreed(t *testing.T) {
	dir := t.TempDir()
	s := &server{
		transport: "local",
		auditDir:  dir,
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  1, // task2 can only be admitted once task1's slot frees
	}
	p := policy.Default()
	p.TTL = time.Hour

	_, task1, err := s.mkTask(context.Background(), p, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if task1.Name != "foo" {
		t.Fatalf("task1 must get the preferred name, got %q", task1.Name)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.expire(task1.ID)
	}()

	deadline := time.Now().Add(2 * time.Second)
	claimed := false
	for time.Now().Before(deadline) && !claimed {
		_, task2, err := s.mkTask(context.Background(), p, "foo")
		if err != nil {
			continue // slot/name not free yet: task1 hasn't fully detached
		}
		claimed = true
		if task2.Name != "foo" {
			t.Fatalf("task2 should have claimed the freed name, got %q", task2.Name)
		}
		// The instant a new grant can claim "foo", task1 must already be
		// unable to serve as an ACTIVE task under it.
		if task1.StateOf() == gateway.StateActive {
			t.Error("task1 was still ACTIVE when its name became reusable")
		}
	}
	<-done
	if !claimed {
		t.Fatal("task1 never released its slot/name within the deadline")
	}
}

// TestStopDetachedOwnershipMatchesWinner covers the P1 fix: stopDetached
// used to decide "who won" by which caller's RequestStop happened to
// delete the live entry first — a step that runs AFTER RequestStop, by
// which point both callers may already have called RequestStop with
// their own reason. So the caller reporting success (and thus the
// admin API's revoke status) did not necessarily match whichever reason
// actually reached Task.Stop's cancellation cause and terminal audit
// record. stopDetached now claims termination ownership (lt.stopping)
// BEFORE calling RequestStop, so exactly one caller's reason is ever
// used, and that caller is always the one reporting success.
func TestStopDetachedOwnershipMatchesWinner(t *testing.T) {
	dir := t.TempDir()
	s := &server{
		transport: "local",
		auditDir:  dir,
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  1,
	}
	p := policy.Default()
	p.TTL = time.Hour
	_, task, err := s.mkTask(context.Background(), p, "")
	if err != nil {
		t.Fatal(err)
	}

	var wonExpired, wonRevoked bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); wonExpired = s.stopDetached(task.ID, "expired") }()
	go func() { defer wg.Done(); wonRevoked = s.stopDetached(task.ID, "revoked") }()
	wg.Wait()

	if wonExpired == wonRevoked {
		t.Fatalf("exactly one of expire/revoke must win the race, got expired=%v revoked=%v", wonExpired, wonRevoked)
	}

	cause := context.Cause(task.Context())
	if wonExpired && !errors.Is(cause, gateway.ErrTaskExpired) {
		t.Errorf("expire won the claim but cancellation cause is %v, want ErrTaskExpired", cause)
	}
	if wonRevoked && !errors.Is(cause, gateway.ErrTaskRevoked) {
		t.Errorf("revoke won the claim but cancellation cause is %v, want ErrTaskRevoked", cause)
	}
}

// TestRevokeSelfVsExpiryOwnershipMatchesWinner covers Phase 0's
// termination-ownership unification across package boundaries: an admin-
// side TTL expiry (cli's stopDetached) racing the agent's own
// revoke_self (a gateway-internal RPC path) must still agree on exactly
// one winner, and stopDetached's reported outcome must match whichever
// reason actually reached the task's cancellation cause — regardless of
// which package initiated it.
func TestRevokeSelfVsExpiryOwnershipMatchesWinner(t *testing.T) {
	dir := t.TempDir()
	s := &server{
		transport: "local",
		auditDir:  dir,
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  1,
	}
	p := policy.Default()
	p.TTL = time.Hour
	cap, task, err := s.mkTask(context.Background(), p, "")
	if err != nil {
		t.Fatal(err)
	}

	var wonExpire bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		wonExpire = s.stopDetached(task.ID, "expired")
	}()
	go func() {
		defer wg.Done()
		c1, c2 := net.Pipe()
		defer func() { _ = c1.Close() }()
		defer func() { _ = c2.Close() }()
		go s.store.HandlerFor(cap.TaskID)(c2)
		if werr := rpc.WriteRequest(c1, rpc.Request{Task: cap.TaskID, Secret: cap.TaskSecret, ID: 1, Tool: rpc.ToolRevokeSelf}); werr != nil {
			return
		}
		_, _ = rpc.ReadResponse(bufio.NewReader(c1))
	}()
	wg.Wait()

	causeExpired := errors.Is(context.Cause(task.Context()), gateway.ErrTaskExpired)
	causeRevoked := errors.Is(context.Cause(task.Context()), gateway.ErrTaskRevoked)
	if causeExpired == causeRevoked {
		t.Fatalf("exactly one cause must win, got expired=%v revoked=%v", causeExpired, causeRevoked)
	}
	if wonExpire != causeExpired {
		t.Errorf("stopDetached(expired)'s won=%v must match the actual cause (expired=%v)", wonExpire, causeExpired)
	}
}

// TestShutdownVsRevokeOwnershipMatchesWinner covers Phase 0: a process
// shutdown (SIGINT/SIGTERM) racing an admin revoke of the same task must
// still agree on exactly one winner and one reason.
func TestShutdownVsRevokeOwnershipMatchesWinner(t *testing.T) {
	dir := t.TempDir()
	s := &server{
		transport: "local",
		auditDir:  dir,
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  1,
	}
	p := policy.Default()
	p.TTL = time.Hour
	_, task, err := s.mkTask(context.Background(), p, "")
	if err != nil {
		t.Fatal(err)
	}

	var wonRevoke bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); wonRevoke = s.stopDetached(task.ID, "revoked") }()
	go func() { defer wg.Done(); s.shutdown() }()
	wg.Wait()

	causeRevoked := errors.Is(context.Cause(task.Context()), gateway.ErrTaskRevoked)
	causeShutdown := errors.Is(context.Cause(task.Context()), gateway.ErrTaskShutdown)
	if causeRevoked == causeShutdown {
		t.Fatalf("exactly one cause must win, got revoked=%v shutdown=%v", causeRevoked, causeShutdown)
	}
	if wonRevoke != causeRevoked {
		t.Errorf("stopDetached(revoked)'s won=%v must match the actual cause (revoked=%v)", wonRevoke, causeRevoked)
	}
}

// TestTaskContextDecoupledFromSignalContext covers Phase 0: a task's own
// context must be cancelled ONLY through TryRequestStop, with the
// correct cause, never implicitly by being a descendant of the process's
// SIGINT/SIGTERM signal context. mkTask uses context.WithoutCancel for
// exactly this reason; this test cancels the "signal" context directly
// (standing in for the real signal.NotifyContext one RunGateway uses)
// and asserts the task's own context is unaffected — only shutdown()'s
// explicit TryRequestStop("shutdown") may cancel it, which is exercised
// by TestShutdownVsRevokeOwnershipMatchesWinner.
func TestTaskContextDecoupledFromSignalContext(t *testing.T) {
	dir := t.TempDir()
	s := &server{
		transport: "local",
		auditDir:  dir,
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  1,
	}
	p := policy.Default()
	p.TTL = time.Hour

	signalCtx, cancelSignal := context.WithCancel(context.Background())
	_, task, err := s.mkTask(signalCtx, p, "")
	if err != nil {
		t.Fatal(err)
	}

	cancelSignal() // simulates SIGTERM firing

	if task.Context().Err() != nil {
		t.Errorf("task context must not be cancelled by the signal context alone, got %v", task.Context().Err())
	}
	if task.StateOf() != gateway.StateActive {
		t.Errorf("task must remain ACTIVE, got state=%v", task.StateOf())
	}
}

// TestConcurrentGrantsNeverDuplicateName covers the P1 fix: deciding a
// task's name (against s.live) and committing it into s.live used to be
// two separate critical sections, so two concurrent grants could both
// decide "foo" is free and both commit as "foo" — breaking the "unique
// per serve process" invariant the field's own doc comment claims.
// reserve() now resolves and reserves the name as one atomic step.
func TestConcurrentGrantsNeverDuplicateName(t *testing.T) {
	const n = 16
	s := &server{
		transport: "local",
		store:     &gateway.Store{},
		live:      map[string]*liveTask{},
		maxTasks:  n,
	}
	p := policy.Default()
	p.TTL = time.Hour

	var wg sync.WaitGroup
	names := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Every goroutine prefers the SAME name: at most one can get
			// it, the rest must fall back to a minted name, and no two
			// of those may collide either.
			_, task, err := s.mkTask(context.Background(), p, "same-name")
			if err != nil {
				errs[i] = err
				return
			}
			names[i] = task.Name
		}(i)
	}
	wg.Wait()

	seen := map[string]int{}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("grant %d failed: %v", i, err)
		}
		seen[NormalizeName(names[i])]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("name %q assigned to %d concurrent tasks, want at most 1", name, count)
		}
	}
	preferred := 0
	for _, name := range names {
		if NormalizeName(name) == NormalizeName("same-name") {
			preferred++
		}
	}
	if preferred != 1 {
		t.Errorf("preferred name went to %d tasks, want exactly 1", preferred)
	}
}
