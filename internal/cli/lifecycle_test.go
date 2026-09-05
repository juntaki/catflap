package cli

import (
	"bufio"
	"context"
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
