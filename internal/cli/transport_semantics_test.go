package cli

import (
	"context"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/gateway"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/policy"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// These two tests are catflap's "pair vs task transport" semantic
// contract, exercised through the REAL production call sites
// (mkTask, issuePairCode) rather than the tailcat adapter directly
// (see internal/transport/tailcat's own security_contract_test.go for
// that layer). A task's Tailcat server and a pair server's Tailcat
// server MUST use opposite AllowedClients semantics — exactly one
// intended identity for a task, none at all (open) for a pair server —
// and mixing these up at either call site would be a real
// vulnerability (a task server that accepted any client) or a real
// functional break (a pair server that rejected the very client it was
// started for). Both need a real DERP round trip; skipped under -short.

// TestMkTaskGrantsOnlyItsOwnClientIdentity covers the task side: the
// capability's ClientPriv can reach the task's Tailcat server, but a
// freshly generated, never-granted key cannot — mkTask's
// `[]string{agentKey}` allowlist argument (see serve.go) must keep
// meaning "exactly this one identity", not silently widen to "anyone".
func TestMkTaskGrantsOnlyItsOwnClientIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a real Tailcat/DERP round trip")
	}
	s := &server{
		transport: "tailcat",
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
	defer task.Stop("revoked")

	grantedClient, err := tct.Dialer(cap.Endpoint, cap.ClientPriv, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = grantedClient.Close() }()
	gctx, gcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gcancel()
	gconn, gerr := grantedClient.Dial(gctx)
	if gerr != nil {
		t.Fatalf("the task's own granted client must be able to dial its Tailcat server, got: %v", gerr)
	}
	_ = gconn.Close()

	strangerPriv, _, err := tct.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	strangerClient, err := tct.Dialer(cap.Endpoint, strangerPriv, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = strangerClient.Close() }()
	sctx, scancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer scancel()
	if _, serr := strangerClient.Dial(sctx); serr == nil {
		t.Fatal("a client that was never granted this task must not be able to dial its Tailcat server")
	}
}

// TestIssuePairCodeAcceptsAnyClientOverTailcat covers the pair side:
// the temporary pair server issuePairCode starts must accept a
// completely unrelated, freshly generated client identity — the pair
// server has no allowlist by design (the address itself is the
// bootstrap secret, see internal/pair's package doc), so its
// AllowedClients argument must stay "open", never accidentally
// narrowed to some specific identity the caller happens to have on
// hand (which would break every real pairing attempt, since the agent
// side has no pre-shared identity to offer).
func TestIssuePairCodeAcceptsAnyClientOverTailcat(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a real Tailcat/DERP round trip")
	}
	s := &server{
		transport: "tailcat",
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
	defer task.Stop("revoked")

	code, _, err := s.issuePairCode(task.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transportName, addr, derr := pair.Decode(code)
	if derr != nil {
		t.Fatal(derr)
	}
	if transportName != "tailcat" {
		t.Fatalf("expected a tailcat pairing code, got transport %q", transportName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, ferr := pair.Fetch(ctx, transportName, addr, false); ferr != nil {
		t.Fatalf("a completely unrelated client identity must be able to claim the pair server, got: %v", ferr)
	}
}
