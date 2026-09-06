package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/gateway"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/policy"
)

// TestShareAnnouncePrintsOnlyTheCode covers share's core contract: the
// pairing code (not the capability) is what gets printed, and directly
// fetching that code afterward (mirroring what the MCP pair tool does)
// recovers the exact capability the pair server was started with.
func TestShareAnnouncePrintsOnlyTheCode(t *testing.T) {
	cap := &capability.Capability{
		Version: 1, TaskID: "agt_test", Name: "calm-panda",
		Transport: "local", Endpoint: "127.0.0.1:1", TaskSecret: "s3cr3t-do-not-print",
		ExpiresAt: time.Now().Add(15 * time.Minute), Policy: "readonly-debug",
	}
	task := &gateway.Task{ID: cap.TaskID, Name: cap.Name, ExpiresAt: cap.ExpiresAt}

	var ps *pair.Server
	t.Cleanup(func() {
		if ps != nil {
			ps.Close()
		}
	})

	var out bytes.Buffer
	announce := shareAnnounce(time.Minute, policy.Default(), &out)
	a := Announce{Cap: cap, Task: task, Transport: "local"}
	a.IssuePairCode = func(requestedTTL time.Duration) (string, time.Duration, error) {
		var serr error
		ps, serr = pair.Serve("local", cap, requestedTTL, false, nil)
		if serr != nil {
			return "", 0, serr
		}
		code, eerr := pair.Encode("local", ps.Addr())
		if eerr != nil {
			return "", 0, eerr
		}
		return code, requestedTTL, nil
	}
	if err := announce(a); err != nil {
		t.Fatalf("announce: %v", err)
	}

	printed := out.String()
	if strings.Contains(printed, cap.TaskSecret) {
		t.Error("announce output must never contain the task secret")
	}
	if !strings.Contains(printed, "Pairing code") || !strings.Contains(printed, "CAT-") {
		t.Errorf("announce output must contain a pairing code, got:\n%s", printed)
	}

	code := extractCode(t, printed)
	transportName, addr, err := pair.Decode(code)
	if err != nil {
		t.Fatalf("printed code failed to decode: %v", err)
	}
	got, err := pair.Fetch(context.Background(), transportName, addr, false)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got.TaskID != cap.TaskID || got.TaskSecret != cap.TaskSecret {
		t.Errorf("fetched capability = %+v, want it to match the original", got)
	}
}

// TestShareAnnounceIssueFailureNeverPrints covers the P1 contract: a
// pair server failing to start must return an error (which is
// RunGateway's signal to tear the just-minted task back down) and must
// NOT fall back to printing the capability, or anything else, to the
// operator.
func TestShareAnnounceIssueFailureNeverPrints(t *testing.T) {
	cap := &capability.Capability{
		Version: 1, TaskID: "agt_test", Name: "calm-panda",
		Transport: "local", Endpoint: "127.0.0.1:1", TaskSecret: "s3cr3t-do-not-print",
		ExpiresAt: time.Now().Add(15 * time.Minute), Policy: "readonly-debug",
	}
	task := &gateway.Task{ID: cap.TaskID, Name: cap.Name, ExpiresAt: cap.ExpiresAt}

	var out bytes.Buffer
	announce := shareAnnounce(time.Minute, policy.Default(), &out)
	a := Announce{Cap: cap, Task: task, Transport: "local"}
	a.IssuePairCode = func(time.Duration) (string, time.Duration, error) {
		return "", 0, errors.New("simulated pair server failure")
	}
	err := announce(a)
	if err == nil {
		t.Fatal("announce must return an error when the pair server fails to start")
	}
	if out.Len() != 0 {
		t.Errorf("nothing must be printed on failure, got:\n%s", out.String())
	}
}

// TestRunGatewayRevokesTaskOnAnnounceFailure covers the contract
// share() relies on instead of duplicating a revoke call: RunGateway
// must tear the just-minted task down and leave no state file when the
// caller's announce callback returns an error, whatever the reason.
func TestRunGatewayRevokesTaskOnAnnounceFailure(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	rc := RunGateway(GatewayOptions{
		Transport: "local", AuditDir: "", StatePath: statePath,
		AdminAddr: "127.0.0.1:0", MaxTasks: 1, Policy: policy.Default(),
	}, func(Announce) error {
		return errors.New("simulated announce failure")
	})
	if rc == 0 {
		t.Error("RunGateway must fail (non-zero exit) when announce fails")
	}
	if _, err := os.Stat(statePath); err == nil {
		t.Error("no state file must be left behind after a failed announce")
	}
}

// extractCode pulls the pairing code out of shareAnnounce's printed
// output (the line reading "  CAT-...").
func extractCode(t *testing.T, printed string) string {
	t.Helper()
	i := strings.Index(printed, "CAT-")
	if i < 0 {
		t.Fatalf("no pairing code found in:\n%s", printed)
	}
	rest := printed[i:]
	end := strings.IndexAny(rest, "\n ")
	if end < 0 {
		end = len(rest)
	}
	return strings.TrimSpace(rest[:end])
}
