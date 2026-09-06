package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http/httptest"
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

// TestShareAnnouncePublishesAndPrintsOnlyTheCode covers share's core
// contract: the pairing code (not the capability) is what gets printed,
// and a real rendezvous fetch afterward recovers the exact capability
// that was announced.
func TestShareAnnouncePublishesAndPrintsOnlyTheCode(t *testing.T) {
	rsrv := httptest.NewServer(pair.NewServer(100, 1000, 1000).Handler())
	defer rsrv.Close()

	cap := &capability.Capability{
		Version: 1, TaskID: "agt_test", Name: "calm-panda",
		Transport: "local", Endpoint: "127.0.0.1:1", TaskSecret: "s3cr3t-do-not-print",
		ExpiresAt: time.Now().Add(15 * time.Minute), Policy: "readonly-debug",
	}
	task := &gateway.Task{ID: cap.TaskID, Name: cap.Name, ExpiresAt: cap.ExpiresAt}

	var out bytes.Buffer
	announce := shareAnnounce(rsrv.URL, time.Minute, policy.Default(), &out)
	if err := announce(Announce{Cap: cap, Task: task, Transport: "local"}); err != nil {
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
	id, key, err := pair.ParseCode(code)
	if err != nil {
		t.Fatalf("printed code failed to parse: %v", err)
	}
	env, err := pair.Fetch(context.Background(), rsrv.URL, id)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	pt, err := pair.Open(env, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := capability.Decode(capability.Prefix + base64.RawURLEncoding.EncodeToString(pt))
	if err != nil {
		t.Fatalf("decode published capability: %v", err)
	}
	if got.TaskID != cap.TaskID || got.TaskSecret != cap.TaskSecret {
		t.Errorf("published capability = %+v, want it to match the original", got)
	}
}

// TestShareAnnouncePublishFailureNeverPrints covers the P1 contract: a
// publish failure must return an error (which is RunGateway's signal to
// tear the just-minted task back down) and must NOT fall back to
// printing the capability, or anything else, to the operator.
func TestShareAnnouncePublishFailureNeverPrints(t *testing.T) {
	cap := &capability.Capability{
		Version: 1, TaskID: "agt_test", Name: "calm-panda",
		Transport: "local", Endpoint: "127.0.0.1:1", TaskSecret: "s3cr3t-do-not-print",
		ExpiresAt: time.Now().Add(15 * time.Minute), Policy: "readonly-debug",
	}
	task := &gateway.Task{ID: cap.TaskID, Name: cap.Name, ExpiresAt: cap.ExpiresAt}

	var out bytes.Buffer
	// Nothing listening: Publish fails fast (connection refused).
	announce := shareAnnounce("http://127.0.0.1:1", time.Minute, policy.Default(), &out)
	err := announce(Announce{Cap: cap, Task: task, Transport: "local"})
	if err == nil {
		t.Fatal("announce must return an error when publish fails")
	}
	if out.Len() != 0 {
		t.Errorf("nothing must be printed on publish failure, got:\n%s", out.String())
	}
}

// TestShareRevokesTaskOnPublishFailure covers the same contract at the
// Share() entry point: RunGateway must tear the task down and leave no
// state file when announce (shareAnnounce) fails.
func TestShareRevokesTaskOnPublishFailure(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	rc := Share([]string{
		"--transport", "local", "--admin", "127.0.0.1:0", "--audit", "",
		"--state", statePath, "--rendezvous", "http://127.0.0.1:1", "--ttl", "1m",
	})
	if rc == 0 {
		t.Error("share must fail (non-zero exit) when publish fails")
	}
	if _, err := os.Stat(statePath); err == nil {
		t.Error("no state file must be left behind after a failed share")
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
