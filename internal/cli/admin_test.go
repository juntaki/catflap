package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/policy"
)

func adminPOST(t *testing.T, body string) *http.Request {
	t.Helper()
	return httptest.NewRequestWithContext(context.Background(),
		"POST", "/grant", strings.NewReader(body))
}

func TestDecodeAdminBodyStrict(t *testing.T) {
	// Valid request passes.
	var good GrantRequest
	rec := httptest.NewRecorder()
	req := adminPOST(t, `{"ttl_override_ms":60000}`)
	if err := decodeAdminBody(rec, req, &good); err != nil {
		t.Errorf("valid body rejected: %v", err)
	}
	if good.TTLOverrideMs != 60000 {
		t.Errorf("bad decode: %+v", good)
	}
	// Broken JSON fails closed (never a zero-value grant).
	for name, body := range map[string]string{
		"truncated":   `{`,
		"not json":    `hello`,
		"unknown key": `{"warp_drive":9}`,
		"trailing":    `{} {}`,
		"array":       `[]`,
	} {
		var out GrantRequest
		rec := httptest.NewRecorder()
		req := adminPOST(t, body)
		if err := decodeAdminBody(rec, req, &out); err == nil {
			t.Errorf("%s: malformed admin body must fail closed", name)
		}
	}
}

func TestEmptyToolsRoundTrip(t *testing.T) {
	// A policy granting nothing must encode tools:[] (non-nil), never
	// collapse into a legacy (field-absent) capability.
	p := &policy.Policy{Name: "empty"}
	tools := toolsForPolicy(p)
	if tools == nil {
		t.Fatal("empty grant must yield non-nil tools")
	}
	cap := &capability.Capability{
		Version: 1, TaskID: "agt_x", Transport: "local",
		Endpoint: "127.0.0.1:1", TaskSecret: "s", Tools: tools,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	back, err := capability.Decode(cap.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if back.Tools == nil || len(back.Tools) != 0 {
		t.Errorf("round trip must preserve empty non-nil tools, got %#v", back.Tools)
	}
}

// TestToolsForPolicyExcludesUnusableWrite covers the P2 fix: a legacy
// roots-only write grant parses successfully but denies every write, so
// remote_write must not appear in tools/list for it — otherwise a tool
// the policy can never authorize is still advertised.
func TestToolsForPolicyExcludesUnusableWrite(t *testing.T) {
	p, err := policy.Parse([]byte("version: 1\nname: x\nttl: 15m\ntools:\n  file:\n    write: [\"./work\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range toolsForPolicy(p) {
		if tool == "remote_write" {
			t.Error("legacy roots-only write must not expose remote_write")
		}
	}
}

func TestCapFileNoClobberRace(t *testing.T) {
	dir := capTestDir(t)
	p := dir + "/race.cap"
	const racers = 16
	start := make(chan struct{})
	results := make(chan error, racers)
	for i := 0; i < racers; i++ {
		go func() {
			<-start
			results <- writeCapFile(p, "agc1_racer", false)
		}()
	}
	close(start)
	wins := 0
	for i := 0; i < racers; i++ {
		if err := <-results; err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("concurrent no-clobber publish: %d wins, want exactly 1", wins)
	}
}
