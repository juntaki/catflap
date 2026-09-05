package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/gateway"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/policy"
	"github.com/juntaki/catflap/internal/rpc"
	"github.com/juntaki/catflap/internal/transport/local"
)

// exposedNames lists the canonical tool names a grant exposes, in toolDefs
// order. It mirrors registration filtering (see Serve): a task MUST NOT
// expose a tool its policy cannot authorize.
func exposedNames(granted []string) []string {
	s := &Server{cap: &capability.Capability{Tools: granted}}
	var out []string
	for _, def := range toolDefs() {
		name, _ := def["name"].(string)
		if s.exposed(name) {
			out = append(out, name)
		}
	}
	return out
}

func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExposed(t *testing.T) {
	// Legacy (nil) capabilities: exec/read/stat, never write.
	if got := exposedNames(nil); !equalNames(got,
		[]string{rpc.ToolExec, rpc.ToolRead, rpc.ToolStat}) {
		t.Errorf("legacy tools = %v", got)
	}
	// Explicit grant: exactly the listed tools, in canonical order.
	if got := exposedNames([]string{rpc.ToolWrite, rpc.ToolExec}); !equalNames(got,
		[]string{rpc.ToolExec, rpc.ToolWrite}) {
		t.Errorf("filtered tools = %v", got)
	}
	// Empty grant: nothing visible.
	if got := exposedNames([]string{}); len(got) != 0 {
		t.Errorf("empty grant must hide all tools, got %v", got)
	}
	// Unknown names are ignored, never advertised.
	if got := exposedNames([]string{"remote_shell"}); len(got) != 0 {
		t.Errorf("unknown tools must not appear, got %v", got)
	}
	legacy := &Server{cap: &capability.Capability{}}
	if !legacy.exposed(rpc.ToolExec) || legacy.exposed(rpc.ToolWrite) {
		t.Error("legacy capability must expose exec but not write")
	}
	narrow := &Server{cap: &capability.Capability{Tools: []string{rpc.ToolRead}}}
	if narrow.exposed(rpc.ToolExec) || !narrow.exposed(rpc.ToolRead) {
		t.Error("narrow grant must expose only its tools")
	}
}

// resultText extracts the text of a CallToolResult's first content item.
func resultText(t *testing.T, res *mcpsdk.CallToolResult) string {
	t.Helper()
	tc, ok := res.Content[0].(*mcpsdk.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	return tc.Text
}

// callToolRequest builds a minimal CallToolRequest carrying the given
// arguments as raw wire JSON, matching what the SDK hands a ToolHandler.
func callToolRequest(t *testing.T, args any) *mcpsdk.CallToolRequest {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return &mcpsdk.CallToolRequest{Params: &mcpsdk.CallToolParamsRaw{Arguments: raw}}
}

// liveLocalTask builds a real local-transport task an mcp.Server can
// actually dial, mirroring what serve/share would produce.
func liveLocalTask(t *testing.T, tools []string) (*capability.Capability, func()) {
	t.Helper()
	alog, err := audit.Open("", "agt_test", "")
	if err != nil {
		t.Fatal(err)
	}
	task := &gateway.Task{ID: "agt_test", Secret: "s3cret", Policy: policy.Default(), ExpiresAt: time.Now().Add(time.Hour), Audit: alog}
	task.InitContext(context.Background())
	store := &gateway.Store{}
	store.Add(task)
	task.TryActivate()
	srv, err := local.Serve(store.HandlerFor(task.ID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cp := &capability.Capability{
		Version: 1, TaskID: task.ID, Name: "calm-panda",
		Transport: "local", Endpoint: srv.Addr(),
		TaskSecret: task.Secret, ExpiresAt: task.ExpiresAt,
		Policy: "readonly-debug", Tools: tools,
	}
	return cp, func() { task.Stop("revoked") }
}

// publishPairingCode seals cp behind a fresh pairing code on a throwaway
// rendezvous server and returns the code and the rendezvous URL.
func publishPairingCode(t *testing.T, cp *capability.Capability) (code, rendezvousURL string) {
	t.Helper()
	payload, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	id, key, code, err := pair.Mint()
	if err != nil {
		t.Fatal(err)
	}
	env, err := pair.Seal(id, payload, key)
	if err != nil {
		t.Fatal(err)
	}
	rsrv := httptest.NewServer(pair.NewServer(100, 1000, 1000).Handler())
	t.Cleanup(rsrv.Close)
	if err := pair.Publish(context.Background(), rsrv.URL, env, time.Minute); err != nil {
		t.Fatal(err)
	}
	return code, rsrv.URL
}

// TestPairEndToEnd exercises the full pair tool path: ParseCode -> Fetch
// (burns the envelope) -> Open -> decode capability -> dial -> ping ->
// commit. Only after a genuine live task answers ping should pairing
// succeed and its granted tools appear.
func TestPairEndToEnd(t *testing.T) {
	cp, stop := liveLocalTask(t, []string{rpc.ToolRead, rpc.ToolStat})
	defer stop()
	code, rendezvousURL := publishPairingCode(t, cp)

	s := newServer(false)
	s.rendezvousURL = rendezvousURL

	if _, cl := s.snapshot(); cl != nil {
		t.Fatal("must start unpaired")
	}
	res, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: code}))
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("pair failed: %+v", res.Content)
	}

	got, _ := s.snapshot()
	if got == nil || got.TaskID != cp.TaskID {
		t.Fatalf("pair did not commit the capability, got %+v", got)
	}
	if !s.exposed(rpc.ToolRead) || !s.exposed(rpc.ToolStat) {
		t.Error("granted tools must be exposed after pairing")
	}
	if s.exposed(rpc.ToolExec) || s.exposed(rpc.ToolWrite) {
		t.Error("ungranted tools must stay hidden after pairing")
	}

	statusRes, err := s.handleStatus(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if uerr := json.Unmarshal([]byte(resultText(t, statusRes)), &status); uerr != nil {
		t.Fatal(uerr)
	}
	if status["paired"] != true || status["name"] != "calm-panda" {
		t.Errorf("status after pairing = %v", status)
	}
	for _, secretField := range []string{"task_secret", "TaskSecret", "client_priv", "ClientPriv"} {
		if _, present := status[secretField]; present {
			t.Errorf("status must never include %s", secretField)
		}
	}

	// A second pair attempt, even with a fresh valid code, must be
	// refused: already paired.
	code2, rdv2 := publishPairingCode(t, cp)
	s.rendezvousURL = rdv2
	res2, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: code2}))
	if err != nil {
		t.Fatal(err)
	}
	if !res2.IsError {
		t.Error("pairing twice must be refused")
	}
}

// TestPairBadCodeNeverFetches covers the pairing checksum's whole point:
// a typo'd/garbage code must fail locally, before any network call that
// could burn a real envelope.
func TestPairBadCodeNeverFetches(t *testing.T) {
	s := newServer(false)
	s.rendezvousURL = "http://127.0.0.1:1" // nothing listening; a Fetch here would error, not just fail-fast
	res, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: "CAT-not-a-real-code"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Error("garbage pairing code must be rejected")
	}
	if _, cl := s.snapshot(); cl != nil {
		t.Error("must remain unpaired after a bad code")
	}
}

// TestPairUnreachableTaskDoesNotCommit covers the ping-gated commit: a
// task that has already been revoked/expired by the time pairing
// completes Fetch+Open must not be treated as paired just because the
// envelope itself was valid.
func TestPairUnreachableTaskDoesNotCommit(t *testing.T) {
	cp, stop := liveLocalTask(t, []string{rpc.ToolRead})
	stop() // revoke the task before pairing ever reaches it
	code, rendezvousURL := publishPairingCode(t, cp)

	s := newServer(false)
	s.rendezvousURL = rendezvousURL
	res, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: code}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Error("pairing against an already-revoked task must fail")
	}
	if _, cl := s.snapshot(); cl != nil {
		t.Error("must not commit pair state for an unreachable task")
	}
	if fmt.Sprint(res.Content) == "" {
		t.Error("expected a non-empty error message")
	}
}

// TestServeUsesUnpairedToolsUntilCapGiven documents the entry-point
// split without needing to run the real stdio loop: newServer alone
// (ServeUnpaired's constructor, minus Run) starts with no capability.
func TestServeUsesUnpairedToolsUntilCapGiven(t *testing.T) {
	s := newServer(false)
	if cp, cl := s.snapshot(); cp != nil || cl != nil {
		t.Error("a freshly constructed server must be unpaired")
	}
	res, err := s.handleStatus(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if uerr := json.Unmarshal([]byte(resultText(t, res)), &status); uerr != nil {
		t.Fatal(uerr)
	}
	if status["paired"] != false {
		t.Errorf("status = %v, want paired:false", status)
	}
}
