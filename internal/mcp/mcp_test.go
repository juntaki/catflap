package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	"github.com/juntaki/catflap/internal/transport"
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

// liveLocalTaskWithServer is liveLocalTask but also returns the raw
// transport server, for tests that need to simulate the endpoint itself
// going unreachable (closing the listener), as distinct from the task
// merely being stopped (which still answers with a normal deny/expired
// response, not a dial failure).
func liveLocalTaskWithServer(t *testing.T, tools []string) (*capability.Capability, *gateway.Task, transport.Server) {
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
	cp := &capability.Capability{
		Version: 1, TaskID: task.ID, Name: "calm-panda",
		Transport: "local", Endpoint: srv.Addr(),
		TaskSecret: task.Secret, ExpiresAt: task.ExpiresAt,
		Policy: "readonly-debug", Tools: tools,
	}
	return cp, task, srv
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

// pairServer builds a Server already paired against a live local task,
// via the real pair flow (Mint/Seal/Publish/Fetch/pair tool) — not by
// poking s.cap directly — so these tests exercise the same commit path
// TestPairEndToEnd does.
func pairServer(t *testing.T, tools []string) (*Server, *capability.Capability) {
	t.Helper()
	cp, _ := liveLocalTask(t, tools)
	code, rendezvousURL := publishPairingCode(t, cp)
	s := newServer(false)
	s.rendezvousURL = rendezvousURL
	res, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: code}))
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("setup: pair failed: %+v", res.Content)
	}
	return s, cp
}

// TestDisconnectConfirmedRevokeClearsState covers disconnect's
// confirmed-revoke path: the gateway answers revoke_self successfully,
// so local pairing is discarded and every tool pairing added
// (disconnect, remote_read) disappears again — only pair/status remain,
// and a fresh pair call succeeds.
func TestDisconnectConfirmedRevokeClearsState(t *testing.T) {
	s, _ := pairServer(t, []string{rpc.ToolRead})
	if !s.exposed(rpc.ToolRead) {
		t.Fatal("setup: expected remote_read to be exposed after pairing")
	}

	res, err := s.handleDisconnect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("disconnect against a live task must succeed: %+v", res.Content)
	}
	var body map[string]any
	if uerr := json.Unmarshal([]byte(resultText(t, res)), &body); uerr != nil {
		t.Fatal(uerr)
	}
	if body["disconnected"] != true || body["status"] != "revoked" {
		t.Errorf("disconnect result = %v", body)
	}

	if cp, cl := s.snapshot(); cp != nil || cl != nil {
		t.Error("local pairing state must be cleared after a confirmed disconnect")
	}
	if s.exposed(rpc.ToolRead) {
		t.Error("granted tools must disappear after disconnect")
	}

	// A fresh pair must be possible again.
	cp2, _ := liveLocalTask(t, []string{rpc.ToolStat})
	code2, rendezvousURL2 := publishPairingCode(t, cp2)
	s.rendezvousURL = rendezvousURL2
	res2, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: code2}))
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsError {
		t.Errorf("re-pairing after disconnect must succeed: %+v", res2.Content)
	}
}

// TestDisconnectAlreadyGoneClearsState covers the "already gone" branch:
// the task was already stopped by something else (expiry, admin revoke)
// before disconnect ever runs. The gateway is still reachable and
// answers with a deny that specifically means "this task no longer
// exists", not an arbitrary denial — disconnect must still treat that
// as confirmed and clear local state, not leave the agent stuck thinking
// it's paired with a task that can never respond again.
func TestDisconnectAlreadyGoneClearsState(t *testing.T) {
	cp, task, srv := liveLocalTaskWithServer(t, []string{rpc.ToolRead})
	defer func() { _ = srv.Close() }()
	code, rendezvousURL := publishPairingCode(t, cp)
	s := newServer(false)
	s.rendezvousURL = rendezvousURL
	if res, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: code})); err != nil {
		t.Fatal(err)
	} else if res.IsError {
		t.Fatalf("setup: pair failed: %+v", res.Content)
	}

	// Stop the task server-side (simulating an admin revoke or TTL
	// expiry that landed first) without closing the transport: the
	// gateway is still reachable and will deny with "task stopping",
	// which means "already gone", not "network trouble".
	task.Stop("revoked")

	res, err := s.handleDisconnect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("disconnect against an already-expired task must still confirm, got: %+v", res.Content)
	}
	var body map[string]any
	if uerr := json.Unmarshal([]byte(resultText(t, res)), &body); uerr != nil {
		t.Fatal(uerr)
	}
	if body["disconnected"] != true || body["status"] != "already gone" {
		t.Errorf("disconnect result = %v, want status \"already gone\"", body)
	}
	if cp, cl := s.snapshot(); cp != nil || cl != nil {
		t.Error("local pairing state must be cleared once the task is confirmed already gone")
	}
}

// TestDisconnectAmbiguousKeepsState covers the core disconnect
// contract: if the remote task can't be reached AT ALL (here: the
// transport endpoint itself is gone, so the dial fails), disconnect
// must NOT claim the task was revoked — it may still be fully live and
// reachable a moment later — so local pairing state is kept.
func TestDisconnectAmbiguousKeepsState(t *testing.T) {
	s, _ := pairServer(t, []string{rpc.ToolRead})
	cp, _ := s.snapshot()

	// Simulate the endpoint becoming completely unreachable by swapping
	// in a client that dials a definitely-closed port. Mutating
	// s.cap.Endpoint alone wouldn't do it — s.client already captured
	// its dial target when pairing committed.
	s.mu.Lock()
	oldClient := s.client
	s.client = local.Dialer("127.0.0.1:1")
	s.mu.Unlock()
	_ = oldClient.Close()

	res, err := s.handleDisconnect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Error("disconnect must not report success when the task can't be reached at all")
	}
	if got, _ := s.snapshot(); got == nil || got.TaskID != cp.TaskID {
		t.Error("local pairing state must be KEPT when the remote revoke can't be confirmed")
	}
	if !s.exposed(rpc.ToolRead) {
		t.Error("granted tools must still be exposed: pairing was never actually torn down")
	}
}

// TestDisconnectNotPaired covers disconnect's precondition check.
func TestDisconnectNotPaired(t *testing.T) {
	s := newServer(false)
	res, err := s.handleDisconnect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Error("disconnect with nothing paired must be an error")
	}
}

// stubDialer is a transport.Client that always hands out the same
// pre-built connection, for tests that need to control exactly what's on
// the other end.
type stubDialer struct{ conn net.Conn }

func (d stubDialer) Dial(context.Context) (net.Conn, error) { return d.conn, nil }
func (d stubDialer) Close() error                           { return nil }

// TestRevokeSelfRespectsCallerCancellation covers the P1 codex's Phase 3
// review caught: revokeSelf (and pingGateway, same fix) used to bound
// only the dial and read with fixed internal deadlines (15s query
// context, plus rpc.WriteRequest's own fixed 30s write deadline) with
// nothing tying an in-flight write/read to the CALLER's context — so a
// stalled write (peer accepted the connection but never reads) could
// outlive a caller cancellation that arrives well before those fixed
// windows elapse, delaying the ambiguous-outcome report. Both now force
// the connection closed via context.AfterFunc the moment their internal
// deadline (or an earlier caller cancellation) fires.
func TestRevokeSelfRespectsCallerCancellation(t *testing.T) {
	// net.Pipe is unbuffered and synchronous: a Write on c1 blocks until
	// something reads c2, or c1/c2 is closed. Nothing here ever reads
	// c2, simulating a peer that accepted the connection but stalled.
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	cp := &capability.Capability{TaskID: "agt_test", TaskSecret: "s3cret"}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, err := revokeSelf(ctx, stubDialer{conn: c1}, cp)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error when the write stalls past the caller's context deadline")
	}
	if elapsed > 2*time.Second {
		t.Errorf("revokeSelf took %s to return after a 200ms context deadline — the stalled write outlived caller cancellation", elapsed)
	}
}
