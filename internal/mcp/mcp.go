package mcp

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/juntaki/catflap/internal/buildinfo"
	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/rpc"
	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/local"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// Server bridges MCP (Claude Code / Codex / Cursor) to one gateway
// capability over Tailcat (or local TCP for tests).
//
// Protocol handling (stdio framing, initialize/server/discover negotiation,
// tools/list, notifications) is delegated to the official MCP Go SDK,
// pinned to a spec-compatible release in go.mod. Catflap only declares its
// tools and translates calls to the task gateway. See README for the
// protocol baseline.
//
// A Server starts in one of two states: paired-from-start (Serve, given a
// capability up front — the legacy --cap/--cap-file flow) or UNPAIRED
// (ServeUnpaired, no capability yet). UNPAIRED exposes only pair/status;
// once pair succeeds, cap/client commit and the capability's granted
// remote_* tools are added, with the SDK sending tools/list_changed on its
// own (AddTool always notifies). cap/client are read and written from
// multiple goroutines (concurrent tool calls) once Run has started, so
// every access goes through mu — never read the fields directly outside
// this file.
type Server struct {
	sdk     *mcpsdk.Server
	verbose bool
	id      int64

	mu      sync.Mutex
	cap     *capability.Capability // nil until paired
	client  transport.Client       // nil until paired
	pairing bool                   // claimed by one in-flight pair call

	// rendezvousURL is where the pair tool fetches envelopes from.
	// Unused once paired (only pair itself needs it).
	rendezvousURL string
}

// Serve runs the MCP stdio loop, already paired with capStr, until stdin
// closes. This is the legacy --cap/--cap-file entry point.
func Serve(capStr string, verbose bool) error {
	cap, err := capability.Decode(capStr)
	if err != nil {
		return err
	}
	if cap.Expired(time.Now()) {
		return fmt.Errorf("capability expired (task %s expired at %s)", cap.TaskID, cap.ExpiresAt.Format(time.RFC3339))
	}
	client, err := dialerFor(cap, verbose)
	if err != nil {
		return err
	}
	// Fail fast: one dial to prove reachability before advertising tools.
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	conn, err := client.Dial(ctx)
	cancel()
	if err != nil {
		_ = client.Close()
		return fmt.Errorf("dial gateway: %w", err)
	}
	_ = conn.Close()

	s := newServer(verbose)
	s.commitPaired(cap, client)
	return s.run()
}

// ServeUnpaired runs the MCP stdio loop with no capability yet: only
// pair/status are exposed until the pair tool succeeds, at which point
// the capability's granted remote_* tools are added and advertised via
// tools/list_changed — no reconnect needed on the client side.
func ServeUnpaired(rendezvousURL string, verbose bool) error {
	s := newServer(verbose)
	s.rendezvousURL = rendezvousURL
	return s.run()
}

func newServer(verbose bool) *Server {
	s := &Server{verbose: verbose}
	s.sdk = mcpsdk.NewServer(&mcpsdk.Implementation{Name: "catflap", Version: buildinfo.Version}, nil)
	s.sdk.AddTool(&mcpsdk.Tool{
		Name:        "pair",
		Description: "Pair with a Catflap task using a pairing code (looks like \"CAT-XXXX-...\"). Fetches and verifies the task's capability, then confirms the task is actually reachable before this tool exposes any of its granted tools.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"code": map[string]any{"type": "string", "description": "The pairing code, e.g. CAT-XXXX-XXXX-..."}},
			"required":   []string{"code"},
		},
	}, s.handlePair)
	s.sdk.AddTool(&mcpsdk.Tool{
		Name:        "status",
		Description: "Report whether this MCP server is paired with a Catflap task, and if so, which one (name, policy, expiry) — never the task secret.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, s.handleStatus)
	return s
}

func (s *Server) run() error {
	return s.sdk.Run(context.Background(), &mcpsdk.StdioTransport{})
}

// snapshot returns the current capability and client together, so a
// handler never observes one updated and the other stale from a
// concurrent pair.
func (s *Server) snapshot() (*capability.Capability, transport.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cap, s.client
}

// commitPaired records a successfully verified capability/client pair and
// adds its granted remote_* tools. Called only after handlePair has
// already proven reachability (dial + ping) — never speculatively.
func (s *Server) commitPaired(cap *capability.Capability, client transport.Client) {
	s.mu.Lock()
	s.cap = cap
	s.client = client
	s.pairing = false
	s.mu.Unlock()
	s.sdk.AddTool(&mcpsdk.Tool{
		Name:        "disconnect",
		Description: "Disconnect from the currently paired task: asks it to revoke itself, then forgets local pairing state once that's confirmed (either the revoke succeeded, or the task was already gone). If the remote task can't be reached at all, does NOT claim it was revoked — the task may still be live.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, s.handleDisconnect)
	for _, def := range toolDefs() {
		name, _ := def["name"].(string)
		if !s.exposed(name) {
			continue
		}
		desc, _ := def["description"].(string)
		schema, _ := def["inputSchema"].(map[string]any)
		s.sdk.AddTool(&mcpsdk.Tool{
			Name:        name,
			Description: desc,
			InputSchema: schema,
		}, s.handleTool(name))
	}
}

// clearPaired forgets local pairing state and removes every tool that
// pairing added (disconnect, plus whatever remote_* tools were granted).
// Called only once a disconnect attempt is CONFIRMED — see
// handleDisconnect — never on an ambiguous outcome.
func (s *Server) clearPaired() {
	s.mu.Lock()
	client := s.client
	s.cap = nil
	s.client = nil
	s.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
	names := []string{"disconnect"}
	for _, def := range toolDefs() {
		if name, _ := def["name"].(string); name != "" {
			names = append(names, name)
		}
	}
	s.sdk.RemoveTools(names...) // not an error to remove tools that were never added
}

// handleDisconnect implements the disconnect tool. Its outcome is
// exactly one of three things, deliberately not collapsed into a
// binary success/failure:
//
//   - CONFIRMED revoked (the gateway answered revoke_self successfully,
//     or reported a reason that only makes sense for an already-dead
//     task — expired, unknown task/secret, or already stopping): local
//     pairing is discarded.
//   - AMBIGUOUS (couldn't dial, couldn't send, couldn't read a
//     response, or the gateway denied for some other reason): local
//     pairing is KEPT. A network hiccup must never be reported as
//     "revoked" — the task could still be fully live and reachable a
//     moment later.
func (s *Server) handleDisconnect(ctx context.Context, _ *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
	cap, client := s.snapshot()
	if cap == nil || client == nil {
		return toolError("not paired"), nil
	}
	confirmed, status, err := revokeSelf(ctx, client, cap)
	if !confirmed {
		msg := "remote revoke could not be confirmed; keeping local pairing"
		if err != nil {
			msg = fmt.Sprintf("%s (%v)", msg, err)
		}
		return toolError(msg), nil
	}
	s.clearPaired()
	return textResult(map[string]any{"disconnected": true, "status": status})
}

// revokeSelf asks cap's task to revoke itself and classifies the
// outcome as confirmed-gone or ambiguous. confirmed is true only when
// the task is provably no longer usable under this capability, whether
// this call caused that or it already was.
func revokeSelf(ctx context.Context, client transport.Client, cap *capability.Capability) (confirmed bool, status string, err error) {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, derr := client.Dial(dctx)
	if derr != nil {
		return false, "", fmt.Errorf("dial: %w", derr)
	}
	defer func() { _ = conn.Close() }()
	// rpc.WriteRequest/ReadResponse each carry their own fixed deadline
	// (30s write, 15s read via SetReadDeadline below), but neither is
	// tied to dctx: a caller-driven cancellation (e.g. the MCP request
	// itself being cancelled) would otherwise still have to wait out
	// those fixed windows before this returns. Force the connection
	// closed the moment dctx expires or is cancelled, same as
	// handleTool's stop := context.AfterFunc(...) — a write or read
	// already in flight then fails immediately instead of blocking.
	stop := context.AfterFunc(dctx, func() { _ = conn.Close() })
	defer stop()
	if werr := rpc.WriteRequest(conn, rpc.Request{Task: cap.TaskID, Secret: cap.TaskSecret, ID: 1, Tool: rpc.ToolRevokeSelf}); werr != nil {
		return false, "", fmt.Errorf("send: %w", werr)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	res, rerr := rpc.ReadResponse(bufio.NewReader(conn))
	if rerr != nil {
		return false, "", fmt.Errorf("read: %w", rerr)
	}
	if res.OK {
		return true, "revoked", nil
	}
	// These are the only deny reasons that mean "already gone", not
	// "denied but possibly still alive": handleRPC returns them for a
	// task that has already expired, was deleted (unknown/bad secret —
	// e.g. a previous disconnect's revoke landed but the response was
	// lost), or is already mid-teardown for some other reason.
	switch res.Error {
	case "capability expired", "unknown task or bad secret", "task stopping":
		return true, "already gone", nil
	default:
		return false, "", errors.New(res.Error)
	}
}

// pairArgs is the pair tool's input.
type pairArgs struct {
	Code string `json:"code"`
}

// handlePair implements the pair tool: ParseCode (local checksum, so a
// typo can never burn the real envelope) -> Fetch (one-time; burns it
// regardless of what follows) -> Open (AEAD; wrong key/tampered envelope
// fail here) -> decode the capability -> dial -> ping. Only once ping
// actually succeeds does this commit pair state and expose the
// capability's tools — Fetch+Open alone only prove the envelope was
// valid, not that its target task is still alive and reachable right
// now.
func (s *Server) handlePair(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
	if !s.tryClaimPairing() {
		return toolError("already paired, or a pair attempt is already in flight"), nil
	}
	committed := false
	defer func() {
		if !committed {
			s.mu.Lock()
			s.pairing = false
			s.mu.Unlock()
		}
	}()

	var args pairArgs
	if err := unmarshalArgs(req, &args); err != nil {
		return toolError(fmt.Sprintf("bad arguments: %v", err)), nil
	}
	id, key, err := pair.ParseCode(args.Code)
	if err != nil {
		return toolError(err.Error()), nil
	}
	env, err := pair.Fetch(ctx, s.rendezvousURL, id)
	if err != nil {
		return toolError(err.Error()), nil
	}
	pt, err := pair.Open(env, key)
	if err != nil {
		return toolError(fmt.Sprintf("could not open envelope: %v", err)), nil
	}
	// The envelope's plaintext is exactly the bytes capability.Decode
	// expects after base64-decoding its "agc1_" form, so re-wrap and
	// reuse Decode's existing v1 strict validation rather than
	// duplicating it.
	cp, err := capability.Decode(capability.Prefix + base64.RawURLEncoding.EncodeToString(pt))
	if err != nil {
		return toolError(fmt.Sprintf("bad capability: %v", err)), nil
	}
	if cp.Expired(time.Now()) {
		return toolError("capability already expired"), nil
	}
	client, err := dialerFor(cp, s.verbose)
	if err != nil {
		return toolError(err.Error()), nil
	}
	if perr := pingGateway(ctx, client, cp); perr != nil {
		_ = client.Close()
		return toolError(fmt.Sprintf("paired capability is unreachable: %v", perr)), nil
	}
	s.commitPaired(cp, client)
	committed = true
	return textResult(map[string]any{
		"paired":     true,
		"name":       cp.Name,
		"policy":     cp.Policy,
		"expires_at": cp.ExpiresAt.Format(time.RFC3339),
	})
}

// tryClaimPairing admits at most one in-flight pair attempt, and refuses
// once already paired.
func (s *Server) tryClaimPairing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cap != nil || s.pairing {
		return false
	}
	s.pairing = true
	return true
}

// handleStatus reports pairing state. Never includes TaskSecret or
// ClientPriv — status is a diagnostic surface, not a credential one.
func (s *Server) handleStatus(_ context.Context, _ *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
	cp, _ := s.snapshot()
	if cp == nil {
		return textResult(map[string]any{"paired": false})
	}
	return textResult(map[string]any{
		"paired":     true,
		"name":       cp.Name,
		"policy":     cp.Policy,
		"transport":  cp.Transport,
		"expires_at": cp.ExpiresAt.Format(time.RFC3339),
	})
}

// dialerFor builds the transport client for cap's transport.
func dialerFor(cap *capability.Capability, verbose bool) (transport.Client, error) {
	switch cap.Transport {
	case "local":
		return local.Dialer(cap.Endpoint), nil
	default:
		return tct.Dialer(cap.Endpoint, cap.ClientPriv, verbose)
	}
}

// pingGateway proves cap's task is alive and reachable right now, over
// its own short-lived connection. Used only by handlePair, before pair
// state ever commits.
func pingGateway(ctx context.Context, client transport.Client, cap *capability.Capability) error {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := client.Dial(dctx)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	// Same reasoning as revokeSelf: force-close on dctx expiry/cancel so
	// a write or read already in flight can't outlive the caller's
	// cancellation.
	stop := context.AfterFunc(dctx, func() { _ = conn.Close() })
	defer stop()
	if werr := rpc.WriteRequest(conn, rpc.Request{Task: cap.TaskID, Secret: cap.TaskSecret, ID: 1, Tool: rpc.ToolPing}); werr != nil {
		return fmt.Errorf("send: %w", werr)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	res, err := rpc.ReadResponse(bufio.NewReader(conn))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if !res.OK {
		return errors.New(res.Error)
	}
	return nil
}

// unmarshalArgs decodes a tool call's raw wire arguments into v.
func unmarshalArgs(req *mcpsdk.CallToolRequest, v any) error {
	if len(req.Params.Arguments) == 0 {
		return fmt.Errorf("missing arguments")
	}
	return json.Unmarshal(req.Params.Arguments, v)
}

// textResult marshals v as pretty JSON text content, matching handleTool's
// result shape.
func textResult(v any) (*mcpsdk.CallToolResult, error) {
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError(fmt.Sprintf("result encoding failed: %v", err)), nil
	}
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: string(pretty)}},
	}, nil
}

// handleTool returns the SDK handler for one gateway RPC tool. Tool-level
// failures (deny, expiry, transport) surface as IsError results so the
// agent can read and self-correct, matching prior behavior.
func (s *Server) handleTool(name string) mcpsdk.ToolHandler {
	return func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		cap, client := s.snapshot()
		if cap == nil || client == nil {
			return toolError("not paired yet — call pair first"), nil
		}
		// Normalized exposure: tools outside the task's grant fail here, and
		// the gateway would deny them anyway (defense in depth).
		if !s.exposed(name) {
			return toolError(fmt.Sprintf("tool %q is not granted to this task", name)), nil
		}
		args := json.RawMessage("{}")
		if req.Params.Arguments != nil {
			raw, err := json.Marshal(req.Params.Arguments)
			if err != nil {
				return toolError(fmt.Sprintf("bad arguments: %v", err)), nil
			}
			args = raw
		}
		callID := atomic.AddInt64(&s.id, 1)
		// Wait ceiling: the longest permitted operation (from the task's
		// capability) plus margin, so the adapter never gives up while the
		// gateway is still legitimately working. Cancellation still does
		// NOT propagate to the remote operation (future: request-scoped
		// RPC cancel); expiry/revoke kills it server-side meanwhile.
		wait := time.Duration(cap.MaxExecMs) * time.Millisecond
		if wait <= 0 {
			wait = 2 * time.Minute // legacy capabilities: built-in default max
		}
		wait += 30 * time.Second
		ctx, cancel := context.WithTimeout(ctx, wait)
		defer cancel()
		conn, err := client.Dial(ctx)
		if err != nil {
			// Tailcat not yet up vs capability dead: surface expiry distinctly.
			if cap.Expired(time.Now()) {
				return toolError("capability expired"), nil
			}
			return toolError(fmt.Sprintf("dial gateway: %v", err)), nil
		}
		defer func() { _ = conn.Close() }()
		// Local cancellation only: if the MCP caller goes away, close the
		// socket so this handler returns promptly instead of waiting out
		// the full ceiling. The remote operation itself is NOT cancelled
		// (future: request-scoped RPC cancel); expiry/revoke kills it
		// server-side meanwhile.
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		if werr := rpc.WriteRequest(conn, rpc.Request{
			Task: cap.TaskID, Secret: cap.TaskSecret,
			ID: callID, Tool: name, Args: args,
		}); werr != nil {
			return toolError(fmt.Sprintf("send: %v", werr)), nil
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		res, err := rpc.ReadResponse(bufio.NewReader(conn))
		if err != nil {
			return toolError(fmt.Sprintf("gateway read: %v", err)), nil
		}
		if !res.OK {
			return toolError(res.Error), nil
		}
		var v any
		if uerr := json.Unmarshal(res.Result, &v); uerr != nil {
			return toolError(fmt.Sprintf("result decoding failed: %v", uerr)), nil
		}
		pretty, merr := json.MarshalIndent(v, "", "  ")
		if merr != nil {
			return toolError(fmt.Sprintf("result encoding failed: %v", merr)), nil
		}
		return &mcpsdk.CallToolResult{
			Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: string(pretty)}},
		}, nil
	}
}

func toolError(msg string) *mcpsdk.CallToolResult {
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: msg}},
		IsError: true,
	}
}

// legacyTools is the tool set implied by a capability that predates the
// tools field (v0.1.x): exec/read/stat, never write.
var legacyTools = []string{rpc.ToolExec, rpc.ToolRead, rpc.ToolStat}

// exposed reports whether name is in the task's normalized tool set.
func (s *Server) exposed(name string) bool {
	cap, _ := s.snapshot()
	if cap == nil {
		return false
	}
	granted := cap.Tools
	if granted == nil {
		granted = legacyTools
	}
	for _, n := range granted {
		if n == name {
			return true
		}
	}
	return false
}

func toolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        rpc.ToolExec,
			"description": "Run an allowlisted executable on the target machine with explicit argv (no shell; metacharacters are inert). Anything outside the task policy is denied.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command":    map[string]any{"type": "string", "description": "Executable name or absolute path, e.g. \"journalctl\""},
					"args":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Arguments passed directly (no shell)"},
					"timeout_ms": map[string]any{"type": "integer"},
				},
				"required": []string{"command"},
			},
		},
		{
			"name":        rpc.ToolRead,
			"description": "Read a file inside the task's allowed roots.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
				"required":   []string{"path"},
			},
		},
		{
			"name":        rpc.ToolStat,
			"description": "Stat a path inside the task's allowed roots.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
				"required":   []string{"path"},
			},
		},
		{
			"name":        rpc.ToolWrite,
			"description": "Write a file inside the task's file.write grant (separate from read; default denied).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":    map[string]any{"type": "string"},
					"content": map[string]any{"type": "string", "description": "Full replacement content (UTF-8 text)"},
				},
				"required": []string{"path", "content"},
			},
		},
	}
}
