package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/juntaki/catflap/internal/capability"
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
type Server struct {
	sdk     *mcpsdk.Server
	cap     *capability.Capability
	client  transport.Client
	verbose bool
	id      int64
}

// Serve runs the MCP stdio loop until stdin closes.
func Serve(capStr string, verbose bool) error {
	cap, err := capability.Decode(capStr)
	if err != nil {
		return err
	}
	if cap.Expired(time.Now()) {
		return fmt.Errorf("capability expired (task %s expired at %s)", cap.TaskID, cap.ExpiresAt.Format(time.RFC3339))
	}
	var client transport.Client
	switch cap.Transport {
	case "local":
		client = local.Dialer(cap.Endpoint)
	default:
		client, err = tct.Dialer(cap.Endpoint, cap.ClientPriv, verbose)
		if err != nil {
			return err
		}
	}
	defer func() { _ = client.Close() }()
	// Fail fast: one dial to prove reachability before advertising tools.
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	conn, err := client.Dial(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("dial gateway: %w", err)
	}
	_ = conn.Close()

	s := &Server{cap: cap, client: client, verbose: verbose}
	s.sdk = mcpsdk.NewServer(
		&mcpsdk.Implementation{Name: "catflap", Version: "0.2.0"}, nil)
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
	return s.sdk.Run(context.Background(), &mcpsdk.StdioTransport{})
}

// handleTool returns the SDK handler for one gateway RPC tool. Tool-level
// failures (deny, expiry, transport) surface as IsError results so the
// agent can read and self-correct, matching prior behavior.
func (s *Server) handleTool(name string) mcpsdk.ToolHandler {
	return func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
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
		wait := time.Duration(s.cap.MaxExecMs) * time.Millisecond
		if wait <= 0 {
			wait = 2 * time.Minute // legacy capabilities: built-in default max
		}
		wait += 30 * time.Second
		ctx, cancel := context.WithTimeout(ctx, wait)
		defer cancel()
		conn, err := s.client.Dial(ctx)
		if err != nil {
			// Tailcat not yet up vs capability dead: surface expiry distinctly.
			if s.cap.Expired(time.Now()) {
				return toolError("capability expired"), nil
			}
			return toolError(fmt.Sprintf("dial gateway: %v", err)), nil
		}
		defer func() { _ = conn.Close() }()
		if werr := rpc.WriteRequest(conn, rpc.Request{
			Task: s.cap.TaskID, Secret: s.cap.TaskSecret,
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

// visibleTools filters the full tool definitions to the task's normalized
// set. A nil capability list means a legacy capability.
func visibleTools(granted []string) []map[string]any {
	if granted == nil {
		granted = legacyTools
	}
	allow := map[string]bool{}
	for _, name := range granted {
		allow[name] = true
	}
	var out []map[string]any
	for _, def := range toolDefs() {
		name, _ := def["name"].(string)
		if allow[name] {
			out = append(out, def)
		}
	}
	return out
}

// exposed reports whether name is in the task's normalized tool set.
func (s *Server) exposed(name string) bool {
	granted := s.cap.Tools
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
