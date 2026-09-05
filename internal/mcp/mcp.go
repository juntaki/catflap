package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/rpc"
	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/local"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// Server bridges MCP stdio (Claude Code / Codex / Cursor) to one gateway
// capability over Tailcat (or local TCP for tests).
type Server struct {
	cap    *capability.Capability
	client transport.Client
	mu     chan struct{}
	id     int64
	stdout *bufio.Writer
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Serve runs the MCP stdio loop until stdin closes.
func Serve(capStr string, verbose bool) error {
	return ServeReader(capStr, os.Stdin, verbose)
}

// ServeReader is Serve with an injectable input stream (for --cap-stdin,
// where the first line is the token and the rest is MCP traffic).
func ServeReader(capStr string, r io.Reader, verbose bool) error {
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

	s := &Server{cap: cap, client: client, stdout: bufio.NewWriter(os.Stdout)}
	s.mu = make(chan struct{}, 1)
	s.mu <- struct{}{}
	return s.loop(r)
}

func (s *Server) loop(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		// Notifications (no id) need no response; MCP "notifications/initialized" is one.
		if req.ID == nil {
			continue
		}
		s.handle(req)
		_ = s.stdout.Flush()
	}
	return sc.Err()
}

func (s *Server) handle(req rpcRequest) {
	switch req.Method {
	case "initialize":
		s.respond(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "catflap", "version": "0.1.2"},
		}, nil)
	case "ping":
		s.respond(req.ID, map[string]any{}, nil)
	case "tools/list":
		s.respond(req.ID, map[string]any{"tools": toolDefs()}, nil)
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			s.respondErr(req.ID, -32602, "bad params")
			return
		}
		s.callTool(req.ID, p.Name, p.Arguments)
	default:
		s.respondErr(req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
	}
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
	}
}

func (s *Server) callTool(id any, name string, args json.RawMessage) {
	if name != rpc.ToolExec && name != rpc.ToolRead && name != rpc.ToolStat {
		s.respondErr(id, -32602, fmt.Sprintf("unknown tool %q", name))
		return
	}
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	callID := atomic.AddInt64(&s.id, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	conn, err := s.client.Dial(ctx)
	if err != nil {
		// Tailcat not yet up vs capability dead: surface expiry distinctly.
		if s.cap.Expired(time.Now()) {
			s.mcpToolError(id, "capability expired")
			return
		}
		s.mcpToolError(id, fmt.Sprintf("dial gateway: %v", err))
		return
	}
	defer func() { _ = conn.Close() }()
	if werr := rpc.WriteRequest(conn, rpc.Request{
		Task: s.cap.TaskID, Secret: s.cap.TaskSecret,
		ID: callID, Tool: name, Args: args,
	}); werr != nil {
		s.mcpToolError(id, fmt.Sprintf("send: %v", werr))
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Second))
	res, err := rpc.ReadResponse(bufio.NewReader(conn))
	if err != nil {
		if errors.Is(err, io.EOF) || os.IsTimeout(err) {
			s.mcpToolError(id, fmt.Sprintf("gateway read: %v", err))
			return
		}
		s.mcpToolError(id, fmt.Sprintf("gateway read: %v", err))
		return
	}
	if !res.OK {
		s.mcpToolError(id, res.Error)
		return
	}
	var v any
	if uerr := json.Unmarshal(res.Result, &v); uerr != nil {
		s.mcpToolError(id, fmt.Sprintf("result decoding failed: %v", uerr))
		return
	}
	pretty, merr := json.MarshalIndent(v, "", "  ")
	if merr != nil {
		s.mcpToolError(id, fmt.Sprintf("result encoding failed: %v", merr))
		return
	}
	s.respond(id, map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(pretty)}},
	}, nil)
}

func (s *Server) mcpToolError(id any, msg string) {
	s.respond(id, map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}, nil)
}

func (s *Server) respond(id any, result any, _ error) {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	// id/result round-tripped through JSON decode, so encoding cannot fail
	// in practice; dropping the response on failure is fail-closed.
	raw, merr := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
	if merr != nil {
		return
	}
	raw = append(raw, '\n')
	_, _ = s.stdout.Write(raw)
	_ = s.stdout.Flush()
}

func (s *Server) respondErr(id any, code int, msg string) {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	raw, merr := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: id, Error: &struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: msg}})
	if merr != nil {
		return
	}
	raw = append(raw, '\n')
	_, _ = s.stdout.Write(raw)
	_ = s.stdout.Flush()
}

var _ = net.IPv4len
