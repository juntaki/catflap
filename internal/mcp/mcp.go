package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/rpc"
	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/local"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// User-facing tool names. The internal RPC names (remote_*) stay stable;
// agents only ever see these.
const (
	UserPair       = "pair"
	UserStatus     = "status"
	UserDisconnect = "disconnect"
	UserExec       = "run_command"
	UserRead       = "read_file"
	UserStat       = "stat_file"
	UserWrite      = "write_file"
)

// userToRPC maps user tool names to gateway RPC tools.
var userToRPC = map[string]string{
	UserExec:  rpc.ToolExec,
	UserRead:  rpc.ToolRead,
	UserStat:  rpc.ToolStat,
	UserWrite: rpc.ToolWrite,
}

// Server bridges MCP stdio (Claude Code / Codex / Cursor) to one paired
// Catflap task. It starts unpaired — exposing only pair/status — until
// pair succeeds with a pasted capability or a short pairing code.
type Server struct {
	paired     *capability.Capability
	client     transport.Client
	rendezvous string
	verbose    bool
	mu         chan struct{}
	id         int64
	stdout     *bufio.Writer
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
	Method  string `json:"method,omitempty"`
	Params  any    `json:"params,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Serve runs the MCP stdio loop until stdin closes. An empty capStr starts
// unpaired (the normal agent flow: pair at runtime).
func Serve(capStr, rendezvous string, verbose bool) error {
	return ServeReader(capStr, os.Stdin, rendezvous, verbose)
}

// ServeReader is Serve with an injectable input stream (for --cap-stdin,
// where the first line is the token and the rest is MCP traffic).
func ServeReader(capStr string, r io.Reader, rendezvous string, verbose bool) error {
	s := &Server{
		rendezvous: strings.TrimSpace(rendezvous),
		verbose:    verbose,
		stdout:     bufio.NewWriter(os.Stdout),
	}
	s.mu = make(chan struct{}, 1)
	s.mu <- struct{}{}
	if strings.TrimSpace(capStr) != "" {
		// Pre-paired (stored setup / headless): same checks as pair.
		if err := s.adopt(strings.TrimSpace(capStr)); err != nil {
			return err
		}
	}
	return s.loop(r)
}

// adopt validates a pasted capability, proves the endpoint, and pairs it.
func (s *Server) adopt(capStr string) error {
	cap, err := capability.Decode(capStr)
	if err != nil {
		return err
	}
	if cap.Expired(time.Now()) {
		return fmt.Errorf("capability expired (task %s expired at %s)", cap.TaskID, cap.ExpiresAt.Format(time.RFC3339))
	}
	client, err := dialerFor(cap, s.verbose)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	if err := pingGateway(ctx, client, cap); err != nil {
		_ = client.Close()
		return err
	}
	if s.client != nil {
		_ = s.client.Close()
	}
	s.paired, s.client = cap, client
	return nil
}

func dialerFor(cap *capability.Capability, verbose bool) (transport.Client, error) {
	switch cap.Transport {
	case "local":
		return local.Dialer(cap.Endpoint), nil
	default:
		return tct.Dialer(cap.Endpoint, cap.ClientPriv, verbose)
	}
}

// pingGateway proves reachability, client identity, and secret validity in
// one authenticated round trip. The gateway audits it as the pair event.
func pingGateway(ctx context.Context, client transport.Client, cap *capability.Capability) error {
	conn, err := client.Dial(ctx)
	if err != nil {
		if cap.Expired(time.Now()) {
			return fmt.Errorf("capability expired")
		}
		return fmt.Errorf("dial gateway: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	if err := rpc.WriteRequest(conn, rpc.Request{
		Task: cap.TaskID, Secret: cap.TaskSecret,
		ID: 1, Tool: rpc.ToolPing, Args: json.RawMessage("{}"),
	}); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	res, err := rpc.ReadResponse(bufio.NewReader(conn))
	if err != nil {
		return fmt.Errorf("gateway read: %w", err)
	}
	if !res.OK {
		return fmt.Errorf("%s", res.Error)
	}
	return nil
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
			"serverInfo":      map[string]any{"name": "catflap", "version": "0.2.0"},
		}, nil)
	case "ping":
		s.respond(req.ID, map[string]any{}, nil)
	case "tools/list":
		s.respond(req.ID, map[string]any{"tools": s.visibleTools()}, nil)
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

// visibleTools returns pair/status always; disconnect and data tools only
// when paired (data tools further filtered by the task grant).
func (s *Server) visibleTools() []map[string]any {
	out := []map[string]any{pairDef(), statusDef()}
	if s.paired == nil {
		return out
	}
	out = append(out, disconnectDef())
	for _, def := range dataToolDefs() {
		if s.exposed(def.rpc) {
			out = append(out, def.def)
		}
	}
	return out
}

// exposed reports whether the gateway rpc tool is in the task's grant.
// Nil grant list means a legacy capability (exec/read/stat, never write).
func (s *Server) exposed(rpcName string) bool {
	if s.paired == nil {
		return false
	}
	granted := s.paired.Tools
	if granted == nil {
		granted = []string{rpc.ToolExec, rpc.ToolRead, rpc.ToolStat}
	}
	for _, n := range granted {
		if n == rpcName {
			return true
		}
	}
	return false
}

func (s *Server) callTool(id any, name string, args json.RawMessage) {
	switch name {
	case UserPair:
		s.doPair(id, args)
		return
	case UserStatus:
		s.doStatus(id)
		return
	case UserDisconnect:
		s.doDisconnect(id)
		return
	}
	rpcName, ok := userToRPC[name]
	if !ok || !s.exposed(rpcName) {
		s.mcpToolError(id, fmt.Sprintf("tool %q is not available (pair first, or not granted to this task)", name))
		return
	}
	if s.paired == nil || s.client == nil {
		s.mcpToolError(id, "not paired — call pair first")
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
		if s.paired.Expired(time.Now()) {
			s.mcpToolError(id, "capability expired")
			return
		}
		s.mcpToolError(id, fmt.Sprintf("dial gateway: %v", err))
		return
	}
	defer func() { _ = conn.Close() }()
	if werr := rpc.WriteRequest(conn, rpc.Request{
		Task: s.paired.TaskID, Secret: s.paired.TaskSecret,
		ID: callID, Tool: rpcName, Args: args,
	}); werr != nil {
		s.mcpToolError(id, fmt.Sprintf("send: %v", werr))
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Second))
	res, err := rpc.ReadResponse(bufio.NewReader(conn))
	if err != nil {
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

// doPair connects a pairing code: either a pasted capability or a short
// CAT code resolved through the rendezvous.
func (s *Server) doPair(id any, args json.RawMessage) {
	var p struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(args, &p); err != nil || strings.TrimSpace(p.Code) == "" {
		s.mcpToolError(id, "pair needs {\"code\": \"CAT-…\"} (or a pasted capability)")
		return
	}
	code := strings.TrimSpace(p.Code)
	var capStr string
	if strings.HasPrefix(code, capability.Prefix) {
		capStr = code
	} else {
		capStr2, err := s.fetchShortCode(code)
		if err != nil {
			s.mcpToolError(id, err.Error())
			return
		}
		capStr = capStr2
	}
	if err := s.adopt(capStr); err != nil {
		s.mcpToolError(id, fmt.Sprintf("pairing failed: %v", err))
		return
	}
	s.notifyToolsChanged()
	s.respond(id, map[string]any{
		"content": []map[string]any{{"type": "text", "text": s.pairSummary()}},
	}, nil)
}

// fetchShortCode resolves a CAT code through the rendezvous: fetch the
// one-time envelope and open it. The code is single-use — replay burns.
func (s *Server) fetchShortCode(code string) (string, error) {
	if s.rendezvous == "" {
		return "", fmt.Errorf("short pairing codes need a rendezvous (set --rendezvous or CATFLAP_RENDEZVOUS); or paste a full capability instead")
	}
	id, key, err := pair.ParseCode(code)
	if err != nil {
		return "", fmt.Errorf("bad pairing code: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env, err := pair.Fetch(ctx, s.rendezvous, id)
	if err != nil {
		return "", fmt.Errorf("pairing not found or expired (code used, wrong, or too old)")
	}
	pt, err := pair.Open(env, key)
	if err != nil {
		return "", fmt.Errorf("pairing not found or expired (code used, wrong, or too old)")
	}
	return string(pt), nil
}

func (s *Server) pairSummary() string {
	cap := s.paired
	tools := []string{}
	for _, def := range dataToolDefs() {
		if s.exposed(def.rpc) {
			tools = append(tools, def.user)
		}
	}
	return fmt.Sprintf("Connected.\n\nProfile:\n  %s\nTask:\n  %s\nExpires:\n  %s\nTools:\n  %s",
		cap.Policy, cap.Name,
		cap.ExpiresAt.Format(time.RFC3339), strings.Join(tools, ", "))
}

func (s *Server) doStatus(id any) {
	if s.paired == nil {
		s.respond(id, map[string]any{
			"content": []map[string]any{{"type": "text", "text": "Not paired. Call pair with the code shown by `catflap share`."}},
		}, nil)
		return
	}
	s.respond(id, map[string]any{
		"content": []map[string]any{{"type": "text", "text": s.pairSummary()}},
	}, nil)
}

// doDisconnect revokes the task on the target (same teardown as operator
// revoke) and returns to unpaired mode. Best effort on the RPC: even if
// the endpoint is already gone, the local pairing is dropped.
func (s *Server) doDisconnect(id any) {
	if s.paired == nil || s.client == nil {
		s.mcpToolError(id, "not paired")
		return
	}
	cap := s.paired
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := s.client.Dial(ctx)
	if err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		_ = rpc.WriteRequest(conn, rpc.Request{
			Task: cap.TaskID, Secret: cap.TaskSecret,
			ID: 1, Tool: rpc.ToolRevokeSelf, Args: json.RawMessage("{}"),
		})
		_, _ = rpc.ReadResponse(bufio.NewReader(conn))
		_ = conn.Close()
	}
	_ = s.client.Close()
	s.paired, s.client = nil, nil
	s.notifyToolsChanged()
	s.respond(id, map[string]any{
		"content": []map[string]any{{"type": "text", "text": "Disconnected. The task was revoked on the target."}},
	}, nil)
}

// notifyToolsChanged tells the client to re-list tools after pair/disconnect.
func (s *Server) notifyToolsChanged() {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	raw, merr := json.Marshal(rpcResponse{JSONRPC: "2.0", Method: "notifications/tools/list_changed"})
	if merr != nil {
		return
	}
	raw = append(raw, '\n')
	_, _ = s.stdout.Write(raw)
	_ = s.stdout.Flush()
}

type dataTool struct {
	user string
	rpc  string
	def  map[string]any
}

func pairDef() map[string]any {
	return map[string]any{
		"name":        UserPair,
		"description": "Connect to a Catflap task. Pass the pairing code shown by `catflap share` on the target machine (or a pasted capability).",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"code": map[string]any{"type": "string", "description": "Pairing code, e.g. CAT-7KQ9-M2PV-…"}},
			"required":   []string{"code"},
		},
	}
}

func statusDef() map[string]any {
	return map[string]any{
		"name":        UserStatus,
		"description": "Show the current Catflap pairing (task, profile, expiry).",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
	}
}

func disconnectDef() map[string]any {
	return map[string]any{
		"name":        UserDisconnect,
		"description": "Disconnect and revoke the Catflap task on the target machine. The task cannot be used afterward.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
	}
}

func dataToolDefs() []dataTool {
	return []dataTool{
		{UserExec, rpc.ToolExec, map[string]any{
			"name":        UserExec,
			"description": "Run an allowlisted executable on the target machine with explicit argv (no shell; metacharacters are inert). Only commands granted by the operator for the current temporary task. Anything else is denied.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command":    map[string]any{"type": "string", "description": "Executable name or absolute path, e.g. \"journalctl\""},
					"args":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Arguments passed directly (no shell)"},
					"timeout_ms": map[string]any{"type": "integer"},
				},
				"required": []string{"command"},
			},
		}},
		{UserRead, rpc.ToolRead, map[string]any{
			"name":        UserRead,
			"description": "Read a file only from directories explicitly granted by the operator for the current temporary Catflap task.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
				"required":   []string{"path"},
			},
		}},
		{UserStat, rpc.ToolStat, map[string]any{
			"name":        UserStat,
			"description": "Stat a path only inside directories explicitly granted by the operator for the current temporary Catflap task.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
				"required":   []string{"path"},
			},
		}},
		{UserWrite, rpc.ToolWrite, map[string]any{
			"name":        UserWrite,
			"description": "Write a file only inside directories explicitly granted for writing by the operator for the current temporary Catflap task. Unavailable unless granted.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":    map[string]any{"type": "string"},
					"content": map[string]any{"type": "string", "description": "Full replacement content (UTF-8 text)"},
				},
				"required": []string{"path", "content"},
			},
		}},
	}
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
