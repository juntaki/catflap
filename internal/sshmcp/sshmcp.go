// Package sshmcp is the new Claude-side adapter: it bridges MCP to one
// paired SSH endpoint instead of the legacy RPC capability protocol.
// There is exactly one operational tool — exec, running the caller's
// command through the remote login shell with no allowlist — because
// Catflap no longer decides what an agent may run; the OS account
// `catflap share` runs as does, exactly like a normal SSH login. What
// this adapter still owns is proving the endpoint is the one the
// pairing code actually named (host key pinning) and never running
// anything once disconnected.
package sshmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/juntaki/catflap/internal/buildinfo"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/local"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// execTimeout bounds one exec tool call — long enough for a real
// build/test command, short enough that a hung remote command doesn't
// wedge the MCP connection forever. The task's own TTL/revoke is what
// actually kills the remote process; this only bounds how long the
// adapter itself waits for a reply.
const execTimeout = 10 * time.Minute

// Server bridges MCP to one paired SSH endpoint.
type Server struct {
	sdk     *mcpsdk.Server
	verbose bool

	mu      sync.Mutex
	client  transport.Client // transport-level client; Close destroys any ephemeral network identity
	ssh     *gossh.Client
	taskID  string
	pairing bool
}

// ServeUnpaired runs the MCP stdio loop with no pairing yet: only
// pair/status are exposed until pair succeeds, at which point exec/
// disconnect are added and advertised via tools/list_changed.
func ServeUnpaired(verbose bool) error {
	s := newServer(verbose)
	return s.sdk.Run(context.Background(), &mcpsdk.StdioTransport{})
}

func newServer(verbose bool) *Server {
	s := &Server{verbose: verbose}
	s.sdk = mcpsdk.NewServer(&mcpsdk.Implementation{Name: "catflap", Version: buildinfo.Version}, nil)
	s.sdk.AddTool(&mcpsdk.Tool{
		Name:        "pair",
		Description: "Pair with a Catflap SSH share using a pairing code (looks like \"CAT-XXXX-...\"). Generates a fresh ephemeral SSH key, exchanges it with the host, and connects — verifying the host's SSH key matches what the pairing code's issuer actually offered before this tool exposes exec.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"code": map[string]any{"type": "string", "description": "The pairing code, e.g. CAT-XXXX-XXXX-..."}},
			"required":   []string{"code"},
		},
	}, s.handlePair)
	s.sdk.AddTool(&mcpsdk.Tool{
		Name:        "status",
		Description: "Report whether this MCP server is paired with a Catflap SSH share, and if so, which task.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, s.handleStatus)
	return s
}

func (s *Server) snapshot() (*gossh.Client, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ssh, s.taskID
}

func (s *Server) tryClaimPairing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ssh != nil || s.pairing {
		return false
	}
	s.pairing = true
	return true
}

func (s *Server) commitPaired(client transport.Client, sshClient *gossh.Client, taskID string) {
	s.mu.Lock()
	s.client = client
	s.ssh = sshClient
	s.taskID = taskID
	s.pairing = false
	s.mu.Unlock()
	// The task can die (TTL, revoke) without this adapter ever calling
	// disconnect itself — Wait blocks until the underlying SSH
	// connection actually closes, at which point pairing state must be
	// forgotten automatically so a fresh pairing code can be used on
	// this same running adapter instead of it staying stuck reporting
	// "already paired" against a connection that no longer exists.
	go func() {
		_ = sshClient.Wait()
		s.clearIfCurrent(sshClient)
	}()
	s.sdk.AddTool(&mcpsdk.Tool{
		Name:        "disconnect",
		Description: "Disconnect from the currently paired SSH share and forget local pairing state. This only ends THIS adapter's connection — it does not revoke the task itself; the operator's own `catflap ssh-share` process (Ctrl-C, or its TTL) is what ends access for good.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, s.handleDisconnect)
	s.sdk.AddTool(&mcpsdk.Tool{
		Name:        "exec",
		Description: "Run a command on the paired machine over SSH, through its login shell (pipes, &&, quoting all work normally — exactly like a real ssh client). Catflap applies no command restriction of its own: the OS account `catflap share` was run as is what defines what's allowed. Deciding whether a given command is safe to run is this caller's own responsibility.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command": map[string]any{"type": "string", "description": "The shell command line to run"},
			},
			"required": []string{"command"},
		},
	}, s.handleExec)
}

// clearIfCurrent forgets pairing state and removes exec/disconnect, but
// only if sshClient is still the CURRENT paired connection: the
// auto-unpair goroutine (commitPaired) and an explicit disconnect call
// can both race to clear the same dead connection, and a disconnect
// racing a NEWER pairing (already replaced by the time this runs) must
// never clobber that newer pairing's state. Returns whether it actually
// cleared anything.
func (s *Server) clearIfCurrent(sshClient *gossh.Client) bool {
	s.mu.Lock()
	if s.ssh != sshClient {
		s.mu.Unlock()
		return false
	}
	client := s.client
	s.client, s.ssh, s.taskID = nil, nil, ""
	s.mu.Unlock()
	if sshClient != nil {
		_ = sshClient.Close()
	}
	if client != nil {
		_ = client.Close()
	}
	s.sdk.RemoveTools("disconnect", "exec")
	return true
}

type pairArgs struct {
	Code string `json:"code"`
}

// handlePair implements the pair tool: Decode (local checksum) ->
// FetchSSHOffer (dials the pair server directly, one-shot, mints a
// fresh ephemeral client key and hands the public half back) -> dial
// the task's real SSH endpoint, pinning its host key to exactly what
// the offer named -> commit. A pairing code can only ever be claimed
// once; if the SSH handshake itself fails after that, this adapter has
// nothing to fall back to and the operator must issue a fresh code.
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
	transportName, addr, err := pair.Decode(args.Code)
	if err != nil {
		return toolError(err.Error()), nil
	}
	offer, clientKey, err := pair.FetchSSHOffer(ctx, transportName, addr, s.verbose)
	if err != nil {
		return toolError(err.Error()), nil
	}
	if time.Now().After(offer.ExpiresAt) {
		return toolError("task already expired"), nil
	}
	wantHostKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(offer.HostKey))
	if err != nil {
		return toolError(fmt.Sprintf("bad host key in offer: %v", err)), nil
	}
	signer, err := gossh.NewSignerFromKey(clientKey)
	if err != nil {
		return toolError(fmt.Sprintf("wrap client key: %v", err)), nil
	}

	client, sshClient, derr := dialSSH(ctx, offer, signer, wantHostKey, s.verbose)
	if derr != nil {
		return toolError(fmt.Sprintf("SSH handshake failed: %v", derr)), nil
	}
	s.commitPaired(client, sshClient, offer.TaskID)
	committed = true
	return textResult(map[string]any{
		"paired":     true,
		"task":       offer.TaskID,
		"expires_at": offer.ExpiresAt.Format(time.RFC3339),
	})
}

// dialSSH connects to the offer's endpoint (over its transport) and
// completes the SSH handshake, rejecting any host key other than
// wantHostKey — the pairing exchange (itself carried over an
// independently-authenticated Tailcat tunnel) is what the client is
// trusting here, not blind SSH TOFU.
func dialSSH(ctx context.Context, offer pair.SSHOffer, signer gossh.Signer, wantHostKey gossh.PublicKey, verbose bool) (transport.Client, *gossh.Client, error) {
	var client transport.Client
	switch offer.Transport {
	case "tailcat":
		priv, _, kerr := tct.GenerateClientKey()
		if kerr != nil {
			return nil, nil, fmt.Errorf("generate transport client key: %w", kerr)
		}
		c, derr := tct.Dialer(offer.Endpoint, priv, verbose)
		if derr != nil {
			return nil, nil, fmt.Errorf("dial task endpoint: %w", derr)
		}
		client = c
	case "local":
		client = local.Dialer(offer.Endpoint)
	default:
		return nil, nil, fmt.Errorf("unknown transport %q", offer.Transport)
	}
	conn, err := client.Dial(ctx)
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("dial task endpoint: %w", err)
	}
	config := &gossh.ClientConfig{
		User: "catflap",
		Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			if !publicKeysEqual(key, wantHostKey) {
				return fmt.Errorf("host key mismatch: this is not the endpoint the pairing code named")
			}
			return nil
		},
		Timeout: 30 * time.Second,
	}
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, offer.Endpoint, config)
	if err != nil {
		_ = conn.Close()
		_ = client.Close()
		return nil, nil, err
	}
	return client, gossh.NewClient(sshConn, chans, reqs), nil
}

func publicKeysEqual(a, b gossh.PublicKey) bool {
	return string(a.Marshal()) == string(b.Marshal())
}

func (s *Server) handleStatus(_ context.Context, _ *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
	sshClient, taskID := s.snapshot()
	if sshClient == nil {
		return textResult(map[string]any{"paired": false})
	}
	return textResult(map[string]any{"paired": true, "task": taskID})
}

func (s *Server) handleDisconnect(_ context.Context, _ *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
	sshClient, _ := s.snapshot()
	if sshClient == nil {
		return toolError("not paired"), nil
	}
	s.clearIfCurrent(sshClient)
	return textResult(map[string]any{"disconnected": true})
}

type execArgs struct {
	Command string `json:"command"`
}

type execResult struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
}

// maxOutputBytes caps how much of a command's stdout/stderr this
// adapter holds in memory: with no allowlist steering callers toward
// well-behaved commands, `exec` must survive a caller running `yes` or
// dumping a huge build log without OOMing catflap mcp — the SSH session
// itself keeps running to completion (and the remote side is
// unaffected), only what this process buffers is bounded.
const maxOutputBytes = 8 << 20 // 8MiB

// boundedWriter caps how many bytes it retains; past the cap, writes
// are accepted (so the copier driving it never sees a short write and
// aborts) but dropped, and Truncated is set.
type boundedWriter struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	remain := w.max - w.buf.Len()
	if remain <= 0 {
		if len(p) > 0 {
			w.truncated = true
		}
		return len(p), nil
	}
	if len(p) > remain {
		w.buf.Write(p[:remain])
		w.truncated = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

// handleExec runs one command over the paired SSH connection's login
// shell. A non-zero remote exit is NOT an adapter error — it's a
// normal result the caller reads exit_code from, exactly like a local
// Bash tool call; only a connection-level failure (dead session, timed
// out) surfaces as a tool error.
func (s *Server) handleExec(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
	sshClient, _ := s.snapshot()
	if sshClient == nil {
		return toolError("not paired yet — call pair first"), nil
	}
	var args execArgs
	if err := unmarshalArgs(req, &args); err != nil {
		return toolError(fmt.Sprintf("bad arguments: %v", err)), nil
	}
	sess, err := sshClient.NewSession()
	if err != nil {
		return toolError(fmt.Sprintf("open SSH session: %v", err)), nil
	}
	defer func() { _ = sess.Close() }()

	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	// x/crypto/ssh.Session has no context parameter: force the session
	// closed the moment ctx expires or the MCP caller cancels, so this
	// handler returns promptly instead of blocking on a hung remote
	// command until execTimeout's full duration always elapses.
	stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer stop()

	stdout := &boundedWriter{max: maxOutputBytes}
	stderr := &boundedWriter{max: maxOutputBytes}
	sess.Stdout = stdout
	sess.Stderr = stderr
	runErr := sess.Run(args.Command)

	res := execResult{
		Stdout: stdout.buf.String(), Stderr: stderr.buf.String(),
		StdoutTruncated: stdout.truncated, StderrTruncated: stderr.truncated,
	}
	var exitErr *gossh.ExitError
	switch {
	case runErr == nil:
		res.ExitCode = 0
	case asExitError(runErr, &exitErr):
		res.ExitCode = exitErr.ExitStatus()
	default:
		return toolError(fmt.Sprintf("run command: %v", runErr)), nil
	}
	return textResult(res)
}

func asExitError(err error, target **gossh.ExitError) bool {
	ee, ok := err.(*gossh.ExitError) //nolint:errorlint // reason: gossh.Session.Run's documented error type is exactly this concrete type, never wrapped.
	if !ok {
		return false
	}
	*target = ee
	return true
}

func unmarshalArgs(req *mcpsdk.CallToolRequest, v any) error {
	if len(req.Params.Arguments) == 0 {
		return fmt.Errorf("missing arguments")
	}
	return json.Unmarshal(req.Params.Arguments, v)
}

func textResult(v any) (*mcpsdk.CallToolResult, error) {
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError(fmt.Sprintf("result encoding failed: %v", err)), nil
	}
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: string(pretty)}},
	}, nil
}

func toolError(msg string) *mcpsdk.CallToolResult {
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: msg}},
		IsError: true,
	}
}
