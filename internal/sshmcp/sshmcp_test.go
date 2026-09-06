package sshmcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/sshhost"
	"github.com/juntaki/catflap/internal/transport/local"
)

func mustGenEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func callToolRequest(t *testing.T, args any) *mcpsdk.CallToolRequest {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return &mcpsdk.CallToolRequest{Params: &mcpsdk.CallToolParamsRaw{Arguments: raw}}
}

func resultText(t *testing.T, res *mcpsdk.CallToolResult) string {
	t.Helper()
	tc, ok := res.Content[0].(*mcpsdk.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	return tc.Text
}

// liveTaskAndCode starts a real sshhost.Task over the local transport,
// runs the one-shot pairing exchange for it, and returns the pairing
// code an agent adapter would be given.
func liveTaskAndCode(t *testing.T) (task *sshhost.Task, code string) {
	t.Helper()
	task, err := sshhost.NewTask(context.Background(), sshhost.NewID(), time.Hour, nil)
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	t.Cleanup(func() { task.Stop("shutdown") })

	srv, err := local.Serve(task.Handler())
	if err != nil {
		t.Fatalf("local.Serve: %v", err)
	}
	task.OnStopFunc(func() { _ = srv.Close() })

	offer := pair.SSHOffer{
		Version: 1, TaskID: task.ID, Transport: "local",
		Endpoint: srv.Addr(), HostKey: task.HostKeyAuthorizedLine(),
		ExpiresAt: task.ExpiresAt,
	}
	pairSrv, err := pair.ServeSSHOffer("local", offer, 30*time.Second, false, nil, func(pub string) error {
		key, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(pub))
		if perr != nil {
			return perr
		}
		task.SetAllowedKey(key)
		return nil
	})
	if err != nil {
		t.Fatalf("ServeSSHOffer: %v", err)
	}
	t.Cleanup(pairSrv.Close)

	code, err = pair.Encode("local", pairSrv.Addr())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return task, code
}

// TestAdapterPairExecDisconnect drives the real MCP tool handlers
// (pair -> exec -> disconnect) exactly as Claude Code would call them,
// proving the whole adapter path — not just the packages it's built
// from — produces a shell-capable, exact-match-authenticated session
// and cleanly forgets it afterward.
func TestAdapterPairExecDisconnect(t *testing.T) {
	_, code := liveTaskAndCode(t)
	s := newServer(false)

	if res, _ := s.handleExec(context.Background(), callToolRequest(t, execArgs{Command: "echo too early"})); !res.IsError {
		t.Fatal("exec must fail before pairing")
	}

	res, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: code}))
	if err != nil {
		t.Fatalf("handlePair: %v", err)
	}
	if res.IsError {
		t.Fatalf("pair failed: %s", resultText(t, res))
	}

	res, err = s.handleExec(context.Background(), callToolRequest(t, execArgs{Command: "echo one && echo two 1>&2"}))
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	if res.IsError {
		t.Fatalf("exec failed: %s", resultText(t, res))
	}
	var got execResult
	if uerr := json.Unmarshal([]byte(resultText(t, res)), &got); uerr != nil {
		t.Fatalf("unmarshal exec result: %v", uerr)
	}
	if got.Stdout != "one\n" || got.Stderr != "two\n" || got.ExitCode != 0 {
		t.Fatalf("exec result = %+v, want stdout=one\\n stderr=two\\n exit_code=0", got)
	}

	res, err = s.handleExec(context.Background(), callToolRequest(t, execArgs{Command: "exit 7"}))
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	if res.IsError {
		t.Fatalf("a non-zero remote exit must not be a tool error: %s", resultText(t, res))
	}
	if uerr := json.Unmarshal([]byte(resultText(t, res)), &got); uerr != nil {
		t.Fatalf("unmarshal exec result: %v", uerr)
	}
	if got.ExitCode != 7 {
		t.Fatalf("exit_code = %d, want 7", got.ExitCode)
	}

	res, err = s.handleDisconnect(context.Background(), callToolRequest(t, struct{}{}))
	if err != nil {
		t.Fatalf("handleDisconnect: %v", err)
	}
	if res.IsError {
		t.Fatalf("disconnect failed: %s", resultText(t, res))
	}
	if res, _ := s.handleExec(context.Background(), callToolRequest(t, execArgs{Command: "echo after disconnect"})); !res.IsError {
		t.Fatal("exec must fail after disconnect")
	}
}

// TestAdapterRejectsWrongHostKey proves the adapter refuses to pair if
// the SSH endpoint's actual host key doesn't match what the pairing
// exchange offered — the defense against a network-level impersonator
// that somehow answers on the right address but isn't the real task.
func TestAdapterRejectsWrongHostKey(t *testing.T) {
	task, code := liveTaskAndCode(t)
	_ = task

	// Tamper with the code's target: decode it, then re-encode a code
	// pointing at a DIFFERENT (wrong) endpoint the offer never named,
	// simulating an offer whose HostKey field doesn't match whatever
	// actually answers at Endpoint. Simpler: directly exercise dialSSH
	// with a deliberately wrong expected host key.
	transportName, addr, err := pair.Decode(code)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	offer, clientKey, err := pair.FetchSSHOffer(context.Background(), transportName, addr, false)
	if err != nil {
		t.Fatalf("FetchSSHOffer: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := gossh.NewSignerFromKey(mustGenEd25519(t))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = dialSSH(context.Background(), offer, signer, wrongKey.PublicKey(), false)
	if err == nil {
		t.Fatal("expected host key mismatch to be rejected")
	}
}
