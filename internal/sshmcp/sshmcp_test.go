package sshmcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
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

// TestExecTruncatesOversizedOutput is the P1 regression for unbounded
// buffering: with no command allowlist steering callers toward
// well-behaved output sizes, a caller running something like `yes` or
// dumping a huge build log must not be able to OOM `catflap mcp` by
// making it hold the entire stream in memory. The SSH session itself
// must still run to completion; only what this adapter retains is
// capped.
func TestExecTruncatesOversizedOutput(t *testing.T) {
	_, code := liveTaskAndCode(t)
	s := newServer(false)
	if res, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: code})); err != nil || res.IsError {
		t.Fatalf("pair failed: err=%v res=%v", err, res)
	}

	res, err := s.handleExec(context.Background(), callToolRequest(t, execArgs{
		Command: fmt.Sprintf("head -c %d /dev/zero | tr '\\0' 'a'", maxOutputBytes+1<<20),
	}))
	if err != nil {
		t.Fatalf("handleExec: %v", err)
	}
	if res.IsError {
		t.Fatalf("exec of oversized output must not be a tool error: %s", resultText(t, res))
	}
	var got execResult
	if uerr := json.Unmarshal([]byte(resultText(t, res)), &got); uerr != nil {
		t.Fatalf("unmarshal exec result: %v", uerr)
	}
	if !got.StdoutTruncated {
		t.Error("stdout_truncated must be true for output exceeding maxOutputBytes")
	}
	if len(got.Stdout) != maxOutputBytes {
		t.Errorf("retained stdout = %d bytes, want exactly maxOutputBytes (%d)", len(got.Stdout), maxOutputBytes)
	}
	if got.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0 (the remote command itself completed normally)", got.ExitCode)
	}
}

// TestUnpairsAutomaticallyOnTaskDeath is the P2 regression: without
// this, an adapter whose paired task died (TTL, revoke) stayed stuck
// reporting "already paired" against a connection that no longer
// existed, and a fresh pairing code typed into the same still-running
// Claude session could never be used.
func TestUnpairsAutomaticallyOnTaskDeath(t *testing.T) {
	task, code := liveTaskAndCode(t)
	s := newServer(false)
	if res, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: code})); err != nil || res.IsError {
		t.Fatalf("pair failed: err=%v res=%v", err, res)
	}

	task.Stop("revoked")

	deadline := time.Now().Add(3 * time.Second)
	for {
		res, _ := s.handleStatus(context.Background(), callToolRequest(t, struct{}{}))
		var status struct {
			Paired bool `json:"paired"`
		}
		_ = json.Unmarshal([]byte(resultText(t, res)), &status)
		if !status.Paired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("adapter never auto-unpaired after its task died")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A fresh pairing code from a NEW task must now work on this same
	// still-running adapter — the whole point of clearing state
	// automatically instead of requiring an explicit disconnect first.
	_, code2 := liveTaskAndCode(t)
	res, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: code2}))
	if err != nil {
		t.Fatalf("handlePair (second code): %v", err)
	}
	if res.IsError {
		t.Fatalf("re-pairing after auto-unpair must succeed: %s", resultText(t, res))
	}
}

// TestConcurrentPairingTransitionsKeepToolStateConsistent guards a
// logical (not data-race-detectable — verified by hand, not by this
// test flipping red pre-fix under natural scheduling: the window is a
// handful of pointer writes wide and this harness never managed to
// hit it even at 1000 iterations) ordering bug: commitPaired used to
// spawn its auto-unpair watcher goroutine BEFORE calling AddTool for
// exec/disconnect, so a connection that died the instant it was
// committed could have its watcher call RemoveTools before the
// AddTool calls for a DIFFERENT, newer connection ran, or vice versa —
// leaving the tool set out of sync with "paired" state either way.
// transitionMu now serializes commitPaired and clearIfCurrent as one
// atomic transition. This exercises the realistic user-facing version
// of the scenario (revoke, then immediately re-pair) many times and
// asserts the invariant it must never violate: whenever pairing
// reports success, exec is actually callable.
func TestConcurrentPairingTransitionsKeepToolStateConsistent(t *testing.T) {
	s := newServer(false)
	const iterations = 100
	for i := 0; i < iterations; i++ {
		taskA, codeA := liveTaskAndCode(t)
		res, err := s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: codeA}))
		if err != nil || res.IsError {
			t.Fatalf("iteration %d: pair A: err=%v res=%v", i, err, res)
		}

		taskB, codeB := liveTaskAndCode(t)
		go taskA.Stop("revoked")

		// Wait for the auto-unpair via `status`, not by retrying
		// handlePair(codeB) itself: codeB's pair server is one-shot,
		// so a retry loop that calls handlePair repeatedly would burn
		// it on the first attempt that reaches past tryClaimPairing —
		// permanently dooming every later retry if that one attempt
		// hit any transient failure (slow CI, a busy runner). Poll the
		// cheap, non-consuming status check instead, then pair exactly
		// once.
		deadline := time.Now().Add(10 * time.Second)
		for {
			statusRes, _ := s.handleStatus(context.Background(), callToolRequest(t, struct{}{}))
			var status struct {
				Paired bool `json:"paired"`
			}
			_ = json.Unmarshal([]byte(resultText(t, statusRes)), &status)
			if !status.Paired {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("iteration %d: A never auto-unpaired within 10s", i)
			}
			time.Sleep(5 * time.Millisecond)
		}

		res, err = s.handlePair(context.Background(), callToolRequest(t, pairArgs{Code: codeB}))
		if err != nil || res.IsError {
			t.Fatalf("iteration %d: pair B after A's auto-unpair: err=%v res=%v", i, err, res)
		}

		// Tool-state consistency: pairing B just reported success, so
		// exec must actually be registered and usable — never left
		// desynced from a race between A's auto-clear and B's commit.
		execRes, eerr := s.handleExec(context.Background(), callToolRequest(t, execArgs{Command: "echo b"}))
		if eerr != nil {
			t.Fatalf("iteration %d: handleExec: %v", i, eerr)
		}
		if execRes.IsError {
			t.Fatalf("iteration %d: exec must work right after a successful pair, got: %s", i, resultText(t, execRes))
		}

		if _, derr := s.handleDisconnect(context.Background(), callToolRequest(t, struct{}{})); derr != nil {
			t.Fatalf("iteration %d: cleanup disconnect: %v", i, derr)
		}
		// Stop B's underlying task too, not just this adapter's SSH
		// connection to it: disconnect only ends the adapter side —
		// task B's own local-transport listener and hour-long TTL
		// timer would otherwise keep accumulating across all
		// `iterations` runs (t.Cleanup only unwinds them at the very
		// end of the test), piling up hundreds of live goroutines and
		// listening sockets and starving this same test's own
		// goroutines on a resource-constrained CI runner.
		taskB.Stop("shutdown")
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
