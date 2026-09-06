package sshhost_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

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

// dialTask starts a task, wires it to a local transport server, pairs
// a client key directly (bypassing internal/pair — that exchange is
// covered separately), and returns a connected *gossh.Client plus a
// cleanup func.
func dialTask(t *testing.T, ttl time.Duration) (*sshhost.Task, *gossh.Client, func()) {
	t.Helper()
	task, err := sshhost.NewTask(context.Background(), sshhost.NewID(), ttl, nil)
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	srv, err := local.Serve(task.Handler())
	if err != nil {
		t.Fatalf("local.Serve: %v", err)
	}
	task.OnStopFunc(func() { _ = srv.Close() })

	clientKey := mustGenEd25519(t)
	signer, err := gossh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("wrap client key: %v", err)
	}
	task.SetAllowedKey(signer.PublicKey())

	conn, err := local.Dialer(srv.Addr()).Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	config := &gossh.ClientConfig{
		User:            "catflap",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // reason: host key pinning is covered by the pairing exchange test, not this lifecycle test.
		Timeout:         5 * time.Second,
	}
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, srv.Addr(), config)
	if err != nil {
		t.Fatalf("ssh handshake: %v", err)
	}
	client := gossh.NewClient(sshConn, chans, reqs)
	return task, client, func() { _ = client.Close(); task.Stop("shutdown") }
}

// TestRevokeKillsInFlightExec proves Stop cancels a currently-running
// remote command, not just future connection attempts — the same
// "access dies with the task, including anything it started" guarantee
// gateway.Task provides for the legacy RPC path.
func TestRevokeKillsInFlightExec(t *testing.T) {
	task, client, cleanup := dialTask(t, time.Hour)
	defer cleanup()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	done := make(chan error, 1)
	go func() { done <- sess.Run("sleep 30") }()

	// Give the process a moment to actually start before revoking.
	time.Sleep(200 * time.Millisecond)
	task.Stop("revoked")

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the in-flight sleep to be killed by revoke, got a clean exit")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight command was not killed within 5s of revoke")
	}
}

// TestRevokeClosesIdleSession proves Stop disconnects a client sitting
// in a session with nothing currently running (e.g. between commands,
// or an idle interactive shell) — cancelling the task context alone
// doesn't touch an already-established net.Conn.
func TestRevokeClosesIdleSession(t *testing.T) {
	task, client, cleanup := dialTask(t, time.Hour)
	defer cleanup()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// Run something trivial first so the session handshake fully
	// completes, then revoke while the connection is otherwise idle.
	if err := sess.Run("true"); err != nil {
		t.Fatalf("warm-up command: %v", err)
	}

	task.Stop("revoked")

	// A new session request on the same (now-severed) connection must
	// fail — the underlying gliderssh.Server.Close tore the connection
	// down, it's not just refusing new top-level dials.
	if _, err := client.NewSession(); err == nil {
		t.Fatal("expected the connection to be closed by revoke")
	}
}

// TestTaskDoubleStopIsSafe proves Stop is idempotent — TTL expiry and
// an explicit revoke racing each other must not panic or double-close.
func TestTaskDoubleStopIsSafe(t *testing.T) {
	task, err := sshhost.NewTask(context.Background(), sshhost.NewID(), time.Hour, nil)
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	task.OnStopFunc(func() {})
	task.Stop("revoked")
	task.Stop("expired")
	select {
	case <-task.Done():
	default:
		t.Fatal("task should be done after Stop")
	}
}
