package pair_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

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

// TestSSHVerticalSlice proves the Phase 1 acceptance criterion end to
// end over the local transport: share -> pairing code -> ephemeral
// client key -> embedded SSH -> `echo hello`. Tailcat itself is
// exercised separately by the transport contract suite; this test is
// about the pairing/SSH wiring, not the reachability layer.
func TestSSHVerticalSlice(t *testing.T) {
	task, err := sshhost.NewTask(context.Background(), sshhost.NewID(), time.Hour, nil)
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	defer task.Stop("shutdown")

	taskSrv, err := local.Serve(task.Handler())
	if err != nil {
		t.Fatalf("start task server: %v", err)
	}
	task.OnStopFunc(func() { _ = taskSrv.Close() })

	offer := pair.SSHOffer{
		Version: 1, TaskID: task.ID, Transport: "local",
		Endpoint: taskSrv.Addr(), HostKey: task.HostKeyAuthorizedLine(),
		ExpiresAt: task.ExpiresAt,
	}
	var gotKey string
	pairSrv, err := pair.ServeSSHOffer("local", offer, 30*time.Second, false, nil, func(pub string) error {
		gotKey = pub
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
	defer pairSrv.Close()

	code, err := pair.Encode("local", pairSrv.Addr())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// --- client side: decode the code, fetch the offer, dial the task ---
	transportName, addr, err := pair.Decode(code)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	gotOffer, clientKey, err := pair.FetchSSHOffer(context.Background(), transportName, addr, false)
	if err != nil {
		t.Fatalf("FetchSSHOffer: %v", err)
	}
	if gotOffer.TaskID != task.ID {
		t.Fatalf("offer task id = %q, want %q", gotOffer.TaskID, task.ID)
	}
	if gotKey == "" {
		t.Fatal("server never received the client's public key")
	}

	signer, err := gossh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("wrap client key: %v", err)
	}
	wantHostKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(gotOffer.HostKey))
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}
	config := &gossh.ClientConfig{
		User: "catflap",
		Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), wantHostKey.Marshal()) {
				return fmt.Errorf("host key mismatch")
			}
			return nil
		},
		Timeout: 5 * time.Second,
	}

	dialer := local.Dialer(gotOffer.Endpoint)
	conn, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial task endpoint: %v", err)
	}
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, gotOffer.Endpoint, config)
	if err != nil {
		t.Fatalf("ssh handshake: %v", err)
	}
	client := gossh.NewClient(sshConn, chans, reqs)
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	out, err := sess.Output("echo hello")
	if err != nil {
		t.Fatalf("run echo hello: %v", err)
	}
	if got := string(out); got != "hello\n" {
		t.Fatalf("output = %q, want %q", got, "hello\n")
	}
}

// TestSSHVerticalSliceWrongKeyRejected proves a client presenting any
// key other than the one pairing registered is rejected outright.
func TestSSHVerticalSliceWrongKeyRejected(t *testing.T) {
	task, err := sshhost.NewTask(context.Background(), sshhost.NewID(), time.Hour, nil)
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	defer task.Stop("shutdown")

	taskSrv, err := local.Serve(task.Handler())
	if err != nil {
		t.Fatalf("start task server: %v", err)
	}
	task.OnStopFunc(func() { _ = taskSrv.Close() })

	allowedSigner, err := gossh.NewSignerFromKey(mustGenEd25519(t))
	if err != nil {
		t.Fatal(err)
	}
	task.SetAllowedKey(allowedSigner.PublicKey())

	wrongSigner, err := gossh.NewSignerFromKey(mustGenEd25519(t))
	if err != nil {
		t.Fatal(err)
	}
	config := &gossh.ClientConfig{
		User:            "catflap",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(wrongSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // reason: test only cares that publickey auth itself is rejected.
		Timeout:         5 * time.Second,
	}
	dialer := local.Dialer(taskSrv.Addr())
	conn, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial task endpoint: %v", err)
	}
	_, _, _, err = gossh.NewClientConn(conn, taskSrv.Addr(), config)
	if err == nil {
		t.Fatal("expected auth failure for a key pairing never registered")
	}
}
