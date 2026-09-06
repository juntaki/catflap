package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/sshhost"
	"github.com/juntaki/catflap/internal/transport/local"
)

// extractCode pulls the pairing code out of runSSHShare's printed
// output (the line reading "  CAT-...").
func extractCode(t *testing.T, printed string) string {
	t.Helper()
	i := strings.Index(printed, "CAT-")
	if i < 0 {
		t.Fatalf("no pairing code found in:\n%s", printed)
	}
	rest := printed[i:]
	end := strings.IndexAny(rest, "\n ")
	if end < 0 {
		end = len(rest)
	}
	return strings.TrimSpace(rest[:end])
}

// TestSSHShareEndToEnd drives runSSHShare exactly as Share does,
// then plays the client side (decode -> fetch offer -> SSH handshake
// -> exec) the way an agent adapter will — proving the CLI wiring
// (not just the packages in isolation) produces a working pairing
// code and a working, exact-match-authenticated SSH endpoint.
func TestSSHShareEndToEnd(t *testing.T) {
	task, err := sshhost.NewTask(context.Background(), sshhost.NewID(), time.Hour, nil)
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	defer task.Stop("shutdown")

	srv, err := local.Serve(task.Handler())
	if err != nil {
		t.Fatalf("local.Serve: %v", err)
	}
	task.OnStopFunc(func() { _ = srv.Close() })

	var out bytes.Buffer
	if serr := runSSHShare(context.Background(), task, srv.Addr(), 30*time.Second, "local", false, &out); serr != nil {
		t.Fatalf("runSSHShare: %v", serr)
	}

	printed := out.String()
	code := extractCode(t, printed)

	transportName, addr, err := pair.Decode(code)
	if err != nil {
		t.Fatalf("decode printed code: %v", err)
	}
	offer, clientKey, err := pair.FetchSSHOffer(context.Background(), transportName, addr, false)
	if err != nil {
		t.Fatalf("FetchSSHOffer: %v", err)
	}
	if offer.TaskID != task.ID {
		t.Fatalf("offer task id = %q, want %q", offer.TaskID, task.ID)
	}

	signer, err := gossh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("wrap client key: %v", err)
	}
	config := &gossh.ClientConfig{
		User:            "catflap",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // reason: host key pinning is exercised by internal/pair's own offer test; this test is about the CLI wiring end to end.
		Timeout:         5 * time.Second,
	}
	conn, err := local.Dialer(offer.Endpoint).Dial(context.Background())
	if err != nil {
		t.Fatalf("dial task endpoint: %v", err)
	}
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, offer.Endpoint, config)
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

	got, err := sess.Output("echo hello")
	if err != nil {
		t.Fatalf("run echo hello: %v", err)
	}
	if string(got) != "hello\n" {
		t.Fatalf("output = %q, want %q", got, "hello\n")
	}
}

// TestShareExitsOnTTLExpiry is the P1 regression: Share's own tail
// used to be a bare `<-ctx.Done()`, which only reacts to a
// SIGINT/SIGTERM — a task expiring on its own TTL timer called
// task.Stop("expired") internally (killing the SSH server and any
// in-flight command) but left the `catflap share` PROCESS itself
// running forever, waiting on a signal nothing was ever going to send.
// An operator's `share` was never going to exit on its own once the
// access it printed a code for was already gone.
func TestShareExitsOnTTLExpiry(t *testing.T) {
	done := make(chan int, 1)
	go func() {
		done <- Share([]string{
			"--transport", "local",
			"--ttl", "150ms",
			"--pairing-ttl", "150ms",
			"--audit", t.TempDir(),
		})
	}()

	select {
	case rc := <-done:
		if rc != 0 {
			t.Errorf("Share() on TTL expiry returned %d, want 0", rc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Share() never returned after its task's TTL expired — the process would hang forever")
	}
}
