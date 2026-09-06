package pair

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/transport/local"
)

var errNotOK = errors.New("pair server rejected the accept")

// testOffer mirrors the old testCap() fixture, adapted to the SSH
// offer's own required fields.
func testOffer() SSHOffer {
	return SSHOffer{
		Version: 1, TaskID: "agt_test", Name: "calm-panda",
		Transport: "local", Endpoint: "127.0.0.1:1",
		HostKey:   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogus test@catflap\n",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
}

func serveOffer(t *testing.T, offer SSHOffer, ttl time.Duration, stillLive func() bool) (*SSHOfferServer, *string) {
	t.Helper()
	var got string
	srv, err := ServeSSHOffer("local", offer, ttl, false, stillLive, func(pub string) error {
		got = pub
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv, &got
}

const testClientKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClientBogus test-client@catflap\n"

// fetchAccept plays the client side directly (rather than through
// FetchSSHOffer, which mints a real key) so these lifecycle tests can
// focus purely on the one-shot/claim/TTL contract without also paying
// for key generation each time.
func fetchAccept(t *testing.T, addr string) error {
	t.Helper()
	conn, err := local.Dialer(addr).Dial(context.Background())
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := readFrame(conn, sshExchangeMaxBytes, sshExchangeTimeout); err != nil {
		return err
	}
	accept := SSHOfferAccept{PublicKey: testClientKeyLine}
	raw, merr := json.Marshal(accept)
	if merr != nil {
		return merr
	}
	if err := writeFrame(conn, raw, sshExchangeTimeout); err != nil {
		return err
	}
	ok, aerr := readAckStatus(conn, sshExchangeTimeout)
	_ = conn.SetWriteDeadline(time.Now().Add(sshExchangeTimeout))
	_, _ = conn.Write([]byte{0}) // final ack, matching FetchSSHOffer's own real client behavior
	if aerr != nil {
		return aerr
	}
	if !ok {
		return errNotOK
	}
	return nil
}

// TestServeSSHOfferDeliversOnce covers the core one-shot contract: the
// first accept gets the server's onAccept call with the exact key the
// client sent.
func TestServeSSHOfferDeliversOnce(t *testing.T) {
	srv, got := serveOffer(t, testOffer(), time.Minute, nil)
	if err := fetchAccept(t, srv.Addr()); err != nil {
		t.Fatalf("fetchAccept: %v", err)
	}
	if *got != testClientKeyLine {
		t.Errorf("onAccept got %q, want %q", *got, testClientKeyLine)
	}
}

// TestServeSSHOfferSecondFetchGetsNothing covers "replays get
// nothing": the pair server destroys itself after its first claim.
func TestServeSSHOfferSecondFetchGetsNothing(t *testing.T) {
	srv, _ := serveOffer(t, testOffer(), time.Minute, nil)
	addr := srv.Addr()
	if err := fetchAccept(t, addr); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	if err := fetchAccept(t, addr); err == nil {
		t.Error("second accept against an already-claimed pair server must fail")
	}
}

// TestServeSSHOfferConcurrentFetchesExactlyOneWinner covers the
// atomic-claim property under real concurrency.
func TestServeSSHOfferConcurrentFetchesExactlyOneWinner(t *testing.T) {
	srv, _ := serveOffer(t, testOffer(), time.Minute, nil)
	addr := srv.Addr()

	const n = 8
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { results <- fetchAccept(t, addr) }()
	}
	wins := 0
	for i := 0; i < n; i++ {
		if err := <-results; err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("concurrent accept: %d winners, want exactly 1", wins)
	}
}

// TestServeSSHOfferClosesAfterTTL covers "short-lived": nobody ever
// connects, but the pair server must stop accepting once its TTL
// elapses.
func TestServeSSHOfferClosesAfterTTL(t *testing.T) {
	srv, _ := serveOffer(t, testOffer(), 100*time.Millisecond, nil)
	addr := srv.Addr()
	time.Sleep(300 * time.Millisecond)
	if err := fetchAccept(t, addr); err == nil {
		t.Error("accept must fail once the pair server's TTL has elapsed")
	}
}

// TestServeSSHOfferChecksStillLiveAtDeliveryTime mirrors the legacy
// capability pair server's stillLive re-check: a task that died
// between issuance and delivery must get nothing, but the claim is
// still burned (no replay).
func TestServeSSHOfferChecksStillLiveAtDeliveryTime(t *testing.T) {
	live := false
	onAcceptCalled := false
	srv, err := ServeSSHOffer("local", testOffer(), time.Minute, false, func() bool { return live }, func(string) error {
		onAcceptCalled = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	addr := srv.Addr()

	if err := fetchAccept(t, addr); err == nil {
		t.Error("accept must fail when stillLive reports the task is no longer live")
	}
	if onAcceptCalled {
		t.Error("onAccept must never be called when stillLive is false")
	}
	if err := fetchAccept(t, addr); err == nil {
		t.Error("a dead-on-arrival delivery must still burn the one-shot claim")
	}
}

// TestServeSSHOfferRejectsTTLAboveMaxCodeTTL covers the hard ceiling
// that stands between a long-lived task and a pairing code that stays
// claimable for just as long.
func TestServeSSHOfferRejectsTTLAboveMaxCodeTTL(t *testing.T) {
	if _, err := ServeSSHOffer("local", testOffer(), MaxCodeTTL+time.Second, false, nil, func(string) error { return nil }); err == nil {
		t.Error("ServeSSHOffer must reject a ttl above MaxCodeTTL")
	}
	srv, err := ServeSSHOffer("local", testOffer(), MaxCodeTTL, false, nil, func(string) error { return nil })
	if err != nil {
		t.Errorf("ServeSSHOffer must accept a ttl exactly at MaxCodeTTL, got %v", err)
	} else {
		srv.Close()
	}
}

// TestServeSSHOfferRejectsNonPositiveTTL covers a construction-time
// guard: ttl<=0 must fail loudly, not silently start an
// already-expired pair server.
func TestServeSSHOfferRejectsNonPositiveTTL(t *testing.T) {
	if _, err := ServeSSHOffer("local", testOffer(), 0, false, nil, func(string) error { return nil }); err == nil {
		t.Error("ServeSSHOffer with ttl=0 must fail")
	}
	if _, err := ServeSSHOffer("local", testOffer(), -time.Second, false, nil, func(string) error { return nil }); err == nil {
		t.Error("ServeSSHOffer with a negative ttl must fail")
	}
}

// TestFetchSSHOfferRejectsMissingFields covers the FetchSSHOffer-side
// strict validation of a delivered offer — a malformed offer (missing
// task id, endpoint, host key, or expiry) must be rejected instead of
// handed to the caller to dial blindly.
func TestFetchSSHOfferRejectsMissingFields(t *testing.T) {
	base := testOffer()
	cases := []struct {
		name   string
		mutate func(*SSHOffer)
	}{
		{"version", func(o *SSHOffer) { o.Version = 2 }},
		{"task", func(o *SSHOffer) { o.TaskID = "" }},
		{"endpoint", func(o *SSHOffer) { o.Endpoint = "" }},
		{"hostkey", func(o *SSHOffer) { o.HostKey = "" }},
		{"expiry", func(o *SSHOffer) { o.ExpiresAt = time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			offer := base
			tc.mutate(&offer)
			srv, err := ServeSSHOffer("local", offer, time.Minute, false, nil, func(string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			if _, _, ferr := FetchSSHOffer(context.Background(), "local", srv.Addr(), false); ferr == nil {
				t.Errorf("FetchSSHOffer must reject an offer with a broken %s field", tc.name)
			}
		})
	}
}
