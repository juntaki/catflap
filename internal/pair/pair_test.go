package pair

import (
	"context"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/capability"
)

func testCap() *capability.Capability {
	return &capability.Capability{
		Version: 1, TaskID: "agt_test", Name: "calm-panda",
		Transport: "local", Endpoint: "127.0.0.1:1", TaskSecret: "s3cr3t",
		ExpiresAt: time.Now().Add(15 * time.Minute), Policy: "readonly-debug",
	}
}

func TestEncodeDecodeRoundTrips(t *testing.T) {
	for _, tc := range []struct{ transportName, addr string }{
		{"local", "127.0.0.1:54321"},
		{"tailcat", "tcomFwWC1234567890abcdef"},
	} {
		code, err := Encode(tc.transportName, tc.addr)
		if err != nil {
			t.Fatalf("Encode(%q, %q): %v", tc.transportName, tc.addr, err)
		}
		if code[:len(CodePrefix)] != CodePrefix {
			t.Errorf("code %q missing prefix %q", code, CodePrefix)
		}
		gotTransport, gotAddr, err := Decode(code)
		if err != nil {
			t.Fatalf("Decode(%q): %v", code, err)
		}
		if gotTransport != tc.transportName || gotAddr != tc.addr {
			t.Errorf("Decode(%q) = (%q, %q), want (%q, %q)", code, gotTransport, gotAddr, tc.transportName, tc.addr)
		}
	}
}

func TestDecodeToleratesFormatting(t *testing.T) {
	code, err := Encode("local", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	messy := " " + code + " "
	gotTransport, gotAddr, err := Decode(messy)
	if err != nil {
		t.Fatalf("Decode with surrounding whitespace: %v", err)
	}
	if gotTransport != "local" || gotAddr != "127.0.0.1:9" {
		t.Errorf("Decode(%q) = (%q, %q)", messy, gotTransport, gotAddr)
	}
}

func TestDecodeRejectsChecksumMismatch(t *testing.T) {
	code, err := Encode("local", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	// Flip the last character so the CRC no longer matches.
	mangled := code[:len(code)-1] + flip(code[len(code)-1])
	if _, _, err := Decode(mangled); err == nil {
		t.Error("Decode must reject a code with a mismatched checksum")
	}
}

func flip(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not a code", "CAT-", "CAT-@@@@"} {
		if _, _, err := Decode(bad); err == nil {
			t.Errorf("Decode(%q) must fail", bad)
		}
	}
}

// TestServeDeliversCapabilityOnce covers the core one-shot contract:
// the first Fetch gets the exact capability handed to Serve.
func TestServeDeliversCapabilityOnce(t *testing.T) {
	cap := testCap()
	srv, err := Serve("local", cap, time.Minute, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	got, err := Fetch(context.Background(), "local", srv.Addr(), false)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.TaskID != cap.TaskID || got.TaskSecret != cap.TaskSecret {
		t.Errorf("Fetch() = %+v, want it to match the served capability", got)
	}
}

// TestServeSecondFetchGetsNothing covers "replays get nothing": once
// claimed, the pair server has already destroyed itself, so a second
// Fetch — even against the exact same address — must fail.
func TestServeSecondFetchGetsNothing(t *testing.T) {
	cap := testCap()
	srv, err := Serve("local", cap, time.Minute, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.Addr()

	if _, err := Fetch(context.Background(), "local", addr, false); err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if _, err := Fetch(context.Background(), "local", addr, false); err == nil {
		t.Error("second Fetch against an already-claimed pair server must fail")
	}
}

// TestServeConcurrentFetchesExactlyOneWinner covers the atomic-claim
// property under real concurrency, not just sequential calls.
func TestServeConcurrentFetchesExactlyOneWinner(t *testing.T) {
	cap := testCap()
	srv, err := Serve("local", cap, time.Minute, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.Addr()

	const n = 8
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, ferr := Fetch(context.Background(), "local", addr, false)
			results <- ferr
		}()
	}
	wins := 0
	for i := 0; i < n; i++ {
		if err := <-results; err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("concurrent Fetch: %d winners, want exactly 1", wins)
	}
}

// TestServeClosesAfterTTL covers "short-lived": nobody ever connects,
// but the pair server must still stop accepting once its TTL elapses.
func TestServeClosesAfterTTL(t *testing.T) {
	cap := testCap()
	srv, err := Serve("local", cap, 100*time.Millisecond, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.Addr()

	time.Sleep(300 * time.Millisecond)
	if _, err := Fetch(context.Background(), "local", addr, false); err == nil {
		t.Error("Fetch must fail once the pair server's TTL has elapsed")
	}
}

// TestServeChecksStillLiveAtDeliveryTime covers the codex-round-2 fix:
// a caller's own liveness check, taken before Serve even starts (real
// wall-clock time for tailcat's DERP handshake), can never fully close
// the window between that check and a connection actually landing — the
// task can start dying in that gap. stillLive is re-consulted right
// before the bytes are written, not just once at issuance, so a task
// that died in that window gets nothing delivered even though the
// connection still burns the one-shot claim (no replay either).
func TestServeChecksStillLiveAtDeliveryTime(t *testing.T) {
	cap := testCap()
	live := false // simulates "the task already died by delivery time"
	srv, err := Serve("local", cap, time.Minute, false, func() bool { return live })
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.Addr()

	if _, err := Fetch(context.Background(), "local", addr, false); err == nil {
		t.Error("Fetch must get nothing when stillLive reports the task is no longer live")
	}
	// The claim is still burned: no second chance, even though nothing
	// was actually delivered the first time.
	if _, err := Fetch(context.Background(), "local", addr, false); err == nil {
		t.Error("a dead-on-arrival delivery must still burn the one-shot claim")
	}
}

// TestServeRejectsTTLAboveMaxCodeTTL covers a real regression: this
// hard ceiling is what stands between a long-lived task (hours) and a
// pairing code that stays claimable for just as long. It must be
// enforced at Serve itself — the single lowest-level chokepoint every
// pairing code goes through — independent of any caller's own clamping.
func TestServeRejectsTTLAboveMaxCodeTTL(t *testing.T) {
	if _, err := Serve("local", testCap(), MaxCodeTTL+time.Second, false, nil); err == nil {
		t.Error("Serve must reject a ttl above MaxCodeTTL")
	}
	if _, err := Serve("local", testCap(), MaxCodeTTL, false, nil); err != nil {
		t.Errorf("Serve must accept a ttl exactly at MaxCodeTTL, got %v", err)
	}
}

// TestFetchRejectsUnsupportedCapabilityVersion, TestFetchRejectsMissingClientPrivForTailcat,
// and TestFetchRejectsZeroExpiry cover a real regression: Fetch used to
// only check TaskID/Endpoint/TaskSecret non-empty, not the same strict
// v1 validation (capability.Decode) the legacy --cap-file path has
// always gone through — an unsupported version, a tailcat capability
// missing its client identity, or a capability with no expiry at all
// would all have been accepted and handed straight to dialerFor/ping.
func TestFetchRejectsUnsupportedCapabilityVersion(t *testing.T) {
	cap := testCap()
	cap.Version = 2
	srv, err := Serve("local", cap, time.Minute, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, err := Fetch(context.Background(), "local", srv.Addr(), false); err == nil {
		t.Error("Fetch must reject an unsupported capability version")
	}
}

func TestFetchRejectsMissingClientPrivForTailcat(t *testing.T) {
	cap := testCap()
	cap.Transport = "tailcat" // claims tailcat but never sets ClientPriv
	srv, err := Serve("local", cap, time.Minute, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, err := Fetch(context.Background(), "local", srv.Addr(), false); err == nil {
		t.Error("Fetch must reject a tailcat capability with no client_priv")
	}
}

func TestFetchRejectsZeroExpiry(t *testing.T) {
	cap := testCap()
	cap.ExpiresAt = time.Time{}
	srv, err := Serve("local", cap, time.Minute, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, err := Fetch(context.Background(), "local", srv.Addr(), false); err == nil {
		t.Error("Fetch must reject a capability with no expires_at")
	}
}

// TestServeRejectsNonPositiveTTL covers a construction-time guard: a
// caller forgetting to clamp TTL to something positive must fail
// loudly, not silently start a pair server that's already "expired".
func TestServeRejectsNonPositiveTTL(t *testing.T) {
	if _, err := Serve("local", testCap(), 0, false, nil); err == nil {
		t.Error("Serve with ttl=0 must fail")
	}
	if _, err := Serve("local", testCap(), -time.Second, false, nil); err == nil {
		t.Error("Serve with a negative ttl must fail")
	}
}
