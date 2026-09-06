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
	srv, err := Serve("local", cap, time.Minute, false)
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
	srv, err := Serve("local", cap, time.Minute, false)
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
	srv, err := Serve("local", cap, time.Minute, false)
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
	srv, err := Serve("local", cap, 100*time.Millisecond, false)
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

// TestServeRejectsNonPositiveTTL covers a construction-time guard: a
// caller forgetting to clamp TTL to something positive must fail
// loudly, not silently start a pair server that's already "expired".
func TestServeRejectsNonPositiveTTL(t *testing.T) {
	if _, err := Serve("local", testCap(), 0, false); err == nil {
		t.Error("Serve with ttl=0 must fail")
	}
	if _, err := Serve("local", testCap(), -time.Second, false); err == nil {
		t.Error("Serve with a negative ttl must fail")
	}
}
