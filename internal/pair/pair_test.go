package pair

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCodeRoundTrip(t *testing.T) {
	id, key, code, err := Mint()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, CodePrefix) {
		t.Errorf("code missing prefix: %s", code)
	}
	id2, key2, err := ParseCode(strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	if err != nil {
		t.Fatalf("code with spaces/lowercase must parse: %v", err)
	}
	if id2 != id || string(key2) != string(key) {
		t.Error("code round trip mismatch")
	}
	for _, bad := range []string{"", "agc1_xxx", "CAT-!!!!", "CAT-ABCD", "DOG-" + code[4:]} {
		if _, _, err := ParseCode(bad); err == nil {
			t.Errorf("bad code accepted: %q", bad)
		}
	}
}

func TestCodeChecksumCatchesTypo(t *testing.T) {
	_, _, code, err := Mint()
	if err != nil {
		t.Fatal(err)
	}
	// Mutate one payload character (keep prefix): must fail locally,
	// before any fetch could burn the real envelope.
	compact := strings.ReplaceAll(strings.TrimPrefix(code, CodePrefix), "-", "")
	chars := []byte(compact)
	if chars[5] == 'A' {
		chars[5] = 'B'
	} else {
		chars[5] = 'A'
	}
	mutated := CodePrefix + string(chars)
	if _, _, err := ParseCode(mutated); err == nil {
		t.Error("single-char typo must fail the checksum")
	}
	if _, _, err := ParseCode(code); err != nil {
		t.Errorf("valid code rejected: %v", err)
	}
}

func TestCRC16Vector(t *testing.T) {
	if got := crc16CCITT([]byte("123456789")); got != 0x29B1 {
		t.Errorf("crc16 = %#x, want 0x29b1", got)
	}
}

func TestSealOpen(t *testing.T) {
	id, key, _, err := Mint()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(id, []byte(`{"task":"agt_1"}`), key)
	if err != nil {
		t.Fatal(err)
	}
	env.ExpiresAt = time.Now().Add(time.Minute)
	pt, err := Open(env, key)
	if err != nil || string(pt) != `{"task":"agt_1"}` {
		t.Errorf("open failed: %v %q", err, pt)
	}
	if _, err := Open(env, []byte("0123456789abcdef")); err == nil {
		t.Error("wrong key must fail")
	}
	env2 := *env
	ct := env2.Ciphertext
	if len(ct) > 4 {
		env2.Ciphertext = ct[:len(ct)-4] + "AAAA"
	}
	if _, err := Open(&env2, key); err == nil {
		t.Error("tampered envelope must fail")
	}
	env3 := *env
	env3.ID = "deadbeefcafe"
	if _, err := Open(&env3, key); err == nil {
		t.Error("rebound envelope must fail")
	}
}

func testServer() *httptest.Server {
	return httptest.NewServer(NewServer(100, 1000, 1000).Handler())
}

func TestPublishFetchBurn(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	ctx := context.Background()
	id, key, _, err := Mint()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(id, []byte("secret-payload"), key)
	if err != nil {
		t.Fatal(err)
	}
	if perr := Publish(ctx, srv.URL, env, time.Minute); perr != nil {
		t.Fatalf("publish: %v", perr)
	}
	got, err := Fetch(ctx, srv.URL, id)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	pt, err := Open(got, key)
	if err != nil || string(pt) != "secret-payload" {
		t.Errorf("open fetched: %v %q", err, pt)
	}
	if _, err := Fetch(ctx, srv.URL, id); err == nil {
		t.Error("second fetch must fail (burned)")
	}
}

// TestConcurrentFetchExactlyOnce proves, under -race, the one-time-fetch
// claim in the package doc comment: many goroutines racing to fetch the
// same id must see exactly one success, everyone else 404 — not two
// successes from a check-then-delete race.
func TestConcurrentFetchExactlyOnce(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	ctx := context.Background()
	id, key, _, err := Mint()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(id, []byte("only-once"), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(ctx, srv.URL, env, time.Minute); err != nil {
		t.Fatal(err)
	}

	const n = 32
	results := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ferr := Fetch(ctx, srv.URL, id)
			results <- ferr
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	for ferr := range results {
		if ferr == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("got %d successful fetches out of %d concurrent callers, want exactly 1", successes, n)
	}
}

func TestPublishConflict(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	ctx := context.Background()
	id, key, _, _ := Mint()
	env, _ := Seal(id, []byte("first"), key)
	if err := Publish(ctx, srv.URL, env, time.Minute); err != nil {
		t.Fatal(err)
	}
	// Same live id again: conflict, never silent overwrite.
	env2, _ := Seal(id, []byte("second"), key)
	if err := Publish(ctx, srv.URL, env2, time.Minute); err == nil {
		t.Fatal("duplicate live id must conflict")
	} else if !strings.Contains(err.Error(), "409") {
		t.Errorf("expected 409, got %v", err)
	}
	// The original envelope is intact.
	got, err := Fetch(ctx, srv.URL, id)
	if err != nil {
		t.Fatal(err)
	}
	pt, _ := Open(got, key)
	if string(pt) != "first" {
		t.Errorf("original envelope replaced: %q", pt)
	}
}

func TestFetchMissingAndExpired(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	ctx := context.Background()
	if _, err := Fetch(ctx, srv.URL, "deadbeefcafe"); !errors.Is(err, ErrPairingNotFound) {
		t.Errorf("missing id must be ErrPairingNotFound, got %v", err)
	}
	id, key, _, _ := Mint()
	env, _ := Seal(id, []byte("x"), key)
	if err := Publish(ctx, srv.URL, env, time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := Fetch(ctx, srv.URL, id); !errors.Is(err, ErrPairingNotFound) {
		t.Errorf("expired envelope must be ErrPairingNotFound, got %v", err)
	}
}

func TestServerExpiryStampedByServer(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	ctx := context.Background()
	id, key, _, _ := Mint()
	env, _ := Seal(id, []byte("x"), key)
	env.ExpiresAt = time.Now().Add(100 * time.Hour)
	before := time.Now()
	if err := Publish(ctx, srv.URL, env, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := Fetch(ctx, srv.URL, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExpiresAt.Sub(before) > 2*time.Minute {
		t.Errorf("server must stamp its own expiry, got %s", got.ExpiresAt.Sub(before))
	}
}

func TestRateLimit(t *testing.T) {
	srv := httptest.NewServer(NewServer(100, 2, 1000).Handler())
	defer srv.Close()
	ctx := context.Background()
	publish := func() error {
		id, key, _, _ := Mint()
		env, _ := Seal(id, []byte("x"), key)
		return Publish(ctx, srv.URL, env, time.Minute)
	}
	if err := publish(); err != nil {
		t.Fatal(err)
	}
	if err := publish(); err != nil {
		t.Fatal(err)
	}
	if err := publish(); err == nil {
		t.Error("third publish in a 2/min budget must 429")
	} else if !strings.Contains(err.Error(), "429") {
		t.Errorf("expected 429, got %v", err)
	}
}

// TestFetchRateLimitedDistinctFromNotFound covers the P2 fix: a 429 means
// "the envelope was NOT burned, retry later", which a caller must not
// confuse with 404's "this code is dead" — collapsing every non-200 into
// one message told the pairing UX to give up on a code it should retry.
func TestFetchRateLimitedDistinctFromNotFound(t *testing.T) {
	srv := httptest.NewServer(NewServer(100, 1000, 1).Handler())
	defer srv.Close()
	ctx := context.Background()
	if _, err := Fetch(ctx, srv.URL, "deadbeefcafe"); !errors.Is(err, ErrPairingNotFound) {
		t.Fatalf("first fetch (within budget) must be ErrPairingNotFound, got %v", err)
	}
	if _, err := Fetch(ctx, srv.URL, "deadbeefcafe"); !errors.Is(err, ErrRendezvousRateLimited) {
		t.Errorf("second fetch (over budget) must be ErrRendezvousRateLimited, got %v", err)
	}
}

func TestTrustedProxy(t *testing.T) {
	ps := NewServer(100, 1, 1000)
	if err := ps.SetTrustedProxies([]string{"127.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	if err := ps.SetTrustedProxies([]string{"bogus"}); err == nil {
		t.Error("bad CIDR must fail")
	}
	srv := httptest.NewServer(ps.Handler())
	defer srv.Close()
	publishAs := func(xff string) int {
		id, key, _, _ := Mint()
		env, _ := Seal(id, []byte("x"), key)
		env.ExpiresAt = time.Now().Add(time.Minute)
		body, _ := EncodeEnvelope(env)
		req, _ := http.NewRequestWithContext(context.Background(), "POST",
			srv.URL+"/v1/envelopes?ttl_seconds=60", strings.NewReader(string(body)))
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		return res.StatusCode
	}
	if code := publishAs("10.0.0.1"); code != 200 {
		t.Fatalf("first publish as 10.0.0.1: %d", code)
	}
	if code := publishAs("10.0.0.1"); code != 429 {
		t.Errorf("second publish as 10.0.0.1 must 429, got %d", code)
	}
	if code := publishAs("10.0.0.2"); code != 200 {
		t.Errorf("distinct XFF identity must have own budget, got %d", code)
	}
}

// TestTrustedProxySpoofedPrependRejected covers the P1 fix: a proxy
// appends the address it observed, it never overwrites what's already in
// X-Forwarded-For, so a client behind a trusted proxy can prepend an
// arbitrary fake entry to the LEFT of whatever the proxy appends. Taking
// the leftmost entry (the old behavior) trusted exactly what the client
// wrote; the real client address is the rightmost entry that is not
// itself one of the trusted proxies.
func TestTrustedProxySpoofedPrependRejected(t *testing.T) {
	ps := NewServer(100, 1, 1000)
	if err := ps.SetTrustedProxies([]string{"127.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(ps.Handler())
	defer srv.Close()
	publishAs := func(xff string) int {
		id, key, _, _ := Mint()
		env, _ := Seal(id, []byte("x"), key)
		env.ExpiresAt = time.Now().Add(time.Minute)
		body, _ := EncodeEnvelope(env)
		req, _ := http.NewRequestWithContext(context.Background(), "POST",
			srv.URL+"/v1/envelopes?ttl_seconds=60", strings.NewReader(string(body)))
		req.Header.Set("X-Forwarded-For", xff)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		return res.StatusCode
	}
	// The trusted proxy appended the real client (10.0.0.9); the client
	// prepended a fake first hop that changes on every request.
	if code := publishAs("1.1.1.1, 10.0.0.9"); code != 200 {
		t.Fatalf("first publish: %d", code)
	}
	if code := publishAs("2.2.2.2, 10.0.0.9"); code != 429 {
		t.Errorf("changing the spoofable prefix must not evade the real client's budget, got %d", code)
	}
	// A genuinely different real client (as seen by the trusted proxy)
	// still gets its own budget.
	if code := publishAs("1.1.1.1, 10.0.0.10"); code != 200 {
		t.Errorf("distinct real client (rightmost hop) must have its own budget, got %d", code)
	}
}

func TestUntrustedProxyIgnoresXFF(t *testing.T) {
	ps := NewServer(100, 1, 1000) // no trusted proxies
	srv := httptest.NewServer(ps.Handler())
	defer srv.Close()
	publishAs := func(xff string) int {
		id, key, _, _ := Mint()
		env, _ := Seal(id, []byte("x"), key)
		env.ExpiresAt = time.Now().Add(time.Minute)
		body, _ := EncodeEnvelope(env)
		req, _ := http.NewRequestWithContext(context.Background(), "POST",
			srv.URL+"/v1/envelopes?ttl_seconds=60", strings.NewReader(string(body)))
		req.Header.Set("X-Forwarded-For", xff)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		return res.StatusCode
	}
	if code := publishAs("10.9.9.9"); code != 200 {
		t.Fatalf("first publish: %d", code)
	}
	// Spoofed XFF must not mint a fresh budget: still the loopback peer.
	if code := publishAs("10.9.9.10"); code != 429 {
		t.Errorf("untrusted XFF must not bypass rate limit, got %d", code)
	}
}

func TestOversizeRejected(t *testing.T) {
	env := &Envelope{V: 1, ID: "abc", Nonce: "x", Ciphertext: strings.Repeat("A", MaxEnvelopeBytes)}
	if _, err := EncodeEnvelope(env); err == nil {
		t.Error("oversize envelope must be rejected client-side")
	}
}

func TestBadIDPath(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	req, err := http.NewRequestWithContext(context.Background(), "GET", srv.URL+"/v1/envelopes/ZZZ!!!", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("bad id must 404, got %d", res.StatusCode)
	}
}
