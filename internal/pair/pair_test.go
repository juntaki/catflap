package pair

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if err := Publish(ctx, srv.URL, env, time.Minute); err != nil {
		t.Fatalf("publish: %v", err)
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
	if _, err := Fetch(ctx, srv.URL, "deadbeefcafe"); err == nil {
		t.Error("missing id must 404")
	}
	id, key, _, _ := Mint()
	env, _ := Seal(id, []byte("x"), key)
	if err := Publish(ctx, srv.URL, env, time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := Fetch(ctx, srv.URL, id); err == nil {
		t.Error("expired envelope must 404")
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
		req, _ := http.NewRequest("POST", srv.URL+"/v1/envelopes?ttl_seconds=60",
			strings.NewReader(string(body)))
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

func TestUntrustedProxyIgnoresXFF(t *testing.T) {
	ps := NewServer(100, 1, 1000) // no trusted proxies
	srv := httptest.NewServer(ps.Handler())
	defer srv.Close()
	publishAs := func(xff string) int {
		id, key, _, _ := Mint()
		env, _ := Seal(id, []byte("x"), key)
		env.ExpiresAt = time.Now().Add(time.Minute)
		body, _ := EncodeEnvelope(env)
		req, _ := http.NewRequest("POST", srv.URL+"/v1/envelopes?ttl_seconds=60",
			strings.NewReader(string(body)))
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
	res, err := http.Get(srv.URL + "/v1/envelopes/ZZZ!!!")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("bad id must 404, got %d", res.StatusCode)
	}
}
