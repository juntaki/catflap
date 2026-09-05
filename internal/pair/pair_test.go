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
	// Wrong key fails.
	if _, err := Open(env, []byte("0123456789abcdef")); err == nil {
		t.Error("wrong key must fail")
	}
	// Tampered ciphertext fails.
	env2 := *env
	ct := env2.Ciphertext
	if len(ct) > 4 {
		env2.Ciphertext = ct[:len(ct)-4] + "AAAA"
	}
	if _, err := Open(&env2, key); err == nil {
		t.Error("tampered envelope must fail")
	}
	// Wrong id (rebind attack) fails: AAD covers the id.
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
	// Single-use: second fetch burns.
	if _, err := Fetch(ctx, srv.URL, id); err == nil {
		t.Error("second fetch must fail (burned)")
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
	// Client claims a far-future expiry; server must clamp to its own TTL.
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

func TestOversizeRejected(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	env := &Envelope{V: 1, ID: "abc", Nonce: "x", Ciphertext: strings.Repeat("A", MaxEnvelopeBytes)}
	if _, err := EncodeEnvelope(env); err == nil {
		t.Error("oversize envelope must be rejected client-side")
	}
}

func TestBadMethodAndPath(t *testing.T) {
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
