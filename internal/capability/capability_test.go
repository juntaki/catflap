package capability

import (
	"strings"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	c := &Capability{
		Version: 1, TaskID: NewTaskID(),
		Transport: "local", Endpoint: "127.0.0.1:1234",
		TaskSecret: NewSecret(),
		ExpiresAt:  time.Now().Add(15 * time.Minute),
		Policy:     "readonly-debug", PolicyHash: "abc123",
	}
	s := c.Encode()
	if !strings.HasPrefix(s, Prefix) {
		t.Fatalf("missing prefix: %s", s[:10])
	}
	d, err := Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	if d.TaskID != c.TaskID || d.TaskSecret != c.TaskSecret || d.Endpoint != c.Endpoint {
		t.Error("round trip mismatch")
	}
	if d.Expired(time.Now()) {
		t.Error("should not be expired")
	}
}

// TestV1StrictValidation covers the P2 fix: Decode used to check only
// TaskID/Endpoint/TaskSecret, leaving Version/Transport/ClientPriv and
// expiry unvalidated. With pairing about to make Decode a real protocol
// boundary (encrypted envelope from an untrusted pairing code), a v1
// token with an inconsistent shape must be rejected rather than silently
// patched up like a legacy token.
func TestV1StrictValidation(t *testing.T) {
	base := Capability{
		Version: 1, TaskID: "agt_x", Endpoint: "127.0.0.1:1", TaskSecret: "s",
		ExpiresAt: time.Now().Add(time.Minute),
	}

	valid := base
	valid.Transport = "local"
	if _, err := Decode(valid.Encode()); err != nil {
		t.Errorf("valid v1 local capability must decode: %v", err)
	}

	valid.Transport = "tailcat"
	valid.ClientPriv = "priv"
	if _, err := Decode(valid.Encode()); err != nil {
		t.Errorf("valid v1 tailcat capability must decode: %v", err)
	}

	missingClientPriv := base
	missingClientPriv.Transport = "tailcat"
	if _, err := Decode(missingClientPriv.Encode()); err == nil {
		t.Error("tailcat v1 capability without client_priv must be rejected")
	}

	unknownTransport := base
	unknownTransport.Transport = "carrier-pigeon"
	if _, err := Decode(unknownTransport.Encode()); err == nil {
		t.Error("unknown transport must be rejected")
	}

	noExpiry := base
	noExpiry.Transport = "local"
	noExpiry.ExpiresAt = time.Time{}
	if _, err := Decode(noExpiry.Encode()); err == nil {
		t.Error("v1 capability without expires_at must be rejected")
	}

	badVersion := base
	badVersion.Transport = "local"
	badVersion.Version = 2
	if _, err := Decode(badVersion.Encode()); err == nil {
		t.Error("unsupported version must be rejected")
	}
}

// TestLegacyDecodeUnaffected covers backward compatibility: a v0/
// unversioned capability keeps the original, looser checks so existing
// tokens don't suddenly stop decoding.
func TestLegacyDecodeUnaffected(t *testing.T) {
	c := Capability{TaskID: "agt_x", Endpoint: "127.0.0.1:1", TaskSecret: "s"}
	d, err := Decode(c.Encode())
	if err != nil {
		t.Fatalf("legacy capability must still decode: %v", err)
	}
	if d.Transport != "tailcat" {
		t.Errorf("legacy capability must default to tailcat transport, got %q", d.Transport)
	}
}

func TestExpiredAndInvalid(t *testing.T) {
	c := &Capability{TaskID: "agt_x", Transport: "local", Endpoint: "e", TaskSecret: "s",
		ExpiresAt: time.Now().Add(-time.Second)}
	if !c.Expired(time.Now()) {
		t.Error("should be expired")
	}
	if _, err := Decode("nope"); err == nil {
		t.Error("expected error for bad prefix")
	}
	if _, err := Decode(Prefix + "!!!"); err == nil {
		t.Error("expected error for bad encoding")
	}
}
