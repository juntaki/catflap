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
