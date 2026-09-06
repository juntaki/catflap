package pair

import (
	"context"
	"testing"
	"time"
)

// TestServeOverRealTailcat is a smoke test for the "tailcat" transport
// path specifically — it needs a real DERP round trip, so it's slower
// and network-dependent; skipped with -short.
func TestServeOverRealTailcat(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a real Tailcat/DERP round trip")
	}
	cap := testCap()
	srv, err := Serve("tailcat", cap, time.Minute, true, nil)
	if err != nil {
		t.Fatalf("Serve(tailcat): %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := Fetch(ctx, "tailcat", srv.Addr(), true)
	if err != nil {
		t.Fatalf("Fetch(tailcat): %v", err)
	}
	if got.TaskID != cap.TaskID {
		t.Errorf("got TaskID %q, want %q", got.TaskID, cap.TaskID)
	}
}
