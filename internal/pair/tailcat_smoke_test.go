package pair

import (
	"context"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// TestServeSSHOfferOverRealTailcat is a smoke test for the "tailcat"
// transport path specifically — it needs a real DERP round trip, so
// it's slower and network-dependent; skipped with -short.
func TestServeSSHOfferOverRealTailcat(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a real Tailcat/DERP round trip")
	}
	offer := testOffer()
	var got string
	srv, err := ServeSSHOffer("tailcat", offer, time.Minute, true, nil, func(pub string) error {
		got = pub
		key, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(pub))
		_ = key
		return perr
	})
	if err != nil {
		t.Fatalf("ServeSSHOffer(tailcat): %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gotOffer, _, err := FetchSSHOffer(ctx, "tailcat", srv.Addr(), true)
	if err != nil {
		t.Fatalf("FetchSSHOffer(tailcat): %v", err)
	}
	if gotOffer.TaskID != offer.TaskID {
		t.Errorf("got TaskID %q, want %q", gotOffer.TaskID, offer.TaskID)
	}
	if got == "" {
		t.Error("server never received the client's public key")
	}
}
