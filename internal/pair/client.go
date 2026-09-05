package pair

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// clientTimeout bounds rendezvous round trips. Pairing must fail fast:
// hanging on a helper service is worse than a clear error.
const clientTimeout = 15 * time.Second

// Publish stores env (sealed) for ttl and returns the server record.
// The server never sees plaintext — only id + ciphertext + expiry.
func Publish(ctx context.Context, rendezvousURL string, env *Envelope, ttl time.Duration) error {
	if ttl <= 0 || ttl > MaxEnvelopeTTL {
		return fmt.Errorf("ttl must be within (0, %s]", MaxEnvelopeTTL)
	}
	if env.ExpiresAt.IsZero() {
		env.ExpiresAt = time.Now().Add(ttl)
	}
	body, err := EncodeEnvelope(env)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST",
		strings.TrimSuffix(rendezvousURL, "/")+fmt.Sprintf("/v1/envelopes?ttl_seconds=%d", int(ttl.Seconds())),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("rendezvous publish: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode != 200 {
		return fmt.Errorf("rendezvous publish failed (%d): %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	// A 200 status alone isn't proof the envelope was actually stored: a
	// misbehaving or malicious rendezvous (a custom --rendezvous URL is
	// operator-configurable, not always our own pair.Server) could answer
	// 200 with an empty or wrong-id body while never persisting anything.
	// share's failure-cleanup invariant — a publish that didn't really
	// happen must tear the task down, never print a code for an envelope
	// nobody can fetch — depends on this being a real error, not a
	// silent false-success.
	var ack PublishResponse
	if jerr := json.Unmarshal(raw, &ack); jerr != nil {
		return fmt.Errorf("rendezvous publish: malformed acknowledgement: %w", jerr)
	}
	if ack.ID != env.ID {
		return fmt.Errorf("rendezvous publish: acknowledgement id %q does not match %q", ack.ID, env.ID)
	}
	return nil
}

// ErrPairingNotFound means the id is missing, expired, or already
// consumed — terminal: retrying with the same code cannot succeed.
var ErrPairingNotFound = errors.New("pairing not found or expired (code used, wrong, or too old)")

// ErrRendezvousRateLimited means the rendezvous is rate-limiting this
// client — the envelope was NOT burned; retrying later can still succeed.
var ErrRendezvousRateLimited = errors.New("rendezvous rate limited, retry later")

// ErrRendezvousUnavailable means the rendezvous itself is unreachable or
// erroring (network failure, 5xx) — not a verdict on the code; retrying
// later can still succeed.
var ErrRendezvousUnavailable = errors.New("rendezvous unavailable, retry later")

// Fetch retrieves and burns the envelope for id. A second fetch for the
// same id fails: envelopes are single-use. The returned error is one of
// the sentinels above (via errors.Is) so a caller — the eventual `mcp
// pair` tool included — can tell "this code is dead" apart from
// "rendezvous hiccup, try again", instead of every non-200 collapsing
// into one "not found or expired" message that is simply wrong for a 429
// or a 503.
func Fetch(ctx context.Context, rendezvousURL, id string) (*Envelope, error) {
	if id == "" || strings.ContainsAny(id, "/?#") {
		return nil, fmt.Errorf("bad envelope id")
	}
	ctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET",
		strings.TrimSuffix(rendezvousURL, "/")+"/v1/envelopes/"+id, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRendezvousUnavailable, err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, MaxEnvelopeBytes+1024))
	switch {
	case res.StatusCode == http.StatusOK:
		// fall through
	case res.StatusCode == http.StatusNotFound:
		return nil, ErrPairingNotFound
	case res.StatusCode == http.StatusTooManyRequests:
		return nil, ErrRendezvousRateLimited
	case res.StatusCode >= 500:
		return nil, fmt.Errorf("%w (%d): %s", ErrRendezvousUnavailable, res.StatusCode, strings.TrimSpace(string(raw)))
	default:
		return nil, fmt.Errorf("rendezvous fetch failed (%d): %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	env, err := DecodeEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if env.ID != id {
		return nil, fmt.Errorf("rendezvous returned the wrong envelope")
	}
	return env, nil
}

// PublishResponse is the server's acknowledgement.
type PublishResponse struct {
	ID string `json:"id"`
}

// ErrorResponse is the server's error body.
type ErrorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	raw, merr := json.Marshal(ErrorResponse{Error: msg})
	if merr != nil {
		raw = []byte(`{"error":"internal error"}`)
	}
	_, _ = w.Write(raw)
}
