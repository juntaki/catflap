package pair

import (
	"bytes"
	"context"
	"encoding/json"
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
	return nil
}

// Fetch retrieves and burns the envelope for id. A second fetch for the
// same id fails: envelopes are single-use.
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
		return nil, fmt.Errorf("rendezvous fetch: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, MaxEnvelopeBytes+1024))
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("pairing not found or expired (code used, wrong, or too old)")
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
