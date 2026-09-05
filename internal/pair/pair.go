// Package pair implements Catflap's pairing rendezvous client and crypto.
//
// A pairing code looks like CAT-XXXX-XXXX-… and carries everything the
// local agent needs to fetch ONE encrypted envelope from a rendezvous
// server — and nothing else:
//
//	code = "CAT-" + base32(48-bit random id ‖ 128-bit random wrap key)
//
// Security properties (§8):
//
//   - one-time: fetch burns the envelope; replays get 404;
//   - short-lived: envelopes carry an expiry (default 5 minutes, max 10)
//     enforced server-side;
//   - encrypted: the envelope holds the capability sealed with
//     XChaCha20-Poly1305 under SHA256("catflap-pair-v1" ‖ wrap key).
//     The server sees only id + ciphertext and cannot read plaintext;
//   - brute-force resistant: 48-bit ids behind per-IP rate limits, and an
//     id alone is useless without its 128-bit key;
//   - no derivation: the task secret travels inside the envelope as random
//     bytes; it is never derived from the code;
//   - revocation-aware: pairing a revoked/expired task fails closed at
//     connect time (the rendezvous is blind by design and cannot check).
//
// The rendezvous relays envelopes only. Task traffic itself always goes
// peer-to-peer over Tailcat afterward.
package pair

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// CodePrefix marks pairing codes.
const CodePrefix = "CAT-"

// EnvelopeVersion is the envelope schema version.
const EnvelopeVersion = 1

// MaxEnvelopeBytes caps an envelope body (capabilities are ~1KB).
const MaxEnvelopeBytes = 8192

// DefaultEnvelopeTTL bounds how long an unpublished-picked-up envelope
// lives on the server.
const DefaultEnvelopeTTL = 5 * time.Minute

// MaxEnvelopeTTL caps client-requested envelope lifetimes.
const MaxEnvelopeTTL = 10 * time.Minute

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Envelope is the rendezvous record. Ciphertext seals the capability JSON;
// the server must never see inside.
type Envelope struct {
	V          int       `json:"v"`
	ID         string    `json:"id"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Mint generates a fresh pairing id, wrap key, and printable code.
func Mint() (id string, key []byte, code string, err error) {
	var raw [22]byte // 48-bit id ‖ 128-bit key
	if _, err := rand.Read(raw[:]); err != nil {
		return "", nil, "", err
	}
	idBytes := raw[:6]
	key = append([]byte(nil), raw[6:]...)
	id = fmt.Sprintf("%x", idBytes)
	enc := b32.EncodeToString(raw[:])
	var groups []string
	for i := 0; i < len(enc); i += 4 {
		end := i + 4
		if end > len(enc) {
			end = len(enc)
		}
		groups = append(groups, enc[i:end])
	}
	return id, key, CodePrefix + strings.Join(groups, "-"), nil
}

// ParseCode splits a pairing code back into id and wrap key. Dashes,
// spaces, and letter case are ignored for transcription robustness, so
// "CAT-7KQ9-…" and "cat 7kq9 …" both parse.
func ParseCode(code string) (id string, key []byte, err error) {
	s := strings.ToUpper(strings.TrimSpace(code))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	if !strings.HasPrefix(s, "CAT") {
		return "", nil, fmt.Errorf("not a pairing code (want %q…)", CodePrefix)
	}
	raw, err := b32.DecodeString(strings.TrimPrefix(s, "CAT"))
	if err != nil || len(raw) != 22 {
		return "", nil, fmt.Errorf("malformed pairing code")
	}
	id = fmt.Sprintf("%x", raw[:6])
	return id, append([]byte(nil), raw[6:]...), nil
}

func envelopeAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("wrap key must be 16 bytes")
	}
	sum := sha256.Sum256(append([]byte("catflap-pair-v1"), key...))
	return chacha20poly1305.NewX(sum[:])
}

// Seal encrypts payload into an envelope for id.
func Seal(id string, payload, key []byte) (*Envelope, error) {
	aead, err := envelopeAEAD(key)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce[:], payload, []byte(id))
	return &Envelope{
		V:          EnvelopeVersion,
		ID:         id,
		Nonce:      base64.StdEncoding.EncodeToString(nonce[:]),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Open decrypts an envelope. Wrong keys, wrong ids, and tampered records
// all fail here — authenticated encryption, no silent downgrade.
func Open(env *Envelope, key []byte) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("nil envelope")
	}
	if env.V != EnvelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version %d", env.V)
	}
	aead, err := envelopeAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != 24 {
		return nil, fmt.Errorf("bad envelope nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("bad envelope ciphertext")
	}
	pt, err := aead.Open(nil, nonce, ct, []byte(env.ID))
	if err != nil {
		return nil, fmt.Errorf("envelope authentication failed")
	}
	return pt, nil
}

// EncodeEnvelope marshals with a size cap (server and client both enforce).
func EncodeEnvelope(env *Envelope) ([]byte, error) {
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("envelope too large (%d bytes)", len(raw))
	}
	return raw, nil
}

// DecodeEnvelope parses and size-checks an envelope body.
func DecodeEnvelope(raw []byte) (*Envelope, error) {
	if len(raw) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("envelope too large (%d bytes)", len(raw))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var env Envelope
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("bad envelope: %w", err)
	}
	if env.V != EnvelopeVersion || env.ID == "" || env.Nonce == "" || env.Ciphertext == "" {
		return nil, fmt.Errorf("bad envelope: missing fields")
	}
	if env.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("bad envelope: missing expiry")
	}
	return &env, nil
}
