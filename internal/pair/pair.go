// Package pair implements Catflap's pairing rendezvous client and crypto.
//
// A pairing code looks like CAT-XXXX-XXXX-… and carries everything the
// local agent needs to fetch ONE encrypted envelope from a rendezvous
// server — and nothing else:
//
//	code = "CAT-" + base32(48-bit random id ‖ 128-bit random wrap key ‖ CRC-16)
//
// Security properties (§8):
//
//   - one-time: fetch burns the envelope; replays get 404;
//   - short-lived: envelopes carry an expiry (default 5 minutes, max 10)
//     enforced server-side;
//   - encrypted: the envelope holds the capability sealed with
//     XChaCha20-Poly1305 under SHA256("catflap-pair-v1" ‖ wrap key).
//     The server sees only id + ciphertext and cannot read plaintext;
//   - brute-force resistant: ids behind per-IP rate limits, and an id
//     alone is useless without its 128-bit key;
//   - typo-safe: a CRC-16 over id‖key is verified locally, so mistyped
//     codes fail before any fetch can burn the real envelope;
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

// DefaultRendezvousURL is the canonical public rendezvous both sides use
// unless overridden (flag > env > config file > default).
const DefaultRendezvousURL = "https://pair.catflap.dev"

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

// crc16CCITT detects transcription typos locally (not authenticity — that
// comes from the AEAD plus single-use fetch). Test vector "123456789".
func crc16CCITT(data []byte) uint16 {
	var crc uint16 = 0xFFFF
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// Mint generates a fresh pairing id, wrap key, and printable code.
func Mint() (id string, key []byte, code string, err error) {
	var payload [22]byte // 48-bit id ‖ 128-bit key
	if _, err := rand.Read(payload[:]); err != nil {
		return "", nil, "", err
	}
	idBytes := payload[:6]
	key = append([]byte(nil), payload[6:]...)
	id = fmt.Sprintf("%x", idBytes)
	body := append(append([]byte(nil), payload[:]...), crcBytes(payload[:])...)
	enc := b32.EncodeToString(body)
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

func crcBytes(data []byte) []byte {
	crc := crc16CCITT(data)
	return []byte{byte(crc >> 8), byte(crc)}
}

// ParseCode splits a pairing code back into id and wrap key. Dashes,
// spaces, and letter case are ignored for transcription robustness. The
// checksum is verified BEFORE anything touches the network, so a typo can
// never burn the real envelope.
func ParseCode(code string) (id string, key []byte, err error) {
	s := strings.ToUpper(strings.TrimSpace(code))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	if !strings.HasPrefix(s, "CAT") {
		return "", nil, fmt.Errorf("not a pairing code (want %q…)", CodePrefix)
	}
	raw, err := b32.DecodeString(strings.TrimPrefix(s, "CAT"))
	if err != nil || len(raw) != 24 {
		return "", nil, fmt.Errorf("malformed pairing code")
	}
	body, want := raw[:22], raw[22:]
	var got [2]byte
	got[0], got[1] = want[0], want[1]
	if crc := crc16CCITT(body); crc != uint16(got[0])<<8|uint16(got[1]) {
		return "", nil, fmt.Errorf("pairing code checksum mismatch (typo?)")
	}
	id = fmt.Sprintf("%x", body[:6])
	return id, append([]byte(nil), body[6:]...), nil
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
