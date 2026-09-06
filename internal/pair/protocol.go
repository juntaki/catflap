// Package pair delivers one task's Capability to the agent side over a
// temporary, direct Tailcat (or local) connection — no HTTP rendezvous,
// no separate encryption layer, and no hosted infrastructure of any
// kind. A pairing code encodes exactly the address of a throwaway
// "pair server": a one-shot Tailcat server, started fresh per pairing
// attempt, open to any client (no allowlist), that hands the Capability
// to the first connection it sees and then destroys itself.
//
// Security properties:
//
//   - The pair server's own Tailcat address IS the bootstrap secret:
//     Tailcat addresses embed a random WireGuard pre-shared key, so
//     knowing the address is what lets a client complete the WireGuard
//     handshake at all (see github.com/tailscale/tailcat's ConnInfo /
//     PresharedKey docs). Nothing else needs to be encrypted on top —
//     the tunnel itself already provides confidentiality and
//     authenticity for the one-shot delivery.
//   - one-time: the pair server claims exactly one connection (first
//     wins, atomic) and self-destructs immediately after, whether or
//     not delivery actually succeeded — a second connection, including
//     a replay of the same code, gets nothing.
//   - short-lived: the pair server closes itself after its own TTL,
//     which is always clamped to the task's remaining TTL (see
//     internal/cli/share.go) — a code can never outlive its task.
//   - never carries the task server's own address or client key: the
//     pair server is a SEPARATE Tailcat identity from the task server
//     it delivers a Capability for, so a pair server address leaking
//     (e.g. into a log) exposes nothing about the task server itself
//     beyond what the Capability payload already would.
//   - typo-safe: a CRC-16 over the encoded bytes is verified locally,
//     so a mistyped code is rejected before ever attempting to dial.
package pair

import (
	"encoding/base32"
	"fmt"
	"strings"
	"time"
)

// CodePrefix marks pairing codes.
const CodePrefix = "CAT-"

// DefaultCodeTTL bounds how long a pairing code (and its underlying
// pair server) stays claimable when the caller doesn't ask for
// something else — always further clamped to the task's own remaining
// TTL and to MaxCodeTTL (see internal/cli/serve.go's issuePairCode).
const DefaultCodeTTL = 5 * time.Minute

// MaxCodeTTL is a hard ceiling on how long any pairing code can stay
// claimable, independent of the task's own TTL. A long-lived task
// (hours) must not let an operator (deliberately or via a careless
// --pairing-ttl) turn a leaked pairing code into an hours-long
// authorization window — the code is a bootstrap secret in transit
// (over chat logs, screenshots, a operator's clipboard) and should be
// short-lived on its own terms, not just "no longer than the task".
const MaxCodeTTL = 10 * time.Minute

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// transportTag identifies which transport a pairing code's address is
// for, since a pair server always uses the same transport as the task
// it belongs to (tailcat for real use, local for tests/demos) and the
// client must know which dialer to use before it can connect.
type transportTag byte

const (
	tagTailcat transportTag = 0
	tagLocal   transportTag = 1
)

func tagFor(transportName string) (transportTag, error) {
	switch transportName {
	case "tailcat":
		return tagTailcat, nil
	case "local":
		return tagLocal, nil
	default:
		return 0, fmt.Errorf("unknown transport %q", transportName)
	}
}

func (t transportTag) name() (string, error) {
	switch t {
	case tagTailcat:
		return "tailcat", nil
	case tagLocal:
		return "local", nil
	default:
		return "", fmt.Errorf("unknown transport tag %d", t)
	}
}

// Encode builds a pairing code carrying the pair server's own transport
// and address — nothing else. addr is a tailcat "tc…" address or a
// "host:port" local address, matching transportName.
func Encode(transportName, addr string) (string, error) {
	tag, err := tagFor(transportName)
	if err != nil {
		return "", err
	}
	body := append([]byte{byte(tag)}, []byte(addr)...)
	full := append(body, crcBytes(body)...)
	enc := b32.EncodeToString(full)
	var groups []string
	for i := 0; i < len(enc); i += 4 {
		end := i + 4
		if end > len(enc) {
			end = len(enc)
		}
		groups = append(groups, enc[i:end])
	}
	return CodePrefix + strings.Join(groups, "-"), nil
}

// Decode splits a pairing code back into the transport name and pair
// server address. Dashes, spaces, and letter case are ignored for
// transcription robustness. The checksum is verified before anything
// touches the network, so a typo can never waste the pair server's one
// claim.
func Decode(code string) (transportName, addr string, err error) {
	s := strings.ToUpper(strings.TrimSpace(code))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	if !strings.HasPrefix(s, "CAT") {
		return "", "", fmt.Errorf("not a pairing code (want %q…)", CodePrefix)
	}
	raw, derr := b32.DecodeString(strings.TrimPrefix(s, "CAT"))
	if derr != nil || len(raw) < 1+2 {
		return "", "", fmt.Errorf("malformed pairing code")
	}
	body, want := raw[:len(raw)-2], raw[len(raw)-2:]
	if crc := crc16CCITT(body); crc != uint16(want[0])<<8|uint16(want[1]) {
		return "", "", fmt.Errorf("pairing code checksum mismatch (typo?)")
	}
	tag := transportTag(body[0])
	name, terr := tag.name()
	if terr != nil {
		return "", "", fmt.Errorf("malformed pairing code: %w", terr)
	}
	addr = string(body[1:])
	if addr == "" {
		return "", "", fmt.Errorf("malformed pairing code: empty address")
	}
	return name, addr, nil
}

// crc16CCITT detects transcription typos locally (not authenticity —
// that comes from Tailcat's own WireGuard tunnel plus the pair server's
// single-claim semantics). Test vector "123456789".
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

func crcBytes(data []byte) []byte {
	crc := crc16CCITT(data)
	//nolint:gosec // reason: deliberate truncation to the CRC-16's two bytes, not an overflow.
	return []byte{byte(crc >> 8), byte(crc)}
}
