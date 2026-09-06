package pair

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/local"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// fetchReadTimeout bounds how long Fetch waits for the pair server's
// one delivery, in case something on the other end stalls forever
// instead of writing and closing promptly.
const fetchReadTimeout = 30 * time.Second

// Fetch dials a pair server directly (over transportName, at addr — the
// two values Decode returns) and reads the one capability it delivers.
// This IS the claim: a second Fetch against the same pair server, even
// moments later, gets a connection refused or nothing at all, since the
// pair server destroys itself right after its first connection.
//
// For tailcat, Fetch generates its own throwaway client identity for
// the dial — the pair server has no allowlist, so any client key works,
// and this identity is discarded immediately after (it authorizes
// nothing beyond this one connection to this one pair server).
func Fetch(ctx context.Context, transportName, addr string, verbose bool) (*capability.Capability, error) {
	var client transport.Client
	switch transportName {
	case "tailcat":
		priv, _, kerr := tct.GenerateClientKey()
		if kerr != nil {
			return nil, fmt.Errorf("generate throwaway client key: %w", kerr)
		}
		c, derr := tct.Dialer(addr, priv, verbose)
		if derr != nil {
			return nil, fmt.Errorf("dial pair server: %w", derr)
		}
		client = c
	case "local":
		client = local.Dialer(addr)
	default:
		return nil, fmt.Errorf("unknown transport %q", transportName)
	}
	defer func() { _ = client.Close() }()

	conn, err := client.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dial pair server: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(fetchReadTimeout))

	// Length-prefixed, not read-until-close: the server won't close
	// until it gets our ack below, so relying on EOF to know we have
	// the whole payload would deadlock both ends waiting on each
	// other. See handleConn's matching write for why this replaced a
	// fixed post-write sleep on the server side.
	var lenBuf [frameHeaderLen]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read from pair server: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > MaxCapabilityBytes {
		return nil, fmt.Errorf("pair server response too large")
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return nil, fmt.Errorf("read from pair server: %w", err)
	}
	// Re-wrap as a bearer string and reuse capability.Decode's existing
	// strict v1 validation (version, transport-specific required
	// fields, expiry shape) instead of duplicating it — this is a real
	// protocol boundary (whatever a pair server actually sends in, a
	// Capability out) even though in normal operation the sender is
	// catflap's own code marshaling its own struct: reject anything
	// that doesn't match the exact shape a legitimate pair server would
	// ever produce, the same way the pre-pairing capability.Decode call
	// site (the legacy --cap-file path) always has.
	cp, derr := capability.Decode(capability.Prefix + base64.RawURLEncoding.EncodeToString(raw))
	if derr != nil {
		return nil, fmt.Errorf("bad capability from pair server: %w", derr)
	}
	// Ack only after the capability actually validated: the server
	// tears itself down once this arrives (or ackTimeout elapses), so
	// this is the real signal that delivery succeeded, not just that
	// Write() returned on the server's end.
	_ = conn.SetWriteDeadline(time.Now().Add(fetchReadTimeout))
	_, _ = conn.Write([]byte{ackByte}) // best-effort: the claim already succeeded regardless of whether this lands
	return cp, nil
}
