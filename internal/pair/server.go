package pair

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/local"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// MaxCapabilityBytes caps the delivered capability payload (capabilities
// are ~1KB).
const MaxCapabilityBytes = 8192

// frameHeaderLen is the fixed-size big-endian uint32 length prefix in
// front of the capability payload — see handleConn/Fetch. Explicit
// framing, not "read until the connection closes": the client must be
// able to tell it has the whole payload before it sends its own ack,
// and the server won't close until that ack arrives (or times out).
const frameHeaderLen = 4

// deliverTimeout bounds how long the pair server waits to finish writing
// the capability once a connection lands — a stalled peer must not keep
// the one-shot claim open indefinitely.
const deliverTimeout = 10 * time.Second

// ackTimeout bounds how long the pair server waits, after writing the
// capability, for the client's one-byte acknowledgement that it was
// actually received and validated — see handleConn's doc comment for
// why this replaced a fixed sleep. A stalled or hostile client cannot
// hold the pair server (and its underlying WireGuard engine) open past
// this regardless: the one-shot claim is already burned either way.
const ackTimeout = 10 * time.Second

// ackByte is the client's acknowledgement — its content carries no
// meaning (the server never inspects it beyond "a byte arrived"); its
// arrival is what actually proves the capability got to the other end,
// which conn.Write returning success does not (see handleConn).
const ackByte = 0x06 // ASCII ACK

// Server is a temporary, one-shot capability-delivery server: it starts
// its own ephemeral Tailcat (or local) identity, open to any client (no
// allowlist — the address itself is the bootstrap secret, see the
// package doc), hands cap to the first connection it sees, and then
// destroys itself — whether or not that delivery actually succeeded.
// It also destroys itself after ttl if nobody ever connects.
type Server struct {
	srv     transport.Server
	claimed atomic.Bool
	timer   *time.Timer
	closeMu sync.Mutex
	closed  bool
}

// Serve starts a pair server for cap over transportName ("tailcat" or
// "local"), open for exactly ttl (or one delivery, whichever comes
// first). Callers MUST clamp ttl to the underlying task's own remaining
// TTL before calling this — Serve does not know the task's expiry and
// will happily run for the full ttl requested.
//
// stillLive, if non-nil, is consulted right before actually writing the
// capability to a claimed connection — not just once at issuance time.
// A caller's own "is the task still live" check, taken before starting
// the pair server, can never fully close the window between that check
// and a connection landing (creating the underlying transport server
// itself takes real time, more so for tailcat's DERP handshake) — the
// task can start dying in that gap. Re-checking at the last possible
// moment, right before the bytes actually leave, shrinks that window to
// as close to zero as this package can get without the caller managing
// its own locking here. Pass nil to skip this (e.g. tests with no task
// lifecycle to check).
func Serve(transportName string, cap *capability.Capability, ttl time.Duration, verbose bool, stillLive func() bool) (*Server, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("pair server ttl must be positive")
	}
	if ttl > MaxCodeTTL {
		// Hard ceiling enforced at this single lowest-level chokepoint
		// every pairing code goes through, independent of any caller's
		// own clamping: a pairing code is a bootstrap secret in transit
		// (chat logs, screenshots, a clipboard) and must stay
		// short-lived on its own terms, never just "no longer than the
		// task" — a long-lived task must not turn a careless
		// --pairing-ttl (or a leaked code) into an hours-long window.
		return nil, fmt.Errorf("pair server ttl %s exceeds MaxCodeTTL %s", ttl, MaxCodeTTL)
	}
	payload, err := json.Marshal(cap)
	if err != nil {
		return nil, fmt.Errorf("encode capability: %w", err)
	}
	if len(payload) > MaxCapabilityBytes {
		// Can't happen for a real Capability (~1KB) — but this bound
		// is exactly what Fetch enforces on the read side, and it's
		// what keeps the length prefix below a safe uint32 cast.
		return nil, fmt.Errorf("encoded capability (%d bytes) exceeds MaxCapabilityBytes", len(payload))
	}

	s := &Server{}
	// Held for the whole setup below: the underlying transport's accept
	// loop can start dispatching connections to handleConn (and thus
	// call s.Close, which needs s.srv/s.timer) before this function
	// returns — Close must block until s.srv and s.timer are actually
	// set, not race to read them while Serve is still writing them.
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	handler := func(conn net.Conn) { s.handleConn(conn, payload, stillLive) }

	var underlying transport.Server
	switch transportName {
	case "tailcat":
		underlying, err = tct.Serve(handler, nil, verbose) // nil allow: open to any client
	case "local":
		underlying, err = local.Serve(handler)
	default:
		return nil, fmt.Errorf("unknown transport %q", transportName)
	}
	if err != nil {
		return nil, fmt.Errorf("start pair server: %w", err)
	}
	s.srv = underlying
	s.timer = time.AfterFunc(ttl, s.Close)
	return s, nil
}

// handleConn is Server's transport.Handler. Exactly one caller across
// the whole process ever gets past the CompareAndSwap — every other
// concurrent (or later) connection is dropped with nothing written,
// including a replay of the same pairing code once the first has
// landed. Whether or not delivery actually succeeds, the server
// self-destructs once this returns: a stalled or dropped peer does not
// get a second chance, matching the old rendezvous's "fetch burns the
// envelope regardless of what follows" semantics.
//
// After writing, this waits for the client's one-byte ack (bounded by
// ackTimeout) instead of a fixed sleep before tearing the whole pair
// server down. An earlier version closed the server immediately after
// Write returned — but over Tailcat, Write returning only means the
// bytes reached the local netstack's send queue, not that they've
// actually gone out over the (async, possibly DERP-relayed) tunnel
// yet. Closing the WireGuard engine that fast killed the connection
// mid-flight and the client's Fetch timed out waiting for data that
// was never going to arrive — discovered by actually running this over
// real Tailcat, not just the local-transport tests. Waiting for a real
// signal that the client actually got the bytes (or giving up after a
// bounded timeout either way) replaces that guess with a fact.
func (s *Server) handleConn(conn net.Conn, payload []byte, stillLive func() bool) {
	if !s.claimed.CompareAndSwap(false, true) {
		_ = conn.Close()
		return
	}
	defer func() {
		_ = conn.Close()
		s.Close()
	}()
	if stillLive != nil && !stillLive() {
		// The task died between Serve's own caller-side check and this
		// connection actually landing — the claim is still burned (no
		// second chance for a replay), but nothing is delivered.
		return
	}
	// Length-prefixed, not newline/close-delimited: the client must be
	// able to tell the capability frame is fully received WITHOUT
	// waiting for this connection to close — it has to send its own
	// ack (below) before we do that, so "close signals end of payload"
	// would deadlock both ends waiting on each other.
	frame := make([]byte, frameHeaderLen+len(payload))
	//nolint:gosec // reason: len(payload) is already bounded to MaxCapabilityBytes (8192) by the check in Serve, far below uint32's range.
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[frameHeaderLen:], payload)
	_ = conn.SetWriteDeadline(time.Now().Add(deliverTimeout))
	if _, werr := conn.Write(frame); werr != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(ackTimeout))
	ack := make([]byte, 1)
	_, _ = io.ReadFull(conn, ack) // content and timeout-vs-arrival are both irrelevant beyond "stop waiting now"
}

// Addr returns the pair server's own address (a tailcat "tc…" address,
// or "host:port" for local) — never the task's own address, since the
// pair server is a separate Tailcat identity.
func (s *Server) Addr() string {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.srv.Addr()
}

// Close tears the pair server down. Idempotent and safe to call from
// within handleConn itself, from the TTL timer, or from an external
// caller (task revoke/expiry must close any still-open pair server for
// it — see internal/cli/serve.go).
func (s *Server) Close() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.timer.Stop()
	_ = s.srv.Close()
}
