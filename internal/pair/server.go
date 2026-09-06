package pair

import (
	"encoding/json"
	"fmt"
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

// deliverTimeout bounds how long the pair server waits to finish writing
// the capability once a connection lands — a stalled peer must not keep
// the one-shot claim open indefinitely.
const deliverTimeout = 10 * time.Second

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
func Serve(transportName string, cap *capability.Capability, ttl time.Duration, verbose bool) (*Server, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("pair server ttl must be positive")
	}
	payload, err := json.Marshal(cap)
	if err != nil {
		return nil, fmt.Errorf("encode capability: %w", err)
	}

	s := &Server{}
	// Held for the whole setup below: the underlying transport's accept
	// loop can start dispatching connections to handleConn (and thus
	// call s.Close, which needs s.srv/s.timer) before this function
	// returns — Close must block until s.srv and s.timer are actually
	// set, not race to read them while Serve is still writing them.
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	handler := func(conn net.Conn) { s.handleConn(conn, payload) }

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

// teardownGrace is how long handleConn waits after writing before it
// tears down the WHOLE pair server (WireGuard engine included). This
// is not cosmetic: over Tailcat, conn.Write returning only means the
// bytes reached the local netstack's send queue, not that they've
// actually gone out over the (async, relayed-over-DERP) tunnel yet.
// Closing the underlying transport.Server immediately after Write — as
// a first version of this did — killed the WireGuard engine before the
// just-written capability had actually left the box, so the client's
// connection died mid-flight and Fetch timed out waiting for data that
// was never going to arrive. Discovered by actually running this over
// real Tailcat, not just the local-transport tests.
const teardownGrace = 2 * time.Second

// handleConn is Server's transport.Handler. Exactly one caller across
// the whole process ever gets past the CompareAndSwap — every other
// concurrent (or later) connection is dropped with nothing written,
// including a replay of the same pairing code once the first has
// landed. Whether or not the write below actually succeeds, the server
// self-destructs shortly after (see teardownGrace): a stalled or
// dropped peer does not get a second chance, matching the old
// rendezvous's "fetch burns the envelope regardless of what follows"
// semantics.
func (s *Server) handleConn(conn net.Conn, payload []byte) {
	if !s.claimed.CompareAndSwap(false, true) {
		_ = conn.Close()
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(deliverTimeout))
	_, _ = conn.Write(append(append([]byte(nil), payload...), '\n'))
	_ = conn.Close()
	time.AfterFunc(teardownGrace, s.Close)
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
