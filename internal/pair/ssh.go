package pair

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/local"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// sshExchangeMaxBytes bounds both frames of the SSH pairing exchange —
// generous for an offer (endpoint string + host key line) or an accept
// (one public key line), far below anything that would strain the
// frameHeaderLen uint32 prefix.
const sshExchangeMaxBytes = 4096

// sshExchangeTimeout bounds each read/write of the exchange. Unlike the
// legacy capability delivery (one write, one best-effort ack), this
// exchange has a real second half the pairing depends on — the
// server's own timeout, not just the client's, must not let the pair
// server's one-shot claim hang open indefinitely on a stalled peer.
const sshExchangeTimeout = 15 * time.Second

// SSHOffer is what the pair server sends first, over the one-shot pair
// connection: enough for the client to dial the task's real SSH
// endpoint and pin its host key before ever attempting the SSH
// handshake. It never carries a client credential — that flows the
// other direction as SSHOfferAccept.
type SSHOffer struct {
	Version   int       `json:"v"`
	TaskID    string    `json:"task"`
	Name      string    `json:"name,omitempty"`
	Transport string    `json:"transport"` // "tailcat" or "local"
	Endpoint  string    `json:"endpoint"`  // the TASK server's own address, not the pair server's
	HostKey   string    `json:"host_key"`  // authorized_keys-format line for the task's SSH host key
	ExpiresAt time.Time `json:"expires_at"`
}

// SSHOfferAccept is what the client sends back over the same
// connection: the ephemeral SSH client key it generated for this
// pairing, to be registered as the task's one allowed identity.
type SSHOfferAccept struct {
	PublicKey string `json:"public_key"` // authorized_keys-format line
}

// SSHOfferServer is a one-shot pair server for the SSH pairing
// exchange: it hands its offer to the first connection, reads back the
// client's accept, and calls onAccept with the delivered public key —
// then self-destructs, exactly like Server (see that type's doc
// comment for the shared one-shot/self-destruct/ttl semantics this
// duplicates rather than shares, to avoid entangling the legacy
// capability delivery path with this one while both exist).
type SSHOfferServer struct {
	srv     transport.Server
	claimed atomic.Bool
	timer   *time.Timer
	closeMu sync.Mutex
	closed  bool
}

// ServeSSHOffer starts a one-shot pair server for offer. stillLive, if
// non-nil, is re-checked immediately before the offer is actually
// written, same as Serve's stillLive — see that function's doc comment
// for why the caller's own pre-check can't close this window alone.
// onAccept is called with the client's delivered public key line
// (never empty) once received; its return value has no effect on the
// wire (the claim is already burned either way) but is available to
// the caller for logging/error surfacing.
func ServeSSHOffer(transportName string, offer SSHOffer, ttl time.Duration, verbose bool, stillLive func() bool, onAccept func(publicKeyLine string) error) (*SSHOfferServer, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("pair server ttl must be positive")
	}
	if ttl > MaxCodeTTL {
		return nil, fmt.Errorf("pair server ttl %s exceeds MaxCodeTTL %s", ttl, MaxCodeTTL)
	}
	payload, err := json.Marshal(offer)
	if err != nil {
		return nil, fmt.Errorf("encode offer: %w", err)
	}
	if len(payload) > sshExchangeMaxBytes {
		return nil, fmt.Errorf("encoded offer (%d bytes) exceeds %d", len(payload), sshExchangeMaxBytes)
	}

	s := &SSHOfferServer{}
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	handler := func(conn net.Conn) { s.handleConn(conn, payload, stillLive, onAccept) }

	var underlying transport.Server
	switch transportName {
	case "tailcat":
		underlying, err = tct.Serve(handler, nil, verbose) // nil allow: open to any client, same as the legacy pair server
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

func (s *SSHOfferServer) handleConn(conn net.Conn, payload []byte, stillLive func() bool, onAccept func(string) error) {
	if !s.claimed.CompareAndSwap(false, true) {
		_ = conn.Close()
		return
	}
	defer func() {
		_ = conn.Close()
		s.Close()
	}()
	if stillLive != nil && !stillLive() {
		return
	}
	if err := writeFrame(conn, payload, sshExchangeTimeout); err != nil {
		return
	}
	accept, err := readFrame(conn, sshExchangeMaxBytes, sshExchangeTimeout)
	if err != nil {
		return
	}
	var a SSHOfferAccept
	if err := json.Unmarshal(accept, &a); err != nil || a.PublicKey == "" {
		_ = writeAckStatus(conn, false)
		return
	}
	ok := onAccept(a.PublicKey) == nil
	// The client must not proceed to dial the task endpoint until it
	// knows the key it just sent was actually registered — otherwise
	// FetchSSHOffer could return (and the caller start dialing) before
	// this goroutine's onAccept call has run at all, since writing the
	// accept frame only proves the bytes reached this connection, not
	// that registration happened. See writeAckStatus/readAckStatus.
	_ = writeAckStatus(conn, ok)
}

// Addr returns the pair server's own address.
func (s *SSHOfferServer) Addr() string {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.srv.Addr()
}

// Close tears the pair server down. Idempotent.
func (s *SSHOfferServer) Close() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.timer.Stop()
	_ = s.srv.Close()
}

// FetchSSHOffer dials a pair server directly (over transportName, at
// addr — the two values Decode returns), reads its SSHOffer, mints a
// fresh ephemeral Ed25519 SSH client key, and sends the public half
// back as this pairing's SSHOfferAccept. The returned private key
// authenticates the SUBSEQUENT dial to offer.Endpoint — it authorizes
// nothing at the pair server itself, which never checks it.
func FetchSSHOffer(ctx context.Context, transportName, addr string, verbose bool) (offer SSHOffer, clientKey ed25519.PrivateKey, err error) {
	var client transport.Client
	switch transportName {
	case "tailcat":
		priv, _, kerr := tct.GenerateClientKey()
		if kerr != nil {
			return SSHOffer{}, nil, fmt.Errorf("generate throwaway client key: %w", kerr)
		}
		c, derr := tct.Dialer(addr, priv, verbose)
		if derr != nil {
			return SSHOffer{}, nil, fmt.Errorf("dial pair server: %w", derr)
		}
		client = c
	case "local":
		client = local.Dialer(addr)
	default:
		return SSHOffer{}, nil, fmt.Errorf("unknown transport %q", transportName)
	}
	defer func() { _ = client.Close() }()

	conn, derr := client.Dial(ctx)
	if derr != nil {
		return SSHOffer{}, nil, fmt.Errorf("dial pair server: %w", derr)
	}
	defer func() { _ = conn.Close() }()

	raw, rerr := readFrame(conn, sshExchangeMaxBytes, sshExchangeTimeout)
	if rerr != nil {
		return SSHOffer{}, nil, fmt.Errorf("read offer: %w", rerr)
	}
	if uerr := json.Unmarshal(raw, &offer); uerr != nil {
		return SSHOffer{}, nil, fmt.Errorf("bad offer: %w", uerr)
	}
	if offer.Version != 1 || offer.TaskID == "" || offer.Endpoint == "" || offer.HostKey == "" || offer.ExpiresAt.IsZero() {
		return SSHOffer{}, nil, fmt.Errorf("offer missing required fields")
	}

	pub, priv, kerr := ed25519.GenerateKey(rand.Reader)
	if kerr != nil {
		return SSHOffer{}, nil, fmt.Errorf("generate client key: %w", kerr)
	}
	sshPub, kerr := gossh.NewPublicKey(pub)
	if kerr != nil {
		return SSHOffer{}, nil, fmt.Errorf("wrap client key: %w", kerr)
	}
	accept := SSHOfferAccept{PublicKey: string(gossh.MarshalAuthorizedKey(sshPub))}
	acceptRaw, merr := json.Marshal(accept)
	if merr != nil {
		return SSHOffer{}, nil, fmt.Errorf("encode accept: %w", merr)
	}
	if werr := writeFrame(conn, acceptRaw, sshExchangeTimeout); werr != nil {
		return SSHOffer{}, nil, fmt.Errorf("send accept: %w", werr)
	}
	ok, aerr := readAckStatus(conn, sshExchangeTimeout)
	if aerr != nil {
		return SSHOffer{}, nil, fmt.Errorf("read pairing confirmation: %w", aerr)
	}
	if !ok {
		return SSHOffer{}, nil, fmt.Errorf("host rejected this pairing")
	}
	return offer, priv, nil
}

// ackStatusOK/ackStatusFail are the one-byte confirmation the pair
// server sends after processing (not just receiving) the client's
// accept: writeFrame returning success only proves the bytes reached
// this connection, not that onAccept has run, so the client must wait
// for this before it can safely dial the task endpoint expecting its
// key to already be registered.
const (
	ackStatusFail byte = 0x00
	ackStatusOK   byte = 0x01
)

func writeAckStatus(conn net.Conn, ok bool) error {
	b := ackStatusFail
	if ok {
		b = ackStatusOK
	}
	_ = conn.SetWriteDeadline(time.Now().Add(sshExchangeTimeout))
	_, err := conn.Write([]byte{b})
	return err
}

func readAckStatus(conn net.Conn, timeout time.Duration) (bool, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		return false, err
	}
	return b[0] == ackStatusOK, nil
}

// writeFrame/readFrame implement the same big-endian length-prefixed
// framing as the legacy capability delivery (see handleConn/Fetch in
// server.go/client.go): explicit framing, not read-until-close, so
// either side can tell a message is fully received without waiting for
// the connection itself to close.
func writeFrame(conn net.Conn, payload []byte, timeout time.Duration) error {
	frame := make([]byte, frameHeaderLen+len(payload))
	//nolint:gosec // reason: payload is bounded to sshExchangeMaxBytes (4096) by callers, far below uint32's range.
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[frameHeaderLen:], payload)
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write(frame)
	return err
}

func readFrame(conn net.Conn, max uint32, timeout time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var lenBuf [frameHeaderLen]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > max {
		return nil, fmt.Errorf("frame too large (%d bytes)", n)
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return nil, err
	}
	return raw, nil
}
