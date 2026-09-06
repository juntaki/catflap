package tailcat

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tailscale/tailcat" //nolint:depguard // quarantine: this package IS the adapter boundary.
	"tailscale.com/types/key"      //nolint:depguard // quarantine: this package IS the adapter boundary.

	"github.com/juntaki/catflap/internal/transport"
)

// dialRawPort dials addr on an arbitrary TCP port, bypassing this
// package's own Dialer (which always dials transport.RPCPort) — used
// only to prove no OTHER port is reachable. Uses the raw upstream
// client directly, which this package (the sanctioned adapter
// boundary) is allowed to do.
func dialRawPort(t *testing.T, addr, privText string, port uint16, timeout time.Duration) (net.Conn, error) {
	t.Helper()
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte(privText)); err != nil {
		t.Fatalf("invalid client key: %v", err)
	}
	c := tailcat.NewClient(tailcat.Addr(addr))
	c.Key = priv
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := c.DialTCPPort(ctx, port)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	// c.Close() must NOT run before this function returns: a defer
	// here would tear the underlying client (and thus conn) down
	// before the caller ever receives it, since deferred calls run
	// after a return statement's value is computed but before the
	// function actually returns. Clean up at test end instead, once
	// the caller is done with conn.
	t.Cleanup(func() { _ = c.Close() })
	return conn, nil
}

// denyTimeout bounds how long a "must be denied" sub-test waits. An
// unauthorized WireGuard peer isn't actively rejected — the server
// simply never completes a handshake with it — so denial can only be
// observed as the dial's own context deadline expiring, not a fast
// explicit refusal. This must stay short enough for the suite to be
// usable in normal CI while still giving a real handshake attempt time
// to genuinely fail rather than a false "denied" from too tight a
// deadline.
const denyTimeout = 15 * time.Second

// This file is catflap's Tailcat SECURITY contract — everything the
// rest of the codebase assumes about AllowedClients, port restriction,
// and per-Serve identity, kept separate from transporttest's
// transport-agnostic behavioral contract (common_contract_test.go)
// specifically so a future change to what "empty allowlist" or "which
// port is served" means in a Tailcat upgrade gets caught here, not
// mixed in with generic Serve/Dial/Close behavior every transport must
// satisfy the same way.
//
// Every test here needs a real DERP round trip; skipped under -short.

func skipIfShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("needs a real Tailcat/DERP round trip")
	}
}

func echoHandler(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	_, _ = conn.Write(buf)
}

func mustDial(t *testing.T, addr, priv string, timeout time.Duration) (net.Conn, error) {
	t.Helper()
	cl, err := Dialer(addr, priv, false)
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	defer func() { _ = cl.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return cl.Dial(ctx)
}

// TestAllowedClientCanConnect covers the basic allow path: a client
// whose public key was passed to Serve's allow list can dial in.
func TestAllowedClientCanConnect(t *testing.T) {
	skipIfShort(t)
	priv, pub, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Serve(echoHandler, []string{pub}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	conn, derr := mustDial(t, srv.Addr(), priv, 30*time.Second)
	if derr != nil {
		t.Fatalf("allowed client failed to dial: %v", derr)
	}
	_ = conn.Close()
}

// TestWrongClientCannotConnect covers the deny path: a client whose
// key was never added to Serve's allow list must not be able to
// establish a stream, even though it knows the correct address (and
// thus the address's embedded pre-shared key).
func TestWrongClientCannotConnect(t *testing.T) {
	skipIfShort(t)
	_, allowedPub, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongPriv, _, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Serve(echoHandler, []string{allowedPub}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	if _, derr := mustDial(t, srv.Addr(), wrongPriv, denyTimeout); derr == nil {
		t.Fatal("a client not on the allow list must not be able to connect")
	}
}

// TestEmptyAllowlistAcceptsAnyClient covers the pairing use case: a
// pair server is deliberately started with no allowlist at all (nil),
// so any client that knows its address — the bootstrap secret — can
// claim it. This is the exact semantic internal/pair's Server depends
// on; a Tailcat upgrade that changed "empty means open" to "empty
// means closed" would silently break pairing everywhere, so pin it
// here explicitly.
func TestEmptyAllowlistAcceptsAnyClient(t *testing.T) {
	skipIfShort(t)
	priv, _, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Serve(echoHandler, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	conn, derr := mustDial(t, srv.Addr(), priv, 30*time.Second)
	if derr != nil {
		t.Fatalf("a client must be able to connect to a server with an empty allowlist, got: %v", derr)
	}
	_ = conn.Close()
}

// TestAddAllowedClientAdmitsNewClientWithoutOpeningToOthers covers
// AddAllowedClient's runtime-add semantics: a client added after Serve
// has already started must be admitted, an already-allowed client must
// remain admitted, and a client that was NEVER added — even after
// AddAllowedClient has been called for someone else — must still be
// denied. This is the exact mechanism `catflap grant` (adding a second
// task) and any future incremental-trust flow would depend on.
func TestAddAllowedClientAdmitsNewClientWithoutOpeningToOthers(t *testing.T) {
	skipIfShort(t)
	origPriv, origPub, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	newPriv, newPub, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	neverPriv, _, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Serve(echoHandler, []string{origPub}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	if _, derr := mustDial(t, srv.Addr(), newPriv, denyTimeout); derr == nil {
		t.Fatal("a not-yet-added client must be denied before AddAllowedClient")
	}

	if aerr := srv.AddAllowedClient(newPub); aerr != nil {
		t.Fatalf("AddAllowedClient: %v", aerr)
	}

	conn, derr := mustDial(t, srv.Addr(), newPriv, 30*time.Second)
	if derr != nil {
		t.Fatalf("the newly added client must now be able to connect, got: %v", derr)
	}
	_ = conn.Close()

	conn2, derr2 := mustDial(t, srv.Addr(), origPriv, 30*time.Second)
	if derr2 != nil {
		t.Fatalf("the originally allowed client must still be able to connect, got: %v", derr2)
	}
	_ = conn2.Close()

	if _, derr3 := mustDial(t, srv.Addr(), neverPriv, denyTimeout); derr3 == nil {
		t.Fatal("a client that was never added must still be denied, even after AddAllowedClient was called for someone else")
	}
}

// TestCloseThenReconnectDenied covers the identity-death half of "1
// task = 1 server, expiry = Close": once a server is closed, its
// address must not become dialable again — not by an originally
// allowed client, and not via any lingering state.
func TestCloseThenReconnectDenied(t *testing.T) {
	skipIfShort(t)
	priv, pub, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Serve(echoHandler, []string{pub}, false)
	if err != nil {
		t.Fatal(err)
	}
	addr := srv.Addr()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, derr := mustDial(t, addr, priv, denyTimeout); derr == nil {
		t.Fatal("dialing a closed server's address must fail, even for its originally allowed client")
	}
}

// TestFreshServeYieldsDifferentIdentity covers "fresh keys every time":
// two independent Serve calls must never produce the same address —
// each task, and each pair server, gets its own unguessable identity.
//
// Compares the decoded ConnInfo.ServerPublic node key, not the raw
// address string: a Tailcat address also embeds a fresh, independently
// random pre-shared key (see ConnInfo's own doc comment), so two
// addresses could differ solely because of PSK rotation while the
// underlying server node identity was actually reused — comparing
// opaque strings alone wouldn't catch that.
func TestFreshServeYieldsDifferentIdentity(t *testing.T) {
	skipIfShort(t)
	srv1, err := Serve(echoHandler, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv1.Close() }()
	srv2, err := Serve(echoHandler, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv2.Close() }()

	if srv1.Addr() == srv2.Addr() {
		t.Fatal("two independent Serve calls produced the same address")
	}

	info1, err := tailcat.ParseAddr(tailcat.Addr(srv1.Addr()))
	if err != nil {
		t.Fatalf("parse srv1 address: %v", err)
	}
	info2, err := tailcat.ParseAddr(tailcat.Addr(srv2.Addr()))
	if err != nil {
		t.Fatalf("parse srv2 address: %v", err)
	}
	if info1.ServerPublic == info2.ServerPublic {
		t.Fatal("two independent Serve calls produced the SAME server node identity (ServerPublic) — only the address's embedded pre-shared key differed")
	}
}

// TestOnlyRPCPortIsServed covers port restriction: the adapter serves
// exactly transport.RPCPort and nothing else, even for an otherwise
// fully-allowed client — a Tailcat upgrade that started dispatching
// other ports by default (or ignoring ServedTCPPorts) must be caught
// here rather than silently widening what an agent can reach.
func TestOnlyRPCPortIsServed(t *testing.T) {
	skipIfShort(t)
	priv, pub, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Serve(echoHandler, []string{pub}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	// Positive control, through the SAME raw-client mechanism the
	// denial check below uses: this proves dialRawPort itself can
	// actually establish a connection at all, so the denial below means
	// "this port is blocked", not "this raw dial path is broken for an
	// unrelated reason" (a setup/handshake failure that had nothing to
	// do with port restriction).
	if conn, derr := dialRawPort(t, srv.Addr(), priv, transport.RPCPort, 30*time.Second); derr != nil {
		t.Fatalf("positive control: raw dial to the real RPC port failed: %v", derr)
	} else {
		_ = conn.Close()
	}

	otherPort := transport.RPCPort + 1
	if _, derr := dialRawPort(t, srv.Addr(), priv, otherPort, denyTimeout); derr == nil {
		t.Fatalf("dialing port %d (not the configured RPCPort) must fail", otherPort)
	}
}
