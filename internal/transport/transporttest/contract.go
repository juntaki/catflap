// Package transporttest is the shared conformance suite every
// transport.Server/transport.Client implementation must satisfy,
// independent of which one (local, tailcat, or a future one) backs it.
//
// This is deliberately NOT a security-semantics suite: local
// intentionally ignores AddAllowedClient (there is no client identity
// to restrict on loopback TCP), so "wrong client denied" and friends
// are NOT here — they belong to a transport-specific security contract
// (see internal/transport/tailcat's own security contract tests). What
// IS here is the behavioral contract catflap's own code (mkTask, the
// pair server, the MCP client) depends on regardless of transport:
// Serve/Dial/Close work, connections carry bidirectional bytes, a
// closed server refuses new dials, nothing panics or leaks under
// concurrency.
package transporttest

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/transport"
)

// ServeFunc starts a fresh server dispatching connections to handler.
type ServeFunc func(handler transport.Handler) (transport.Server, error)

// DialFunc dials addr, returning a fresh client. Implementations that
// need a per-dial identity (tailcat's ephemeral client key) generate
// one internally — the contract suite only ever calls this once per
// connection it wants, exactly like real callers do.
type DialFunc func(addr string) (transport.Client, error)

// RunCommonContract runs the full transport-agnostic conformance suite
// against one Serve/Dial pair. name is used only for sub-test labels.
func RunCommonContract(t *testing.T, name string, serve ServeFunc, dial DialFunc) {
	t.Run(name+"/ServeAddrDial", func(t *testing.T) { testServeAddrDial(t, serve, dial) })
	t.Run(name+"/BidirectionalOnOneConnection", func(t *testing.T) { testBidirectional(t, serve, dial) })
	t.Run(name+"/MultipleConcurrentStreams", func(t *testing.T) { testMultipleStreams(t, serve, dial) })
	t.Run(name+"/ContextCancellationAbortsDial", func(t *testing.T) { testContextCancellation(t, serve, dial) })
	t.Run(name+"/ClientCloseIdempotent", func(t *testing.T) { testClientCloseIdempotent(t, serve, dial) })
	t.Run(name+"/ServerCloseIdempotent", func(t *testing.T) { testServerCloseIdempotent(t, serve) })
	t.Run(name+"/NoDialAfterServerClose", func(t *testing.T) { testNoDialAfterServerClose(t, serve, dial) })
	t.Run(name+"/HandlerEndsOnConnectionClose", func(t *testing.T) { testHandlerEndsOnConnectionClose(t, serve, dial) })
	t.Run(name+"/ConcurrentDialNoRaceOrPanic", func(t *testing.T) { testConcurrentDial(t, serve, dial) })
	t.Run(name+"/NoGoroutineLeakAcrossCycles", func(t *testing.T) { testNoGoroutineLeak(t, serve, dial) })
}

func dialConn(t *testing.T, dial DialFunc, addr string) (transport.Client, net.Conn) {
	t.Helper()
	cl, err := dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := cl.Dial(ctx)
	if err != nil {
		_ = cl.Close()
		t.Fatalf("Dial(ctx): %v", err)
	}
	return cl, conn
}

// testServeAddrDial covers the basic contract: Serve produces a
// non-empty Addr, and dialing it succeeds.
func testServeAddrDial(t *testing.T, serve ServeFunc, dial DialFunc) {
	srv, err := serve(func(net.Conn) {})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer func() { _ = srv.Close() }()
	if srv.Addr() == "" {
		t.Fatal("Addr() must not be empty once the server is up")
	}
	cl, conn := dialConn(t, dial, srv.Addr())
	defer func() { _ = cl.Close() }()
	_ = conn.Close()
}

// testBidirectional covers the actual payload contract every RPC
// exchange (gateway request/response, pair server delivery) depends
// on: bytes written on one end of a connection are read intact on the
// other, in both directions.
func testBidirectional(t *testing.T, serve ServeFunc, dial DialFunc) {
	const clientMsg = "hello from client"
	const serverMsg = "hello from server"
	srv, err := serve(func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, len(clientMsg))
		if _, rerr := io.ReadFull(conn, buf); rerr != nil {
			return
		}
		if string(buf) != clientMsg {
			return
		}
		_, _ = conn.Write([]byte(serverMsg))
	})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer func() { _ = srv.Close() }()

	cl, conn := dialConn(t, dial, srv.Addr())
	defer func() { _ = cl.Close() }()
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(clientMsg)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, len(serverMsg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != serverMsg {
		t.Fatalf("got %q, want %q", buf, serverMsg)
	}
}

// testMultipleStreams covers concurrent, independent connections: each
// must be routed to its own handler invocation with no cross-talk, the
// way concurrent MCP tool calls each open their own connection to the
// same task.
func testMultipleStreams(t *testing.T, serve ServeFunc, dial DialFunc) {
	const n = 5
	srv, err := serve(func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 1)
		if _, rerr := io.ReadFull(conn, buf); rerr != nil {
			return
		}
		_, _ = conn.Write(buf) // echo the one byte back
	})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer func() { _ = srv.Close() }()

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(b byte) {
			defer wg.Done()
			cl, err := dial(srv.Addr())
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = cl.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, derr := cl.Dial(ctx)
			if derr != nil {
				errs <- derr
				return
			}
			defer func() { _ = conn.Close() }()
			if _, werr := conn.Write([]byte{b}); werr != nil {
				errs <- werr
				return
			}
			got := make([]byte, 1)
			if _, rerr := io.ReadFull(conn, got); rerr != nil {
				errs <- rerr
				return
			}
			if got[0] != b {
				errs <- io.ErrUnexpectedEOF
			}
		}(byte('a' + i))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("stream error: %v", err)
		}
	}
}

// testContextCancellation covers a caller-side cancellation reaching
// Dial promptly instead of it hanging past the caller's own deadline.
func testContextCancellation(t *testing.T, serve ServeFunc, dial DialFunc) {
	srv, err := serve(func(net.Conn) {})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer func() { _ = srv.Close() }()

	cl, err := dial(srv.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = cl.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Dial is even called
	start := time.Now()
	_, derr := cl.Dial(ctx)
	if derr == nil {
		t.Fatal("Dial with an already-cancelled context must fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Dial with a cancelled context took %s — must fail promptly, not hang", elapsed)
	}
}

// testClientCloseIdempotent covers a real usage pattern: several call
// sites in this codebase defer Close() and may also call it explicitly
// on an error path — a double Close must never panic.
func testClientCloseIdempotent(t *testing.T, serve ServeFunc, dial DialFunc) {
	srv, err := serve(func(net.Conn) {})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer func() { _ = srv.Close() }()
	cl, err := dial(srv.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = cl.Close()
	_ = cl.Close() // must not panic
}

// testServerCloseIdempotent mirrors testClientCloseIdempotent for the
// server side — task teardown (revoke/expire/shutdown) and a pair
// server's own TTL timer can both race to call Close on the same
// server.
func testServerCloseIdempotent(t *testing.T, serve ServeFunc) {
	srv, err := serve(func(net.Conn) {})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	_ = srv.Close()
	_ = srv.Close() // must not panic
}

// testNoDialAfterServerClose covers the core lifecycle guarantee every
// task/pair-server teardown depends on: once Close() returns, the
// address is genuinely dead, not just "about to become dead".
func testNoDialAfterServerClose(t *testing.T, serve ServeFunc, dial DialFunc) {
	srv, err := serve(func(net.Conn) {})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	addr := srv.Addr()
	_ = srv.Close()

	cl, err := dial(addr)
	if err != nil {
		// Some transports may fail at dial-construction time once the
		// server is gone; that's an acceptable way to satisfy this
		// contract too.
		return
	}
	defer func() { _ = cl.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, derr := cl.Dial(ctx); derr == nil {
		t.Fatal("Dial must fail once the server has been Closed")
	}
}

// testHandlerEndsOnConnectionClose covers a resource-cleanup contract:
// when the CLIENT closes its end, the server-side handler must observe
// that (via a read error) and be able to return — a handler that
// blocks forever on a dead connection would leak a goroutine per call.
func testHandlerEndsOnConnectionClose(t *testing.T, serve ServeFunc, dial DialFunc) {
	handlerDone := make(chan struct{})
	srv, err := serve(func(conn net.Conn) {
		defer close(handlerDone)
		buf := make([]byte, 1)
		_, _ = conn.Read(buf) // blocks until the client closes, then returns an error
	})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer func() { _ = srv.Close() }()

	cl, conn := dialConn(t, dial, srv.Addr())
	defer func() { _ = cl.Close() }()
	_ = conn.Close()

	select {
	case <-handlerDone:
	case <-time.After(15 * time.Second):
		t.Fatal("server-side handler never returned after the client closed its connection")
	}
}

// testConcurrentDial is a bare panic/race smoke test: many goroutines
// dialing and tearing down connections against the same server at once
// must never panic or (under -race) report a data race, independent of
// whatever else this suite checks.
func testConcurrentDial(t *testing.T, serve ServeFunc, dial DialFunc) {
	srv, err := serve(func(conn net.Conn) { _ = conn.Close() })
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	defer func() { _ = srv.Close() }()

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cl, err := dial(srv.Addr())
			if err != nil {
				return
			}
			defer func() { _ = cl.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, derr := cl.Dial(ctx)
			if derr != nil {
				return
			}
			_ = conn.Close()
		}()
	}
	wg.Wait()
}

// testNoGoroutineLeak repeats a full serve/dial/close cycle several
// times and checks the goroutine count settles back down rather than
// growing per cycle — the transport-level analogue of the pair
// package's own mint/pair/revoke leak-stress test.
func testNoGoroutineLeak(t *testing.T, serve ServeFunc, dial DialFunc) {
	const cycles = 5 // kept small: real Tailcat cycles involve a DERP round trip each
	runtime.GC()
	baseline := runtime.NumGoroutine()

	for i := 0; i < cycles; i++ {
		srv, err := serve(func(conn net.Conn) {
			buf := make([]byte, 1)
			_, _ = conn.Read(buf)
			_ = conn.Close()
		})
		if err != nil {
			t.Fatalf("cycle %d: serve: %v", i, err)
		}
		cl, conn := dialConn(t, dial, srv.Addr())
		_ = conn.Close()
		_ = cl.Close()
		_ = srv.Close()
	}

	deadline := time.Now().Add(10 * time.Second)
	var after int
	for {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= baseline+10 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if growth := after - baseline; growth > 15 {
		t.Errorf("goroutine count grew by %d after %d serve/dial/close cycles (baseline %d, after %d)",
			growth, cycles, baseline, after)
	}
}
