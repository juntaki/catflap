package local

import (
	"testing"

	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/transporttest"
)

// TestCommonContract runs the transport-agnostic conformance suite
// against the local (loopback) transport — see
// internal/transport/transporttest for what this covers and why local
// carries no security-semantics contract of its own (there is no
// client identity on loopback TCP to restrict).
func TestCommonContract(t *testing.T) {
	transporttest.RunCommonContract(t, "local",
		func(h transport.Handler) (transport.Server, error) { return Serve(h) },
		func(addr string) (transport.Client, error) { return Dialer(addr), nil },
	)
}
