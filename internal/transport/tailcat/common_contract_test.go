package tailcat

import (
	"testing"

	"github.com/juntaki/catflap/internal/transport"
	"github.com/juntaki/catflap/internal/transport/transporttest"
)

// TestCommonContract runs the transport-agnostic conformance suite
// against real Tailcat (a real DERP round trip per dial) — see
// internal/transport/transporttest for what this covers. Skipped
// under -short: every sub-test here is a real network operation, and
// this package's security-semantics contract (allowlist enforcement,
// port restriction, identity-per-Serve) lives separately in
// security_contract_test.go.
func TestCommonContract(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a real Tailcat/DERP round trip")
	}
	transporttest.RunCommonContract(t, "tailcat",
		func(h transport.Handler) (transport.Server, error) { return Serve(h, nil, false) },
		func(addr string) (transport.Client, error) {
			priv, _, err := GenerateClientKey()
			if err != nil {
				return nil, err
			}
			return Dialer(addr, priv, false)
		},
	)
}
