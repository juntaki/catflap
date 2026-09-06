package pair

import (
	"context"
	"encoding/json"
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

	raw, err := io.ReadAll(io.LimitReader(conn, MaxCapabilityBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read from pair server: %w", err)
	}
	if len(raw) > MaxCapabilityBytes {
		return nil, fmt.Errorf("pair server response too large")
	}
	var cp capability.Capability
	if jerr := json.Unmarshal(raw, &cp); jerr != nil {
		return nil, fmt.Errorf("bad capability from pair server: %w", jerr)
	}
	if cp.TaskID == "" || cp.Endpoint == "" || cp.TaskSecret == "" {
		return nil, fmt.Errorf("bad capability from pair server: missing required fields")
	}
	return &cp, nil
}
