// Package transport defines the narrow seam between catflap and its
// reachability layer. The rest of the codebase must only use these
// interfaces — Tailcat types must not leak past internal/transport/tailcat.
package transport

import (
	"context"
	"net"
)

// RPCPort is the single Tailcat TCP port the gateway serves.
// Fixed so ServedTCPPorts can be locked down to exactly one port.
const RPCPort uint16 = 17871

// Handler handles one inbound gateway connection (one JSONL RPC stream).
type Handler func(conn net.Conn)

// Server is a running reachability listener.
type Server interface {
	// Addr returns the dialable address to embed in capabilities
	// (a tailcat address, or host:port for local transport).
	Addr() string
	// AddAllowedClient restricts the tunnel to one more client identity.
	// The string form is transport-specific (nodekey:... for tailcat,
	// ignored for local).
	AddAllowedClient(identity string) error
	// Close shuts the listener down and destroys ephemeral keys.
	Close() error
}

// Client is a dialer back to one Server.
type Client interface {
	// Dial opens one stream to the gateway RPC port.
	Dial(ctx context.Context) (net.Conn, error)
	// Close destroys the ephemeral client identity.
	Close() error
}
