// Package tailcat adapts github.com/tailscale/tailcat to the transport
// interfaces. This is the ONLY package that may import tailcat.
package tailcat

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	// Each tailscale import below carries the quarantine exception: this
	// package IS the boundary. (Directives apply per import spec.)
	"github.com/tailscale/tailcat"  //nolint:depguard // quarantine: tailcat API stays in this adapter.
	"tailscale.com/types/key"       //nolint:depguard // quarantine: tailscale types stay in this adapter.
	"tailscale.com/types/logger"    //nolint:depguard // quarantine: tailscale types stay in this adapter.
	"tailscale.com/wgengine/filter" //nolint:depguard // quarantine: tailscale types stay in this adapter.

	"github.com/juntaki/catflap/internal/transport"
)

type server struct {
	s *tailcat.Server
}

type client struct {
	c *tailcat.Client
}

// Serve starts an ephemeral Tailcat server dispatching inbound TCP
// connections on transport.RPCPort to handler. The server key and PSK
// are freshly generated; nothing is written to disk.
func Serve(handler transport.Handler, allow []string, verbose bool) (transport.Server, error) {
	var allowed []key.NodePublic
	for _, a := range allow {
		var k key.NodePublic
		if err := k.UnmarshalText([]byte(a)); err != nil {
			return nil, fmt.Errorf("invalid allowed client %q: %w", a, err)
		}
		allowed = append(allowed, k)
	}
	logf := logger.Logf(log.Printf)
	if !verbose {
		logf = logger.Discard
	}
	s := &tailcat.Server{
		Logf:           logf,
		AllowedClients: allowed,
		ServedTCPPorts: []filter.PortRange{{First: transport.RPCPort, Last: transport.RPCPort}},
		OnTCP: func(port uint16) func(net.Conn) {
			if port != transport.RPCPort {
				return nil
			}
			return func(c net.Conn) { handler(c) }
		},
	}
	if err := s.Start(); err != nil {
		return nil, fmt.Errorf("tailcat start: %w", err)
	}
	return &server{s: s}, nil
}

func (s *server) Addr() string { return string(s.s.TailcatAddr()) }

func (s *server) AddAllowedClient(identity string) error {
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(identity)); err != nil {
		return fmt.Errorf("invalid client nodekey: %w", err)
	}
	s.s.AddAllowedClient(k)
	return nil
}

func (s *server) Close() error { return s.s.Close() }

// GenerateClientKey mints a fresh ephemeral client identity and returns
// its private (keep in the capability) and public (give to AddAllowedClient) halves.
func GenerateClientKey() (privText, pubText string, err error) {
	priv := key.NewNode()
	b, err := priv.MarshalText()
	if err != nil {
		return "", "", err
	}
	pb, err := priv.Public().MarshalText()
	if err != nil {
		return "", "", err
	}
	return string(b), string(pb), nil
}

// Dialer connects back to addr using the ephemeral client identity.
func Dialer(addr, clientPrivText string, verbose bool) (transport.Client, error) {
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte(clientPrivText)); err != nil {
		return nil, fmt.Errorf("invalid client key: %w", err)
	}
	logf := logger.Logf(log.Printf)
	if !verbose {
		logf = logger.Discard
	}
	c := tailcat.NewClient(tailcat.Addr(addr))
	c.Key = priv
	c.Logf = logf
	return &client{c: c}, nil
}

func (c *client) Dial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return c.c.DialTCPPort(ctx, transport.RPCPort)
}

func (c *client) Close() error { return c.c.Close() }
