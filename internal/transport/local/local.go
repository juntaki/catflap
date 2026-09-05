// Package local provides a loopback transport with the same interfaces
// as the Tailcat transport. Used for tests and for --transport local demos
// where no DERP round-trip is wanted.
package local

import (
	"context"
	"fmt"
	"net"

	"github.com/juntaki/catflap/internal/transport"
)

type server struct {
	ln net.Listener
}

type client struct {
	addr string
}

func Serve(handler transport.Handler) (transport.Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &server{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(c)
		}
	}()
	return s, nil
}

func (s *server) Addr() string { return s.ln.Addr().String() }

func (s *server) AddAllowedClient(identity string) error { return nil }

func (s *server) Close() error { return s.ln.Close() }

func Dialer(addr string) transport.Client { return &client{addr: addr} }

func (c *client) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("local dial: %w", err)
	}
	return conn, nil
}

func (c *client) Close() error { return nil }
