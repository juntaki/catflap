package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/juntaki/catflap/internal/pair"
)

// Rendezvous runs a pairing rendezvous: a temporary introduction point
// that stores sealed envelopes (never plaintext) and hands each out once.
// It relays no task traffic — agents connect peer-to-peer afterward.
//
// Terminate TLS in front for public use; the server itself speaks plain
// HTTP and trusts only the TCP peer for rate limiting.
func Rendezvous(args []string) int {
	fs := flag.NewFlagSet("rendezvous", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8471", "listen address")
	maxItems := fs.Int("max-items", 10000, "maximum stored envelopes")
	pubPerMin := fs.Int("publish-per-min", 10, "per-IP publish budget per minute")
	fetchPerMin := fs.Int("fetch-per-min", 60, "per-IP fetch budget per minute")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	srv := pair.NewServer(*maxItems, *pubPerMin, *fetchPerMin)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rendezvous: listen: %v\n", err)
		return 1
	}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "catflap rendezvous: listening on %s\n", ln.Addr())
	if err := httpSrv.Serve(ln); err != nil {
		fmt.Fprintf(os.Stderr, "rendezvous: %v\n", err)
		return 1
	}
	return 0
}
