package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/juntaki/catflap/internal/mcp"
)

// MCP runs the agent-side stdio adapter. The capability is a bearer secret:
// prefer --cap-file (0600) over argv, which leaks into shell history, MCP
// config files, and process listings. A capability is now optional: with
// none, the adapter starts UNPAIRED (only the pair/status tools exposed)
// and pairs at runtime via the `pair` tool and a pairing code — this is
// the path `catflap setup claude` wires up, since it registers the MCP
// server once, with no capability, before any task exists.
//
// (--cap-stdin was removed with the MCP SDK migration: stdin is the MCP
// channel and cannot also carry the token. Use --cap-file.)
func MCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	capFlag := fs.String("cap", "", "capability token (discouraged: visible in argv/history)")
	capFile := fs.String("cap-file", "", "read the capability token from this file")
	rendezvous := fs.String("rendezvous", "", "rendezvous URL for the pair tool (default: resolved chain)")
	verbose := fs.Bool("verbose", false, "verbose transport logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	capStr := strings.TrimSpace(*capFlag)
	if capStr == "" && *capFile != "" {
		raw, err := os.ReadFile(*capFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp: read --cap-file: %v\n", err)
			return 1
		}
		capStr = strings.TrimSpace(string(raw))
		// Accept "Capability:\nagc1_…" style files too: take the token line.
		for _, line := range strings.Split(capStr, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "agc1_") {
				capStr = strings.TrimSpace(line)
				break
			}
		}
	}
	if capStr == "" && fs.NArg() > 0 {
		capStr = strings.TrimSpace(fs.Arg(0))
	}
	if capStr == "" {
		capStr = strings.TrimSpace(os.Getenv("CATFLAP_CAP"))
	}
	if capStr == "" {
		capStr = strings.TrimSpace(os.Getenv("AGENTGATE_CAP"))
	}
	if capStr == "" {
		rdv, rerr := ResolveRendezvous(*rendezvous)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "mcp: rendezvous: %v\n", rerr)
			return 1
		}
		if err := mcp.ServeUnpaired(rdv, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "catflap mcp: %v\n", err)
			return 1
		}
		return 0
	}
	if err := mcp.Serve(capStr, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "catflap mcp: %v\n", err)
		return 1
	}
	return 0
}
