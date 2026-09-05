package cli

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/juntaki/catflap/internal/mcp"
)

// DefaultRendezvous returns the configured rendezvous URL, if any.
func DefaultRendezvous() string {
	return strings.TrimSpace(os.Getenv("CATFLAP_RENDEZVOUS"))
}

// MCP runs the agent-side stdio adapter. With no capability it starts
// unpaired (pair/status only) and the agent pairs at runtime — the normal
// flow. A capability may still be given up front for stored/headless setups;
// it is a bearer secret, so prefer --cap-file over argv.
func MCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	capFlag := fs.String("cap", "", "capability token (discouraged: visible in argv/history)")
	capFile := fs.String("cap-file", "", "read the capability token from this file")
	capStdin := fs.Bool("cap-stdin", false, "read the capability token from stdin")
	rendezvous := fs.String("rendezvous", DefaultRendezvous(), "rendezvous URL for short pairing codes (or $CATFLAP_RENDEZVOUS)")
	verbose := fs.Bool("verbose", false, "verbose transport logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	serve := func(capStr string) int {
		if err := mcp.Serve(capStr, *rendezvous, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "catflap mcp: %v\n", err)
			return 1
		}
		return 0
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
	if capStr == "" && *capStdin {
		// First stdin line is the token; the rest is MCP traffic on the
		// same stream. mcp.ServeReader continues from the buffered reader.
		br := bufio.NewReader(os.Stdin)
		line, err := br.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp: read --cap-stdin: %v\n", err)
			return 1
		}
		capStr = strings.TrimSpace(line)
		if err := mcp.ServeReader(capStr, br, *rendezvous, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "catflap mcp: %v\n", err)
			return 1
		}
		return 0
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
	// Empty capability is fine: start unpaired and let the agent pair.
	return serve(capStr)
}
