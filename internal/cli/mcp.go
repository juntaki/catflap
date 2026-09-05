package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/juntaki/catflap/internal/mcp"
)

// MCP runs the agent-side stdio adapter: `catflap mcp <capability>`.
func MCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	capFlag := fs.String("cap", "", "capability token (default: $CATFLAP_CAP / $AGENTGATE_CAP / argv[0])")
	verbose := fs.Bool("verbose", false, "verbose transport logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	capStr := strings.TrimSpace(*capFlag)
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
		fmt.Fprintf(os.Stderr, "usage: catflap mcp <capability>\n")
		return 2
	}
	if err := mcp.Serve(capStr, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "catflap mcp: %v\n", err)
		return 1
	}
	return 0
}
