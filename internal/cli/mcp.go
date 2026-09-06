package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/juntaki/catflap/internal/sshmcp"
)

// MCP runs the Claude-side stdio adapter: unpaired at startup, pairs
// at runtime via the `pair` tool and a pairing code from `catflap
// share`. There is no --cap/--cap-file: there is no capability file in
// this model, only a pairing code typed into the pair tool.
func MCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	verbose := fs.Bool("verbose", false, "verbose transport logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := sshmcp.ServeUnpaired(*verbose); err != nil {
		fmt.Fprintf(os.Stderr, "catflap mcp: %v\n", err)
		return 1
	}
	return 0
}
