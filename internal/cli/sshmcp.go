package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/juntaki/catflap/internal/sshmcp"
)

// SSHMCP runs the new Claude-side stdio adapter: unpaired at startup,
// pairs at runtime via the `pair` tool and a pairing code from
// `catflap ssh-share`. Unlike the legacy MCP command there is no
// --cap/--cap-file: there is no capability file in this model, only a
// pairing code typed into the pair tool.
func SSHMCP(args []string) int {
	fs := flag.NewFlagSet("ssh-mcp", flag.ContinueOnError)
	verbose := fs.Bool("verbose", false, "verbose transport logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := sshmcp.ServeUnpaired(*verbose); err != nil {
		fmt.Fprintf(os.Stderr, "catflap ssh-mcp: %v\n", err)
		return 1
	}
	return 0
}
