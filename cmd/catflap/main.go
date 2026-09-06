// Command catflap grants a temporary, ephemeral SSH login for AI agents.
//
//	No pre-existing network reachability, no persistent credential.
//	The access dies with the task.
package main

import (
	"fmt"
	"os"

	"github.com/juntaki/catflap/internal/buildinfo"
	"github.com/juntaki/catflap/internal/cli"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "share":
		return cli.Share(args[1:])
	case "doctor":
		return cli.Doctor(args[1:])
	case "audit":
		return cli.Audit(args[1:])
	case "mcp":
		return cli.MCP(args[1:])
	case "setup":
		return cli.Setup(args[1:])
	case "version", "--version", "-V":
		fmt.Printf("catflap %s\n", buildinfo.Version)
		return 0
	case "help", "--help", "-h":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `catflap %s — ephemeral SSH access for AI agents

Usage:
  catflap share [--ttl 30m] [--transport tailcat|local]   grant a temporary SSH login, print a pairing code
  catflap setup claude   register the (unpaired) Catflap MCP server with Claude Code
  catflap doctor         check that setup/audit are healthy

Advanced:
  catflap mcp             the Claude-side adapter (started for you by Claude Code once set up)
  catflap audit <verify|anchor> <file>   verify or anchor an audit log's hash chain

No policy, no capability file, no admin API: the OS account `+"`catflap share`"+` runs
as is what defines what an agent can do. Ctrl-C (or the TTL) ends access for good.
`, buildinfo.Version)
}
