// Command catflap mints ephemeral, task-scoped capabilities for AI agents.
//
//	Give an AI agent access to a machine, not a credential.
//	The access dies with the task.
package main

import (
	"fmt"
	"os"

	"github.com/juntaki/catflap/internal/cli"
)

const version = "0.1.2"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "serve":
		return cli.Serve(args[1:])
	case "grant":
		return cli.Grant(args[1:])
	case "revoke":
		return cli.Revoke(args[1:])
	case "mcp":
		return cli.MCP(args[1:])
	case "version", "--version", "-V":
		fmt.Printf("catflap %s\n", version)
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
	fmt.Fprintf(os.Stderr, `catflap %s — ephemeral capability gateway for AI agents

Usage:
  catflap serve [--policy p.yaml] [--ttl 15m] [--transport tailcat|local]
  catflap grant [--policy p.yaml] [--ttl 15m]
  catflap revoke <task>
  catflap mcp --cap-file <cap>

Give an AI agent access to a machine, not a credential.
The access dies with the task.
`, version)
}
