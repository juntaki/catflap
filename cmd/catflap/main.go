// Command catflap mints ephemeral, task-scoped capabilities for AI agents.
//
//	Give an AI agent access to a machine, not a credential.
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
	case "ssh-share":
		return cli.SSHShare(args[1:])
	case "share-code":
		return cli.ShareCode(args[1:])
	case "doctor":
		return cli.Doctor(args[1:])
	case "serve":
		return cli.Serve(args[1:])
	case "grant":
		return cli.Grant(args[1:])
	case "revoke":
		return cli.Revoke(args[1:])
	case "audit":
		return cli.Audit(args[1:])
	case "mcp":
		return cli.MCP(args[1:])
	case "setup":
		return cli.Setup(args[1:])
	case "tasks":
		return cli.Tasks(args[1:])
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
	fmt.Fprintf(os.Stderr, `catflap %s — ephemeral capability gateway for AI agents

Usage:
  catflap share [--policy p.yaml] [--ttl 15m]   grant access and print a pairing code
  catflap setup claude          register the (unpaired) Catflap MCP server with Claude Code
  catflap tasks                 list live tasks on the running serve/share
  catflap share-code <task>     reissue a fresh pairing code for a still-live task
  catflap revoke <task|name>    destroy a task
  catflap doctor                check that setup/audit are all healthy

Advanced:
  catflap serve [--policy p.yaml] [--ttl 15m] [--transport tailcat|local]
  catflap grant [--policy p.yaml] [--ttl 15m]
  catflap mcp [--cap-file <cap>]   (no --cap: starts unpaired; pair with a pairing code)

Give an AI agent access to a machine, not a credential.
The access dies with the task.
`, buildinfo.Version)
}
