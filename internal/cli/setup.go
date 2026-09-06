package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Setup wires Catflap into an agent CLI. Currently: `catflap setup claude`
// registers the (unpaired) Catflap MCP server with Claude Code for the
// whole user account, so every project starts paired-ready. Afterwards the
// normal flow is just `claude` + a pairing code.
func Setup(args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: catflap setup claude\n")
		return 2
	}
	switch args[0] {
	case "claude":
		return setupClaude(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown setup target %q (only \"claude\")\n", args[0])
		return 2
	}
}

func setupClaude(args []string) int {
	fs := flag.NewFlagSet("setup claude", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: cannot locate catflap binary: %v\n", err)
		return 1
	}
	claude, lookErr := exec.LookPath("claude")
	if lookErr != nil {
		fmt.Fprintf(os.Stderr, "setup: `claude` CLI not found in PATH.\n\nRegister manually:\n%s\n", mcpManualJSON(self))
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Always clear any existing USER-scope registration before re-adding,
	// rather than trying to detect "already correctly registered" first.
	// Claude Code resolves MCP servers local > project > user: a
	// `claude mcp get catflap` that finds a local/project-scope entry
	// with a matching rendezvous URL would look "already set up" while
	// the user scope — the one that makes catflap work from every other
	// project — stays unregistered, silently breaking the "setup once,
	// `claude` works everywhere" promise. Setup is not a hot path, so
	// the small extra cost of an unconditional remove+add is worth the
	// certainty. A missing entry makes remove a harmless no-op.
	//nolint:gosec // reason: fixed argv against the operator's PATH-resolved claude binary; no agent input.
	_ = exec.CommandContext(ctx, claude, "mcp", "remove", "--scope", "user", "catflap").Run()

	// Every flag goes before the positional server name and its launch
	// command: `claude mcp add` stops parsing flags at the first
	// positional argument, so a flag placed after "catflap" is read as
	// another positional (or rejected) instead of a flag.
	argv := []string{
		"mcp", "add",
		"--scope", "user",
		"--transport", "stdio",
		"catflap", "--", self, "mcp",
	}
	//nolint:gosec // reason: fixed subcommand with the operator's own binary path; no agent input.
	cmd := exec.CommandContext(ctx, claude, argv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: `claude mcp add` failed:\n%s\nRegister manually:\n%s\n", out, mcpManualJSON(self))
		return 1
	}
	fmt.Printf("✓ Claude Code found\n✓ Catflap MCP registered (user scope)\n\nSetup complete.\n\nFrom now on, start Claude normally:\n\n  claude\n")
	return 0
}

func mcpManualJSON(self string) string {
	return fmt.Sprintf(`{
  "mcpServers": {
    "catflap": {
      "command": %q,
      "args": ["mcp"]
    }
  }
}`, self)
}
