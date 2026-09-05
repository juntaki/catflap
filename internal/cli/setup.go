package cli

import (
	"bytes"
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
	force := fs.Bool("force", false, "re-register even if already present")
	rendezvous := fs.String("rendezvous", "", "rendezvous URL to persist (default: resolved chain)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: cannot locate catflap binary: %v\n", err)
		return 1
	}
	claude, err := exec.LookPath("claude")
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: `claude` CLI not found in PATH.\n\nRegister manually:\n%s\n", mcpManualJSON(self, ""))
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if !*force {
		// Best effort idempotency: if already listed, stop here.
		//nolint:gosec // reason: fixed argv against the operator's PATH-resolved claude binary; no agent input.
		if out, err := exec.CommandContext(ctx, claude, "mcp", "list").Output(); err == nil && bytes.Contains(out, []byte("catflap")) {
			fmt.Printf("✓ Catflap MCP already registered\n")
			return 0
		}
	} else {
		//nolint:gosec // reason: fixed argv against the operator's PATH-resolved claude binary; no agent input.
		_ = exec.CommandContext(ctx, claude, "mcp", "remove", "--scope", "user", "catflap").Run()
	}
	rdv := ResolveRendezvous(*rendezvous)
	argv := []string{"mcp", "add", "--scope", "user", "--transport", "stdio",
		"--env", "CATFLAP_RENDEZVOUS=" + rdv,
		"catflap", "--", self, "mcp"}
	//nolint:gosec // reason: fixed subcommand with the operator's own binary path and resolved rendezvous URL; no agent input.
	cmd := exec.CommandContext(ctx, claude, argv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: `claude mcp add` failed:\n%s\nRegister manually:\n%s\n", out, mcpManualJSON(self, rdv))
		return 1
	}
	fmt.Printf("✓ Claude Code found\n✓ Catflap MCP registered (user scope)\n\nSetup complete.\n\nFrom now on, start Claude normally:\n\n  claude\n")
	return 0
}

func mcpManualJSON(self, rendezvous string) string {
	env := ""
	if rendezvous != "" {
		env = fmt.Sprintf(",\n      \"env\": { \"CATFLAP_RENDEZVOUS\": %q }", rendezvous)
	}
	return fmt.Sprintf(`{
  "mcpServers": {
    "catflap": {
      "command": %q,
      "args": ["mcp"]%s
    }
  }
}`, self, env)
}
