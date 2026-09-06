package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/juntaki/catflap/internal/buildinfo"
)

// Doctor runs a handful of cheap diagnostic checks across the moving
// parts a working Catflap setup depends on (Claude Code registration,
// audit directory writability, an active target) and prints one
// aligned ✓/✗ line per check. It mutates nothing the operator cares
// about — the audit-directory check does create the directory and
// write+remove a small probe file (the same way a real task's
// audit.Open would), but leaves no trace behind.
func Doctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	statePath := fs.String("state", DefaultStatePath(), "state file to check for an active target")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ok := true
	line := func(name, status, detail string) {
		fmt.Printf("%-28s %s", name, status)
		if detail != "" {
			fmt.Printf("  %s", detail)
		}
		fmt.Println()
	}

	line("Catflap", "✓", buildinfo.Version)

	if claude, err := exec.LookPath("claude"); err == nil {
		line("Claude Code", "✓", claude)
		if registered, detail := checkClaudeRegistration(claude); registered {
			line("Claude MCP registration", "✓", detail)
		} else {
			ok = false
			line("Claude MCP registration", "✗", "run: catflap setup claude")
		}
	} else {
		ok = false
		line("Claude Code", "✗", "not found in PATH")
		line("Claude MCP registration", "✗", "n/a (no claude CLI)")
	}

	auditDir := DefaultAuditDir()
	if err := checkWritable(auditDir); err == nil {
		line("Audit directory", "✓", auditDir)
	} else {
		ok = false
		line("Audit directory", "✗", auditDir+" — "+err.Error())
	}

	if st, err := LoadState(*statePath); err == nil {
		if list, lerr := ListTasks(st.AdminAddr, st.AdminToken); lerr == nil {
			switch len(list) {
			case 0:
				line("Active target", "-", "none (no live tasks)")
			case 1:
				line("Active target", "✓", fmt.Sprintf("%s (%s)", list[0].Name, list[0].Task))
			default:
				line("Active target", "✓", fmt.Sprintf("%d live tasks — see `catflap tasks`", len(list)))
			}
		} else {
			line("Active target", "-", "no reachable share/serve")
		}
	} else {
		line("Active target", "-", "none (no state file)")
	}

	if ok {
		fmt.Println("\nReady.")
		return 0
	}
	fmt.Println("\nSome checks failed — see ✗ lines above.")
	return 1
}

// checkClaudeRegistration reports whether Claude Code has a "catflap"
// MCP server entry (any scope) — a best-effort text scan of `claude mcp
// list`'s output rather than assuming a particular subcommand shape, so
// this doesn't break the moment Claude Code's CLI adds a machine-
// readable variant.
func checkClaudeRegistration(claudePath string) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, claudePath, "mcp", "list").CombinedOutput()
	if err != nil {
		return false, "`claude mcp list` failed: " + err.Error()
	}
	for _, ln := range strings.Split(string(out), "\n") {
		if strings.Contains(ln, "catflap") {
			return true, "found in `claude mcp list`"
		}
	}
	return false, ""
}

// checkWritable reports whether dir exists (creating it if missing,
// matching what audit.Open does for a real task) and accepts a write.
func checkWritable(dir string) error {
	if dir == "" {
		return nil // file audit disabled by configuration, not a failure
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	probe := dir + "/.catflap-doctor-probe"
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return err
	}
	return os.Remove(probe)
}
