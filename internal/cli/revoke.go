package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Revoke destroys one task on the running `serve`: in-flight operations
// are cancelled, its endpoint closed, its secrets deleted. Idempotent —
// revoking an unknown or already-gone task succeeds with status "unknown".
func Revoke(args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	statePath := fs.String("state", DefaultStatePath(), "state file written by `serve`")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	taskID := ""
	if fs.NArg() > 0 {
		taskID = strings.TrimSpace(fs.Arg(0))
	}
	if taskID == "" {
		fmt.Fprintf(os.Stderr, "usage: catflap revoke <task>\n")
		return 2
	}
	st, err := LoadState(*statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "revoke: %v\n", err)
		return 1
	}
	res, err := PostRevoke(st.AdminAddr, st.AdminToken, taskID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "revoke: %v\n", err)
		return 1
	}
	fmt.Printf("Task: %s\nStatus: %s\n", res.Task, res.Status)
	return 0
}
