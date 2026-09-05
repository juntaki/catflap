package cli

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

// Tasks lists live tasks on the running `serve`/`share` in human form:
//
//	NAME              ACCESS           EXPIRES   STATE
//	calm-panda        readonly-debug   11m       active
func Tasks(args []string) int {
	fs := flag.NewFlagSet("tasks", flag.ContinueOnError)
	statePath := fs.String("state", DefaultStatePath(), "state file written by `serve`/`share`")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := LoadState(*statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tasks: %v\n", err)
		return 1
	}
	list, err := ListTasks(st.AdminAddr, st.AdminToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tasks: %v\n", err)
		return 1
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintf(w, "NAME\tACCESS\tEXPIRES\tSTATE\n"); err != nil {
		fmt.Fprintf(os.Stderr, "tasks: %v\n", err)
		return 1
	}
	for _, item := range list {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			displayName(item), item.Policy, expiresIn(item.Expires), item.State); err != nil {
			fmt.Fprintf(os.Stderr, "tasks: %v\n", err)
			return 1
		}
	}
	_ = w.Flush()
	return 0
}

func displayName(item TaskListItem) string {
	if item.Name != "" {
		return item.Name
	}
	return item.Task
}

func expiresIn(rfc3339 string) string {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return rfc3339
	}
	d := time.Until(t).Round(time.Second)
	if d <= 0 {
		return "expired"
	}
	if d >= time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	if d >= time.Minute {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
