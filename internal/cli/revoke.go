package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Revoke destroys tasks on the running `serve`/`share`: in-flight
// operations are cancelled, endpoints closed, secrets deleted. Idempotent —
// revoking an unknown or already-gone task succeeds with status "unknown".
// Accepts task ids or human names; --all revokes every live task.
func Revoke(args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	statePath := fs.String("state", DefaultStatePath(), "state file written by `serve`")
	allFlag := fs.Bool("all", false, "revoke every live task")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := LoadState(*statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "revoke: %v\n", err)
		return 1
	}
	var ids []string
	if *allFlag {
		list, err := ListTasks(st.AdminAddr, st.AdminToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "revoke: %v\n", err)
			return 1
		}
		for _, item := range list {
			ids = append(ids, item.Task)
		}
		if len(ids) == 0 {
			fmt.Printf("no live tasks\n")
			return 0
		}
	} else {
		if fs.NArg() == 0 || strings.TrimSpace(fs.Arg(0)) == "" {
			fmt.Fprintf(os.Stderr, "usage: catflap revoke [--all] <task|name>\n")
			return 2
		}
		id, err := resolveTask(st, strings.TrimSpace(fs.Arg(0)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "revoke: %v\n", err)
			return 1
		}
		ids = []string{id}
	}
	rc := 0
	for _, id := range ids {
		res, err := PostRevoke(st.AdminAddr, st.AdminToken, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "revoke %s: %v\n", id, err)
			rc = 1
			continue
		}
		fmt.Printf("Task: %s\nStatus: %s\n", res.Task, res.Status)
	}
	return rc
}

// resolveTask maps a human name or id prefix to a full task id. Unknown
// inputs pass through: the server answers "unknown" idempotently.
func resolveTask(st *StateFile, nameOrID string) (string, error) {
	list, err := ListTasks(st.AdminAddr, st.AdminToken)
	if err != nil {
		return "", err
	}
	want := NormalizeName(nameOrID)
	for _, item := range list {
		if item.Task == nameOrID || NormalizeName(item.Name) == want {
			return item.Task, nil
		}
	}
	for _, item := range list {
		if strings.HasPrefix(item.Task, nameOrID) {
			return item.Task, nil
		}
	}
	return nameOrID, nil
}
