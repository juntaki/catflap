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

// resolveTask maps a human name or id prefix to a full task id, in strict
// precedence order: exact task id (never ambiguous — ids are unique by
// construction) > exact name > id prefix. This is a destructive command,
// so a name or prefix matching more than one live task is a hard error
// rather than "pick the first one" — Store.List's iteration order is a Go
// map's, so silently picking one would nondeterministically revoke the
// wrong task. Unknown inputs pass through: the server answers "unknown"
// idempotently.
func resolveTask(st *StateFile, nameOrID string) (string, error) {
	list, err := ListTasks(st.AdminAddr, st.AdminToken)
	if err != nil {
		return "", err
	}
	for _, item := range list {
		if item.Task == nameOrID {
			return item.Task, nil
		}
	}
	want := NormalizeName(nameOrID)
	var byName []string
	for _, item := range list {
		if NormalizeName(item.Name) == want {
			byName = append(byName, item.Task)
		}
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		// no name match: fall through to prefix match
	default:
		return "", fmt.Errorf("%q matches %d tasks by name; use the full task id", nameOrID, len(byName))
	}
	var byPrefix []string
	for _, item := range list {
		if strings.HasPrefix(item.Task, nameOrID) {
			byPrefix = append(byPrefix, item.Task)
		}
	}
	switch len(byPrefix) {
	case 1:
		return byPrefix[0], nil
	case 0:
		return nameOrID, nil
	default:
		return "", fmt.Errorf("%q matches %d tasks by id prefix; use the full task id", nameOrID, len(byPrefix))
	}
}
