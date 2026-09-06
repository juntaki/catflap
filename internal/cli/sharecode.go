package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/juntaki/catflap/internal/pair"
)

// ShareCode reissues a fresh one-time pairing code for a task that is
// still live on a running `share`/`serve`, without minting a new task.
//
// The gap this closes: a pairing code is single-use (its pair server
// claims exactly one connection and self-destructs) and an MCP server's
// pairing state lives only in that process's memory (ServeUnpaired
// always starts unpaired) — so if the agent-side process restarts
// (Claude quits and reopens, the machine sleeps, whatever) after the
// original code was already claimed, there is no way back in even
// though the target task itself may still have minutes left on its
// TTL. `share-code` asks the running server to start a brand new,
// temporary pair server for the SAME task (over the admin API's /pair
// endpoint), so the still-alive task can be paired again without the
// operator re-running `share` (which would tear down the old task and
// mint an unrelated new one).
func ShareCode(args []string) int {
	fs := flag.NewFlagSet("share-code", flag.ContinueOnError)
	statePath := fs.String("state", DefaultStatePath(), "state file written by `share`/`serve`")
	pairingTTLFlag := fs.String("pairing-ttl", pair.DefaultCodeTTL.String(), "how long the new pairing code stays claimable, e.g. 5m (clamped to the task's own remaining TTL)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 || strings.TrimSpace(fs.Arg(0)) == "" {
		fmt.Fprintf(os.Stderr, "usage: catflap share-code <task|name>\n")
		return 2
	}
	pairingTTL, err := time.ParseDuration(*pairingTTLFlag)
	if err != nil || pairingTTL <= 0 {
		fmt.Fprintf(os.Stderr, "invalid --pairing-ttl %q\n", *pairingTTLFlag)
		return 1
	}

	st, err := LoadState(*statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "share-code: %v\n", err)
		return 1
	}
	taskID, err := resolveTask(st, strings.TrimSpace(fs.Arg(0)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "share-code: %v\n", err)
		return 1
	}
	res, err := PostPair(st.AdminAddr, st.AdminToken, taskID, pairingTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "share-code: %v\n", err)
		return 1
	}
	fmt.Printf(
		"New pairing code for %s (valid %s):\n  %s\n\nTell Claude:\n  Connect to Catflap using %s\n",
		taskID, (time.Duration(res.TTLMs) * time.Millisecond).Round(time.Second), res.Code, res.Code,
	)
	return 0
}
