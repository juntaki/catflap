package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/pair"
)

// ShareCode reissues a fresh one-time pairing code for a task that is
// still live on a running `share`/`serve`, without minting a new task.
//
// The gap this closes: a pairing code is single-use (pair.Fetch
// consumes it) and an MCP server's pairing state lives only in that
// process's memory (ServeUnpaired always starts unpaired) — so if the
// agent-side process restarts (Claude quits and reopens, the machine
// sleeps, whatever) after the original code was already claimed, there
// is no way back in even though the target task itself may still have
// minutes left on its TTL. `share-code` re-publishes the SAME
// capability behind a brand new code, so the still-alive task can be
// paired again without the operator re-running `share` (which would
// tear down the old task and mint an unrelated new one).
func ShareCode(args []string) int {
	fs := flag.NewFlagSet("share-code", flag.ContinueOnError)
	statePath := fs.String("state", DefaultStatePath(), "state file written by `share`/`serve`")
	pairingTTLFlag := fs.String("pairing-ttl", pair.DefaultEnvelopeTTL.String(), "how long the new pairing code stays claimable, e.g. 5m (max 10m)")
	rendezvous := fs.String("rendezvous", "", "rendezvous URL (default: resolved chain)")
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
	rdv, rerr := ResolveRendezvous(*rendezvous)
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "rendezvous: %v\n", rerr)
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
	capRes, err := PostCapability(st.AdminAddr, st.AdminToken, taskID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "share-code: %v\n", err)
		return 1
	}
	// PostCapability already round-tripped this through capability.Decode
	// once (to validate it), but returns the encoded bearer string —
	// decode it back into the struct pair.Seal's payload must be built
	// from (see mintAndPublishPairingCode / the original shareAnnounce
	// flow this mirrors: the envelope carries the Capability's raw JSON,
	// not its "agc1_..." bearer-string encoding).
	cap, derr := capability.Decode(capRes.Capability)
	if derr != nil {
		fmt.Fprintf(os.Stderr, "share-code: decode capability: %v\n", derr)
		return 1
	}
	code, actualTTL, perr := mintAndPublishPairingCode(rdv, pairingTTL, cap)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "share-code: %v\n", perr)
		return 1
	}
	fmt.Printf(
		"New pairing code for %s (valid %s):\n  %s\n\nTell Claude:\n  Connect to Catflap using %s\n\nTask still expires: %s\n",
		taskID, actualTTL.Round(time.Second), code, code, capRes.ExpiresAt,
	)
	return 0
}
