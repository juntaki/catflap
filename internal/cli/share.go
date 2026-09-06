package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/policy"
)

// Share runs the same gateway as Serve, but instead of printing a
// capability to copy by hand, it mints a one-time pairing code, seals
// the initial task's capability behind it, and publishes the sealed
// envelope to a rendezvous server. The other end pairs with `catflap
// setup claude` + the MCP `pair` tool + the printed code — no capability
// blob ever needs to be copy-pasted.
//
// Publish failure is share failure: announce returning an error is
// RunGateway's existing contract for "tear the just-minted task back
// down" (see RunGateway/mkTask) — share relies on that rather than
// duplicating a revoke call, so a capability that could never be
// fetched is never left live, and never falls back to printing itself
// to stdout as a plaintext blob.
func Share(args []string) int {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "YAML policy file (default: built-in readonly-debug)")
	ttlFlag := fs.String("ttl", "", "task TTL, e.g. 15m (default: policy ttl)")
	pairingTTLFlag := fs.String("pairing-ttl", pair.DefaultEnvelopeTTL.String(), "how long the pairing code stays claimable, e.g. 5m (independent of --ttl; max 10m)")
	name := fs.String("name", "", "preferred human name for the task (default: minted)")
	transportFlag := fs.String("transport", "tailcat", "transport: tailcat | local")
	auditDir := fs.String("audit", DefaultAuditDir(), "audit JSONL directory (empty disables file audit)")
	statePath := fs.String("state", DefaultStatePath(), "state file for `grant` coordination")
	adminAddr := fs.String("admin", "127.0.0.1:0", "loopback admin API listen address")
	maxTasks := fs.Int("max-tasks", 16, "maximum live tasks (grants beyond this fail)")
	rendezvous := fs.String("rendezvous", "", "rendezvous URL (default: resolved chain)")
	verbose := fs.Bool("verbose", false, "verbose transport logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	pol, err := loadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy: %v\n", err)
		return 1
	}
	if *ttlFlag != "" {
		ttlDur, ttlErr := time.ParseDuration(*ttlFlag)
		if ttlErr != nil || ttlDur <= 0 {
			fmt.Fprintf(os.Stderr, "invalid --ttl %q\n", *ttlFlag)
			return 1
		}
		pol.TTL = ttlDur
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

	return RunGateway(GatewayOptions{
		Transport: *transportFlag, AuditDir: *auditDir, StatePath: *statePath,
		AdminAddr: *adminAddr, Verbose: *verbose, MaxTasks: *maxTasks,
		TaskName: *name, Policy: pol,
	}, shareAnnounce(rdv, pairingTTL, pol, os.Stdout))
}

// shareAnnounce builds the announce callback RunGateway calls once the
// initial task is live: mint a pairing code, seal the task's capability
// behind it, publish the envelope, and print the code (never the
// capability itself — the pairing code only ever encodes a locator +
// wrap key, per package pair's design). Returning an error here is what
// makes "publish failed" the same as "share failed, task torn back
// down" — see RunGateway.
func shareAnnounce(rendezvousURL string, pairingTTL time.Duration, pol *policy.Policy, out io.Writer) func(Announce) error {
	return func(a Announce) error {
		code, err := mintAndPublishPairingCode(rendezvousURL, pairingTTL, a.Cap)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out,
			"Sharing %s for %s\n\nAccess\n%s\nPairing code (valid %s):\n  %s\n\nTell Claude:\n  Connect to Catflap using %s\n\nExpires: %s\n",
			a.Task.Name, pol.TTL.Round(time.Second), formatEffectiveAccess(pol),
			pairingTTL.Round(time.Second), code, code, a.Task.ExpiresAt.Format(time.RFC3339),
		)
		return nil
	}
}

// mintAndPublishPairingCode mints a fresh one-time pairing code, seals
// cap behind it, and publishes the sealed envelope to rendezvousURL —
// the same sequence `share` uses for a brand-new task, reused by
// `share-code` to reissue a new code for an already-live one. Never
// returns the capability itself, only the pairing code.
func mintAndPublishPairingCode(rendezvousURL string, pairingTTL time.Duration, cap any) (string, error) {
	id, key, code, merr := pair.Mint()
	if merr != nil {
		return "", fmt.Errorf("mint pairing code: %w", merr)
	}
	payload, jerr := json.Marshal(cap)
	if jerr != nil {
		return "", fmt.Errorf("encode capability: %w", jerr)
	}
	env, serr := pair.Seal(id, payload, key)
	if serr != nil {
		return "", fmt.Errorf("seal envelope: %w", serr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if perr := pair.Publish(ctx, rendezvousURL, env, pairingTTL); perr != nil {
		return "", fmt.Errorf("publish to rendezvous: %w", perr)
	}
	return code, nil
}

// formatEffectiveAccess renders what a policy actually grants — read
// roots, write roots, and allowed exec commands — instead of just its
// name, so the operator sees exactly what they're handing over without
// having to go read the policy YAML themselves.
func formatEffectiveAccess(pol *policy.Policy) string {
	read := "none"
	if pol.Tools.File != nil && len(pol.Tools.File.Read) > 0 {
		read = strings.Join(pol.Tools.File.Read, ", ")
	}
	write := "none"
	if pol.Tools.File != nil && pol.Tools.File.Write.Enabled() {
		write = strings.Join(pol.Tools.File.Write.Roots, ", ")
		if pol.Tools.File.Write.Approval.RequiresApproval() {
			write += " (approval required)"
		}
	}
	run := "none"
	if pol.Tools.Exec != nil && len(pol.Tools.Exec.Allow) > 0 {
		seen := map[string]bool{}
		var cmds []string
		for _, rule := range pol.Tools.Exec.Allow {
			label := rule.Command
			if rule.Approval.RequiresApproval() {
				label += "*"
			}
			if !seen[label] {
				seen[label] = true
				cmds = append(cmds, label)
			}
		}
		sort.Strings(cmds)
		run = strings.Join(cmds, ", ")
	}
	suffix := ""
	if run != "none" && strings.Contains(run, "*") {
		suffix = "\n  (* requires operator approval)"
	}
	return fmt.Sprintf("  Read   %s\n  Write  %s\n  Run    %s%s\n", read, write, run, suffix)
}
