package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/policy"
)

// builtinProfiles maps profile names to policy builders. Shortcuts always
// compile down to Policy v1 — there is no second authorization
// implementation.
var builtinProfiles = map[string]func() *policy.Policy{
	"readonly-debug": policy.Default,
	"workspace-edit": func() *policy.Policy {
		p := policy.Default()
		p.Name = "workspace-edit"
		p.Tools.File = &policy.FilePolicy{
			Read: []string{"."},
			Write: &policy.WriteConfig{
				Roots:       []string{"."},
				MaxFileSize: 1 << 20,
				Create:      true,
				Overwrite:   true,
				Atomic:      true,
			},
		}
		return p
	},
}

type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// Share is the normal target-side entrypoint: one command mints a task,
// publishes a pairing code (or a paste-ready capability), and serves until
// SIGINT/SIGTERM.
func Share(args []string) int {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	profile := fs.String("profile", "readonly-debug", "access profile (readonly-debug|workspace-edit)")
	var reads, writes stringSlice
	fs.Var(&reads, "read", "grant a read root (repeatable; replaces profile roots)")
	fs.Var(&writes, "write", "grant a write root (repeatable; create+overwrite+atomic, 1MiB max)")
	ttlFlag := fs.String("ttl", "", "task TTL, e.g. 30m (default: profile ttl)")
	nameFlag := fs.String("name", "", "human task name (default: minted, e.g. calm-panda)")
	transportFlag := fs.String("transport", "tailcat", "transport: tailcat | local")
	auditDir := fs.String("audit", DefaultAuditDir(), "audit JSONL directory")
	statePath := fs.String("state", DefaultStatePath(), "state file for tasks/revoke coordination")
	adminAddr := fs.String("admin", "127.0.0.1:0", "loopback admin API listen address")
	maxTasks := fs.Int("max-tasks", 16, "maximum live tasks")
	rendezvous := fs.String("rendezvous", DefaultRendezvous(), "rendezvous URL for short pairing codes (or $CATFLAP_RENDEZVOUS)")
	pairingTTL := fs.String("pairing-ttl", "5m", "pairing code lifetime (max 10m)")
	verbose := fs.Bool("verbose", false, "verbose transport logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	pol, err := compileSharePolicy(*profile, reads, writes, *ttlFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "share: %v\n", err)
		return 1
	}
	pairTTL, err := time.ParseDuration(*pairingTTL)
	if err != nil || pairTTL <= 0 || pairTTL > pair.MaxEnvelopeTTL {
		fmt.Fprintf(os.Stderr, "invalid --pairing-ttl %q (max %s)\n", *pairingTTL, pair.MaxEnvelopeTTL)
		return 1
	}

	announce := func(a Announce) error {
		return announceShare(a, *rendezvous, pairTTL)
	}
	return RunGateway(GatewayOptions{
		Transport: *transportFlag, AuditDir: *auditDir, StatePath: *statePath,
		AdminAddr: *adminAddr, Verbose: *verbose, MaxTasks: *maxTasks,
		TaskName: *nameFlag, Policy: pol,
	}, announce)
}

// compileSharePolicy builds the task policy: profile base, then shortcut
// overrides, all as Policy v1.
func compileSharePolicy(profile string, reads, writes []string, ttlFlag string) (*policy.Policy, error) {
	build, ok := builtinProfiles[profile]
	if !ok {
		names := []string{}
		for name := range builtinProfiles {
			names = append(names, name)
		}
		return nil, fmt.Errorf("unknown profile %q (have: %s)", profile, strings.Join(names, ", "))
	}
	pol := build()
	if len(reads) > 0 {
		if pol.Tools.File == nil {
			pol.Tools.File = &policy.FilePolicy{}
		}
		pol.Tools.File.Read = append([]string(nil), reads...)
	}
	if len(writes) > 0 {
		if pol.Tools.File == nil {
			pol.Tools.File = &policy.FilePolicy{}
		}
		pol.Tools.File.Write = &policy.WriteConfig{
			Roots:       append([]string(nil), writes...),
			MaxFileSize: 1 << 20,
			Create:      true,
			Overwrite:   true,
			Atomic:      true,
		}
	}
	if ttlFlag != "" {
		d, err := time.ParseDuration(ttlFlag)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("invalid --ttl %q", ttlFlag)
		}
		pol.TTL = d
	}
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	return pol, nil
}

// announceShare prints the human pairing block and publishes the one-time
// envelope when a rendezvous is configured. Without one it prints the
// paste-ready capability instead (copy it into chat).
func announceShare(a Announce, rendezvous string, pairTTL time.Duration) error {
	pol := a.Task.Policy
	code := ""
	if strings.TrimSpace(rendezvous) != "" {
		c, err := publishPairing(rendezvous, a.Cap, pairTTL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "share: pairing publish failed (%v); falling back to paste block\n", err)
		} else {
			code = c
		}
	}
	fmt.Printf("Catflap access ready.\n\n")
	if code != "" {
		fmt.Printf("Pairing code:\n  %s\n\n", code)
	} else {
		fmt.Printf("Give this to Claude:\n  %s\n\n", a.Cap.Encode())
	}
	fmt.Printf("Access:\n  %s\n\nExpires:\n  %s\n\nRead:\n  %s\n\nWrite:\n  %s\n\nNetwork:\n  disabled\n",
		pol.Name, pol.TTL.Round(time.Second),
		joinOrDisabled(readRootsOf(pol)), joinOrDisabled(writeRootsOf(pol)))
	fmt.Fprintf(os.Stderr, "catflap share: task %s (%s); Ctrl-C destroys all keys\n", a.Task.ID, a.Task.Name)
	return nil
}

// publishPairing seals the capability into a one-time envelope and stores
// it at the rendezvous, returning the short human code. The sealed payload
// is the bearer token string itself, so pair() feeds it straight to adopt.
func publishPairing(rendezvous string, cap *capability.Capability, ttl time.Duration) (string, error) {
	raw := []byte(cap.Encode())
	id, key, code, err := pair.Mint()
	if err != nil {
		return "", err
	}
	env, err := pair.Seal(id, raw, key)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := pair.Publish(ctx, rendezvous, env, ttl); err != nil {
		return "", err
	}
	return code, nil
}

func readRootsOf(pol *policy.Policy) []string {
	if pol.Tools.File == nil {
		return nil
	}
	return pol.Tools.File.Read
}

func writeRootsOf(pol *policy.Policy) []string {
	if pol.Tools.File == nil || pol.Tools.File.Write == nil {
		return nil
	}
	return pol.Tools.File.Write.Roots
}

func joinOrDisabled(roots []string) string {
	if len(roots) == 0 {
		return "disabled"
	}
	return strings.Join(roots, ", ")
}
