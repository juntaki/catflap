package cli

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// Grant mints an additional task from a running `serve` via its admin API.
func Grant(args []string) int {
	fs := flag.NewFlagSet("grant", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "YAML policy file (default: server's policy)")
	ttlFlag := fs.String("ttl", "", "TTL override, e.g. 15m")
	statePath := fs.String("state", DefaultStatePath(), "state file written by `serve`")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := LoadState(*statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grant: %v\n", err)
		return 1
	}
	var req GrantRequest
	if *policyPath != "" {
		raw, err := os.ReadFile(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "grant: %v\n", err)
			return 1
		}
		req.PolicyYAML = string(raw)
	}
	if *ttlFlag != "" {
		d, err := time.ParseDuration(*ttlFlag)
		if err != nil || d <= 0 {
			fmt.Fprintf(os.Stderr, "invalid --ttl %q\n", *ttlFlag)
			return 1
		}
		req.TTLOverrideMs = d.Milliseconds()
	}
	res, err := PostGrant(st.AdminAddr, st.AdminToken, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grant: %v\n", err)
		return 1
	}
	fmt.Printf("Task: %s\nCapability:\n%s\nExpires: %s\nPolicy: %s\n",
		res.Task, res.Capability, res.ExpiresAt, res.Policy)
	return 0
}
