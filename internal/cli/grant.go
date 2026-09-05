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
	outPath := fs.String("out", "", "write the capability to this file (0600) instead of stdout")
	outForce := fs.Bool("force", false, "allow --out to overwrite an existing file")
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
		policyRaw, readErr := os.ReadFile(*policyPath)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "grant: %v\n", readErr)
			return 1
		}
		req.PolicyYAML = string(policyRaw)
	}
	if *ttlFlag != "" {
		ttlDur, ttlErr := time.ParseDuration(*ttlFlag)
		if ttlErr != nil || ttlDur <= 0 {
			fmt.Fprintf(os.Stderr, "invalid --ttl %q\n", *ttlFlag)
			return 1
		}
		req.TTLOverrideMs = ttlDur.Milliseconds()
	}
	res, err := PostGrant(st.AdminAddr, st.AdminToken, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grant: %v\n", err)
		return 1
	}
	if *outPath != "" {
		if err := writeCapFile(*outPath, res.Capability, *outForce); err != nil {
			fmt.Fprintf(os.Stderr, "grant: write --out: %v\n", err)
			return 1
		}
		fmt.Printf("Task: %s\nCapability: (written to %s)\nExpires: %s\nPolicy: %s\n",
			res.Task, *outPath, res.ExpiresAt, res.Policy)
		return 0
	}
	fmt.Printf("Task: %s\nCapability:\n%s\nExpires: %s\nPolicy: %s\n",
		res.Task, res.Capability, res.ExpiresAt, res.Policy)
	return 0
}
