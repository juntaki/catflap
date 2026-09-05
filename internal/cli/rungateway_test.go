package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/juntaki/catflap/internal/policy"
)

// TestSanitizeName covers the P2 fix: taskName(preferred) used to only
// strings.TrimSpace its input before it could reach the wire
// (capability.Name) and any terminal that renders a task list — an
// unrestricted name is a control-character/ANSI-escape injection vector.
// Not wired to any user-facing input yet (opts.TaskName is always ""
// today), but the choke point needs to be safe before it is.
func TestSanitizeName(t *testing.T) {
	if v, err := sanitizeName(""); err != nil || v != "" {
		t.Errorf("empty input must mean no preference: %v %q", err, v)
	}
	if v, err := sanitizeName("   "); err != nil || v != "" {
		t.Errorf("whitespace-only input must mean no preference: %v %q", err, v)
	}
	if v, err := sanitizeName("  my-task  "); err != nil || v != "my-task" {
		t.Errorf("normal name must pass through trimmed: %v %q", err, v)
	}
	if _, err := sanitizeName(strings.Repeat("a", 65)); err == nil {
		t.Error("name over 64 bytes must be rejected")
	}
	if v, err := sanitizeName(strings.Repeat("a", 64)); err != nil || v != strings.Repeat("a", 64) {
		t.Errorf("name at exactly 64 bytes must be accepted: %v", err)
	}
	badInputs := []string{
		"foo\x1b[31mbar", // ANSI escape
		"foo\nbar",       // newline
		"foo\x00bar",     // NUL
		"foo\tbar",       // tab (control, even though whitespace)
		"日本語",            // non-ASCII: ASCII allowlist is intentionally strict
		"foo\u200bbar",   // zero-width space
	}
	for _, in := range badInputs {
		if _, err := sanitizeName(in); err == nil {
			t.Errorf("sanitizeName(%q) must be rejected", in)
		}
	}
}

// TestRunGatewayValidatesInvariants covers the P1 fix: RunGateway itself
// must reject a nil/invalid policy, an unknown transport, a non-positive
// max-tasks bound, and a non-loopback admin address — these used to be
// checked only by Serve's flag-parsing path, so a second caller (share,
// once it exists) that called RunGateway directly and forgot to
// duplicate them would silently reopen every one of these holes.
func TestRunGatewayValidatesInvariants(t *testing.T) {
	validPolicy := policy.Default()
	validPolicy.TTL = time.Minute

	cases := []struct {
		name string
		opts GatewayOptions
	}{
		{"nil policy", GatewayOptions{Transport: "local", AdminAddr: "127.0.0.1:0", MaxTasks: 1, Policy: nil}},
		{"invalid policy (ttl over ceiling)", GatewayOptions{
			Transport: "local", AdminAddr: "127.0.0.1:0", MaxTasks: 1,
			Policy: func() *policy.Policy { p := policy.Default(); p.TTL = 48 * time.Hour; return p }(),
		}},
		{"unknown transport", GatewayOptions{Transport: "carrier-pigeon", AdminAddr: "127.0.0.1:0", MaxTasks: 1, Policy: validPolicy}},
		{"zero max tasks", GatewayOptions{Transport: "local", AdminAddr: "127.0.0.1:0", MaxTasks: 0, Policy: validPolicy}},
		{"non-loopback admin addr", GatewayOptions{Transport: "local", AdminAddr: "0.0.0.0:0", MaxTasks: 1, Policy: validPolicy}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc := RunGateway(c.opts, func(Announce) error { return nil })
			if rc == 0 {
				t.Errorf("RunGateway must reject %s, got exit code 0", c.name)
			}
		})
	}
}
