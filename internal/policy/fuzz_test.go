package policy

import "testing"

// FuzzParse hardens the policy YAML decoder: whatever an operator's
// --policy file (or an admin /grant request's inline PolicyYAML)
// contains, Parse must never panic — and any policy it accepts must
// produce a stable CanonicalHash (called twice on the same *Policy
// must never differ) since capability minting depends on that being
// deterministic.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"version: 1\nname: x\nttl: 15m\n",
		"version: 1\nname: x\nttl: 15m\ntools:\n  exec:\n    allow:\n      - command: echo\n        rest: any\n",
		"version: 2\n",
		"version: 1\nunknown_field: true\n",
		"version: 1\n---\nversion: 1\n",
		"not: [valid, yaml: {{{",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		p, err := Parse([]byte(data))
		if err != nil {
			return
		}
		h1 := p.CanonicalHash()
		h2 := p.CanonicalHash()
		if h1 != h2 {
			t.Fatalf("CanonicalHash unstable across calls on the same policy: %q vs %q (input %q)", h1, h2, data)
		}
	})
}
