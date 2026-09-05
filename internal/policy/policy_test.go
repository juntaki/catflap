package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func mustParse(t *testing.T, y string) *Policy {
	t.Helper()
	p, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLegacyCommandsRejected(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
name: old
ttl: 15m
tools:
  exec:
    commands: ["echo *"]
`))
	if err == nil {
		t.Fatal("legacy exec.commands must be rejected")
	}
}

// have reports whether cmd resolves on this machine. Shape-negative cases
// stay meaningful without the binary (deny is deny); shape-positive cases
// are skipped when the binary is absent.
func have(cmd string) bool {
	if filepath.IsAbs(cmd) {
		fi, err := os.Stat(cmd)
		return err == nil && !fi.IsDir() && fi.Mode().Perm()&0o111 != 0
	}
	_, err := exec.LookPath(cmd)
	return err == nil
}

func TestStructuredExec(t *testing.T) {
	p := mustParse(t, `
version: 1
name: demo
ttl: 15m
tools:
  exec:
    allow:
      - command: echo
        rest: any
      - command: journalctl
        args:
          - "-u"
          - { any: true }
          - "-n"
          - { integer: { max: 1000 } }
      - command: /bin/ls
        args:
          - { choice: ["-l", "-la"] }
      - command: python
        args:
          - { match: "/opt/jobs/*" }
      - command: pwd
`)
	cases := []struct {
		cmd  string
		argv []string
		want bool
	}{
		{"echo", []string{"hello"}, true},
		{"echo", []string{"a", "b", "c"}, true},  // rest:any
		{"echo", []string{"hi; rm -rf /"}, true}, // single argv: inert without shell
		{"echo", []string{"$(touch /tmp/x)"}, true},
		{"journalctl", []string{"-u", "myapp", "-n", "50"}, true},
		{"journalctl", []string{"-u", "myapp", "-n", "5000"}, false}, // over max
		{"journalctl", []string{"-u", "myapp"}, false},               // arity
		{"journalctl", []string{"-u", "myapp", "-n", "50", "--extra"}, false},
		{"journalctl", []string{"-x", "myapp", "-n", "50"}, false},
		{"/bin/ls", []string{"-l"}, true},
		{"ls", []string{"-l"}, false}, // rule pins absolute /bin/ls; bare "ls" differs
		{"/bin/ls", []string{"-z"}, false},
		{"python", []string{"/opt/jobs/train.py"}, true},
		{"python", []string{"/evil/x.py"}, false},
		{"pwd", nil, true},
		{"pwd", []string{"x"}, false},
		{"rm", []string{"-rf", "/"}, false},
		{"", []string{"x"}, false},
		{"echo", make([]string, 65), false}, // too many args
	}
	for _, c := range cases {
		_, got := p.MatchExec(c.cmd, c.argv)
		if c.want && !got && !have(c.cmd) {
			t.Logf("note: %s not installed here, shape-match untestable", c.cmd)
			continue
		}
		if got != c.want {
			t.Errorf("MatchExec(%q, %q) = %v, want %v", c.cmd, c.argv, got, c.want)
		}
	}
}

func TestExecutablePinning(t *testing.T) {
	p := mustParse(t, `
version: 1
name: demo
ttl: 15m
tools:
  exec:
    allow:
      - command: echo
`)
	exe1, ok := p.MatchExec("echo", nil)
	if !ok || exe1 == "" {
		t.Fatal("echo should match")
	}
	if !filepath.IsAbs(exe1) {
		t.Errorf("resolved path should be absolute, got %q", exe1)
	}
	if !have("/bin/echo") {
		t.Log("note: /bin/echo absent here, skipping absolute-form check")
		return
	}
	exe2, ok := p.MatchExec("/bin/echo", nil)
	if !ok {
		t.Fatal("absolute /bin/echo should match bare rule by base name")
	}
	if exe1 != exe2 {
		t.Errorf("pinned path should be stable: %q vs %q", exe1, exe2)
	}
}

func TestResolveReadSymlinkEscape(t *testing.T) {
	base := "testdata/symlink-case"
	_ = os.RemoveAll(base)
	if err := os.MkdirAll(base+"/root/sub", 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.WriteFile(base+"/root/sub/ok.txt", []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+"/outside-secret.txt", []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// root/outside -> parent dir (escape via intermediate symlink)
	if err := os.Symlink("..", base+"/root/outside"); err != nil {
		t.Fatal(err)
	}
	// root/linkfile -> sibling file (final-component symlink)
	if err := os.Symlink("../outside-secret.txt", base+"/root/linkfile"); err != nil {
		t.Fatal(err)
	}

	p := mustParse(t, `
version: 1
name: demo
ttl: 15m
tools:
  file:
    read: ["`+base+`/root"]
`)
	absBase, _ := filepath.Abs(base)

	if got, err := p.ResolveRead(absBase + "/root/sub/ok.txt"); err != nil {
		t.Errorf("legit file denied: %v", err)
	} else if got == "" {
		t.Error("empty resolved path")
	}
	if _, err := p.ResolveRead(absBase + "/root/outside/outside-secret.txt"); err == nil {
		t.Error("intermediate-symlink escape must be denied")
	}
	if _, err := p.ResolveRead(absBase + "/root/linkfile"); err == nil {
		t.Error("final-component symlink must be denied")
	}
	if _, err := p.ResolveRead("/etc/passwd"); err == nil {
		t.Error("outside-root path must be denied")
	}
}

func TestParseNestedRoots(t *testing.T) {
	p := mustParse(t, `
version: 1
name: demo
ttl: 15m
tools:
  exec:
    allow:
      - command: echo
  file:
    read:
      roots: ["./testdata"]
`)
	abs, _ := filepath.Abs("./testdata/hello.txt")
	if _, err := p.ResolveRead(abs); err != nil {
		// testdata/hello.txt may not exist in unit-test cwd; the gate itself
		// must pass containment — accept stat errors, reject policy denials.
		if err.Error() == "path not allowed by policy" {
			t.Errorf("expected containment to pass, got %v", err)
		}
	}
	if _, err := p.ResolveRead("/etc/passwd"); err == nil {
		t.Error("expected /etc/passwd denied")
	}
	if _, ok := p.MatchExec("echo", nil); !ok {
		t.Error("expected bare echo allowed")
	}
	if _, ok := p.MatchExec("echo", []string{"hello"}); ok {
		t.Error("rule without args/rest must deny extra argv")
	}
	if _, ok := p.MatchExec("rm", []string{"-rf", "/"}); ok {
		t.Error("expected rm denied")
	}
}

func TestSchemaVersionEnforced(t *testing.T) {
	base := `
name: demo
ttl: 15m
tools:
  exec:
    allow:
      - command: echo
`
	if _, err := Parse([]byte(base)); err == nil {
		t.Error("missing version must be rejected")
	}
	if _, err := Parse([]byte("version: 2\n" + base)); err == nil {
		t.Error("unknown version must be rejected")
	}
	if _, err := Parse([]byte("version: 1\n" + base)); err != nil {
		t.Errorf("version 1 must parse: %v", err)
	}
}

func TestUnknownFieldsRejected(t *testing.T) {
	cases := []string{
		"version: 1\nname: x\nttl: 15m\nbogus: 1\n",
		"version: 1\nname: x\nttl: 15m\ntools:\n  exec:\n    allow:\n      - command: echo\n        frobnicate: true\n",
		"version: 1\nname: x\nttl: 15m\ntools:\n  file:\n    read: [/.]\n    teleport: true\n",
		"version: 1\nname: x\nttl: 15m\nlimits:\n  warp: 9\n",
	}
	for i, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("case %d: unknown field must be rejected", i)
		}
	}
}

func TestCanonicalHashStable(t *testing.T) {
	a := mustParse(t, "version: 1\nname: demo\nttl: 15m\ntools:\n  exec:\n    allow:\n      - command: echo\n        rest: any\n")
	// Same semantics, different formatting/comments/key order.
	b := mustParse(t, "# a comment\nversion:   1\nname: demo\nttl: 15m\ntools:\n  exec:\n    allow:\n      - rest: any\n        command: echo\n")
	if string(a.Canonical()) != string(b.Canonical()) {
		t.Errorf("canonical bytes differ:\n%s\n%s", a.Canonical(), b.Canonical())
	}
	if a.CanonicalHash() != b.CanonicalHash() {
		t.Error("canonical hash must be formatting-independent")
	}
	c := mustParse(t, "version: 1\nname: demo\nttl: 30m\ntools:\n  exec:\n    allow:\n      - command: echo\n        rest: any\n")
	if a.CanonicalHash() == c.CanonicalHash() {
		t.Error("different TTL must hash differently")
	}
}
