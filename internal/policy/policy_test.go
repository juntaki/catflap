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

func TestReadFSSymlinkEscape(t *testing.T) {
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
	fs := p.ReadFS()
	if fs == nil {
		t.Fatal("expected read FS")
	}
	absBase, _ := filepath.Abs(base)

	fh, err := fs.OpenRead(absBase + "/root/sub/ok.txt")
	if err != nil {
		t.Errorf("legit file denied: %v", err)
	} else {
		_ = fh.Close()
	}
	for _, bad := range []string{
		absBase + "/root/outside/outside-secret.txt",
		absBase + "/root/linkfile",
		"/etc/passwd",
	} {
		if fh, err := fs.OpenRead(bad); err == nil {
			_ = fh.Close()
			t.Errorf("escape must be denied: %s", bad)
		}
		if _, err := fs.Stat(bad); err == nil {
			t.Errorf("escape (stat) must be denied: %s", bad)
		}
	}
	if p.WriteFS() != nil {
		t.Error("absent file.write must yield nil FS (default deny)")
	}
}

func TestWriteConfigParse(t *testing.T) {
	p := mustParse(t, `
version: 1
name: demo
ttl: 15m
tools:
  file:
    read: ["./testdata"]
    write:
      roots: ["./testdata/work"]
      max_file_size: 1024
      create: true
      overwrite: false
      atomic: true
`)
	wc := p.Tools.File.Write
	if wc == nil {
		t.Fatal("expected write config")
	}
	if len(wc.Roots) != 1 || wc.MaxFileSize != 1024 || !wc.Create || wc.Overwrite || !wc.Atomic {
		t.Errorf("bad write config: %+v", wc)
	}
	if p.WriteFS() == nil {
		t.Error("expected write FS")
	}
	opts := wc.Options()
	if opts.MaxSize != 1024 || !opts.Create || opts.Overwrite || !opts.Atomic {
		t.Errorf("bad write options: %+v", opts)
	}

	// Legacy roots-only form: present but all ops denied.
	legacy := mustParse(t, `
version: 1
name: demo
ttl: 15m
tools:
  file:
    write: ["./testdata/work"]
`)
	if legacy.Tools.File.Write == nil || len(legacy.Tools.File.Write.Roots) != 1 {
		t.Fatal("expected legacy write roots")
	}
	if opts := legacy.Tools.File.Write.Options(); opts.Create || opts.Overwrite || opts.MaxSize != 0 {
		t.Errorf("legacy form must deny all ops: %+v", opts)
	}

	// Unknown write keys fail closed.
	if _, err := Parse([]byte("version: 1\nname: x\nttl: 15m\ntools:\n  file:\n    write:\n      roots: [/.]\n      teleport: true\n")); err == nil {
		t.Error("unknown file.write key must be rejected")
	}
	// Write without roots fails validation.
	if _, err := Parse([]byte("version: 1\nname: x\nttl: 15m\ntools:\n  file:\n    write:\n      create: true\n")); err == nil {
		t.Error("file.write without roots must be rejected")
	}
	// Write sizes obey the same transport ceiling.
	if _, err := Parse([]byte("version: 1\nname: x\nttl: 15m\ntools:\n  file:\n    write:\n      roots: [/.]\n      max_file_size: 2097152\n")); err == nil {
		t.Error("file.write above 1MiB must be rejected")
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
	if fh, err := p.ReadFS().OpenRead(abs); err != nil {
		// testdata/hello.txt may not exist in unit-test cwd; the gate itself
		// must pass containment — accept stat errors, reject policy denials.
		if err.Error() == "path not allowed by policy" {
			t.Errorf("expected containment to pass, got %v", err)
		}
	} else {
		_ = fh.Close()
	}
	if _, err := p.ReadFS().Stat("/etc/passwd"); err == nil {
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

func TestLimitsParseAndDefaults(t *testing.T) {
	p := mustParse(t, `
version: 1
name: demo
ttl: 15m
limits:
  max_concurrent_calls: 2
  max_exec_duration: 60s
  max_stdout_bytes: 1024
  max_stderr_bytes: 512
  max_read_bytes: 2048
tools:
  exec:
    allow:
      - command: echo
`)
	lim := p.EffectiveLimits()
	if lim.MaxConcurrentCalls != 2 || lim.MaxExecDuration != 60_000_000_000 ||
		lim.MaxStdoutBytes != 1024 || lim.MaxStderrBytes != 512 || lim.MaxReadBytes != 2048 {
		t.Errorf("bad effective limits: %+v", lim)
	}

	// Omitted limits take built-in defaults.
	bare := mustParse(t, "version: 1\nname: x\nttl: 15m\n")
	if bare.EffectiveLimits() != DefaultLimits() {
		t.Errorf("omitted limits must equal defaults: %+v", bare.EffectiveLimits())
	}
	// Omitted vs explicit-defaults hash equal (same enforcement semantics).
	explicit := mustParse(t, "version: 1\nname: x\nttl: 15m\nlimits:\n  max_concurrent_calls: 4\n  max_exec_duration: 120s\n  max_stdout_bytes: 262144\n  max_stderr_bytes: 65536\n  max_read_bytes: 1048576\n")
	if bare.CanonicalHash() != explicit.CanonicalHash() {
		t.Error("omitted limits must hash like explicit defaults")
	}
	// Distinct limits hash distinctly.
	other := mustParse(t, "version: 1\nname: x\nttl: 15m\nlimits:\n  max_concurrent_calls: 1\n")
	if bare.CanonicalHash() == other.CanonicalHash() {
		t.Error("distinct limits must hash distinctly")
	}

	// Out-of-range limits fail closed.
	for _, y := range []string{
		"version: 1\nname: x\nttl: 15m\nlimits:\n  max_concurrent_calls: 0\n",
		"version: 1\nname: x\nttl: 15m\nlimits:\n  max_concurrent_calls: 65\n",
		"version: 1\nname: x\nttl: 15m\nlimits:\n  max_exec_duration: 500ms\n",
		"version: 1\nname: x\nttl: 15m\nlimits:\n  max_exec_duration: 31m\n",
		"version: 1\nname: x\nttl: 15m\nlimits:\n  max_exec_duration: soon\n",
		"version: 1\nname: x\nttl: 15m\nlimits:\n  max_read_bytes: 0\n",
		"version: 1\nname: x\nttl: 15m\nlimits:\n  max_read_bytes: 99999999\n",
		"version: 1\nname: x\nttl: 15m\nlimits:\n  max_read_bytes: big\n",
		// Transport ceiling: results travel in one 2MiB frame, so no
		// grant may promise more than fits (chunking is future work).
		"version: 1\nname: x\nttl: 15m\nlimits:\n  max_stdout_bytes: 2097152\n",
		"version: 1\nname: x\nttl: 15m\nlimits:\n  max_read_bytes: 2097152\n",
		"version: 1\nname: x\nttl: 15m\nlimits:\n  warp_drive: 9\n",
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("bad limits must be rejected: %q", y)
		}
	}
	// 1MiB is the ceiling and parses.
	m := mustParse(t, "version: 1\nname: x\nttl: 15m\nlimits:\n  max_read_bytes: 1048576\n")
	if m.EffectiveLimits().MaxReadBytes != 1048576 {
		t.Error("1MiB must be accepted")
	}
}
