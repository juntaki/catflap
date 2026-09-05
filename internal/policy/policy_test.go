package policy

import "testing"

func TestMatchCommand(t *testing.T) {
	cases := []struct {
		pattern, cmd string
		want         bool
	}{
		{"pwd", "pwd", true},
		{"pwd", "pwd x", false},
		{"echo '*'", "echo hello", true},
		{"echo '*'", "echo 'hello world'", true},
		{`echo "*"`, "echo hello", true},
		{"echo *", "echo hello", true},
		{"systemctl status '*'", "systemctl status myapp", true},
		{"systemctl status '*'", "systemctl restart myapp", false},
		{"journalctl '*'", "journalctl -u myapp -n 50", true},
		{"cat *", "cat /var/log/myapp/app.log", true},
		{"python /opt/jobs/*", "python /opt/jobs/train.py --epochs 3", true},
		{"python /opt/jobs/*", "python /evil/x.py", false},
		{"ls *", "ls -la", true},
		{"nvidia-smi", "nvidia-smi", true},
		{"nvidia-smi", "nvidia-smi -l", false},
		{"", "echo hi", false},
		{"echo *", "", false},
		// Prefix-guard: pattern must match the whole string.
		{"echo hi", "echo hi; rm -rf /", false},
		{"echo *", "echo hi; rm -rf /", true}, // wildcard allows it: keep patterns tight
	}
	for _, c := range cases {
		if got := MatchCommand(c.pattern, c.cmd); got != c.want {
			t.Errorf("MatchCommand(%q, %q) = %v, want %v", c.pattern, c.cmd, got, c.want)
		}
	}
}

func TestParseNestedRoots(t *testing.T) {
	p, err := Parse([]byte(`
name: demo
ttl: 15m
tools:
  exec:
    commands: ["echo *"]
  file:
    read:
      roots: ["./testdata"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if !p.AllowRead("./testdata/hello.txt") {
		t.Error("expected read allowed under ./testdata")
	}
	if p.AllowRead("/etc/passwd") {
		t.Error("expected /etc/passwd denied")
	}
	if !p.AllowExec("echo hello") {
		t.Error("expected echo allowed")
	}
	if p.AllowExec("rm -rf /") {
		t.Error("expected rm denied")
	}
}
