package sshhost_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/sshhost"
	"github.com/juntaki/catflap/internal/transport/local"
)

// dialTaskWithAudit is dialTask plus a real file-backed audit logger,
// for tests that need to read the chain back afterward.
func dialTaskWithAudit(t *testing.T, ttl time.Duration) (*sshhost.Task, *gossh.Client, string, func()) {
	t.Helper()
	auditDir := t.TempDir()
	taskID := sshhost.NewID()
	alog, err := audit.Open(auditDir, taskID, "")
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	task, err := sshhost.NewTask(context.Background(), taskID, ttl, alog)
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	srv, err := local.Serve(task.Handler())
	if err != nil {
		t.Fatalf("local.Serve: %v", err)
	}
	task.OnStopFunc(func() { _ = srv.Close() })

	clientKey := mustGenEd25519(t)
	signer, err := gossh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("wrap client key: %v", err)
	}
	task.SetAllowedKey(signer.PublicKey())

	conn, err := local.Dialer(srv.Addr()).Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	config := &gossh.ClientConfig{
		User:            "catflap",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // reason: host key pinning is covered elsewhere; this test is about process-tree containment and audit ordering.
		Timeout:         5 * time.Second,
	}
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, srv.Addr(), config)
	if err != nil {
		t.Fatalf("ssh handshake: %v", err)
	}
	client := gossh.NewClient(sshConn, chans, reqs)
	return task, client, filepath.Join(auditDir, taskID+".jsonl"), func() { _ = client.Close(); task.Stop("shutdown") }
}

// processAlive reports whether pid names a live process, via signal 0
// (no actual signal delivered, just existence/permission checked).
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// TestRevokeKillsWholeProcessTreeAndAuditsInOrder is the P1 regression
// the pivot's first cut of sshhost missed: exec.CommandContext's
// automatic cancellation only reaches the direct child (the shell) —
// without process-group containment, a grandchild the shell spawned
// (a build's worker, a backgrounded job) survives its own task's
// revoke. It also proves the in-flight command's own ssh_exec audit
// line survives — landing before the terminal task.stop event, not
// lost to the logger sealing before that write happens.
func TestRevokeKillsWholeProcessTreeAndAuditsInOrder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group containment is unix-only")
	}
	task, client, auditPath, cleanup := dialTaskWithAudit(t, time.Hour)
	defer cleanup()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if serr := sess.Start("sleep 60 & echo $!; wait"); serr != nil {
		t.Fatalf("start: %v", serr)
	}
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read grandchild pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("parse grandchild pid %q: %v", line, err)
	}
	if !processAlive(pid) {
		t.Fatalf("grandchild process %d not running before revoke", pid)
	}

	task.Stop("revoked")

	deadline := time.Now().Add(3 * time.Second)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("grandchild process %d (backgrounded by the shell, not the shell itself) still alive %s after revoke — process-group containment isn't killing the whole tree", pid, 3*time.Second)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The killed session's own ssh_exec record must have made it to the
	// audit chain, and it must come BEFORE the terminal task.stop event
	// that revoke's Stop() writes — not lost because Stop sealed the
	// logger before this session's own audit write had a chance to run.
	raw, rerr := os.ReadFile(auditPath) //nolint:gosec // reason: test-owned t.TempDir() path.
	if rerr != nil {
		t.Fatalf("read audit file: %v", rerr)
	}
	var sawExec, sawTerminalAfterExec bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e audit.Entry
		if jerr := json.Unmarshal([]byte(line), &e); jerr != nil {
			t.Fatalf("unmarshal audit line %q: %v", line, jerr)
		}
		if e.Tool == "ssh_exec" {
			sawExec = true
		}
		if e.Tool == audit.TerminalTool {
			if !sawExec {
				t.Fatal("task.stop terminal event landed before the in-flight session's own ssh_exec audit line")
			}
			sawTerminalAfterExec = true
		}
	}
	if !sawExec {
		t.Error("revoked in-flight session never wrote its own ssh_exec audit line")
	}
	if !sawTerminalAfterExec {
		t.Error("no task.stop terminal event found in the audit chain")
	}
}
