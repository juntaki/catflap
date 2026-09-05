//go:build unix

package gateway

import (
	"os"
	"os/exec"
	"syscall"
)

// startDetached puts the child in its own process group and arranges for
// context cancellation to SIGKILL the whole group at that instant:
//
//	task cancel → SIGKILL process group → Run returns
//
// Killing at cancel time (rather than after Run returns) leaves no window
// in which grandchildren can survive the task, and avoids signalling a
// possibly recycled PID after the child has been reaped.
func startDetached(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		killTree(cmd.Process)
		return nil
	}
}

// killTree SIGKILLs the child's process group, then the child itself.
// Missing processes are not errors. This is lifecycle containment for
// task-scoped work, not a sandbox against hostile code (§14).
func killTree(p *os.Process) {
	if p == nil {
		return
	}
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	_ = p.Kill()
}
