//go:build unix

package gateway

import (
	"os"
	"os/exec"
	"syscall"
)

// startDetached puts the child in its own process group so killTree can
// terminate the whole tree (child + grandchildren), not just the direct
// child that os/exec would signal on context cancellation.
func startDetached(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
