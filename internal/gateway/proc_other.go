//go:build !unix

package gateway

import (
	"os"
	"os/exec"
)

// Non-Unix fallback: no process groups available, so cancellation can only
// reach the direct child. The Cancel override mirrors the stdlib default
// explicitly to keep the call site platform-uniform. Platforms without
// tree-kill MUST NOT be marked stable for hostile workloads (§30).
func startDetached(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		killTree(cmd.Process)
		return nil
	}
}

func killTree(p *os.Process) {
	if p == nil {
		return
	}
	_ = p.Kill()
}
