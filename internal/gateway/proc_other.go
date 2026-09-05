//go:build !unix

package gateway

import (
	"os"
	"os/exec"
)

// Non-Unix fallback: no process groups available, so only the direct child
// can be signaled. Platforms without tree-kill MUST NOT be marked stable
// for hostile workloads (§30).
func startDetached(cmd *exec.Cmd) {}

func killTree(p *os.Process) {
	if p == nil {
		return
	}
	_ = p.Kill()
}
