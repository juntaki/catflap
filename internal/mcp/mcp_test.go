package mcp

import (
	"testing"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/rpc"
)

// exposedNames lists the canonical tool names a grant exposes, in toolDefs
// order. It mirrors registration filtering (see Serve): a task MUST NOT
// expose a tool its policy cannot authorize.
func exposedNames(granted []string) []string {
	s := &Server{cap: &capability.Capability{Tools: granted}}
	var out []string
	for _, def := range toolDefs() {
		name, _ := def["name"].(string)
		if s.exposed(name) {
			out = append(out, name)
		}
	}
	return out
}

func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExposed(t *testing.T) {
	// Legacy (nil) capabilities: exec/read/stat, never write.
	if got := exposedNames(nil); !equalNames(got,
		[]string{rpc.ToolExec, rpc.ToolRead, rpc.ToolStat}) {
		t.Errorf("legacy tools = %v", got)
	}
	// Explicit grant: exactly the listed tools, in canonical order.
	if got := exposedNames([]string{rpc.ToolWrite, rpc.ToolExec}); !equalNames(got,
		[]string{rpc.ToolExec, rpc.ToolWrite}) {
		t.Errorf("filtered tools = %v", got)
	}
	// Empty grant: nothing visible.
	if got := exposedNames([]string{}); len(got) != 0 {
		t.Errorf("empty grant must hide all tools, got %v", got)
	}
	// Unknown names are ignored, never advertised.
	if got := exposedNames([]string{"remote_shell"}); len(got) != 0 {
		t.Errorf("unknown tools must not appear, got %v", got)
	}
	legacy := &Server{cap: &capability.Capability{}}
	if !legacy.exposed(rpc.ToolExec) || legacy.exposed(rpc.ToolWrite) {
		t.Error("legacy capability must expose exec but not write")
	}
	narrow := &Server{cap: &capability.Capability{Tools: []string{rpc.ToolRead}}}
	if narrow.exposed(rpc.ToolExec) || !narrow.exposed(rpc.ToolRead) {
		t.Error("narrow grant must expose only its tools")
	}
}
