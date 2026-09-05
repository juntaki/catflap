package mcp

import (
	"testing"

	"github.com/juntaki/catflap/internal/capability"
	"github.com/juntaki/catflap/internal/rpc"
)

func toolNames(defs []map[string]any) []string {
	var out []string
	for _, d := range defs {
		name, _ := d["name"].(string)
		out = append(out, name)
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

func serverWith(cap *capability.Capability) *Server {
	return &Server{paired: cap}
}

func TestVisibleToolsUnpaired(t *testing.T) {
	s := serverWith(nil)
	if got := toolNames(s.visibleTools()); !equalNames(got,
		[]string{UserPair, UserStatus}) {
		t.Errorf("unpaired tools = %v", got)
	}
}

func TestVisibleToolsLegacy(t *testing.T) {
	// Nil grant list = legacy capability: exec/read/stat, never write.
	s := serverWith(&capability.Capability{})
	if got := toolNames(s.visibleTools()); !equalNames(got,
		[]string{UserPair, UserStatus, UserDisconnect, UserExec, UserRead, UserStat}) {
		t.Errorf("legacy tools = %v", got)
	}
}

func TestVisibleToolsFiltered(t *testing.T) {
	s := serverWith(&capability.Capability{
		Tools: []string{rpc.ToolWrite, rpc.ToolExec},
	})
	if got := toolNames(s.visibleTools()); !equalNames(got,
		[]string{UserPair, UserStatus, UserDisconnect, UserExec, UserWrite}) {
		t.Errorf("filtered tools = %v", got)
	}
	empty := serverWith(&capability.Capability{Tools: []string{}})
	if got := toolNames(empty.visibleTools()); !equalNames(got,
		[]string{UserPair, UserStatus, UserDisconnect}) {
		t.Errorf("empty grant must hide data tools, got %v", got)
	}
}

func TestExposed(t *testing.T) {
	legacy := serverWith(&capability.Capability{})
	if !legacy.exposed(rpc.ToolExec) || legacy.exposed(rpc.ToolWrite) {
		t.Error("legacy capability must expose exec but not write")
	}
	narrow := serverWith(&capability.Capability{Tools: []string{rpc.ToolRead}})
	if narrow.exposed(rpc.ToolExec) || !narrow.exposed(rpc.ToolRead) {
		t.Error("narrow grant must expose only its tools")
	}
	if (&Server{}).exposed(rpc.ToolExec) {
		t.Error("unpaired server must expose nothing")
	}
}
