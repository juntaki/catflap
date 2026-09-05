package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func tasksServer(t *testing.T, items []TaskListItem) *StateFile {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(items)
	}))
	t.Cleanup(srv.Close)
	return &StateFile{AdminAddr: srv.Listener.Addr().String(), AdminToken: "t"}
}

// TestResolveTaskExactIDNeverAmbiguous covers the P1 fix: resolveTask must
// try an exact task-id match first, since ids are unique by construction
// — a name or prefix collision must never shadow it.
func TestResolveTaskExactIDNeverAmbiguous(t *testing.T) {
	st := tasksServer(t, []TaskListItem{
		{Task: "agt_abc123", Name: "calm-panda"},
		{Task: "agt_abc456", Name: "calm-panda"}, // duplicate name, doesn't matter
	})
	id, err := resolveTask(st, "agt_abc123")
	if err != nil || id != "agt_abc123" {
		t.Fatalf("exact id match failed: %v %q", err, id)
	}
}

// TestResolveTaskAmbiguousNameErrors covers the P1 fix: this is a
// destructive command, so a name matching more than one live task must
// be a hard error, never "pick the first one" (Store.List's order is a
// Go map's — nondeterministic).
func TestResolveTaskAmbiguousNameErrors(t *testing.T) {
	st := tasksServer(t, []TaskListItem{
		{Task: "agt_abc123", Name: "calm-panda"},
		{Task: "agt_def456", Name: "calm-panda"},
	})
	if _, err := resolveTask(st, "calm-panda"); err == nil {
		t.Error("ambiguous name must error, not silently pick one")
	}
}

// TestResolveTaskAmbiguousPrefixErrors mirrors the name case for id
// prefixes.
func TestResolveTaskAmbiguousPrefixErrors(t *testing.T) {
	st := tasksServer(t, []TaskListItem{
		{Task: "agt_abc123", Name: "calm-panda"},
		{Task: "agt_abc456", Name: "brave-fox"},
	})
	if _, err := resolveTask(st, "agt_abc"); err == nil {
		t.Error("ambiguous id prefix must error, not silently pick one")
	}
}

func TestResolveTaskUniqueNameAndPrefix(t *testing.T) {
	st := tasksServer(t, []TaskListItem{
		{Task: "agt_abc123", Name: "calm-panda"},
		{Task: "agt_def456", Name: "brave-fox"},
	})
	if id, err := resolveTask(st, "calm-panda"); err != nil || id != "agt_abc123" {
		t.Errorf("unique name match failed: %v %q", err, id)
	}
	if id, err := resolveTask(st, "agt_def"); err != nil || id != "agt_def456" {
		t.Errorf("unique prefix match failed: %v %q", err, id)
	}
}

func TestResolveTaskUnknownPassesThrough(t *testing.T) {
	st := tasksServer(t, []TaskListItem{{Task: "agt_abc123", Name: "calm-panda"}})
	id, err := resolveTask(st, "nonexistent")
	if err != nil || id != "nonexistent" {
		t.Errorf("unknown input must pass through for the server's idempotent 404, got %v %q", err, id)
	}
}
