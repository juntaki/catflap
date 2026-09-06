package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestDoctorFailsWhenClaudeCLIMissing covers a real bug: the "claude not
// found in PATH" branch printed two ✗ lines but never set ok=false,
// so Doctor() reported "Ready." (exit 0) even though nothing about
// Claude Code was actually working.
func TestDoctorFailsWhenClaudeCLIMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // guaranteed no "claude" binary anywhere on it
	t.Setenv("CATFLAP_AUDIT", filepath.Join(t.TempDir(), "audit"))

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	rc := Doctor(nil)
	_ = w.Close()
	os.Stdout = old
	_, _ = io.Copy(io.Discard, r)

	if rc != 1 {
		t.Errorf("Doctor() with no claude CLI on PATH = %d, want 1 (unhealthy)", rc)
	}
}

func TestCheckWritableCreatesAndCleansUpProbe(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	if err := checkWritable(dir); err != nil {
		t.Fatalf("checkWritable: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("checkWritable must leave no files behind, found %v", entries)
	}
}

func TestCheckWritableEmptyDirIsNotAFailure(t *testing.T) {
	// An empty audit dir means file audit is disabled by configuration,
	// not a broken setup — doctor must not flag it as unhealthy.
	if err := checkWritable(""); err != nil {
		t.Errorf("checkWritable(\"\") = %v, want nil", err)
	}
}

func TestCheckWritableFailsOnUnwritableParent(t *testing.T) {
	base := t.TempDir()
	//nolint:gosec // reason: test-owned t.TempDir() path, deliberately made unwritable to exercise the failure path.
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // reason: restoring the test-owned t.TempDir() path so cleanup can remove it.
	defer func() { _ = os.Chmod(base, 0o700) }()
	if err := checkWritable(filepath.Join(base, "audit")); err == nil {
		t.Error("checkWritable must fail when the parent directory isn't writable")
	}
}
