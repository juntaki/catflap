package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func capTestDir(t *testing.T) string {
	t.Helper()
	dir := "testdata/capfile-test"
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// readBack reads a file this test just wrote under its own temp dir.
func readBack(t *testing.T, path string) string {
	t.Helper()
	//nolint:gosec // reason: test-only readback of fixtures created by the same test.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestWriteCapFileNew(t *testing.T) {
	dir := capTestDir(t)
	p := filepath.Join(dir, "new.cap")
	if err := writeCapFile(p, "agc1_test", false); err != nil {
		t.Fatal(err)
	}
	if got := readBack(t, p); got != "agc1_test\n" {
		t.Errorf("bad content: %q", got)
	}
	if m := modeOf(t, p); m != 0o600 {
		t.Errorf("mode = %o, want 600", m)
	}
}

func TestWriteCapFileNoClobber(t *testing.T) {
	dir := capTestDir(t)
	p := filepath.Join(dir, "exists.cap")
	if err := os.WriteFile(p, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeCapFile(p, "agc1_new", false); err == nil {
		t.Error("existing destination without --force must be refused")
	}
	if got := readBack(t, p); got != "original\n" {
		t.Errorf("original clobbered: %q", got)
	}
}

func TestWriteCapFileForceFixesMode(t *testing.T) {
	dir := capTestDir(t)
	p := filepath.Join(dir, "lax.cap")
	// Deliberately lax: this fixture proves --force replaces the mode.
	//nolint:gosec // reason: intentionally insecure input to the mode-repair test; target is removed by cleanup.
	if err := os.WriteFile(p, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeCapFile(p, "agc1_new", true); err != nil {
		t.Fatal(err)
	}
	if got := readBack(t, p); got != "agc1_new\n" {
		t.Errorf("bad content: %q", got)
	}
	if m := modeOf(t, p); m != 0o600 {
		t.Errorf("mode = %o, want 600 (lax mode must not survive)", m)
	}
}

func TestWriteCapFileSymlinkRefused(t *testing.T) {
	dir := capTestDir(t)
	target := filepath.Join(dir, "target.cap")
	if err := os.WriteFile(target, []byte("victim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.cap")
	if err := os.Symlink("target.cap", link); err != nil {
		t.Fatal(err)
	}
	if err := writeCapFile(link, "agc1_evil", true); err == nil {
		t.Error("symlink destination must be refused even with --force")
	}
	if got := readBack(t, target); got != "victim\n" {
		t.Errorf("symlink target followed: %q", got)
	}
}
