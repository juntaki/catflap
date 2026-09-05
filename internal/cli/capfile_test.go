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
	if err := os.MkdirAll(dir, 0o755); err != nil {
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

func TestWriteCapFileNew(t *testing.T) {
	dir := capTestDir(t)
	p := filepath.Join(dir, "new.cap")
	if err := writeCapFile(p, "agc1_test", false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil || string(raw) != "agc1_test\n" {
		t.Errorf("bad content: %q, %v", raw, err)
	}
	if m := modeOf(t, p); m != 0o600 {
		t.Errorf("mode = %o, want 600", m)
	}
}

func TestWriteCapFileNoClobber(t *testing.T) {
	dir := capTestDir(t)
	p := filepath.Join(dir, "exists.cap")
	if err := os.WriteFile(p, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeCapFile(p, "agc1_new", false); err == nil {
		t.Error("existing destination without --force must be refused")
	}
	if raw, _ := os.ReadFile(p); string(raw) != "original\n" {
		t.Errorf("original clobbered: %q", raw)
	}
}

func TestWriteCapFileForceFixesMode(t *testing.T) {
	dir := capTestDir(t)
	p := filepath.Join(dir, "lax.cap")
	if err := os.WriteFile(p, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeCapFile(p, "agc1_new", true); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(p); string(raw) != "agc1_new\n" {
		t.Errorf("bad content: %q", raw)
	}
	if m := modeOf(t, p); m != 0o600 {
		t.Errorf("mode = %o, want 600 (lax mode must not survive)", m)
	}
}

func TestWriteCapFileSymlinkRefused(t *testing.T) {
	dir := capTestDir(t)
	target := filepath.Join(dir, "target.cap")
	if err := os.WriteFile(target, []byte("victim\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.cap")
	if err := os.Symlink("target.cap", link); err != nil {
		t.Fatal(err)
	}
	if err := writeCapFile(link, "agc1_evil", true); err == nil {
		t.Error("symlink destination must be refused even with --force")
	}
	if raw, _ := os.ReadFile(target); string(raw) != "victim\n" {
		t.Errorf("symlink target followed: %q", raw)
	}
}
