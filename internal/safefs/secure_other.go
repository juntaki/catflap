//go:build !unix

package safefs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Non-Unix fallback: pre-validate with EvalSymlinks, then open with the
// widest available guards. This is check-then-open and MUST NOT be relied
// on where TOCTOU matters (§30: non-Unix stays experimental for hostile
// workloads). The error taxonomy matches the Unix implementation so the
// gateway classifies decisions identically.
func resolveLegacy(f *FS, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("bad path: %w", err)
	}
	abs = filepath.Clean(abs)
	rootIdx := -1
	for i, root := range f.roots {
		if abs == root || strings.HasPrefix(abs, root+string(filepath.Separator)) {
			rootIdx = i
			break
		}
	}
	if rootIdx < 0 {
		return "", fmt.Errorf("path not allowed by policy")
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("symlinks are not allowed")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}
	resolved = filepath.Clean(resolved)
	realRoot := f.real[rootIdx]
	if resolved != realRoot && !strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes allowed roots (symlink traversal denied)")
	}
	return resolved, nil
}

func openFile(f *FS, rootIdx int, comps []string, display string) (*os.File, error) {
	_ = rootIdx
	_ = comps
	real, err := resolveLegacy(f, display)
	if err != nil {
		return nil, err
	}
	//nolint:gosec // reason: real passed resolveLegacy containment immediately above.
	return os.OpenFile(real, os.O_RDONLY, 0)
}

func statOpened(f *FS, rootIdx int, comps []string, display string) (os.FileInfo, error) {
	_ = rootIdx
	_ = comps
	real, err := resolveLegacy(f, display)
	if err != nil {
		return nil, err
	}
	return os.Stat(real)
}

func writeOpened(f *FS, rootIdx int, comps []string, display string, data []byte, opts WriteOptions) error {
	_ = rootIdx
	_ = comps
	if opts.MaxSize <= 0 {
		return fmt.Errorf("file write is not allowed by policy")
	}
	abs, err := filepath.Abs(display)
	if err != nil {
		return fmt.Errorf("bad path: %w", err)
	}
	abs = filepath.Clean(abs)
	// Existence/type probe without following a final symlink.
	fi, err := os.Lstat(abs)
	exists := true
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat: %w", err)
		}
		exists = false
	}
	if exists {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlinks are not allowed")
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("only regular files may be written")
		}
		if !opts.Overwrite {
			return fmt.Errorf("overwrite is not allowed by policy")
		}
		if !containedResolved(f, abs) {
			return fmt.Errorf("path escapes allowed roots (symlink traversal denied)")
		}
		if opts.Atomic {
			return writeAtomic(filepath.Dir(abs), abs, data, uint32(fi.Mode().Perm()))
		}
		//nolint:gosec // reason: abs passed containment + symlink checks above.
		fh, err := os.OpenFile(abs, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		defer func() { _ = fh.Close() }()
		if _, err := fh.Write(data); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		return nil
	}
	if !opts.Create {
		return fmt.Errorf("create is not allowed by policy")
	}
	parent := filepath.Dir(abs)
	pfi, err := os.Stat(parent)
	if err != nil || !pfi.IsDir() {
		return fmt.Errorf("parent directory does not exist")
	}
	if !containedResolved(f, parent) {
		return fmt.Errorf("path escapes allowed roots (symlink traversal denied)")
	}
	if opts.Atomic {
		return writeAtomic(filepath.Dir(abs), abs, data, 0o600)
	}
	//nolint:gosec // reason: abs passed containment; parent verified above.
	fh, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = fh.Close() }()
	if _, err := fh.Write(data); err != nil {
		_ = os.Remove(abs)
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// containedResolved reports whether path (existing) resolves inside a root.
func containedResolved(f *FS, path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	resolved = filepath.Clean(resolved)
	for _, real := range f.real {
		if resolved == real || strings.HasPrefix(resolved, real+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// writeAtomic writes data to a temp file in dir and renames over dst.
func writeAtomic(dir, dst string, data []byte, mode os.FileMode) error {
	if mode == 0 {
		mode = 0o600
	}
	tmp, err := os.CreateTemp(dir, ".catflap-write-*")
	if err != nil {
		return fmt.Errorf("temp: %w", err)
	}
	tmpName := tmp.Name()
	_ = tmp.Chmod(mode)
	failed := true
	defer func() {
		_ = tmp.Close()
		if failed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	failed = false
	return nil
}
