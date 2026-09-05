// Package safefs is Catflap's dedicated filesystem layer (§15). All agent
// file access goes through it — never ad-hoc path checks in tools.
//
// Security model: every open starts from a directory file descriptor for a
// configured root and walks components one by one with O_NOFOLLOW, so a
// symlink anywhere in the path (final or intermediate) fails the open
// instead of escaping the root. On Linux the final component additionally
// goes through openat2 with RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS, with the
// dirfd walk as fallback. The access decision is tied to the object
// actually opened (fstat on the fd), not to a previously inspected pathname.
//
// Residual risks (documented, not defended): rename races by a concurrent
// local writer with write access to the tree (the agent is not such a
// writer), and non-Unix platforms, which keep EvalSymlinks pre-validation
// (§30: Windows stays experimental).
package safefs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FS confines access to a set of roots.
type FS struct {
	roots []string
	real  []string // resolved roots, aligned with roots
}

// New builds an FS over roots. Wildcard suffixes (/** etc.) are stripped;
// entries are cleaned and resolved best-effort. Unresolvable entries are
// dropped: an FS with no usable roots denies everything.
func New(roots []string) *FS {
	f := &FS{}
	for _, r := range roots {
		rr := StripWildcards(strings.TrimSpace(r))
		if rr == "" || rr == "." {
			rr = "."
		}
		abs, err := filepath.Abs(rr)
		if err != nil {
			continue
		}
		abs = filepath.Clean(abs)
		real := abs
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			real = filepath.Clean(resolved)
		}
		f.roots = append(f.roots, abs)
		f.real = append(f.real, real)
	}
	return f
}

// StripWildcards removes trailing /**, /*, * suffixes from a root.
func StripWildcards(r string) string {
	r = strings.TrimSuffix(r, "/**")
	r = strings.TrimSuffix(r, "/*")
	r = strings.TrimSuffix(r, "*")
	return r
}

// Empty reports whether the FS has no roots (deny everything).
func (f *FS) Empty() bool { return f == nil || len(f.roots) == 0 }

// split maps path to its (root index, relative components). The lexical
// containment check runs first: anything outside every root is denied
// before any syscall.
func (f *FS) split(path string) (int, []string, error) {
	if f.Empty() {
		return -1, nil, fmt.Errorf("file access is not allowed by policy")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return -1, nil, fmt.Errorf("bad path: %w", err)
	}
	abs = filepath.Clean(abs)
	for i, root := range f.roots {
		if abs == root {
			return i, nil, nil
		}
		if strings.HasPrefix(abs, root+string(filepath.Separator)) {
			rel := strings.TrimPrefix(abs, root+string(filepath.Separator))
			return i, strings.Split(rel, string(filepath.Separator)), nil
		}
	}
	return -1, nil, fmt.Errorf("path not allowed by policy")
}

// Stat stats path. The metadata comes from the securely opened object,
// so directories are described correctly too.
func (f *FS) Stat(path string) (os.FileInfo, error) {
	rootIdx, comps, err := f.split(path)
	if err != nil {
		return nil, err
	}
	return statOpened(f, rootIdx, comps, path)
}

// OpenRead opens a regular file for reading. Directories are refused
// (use Stat); symlinks anywhere in the path fail the open.
func (f *FS) OpenRead(path string) (*os.File, error) {
	rootIdx, comps, err := f.split(path)
	if err != nil {
		return nil, err
	}
	if len(comps) == 0 {
		return nil, fmt.Errorf("is a directory (use remote_stat)")
	}
	fh, err := openFile(f, rootIdx, comps, path)
	if err != nil {
		return nil, err
	}
	fi, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("stat: %w", err)
	}
	if fi.IsDir() {
		_ = fh.Close()
		return nil, fmt.Errorf("is a directory (use remote_stat)")
	}
	if !fi.Mode().IsRegular() {
		_ = fh.Close()
		return nil, fmt.Errorf("only regular files may be read")
	}
	return fh, nil
}

// WriteOptions constrains one write. Zero value denies everything.
type WriteOptions struct {
	MaxSize   int64 // max content bytes; <=0 denies
	Create    bool  // allow creating new files (parent must exist)
	Overwrite bool  // allow replacing existing files
	Atomic    bool  // write temp + fsync + rename
}

// WriteFile writes data to path under the FS roots. Regular files only;
// symlinks (final or intermediate escape) fail the open. New files are
// 0600; atomic replace of an existing file preserves its mode.
func (f *FS) WriteFile(path string, data []byte, opts WriteOptions) error {
	if f.Empty() {
		return fmt.Errorf("file write is not allowed by policy")
	}
	if opts.MaxSize <= 0 {
		return fmt.Errorf("file write is not allowed by policy")
	}
	if int64(len(data)) > opts.MaxSize {
		return fmt.Errorf("content exceeds max_file_size (%d > %d)", len(data), opts.MaxSize)
	}
	rootIdx, comps, err := f.split(path)
	if err != nil {
		return err
	}
	if len(comps) == 0 {
		return fmt.Errorf("cannot write the root itself")
	}
	return writeOpened(f, rootIdx, comps, path, data, opts)
}

// ReadAllCapped reads fh up to max+1 bytes (the +1 detects truncation).
func ReadAllCapped(fh *os.File, max int64) (data []byte, truncated bool, err error) {
	data, err = io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return data[:max], true, nil
	}
	return data, false, nil
}
