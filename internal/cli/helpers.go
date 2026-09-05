package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func io_ReadAll(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}

func dirOf(p string) string {
	d := filepath.Dir(p)
	if d == "" {
		return "."
	}
	return d
}

// openAnchorLog opens an anchor log for appending: created 0600, never
// following a symlink, never truncating.
func openAnchorLog(path string) (*os.File, error) {
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlink anchor log %q", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	//nolint:gosec // reason: operator-supplied anchor path, append-only, 0600; symlinks rejected by Lstat above.
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}

// writeCapFile stores a bearer token so it never appears in argv/history.
// Secure file semantics (§10):
//
//   - the destination MUST NOT be a symlink (no following it);
//   - an existing destination is refused unless force is set;
//   - the replacement inode is always created 0600 (a pre-existing lax mode
//     can never survive --out);
//   - write goes to a temp file with fsync, then atomic rename.
//
// On Windows, 0600 is best-effort (closest user-only ACL is future work).
func writeCapFile(path, token string, force bool) error {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink destination %q", path)
		}
		if !force {
			return fmt.Errorf("destination %q exists (use --force to overwrite)", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dirOf(path), ".cap-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// CreateTemp already makes 0600; belt and suspenders for odd umasks.
	_ = f.Chmod(0o600)
	_, werr := io.WriteString(f, token+"\n")
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		if werr != nil {
			return werr
		}
		if serr != nil {
			return serr
		}
		return cerr
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
