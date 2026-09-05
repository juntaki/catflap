package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func dirOf(p string) string {
	d := filepath.Dir(p)
	if d == "" {
		return "."
	}
	return d
}

// stringSliceFlag collects repeatable string flags.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error { *s = append(*s, v); return nil }

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
	return openAppendNoFollow(path)
}

// writeCapFile stores a bearer token so it never appears in argv/history.
// Secure file semantics (§10):
//
//   - the destination MUST NOT be a symlink (no following it);
//   - an existing destination is refused unless force is set;
//   - new files publish atomically without clobbering racers (temp +
//     hard link: a concurrent creator wins, the loser fails);
//   - the replacement inode is always created 0600 (a pre-existing lax mode
//     can never survive --out);
//   - explicit overwrites go through temp + fsync + rename.
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
		return replaceFile(path, []byte(token+"\n"))
	} else if !os.IsNotExist(err) {
		return err
	}
	return publishNewFile(path, []byte(token+"\n"))
}

// publishNewFile atomically publishes data at a path that must not exist.
// The temp file links into place, so concurrent publishers cannot
// overwrite each other: exactly one wins, the rest fail instead of
// hijacking. Symlink destinations are refused.
func publishNewFile(path string, data []byte) error {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink destination %q", path)
		}
		return fmt.Errorf("destination %q exists", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return err
	}
	tmp, err := writeTempFile(dirOf(path), data)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("destination %q appeared concurrently (another writer won)", path)
		}
		return err
	}
	return nil
}

// replaceFile overwrites path via temp + fsync + rename. Only for explicit
// operator overwrites (--force); the temp inode is always 0600.
func replaceFile(path string, data []byte) error {
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return err
	}
	tmp, err := writeTempFile(dirOf(path), data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func writeTempFile(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, ".catflap-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	// CreateTemp already makes 0600; belt and suspenders for odd umasks.
	_ = f.Chmod(0o600)
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		if werr != nil {
			return "", werr
		}
		if serr != nil {
			return "", serr
		}
		return "", cerr
	}
	return tmp, nil
}
