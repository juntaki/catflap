package cli

import (
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

// writeCapFile stores a bearer token so it never appears in argv/history.
// It writes to a temp file (0600) and renames over the target, so a
// pre-existing file with lax permissions cannot keep them: the replacement
// inode is always created 0600.
func writeCapFile(path, token string) error {
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
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(tmp)
		return cerr
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
