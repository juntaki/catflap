package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultAuditDir returns ~/.catflap/audit (or $CATFLAP_AUDIT).
func DefaultAuditDir() string {
	if v := os.Getenv("CATFLAP_AUDIT"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./audit"
	}
	return home + "/.catflap/audit"
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
	return openAppendNoFollow(path)
}
