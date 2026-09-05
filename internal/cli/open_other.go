//go:build !unix

package cli

import (
	"os"
)

// openAppendNoFollow without symlink-safe open: non-Unix stays best-effort
// (§30: non-Unix is experimental for integrity-sensitive use).
func openAppendNoFollow(path string) (*os.File, error) {
	//nolint:gosec // reason: operator-supplied anchor path, append-only, 0600.
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}
