//go:build unix

package cli

import (
	"os"

	"golang.org/x/sys/unix"
)

// openAppendNoFollow opens path for appending without following a trailing
// symlink — the Lstat-then-open sequence it replaces is racy against
// symlink swaps, which matters for audit integrity files.
func openAppendNoFollow(path string) (*os.File, error) {
	//nolint:gosec // reason: operator-supplied anchor path; O_NOFOLLOW rejects trailing symlinks, 0600 on create.
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|unix.O_NOFOLLOW, 0o600)
}
