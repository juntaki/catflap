//go:build linux

package safefs

import (
	"golang.org/x/sys/unix"
)

// openFinal tries openat2 with beneath/no-symlink resolution first, so the
// final component is resolved by the kernel in one step. Unavailable or
// blocked kernels (ENOSYS/EPERM/ENOTSUP, e.g. seccomp) fall back to the
// dirfd walk open; genuine errors (EACCES, ELOOP, …) are returned.
func openFinal(dirFd int, base string, flags int, mode uint32, tryOpenat2 bool) (int, error) {
	if tryOpenat2 {
		how := &unix.OpenHow{
			Flags:   uint64(flags),
			Mode:    uint64(mode),
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		}
		fd, err := unix.Openat2(dirFd, base, how)
		if err == nil {
			return fd, nil
		}
		if err != unix.ENOSYS && err != unix.EPERM && err != unix.ENOTSUP {
			return -1, mapOpenError(err)
		}
	}
	return openFinalWalk(dirFd, base, flags, mode)
}
