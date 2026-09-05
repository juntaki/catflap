//go:build unix && !linux

package safefs

// openFinal on non-Linux Unix is the dirfd walk open: every level,
// including the final component, is opened with O_NOFOLLOW, so symlinks
// anywhere fail instead of escaping the root.
func openFinal(dirFd int, base string, flags int, mode uint32, _ bool) (int, error) {
	return openFinalWalk(dirFd, base, flags, mode)
}
