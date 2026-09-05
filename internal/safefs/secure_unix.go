//go:build unix

package safefs

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// closeFd best-effort closes a raw fd. Cleanup paths have nothing useful
// to do with close errors; using one helper keeps errcheck quiet uniformly.
func closeFd(fd int) {
	_ = unix.Close(fd)
}

// openRoot opens a configured root directory. The root itself is
// operator-configured; O_NOFOLLOW|O_DIRECTORY pins it to a real directory.
func openRoot(root string) (int, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, mapOpenError(err)
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

func validComponent(c string) bool {
	return c != "" && c != "." && c != ".."
}

// walkParent opens root and descends parents (all must be real directories).
// Returns the parent dirfd owned by the caller. Empty parents yields the
// root fd itself.
func walkParent(root string, parents []string) (int, error) {
	rootFd, err := openRoot(root)
	if err != nil {
		return -1, err
	}
	dirFd := rootFd
	for _, c := range parents {
		if !validComponent(c) {
			closeFd(dirFd)
			return -1, fmt.Errorf("bad path component %q", c)
		}
		next, oerr := unix.Openat(dirFd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		closeFd(dirFd)
		if oerr != nil {
			return -1, mapOpenError(oerr)
		}
		unix.CloseOnExec(next)
		dirFd = next
	}
	return dirFd, nil
}

// openAtRoot opens comps under root: intermediates must be directories,
// the final component is opened with finalFlags/finalMode. Every level
// uses O_NOFOLLOW, so symlinks fail the open instead of escaping.
// Returns a file descriptor owned by the caller.
func openAtRoot(root string, comps []string, finalFlags int, finalMode uint32, tryOpenat2 bool) (int, error) {
	if len(comps) == 0 {
		return openRoot(root)
	}
	base := comps[len(comps)-1]
	if !validComponent(base) {
		return -1, fmt.Errorf("bad path component %q", base)
	}
	dirFd, err := walkParent(root, comps[:len(comps)-1])
	if err != nil {
		return -1, err
	}
	defer closeFd(dirFd)
	fd, err := openFinal(dirFd, base, finalFlags, finalMode, tryOpenat2)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

// openFinalWalk opens the final component with plain openat + O_NOFOLLOW.
func openFinalWalk(dirFd int, base string, flags int, mode uint32) (int, error) {
	fd, err := unix.Openat(dirFd, base, flags|unix.O_NOFOLLOW, mode)
	if err != nil {
		return -1, mapOpenError(err)
	}
	return fd, nil
}

// mapOpenError wraps syscall errors as operational failures. Policy denials
// use distinct bare messages elsewhere; anything prefixed here classifies
// as an error (not a deny) at the gateway layer.
func mapOpenError(err error) error {
	return fmt.Errorf("stat: %w", err)
}

// openFile securely opens comps for reading (O_RDONLY, no create).
func openFile(f *FS, rootIdx int, comps []string, display string) (*os.File, error) {
	fd, err := openAtRoot(f.roots[rootIdx], comps, unix.O_RDONLY, 0, true)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), display), nil
}

// statOpened stats via the securely opened object (dirs included).
func statOpened(f *FS, rootIdx int, comps []string, display string) (os.FileInfo, error) {
	fd, err := openAtRoot(f.roots[rootIdx], comps, unix.O_RDONLY, 0, true)
	if err != nil {
		return nil, err
	}
	fh := os.NewFile(uintptr(fd), display)
	fi, err := fh.Stat()
	_ = fh.Close()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	return fi, nil
}
