//go:build unix

package safefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// writeOpened implements FS.WriteFile under an already-split path. The
// parent chain is walked with O_DIRECTORY|O_NOFOLLOW (missing parents and
// symlink escapes both fail there); the final component goes through
// openFinal. Existence and type are read off the probed fd itself, so the
// create vs overwrite decision is made on the opened object.
func writeOpened(f *FS, rootIdx int, comps []string, display string, data []byte, opts WriteOptions) error {
	root := f.roots[rootIdx]
	probeFd, probeErr := openAtRoot(root, comps, unix.O_RDONLY, 0, true)
	if probeErr == nil {
		var st unix.Stat_t
		serr := unix.Fstat(probeFd, &st)
		closeFd(probeFd)
		if serr != nil {
			return mapOpenError(serr)
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			return fmt.Errorf("cannot write a directory")
		case unix.S_IFREG:
			// proceed below
		default:
			return fmt.Errorf("only regular files may be written")
		}
		if !opts.Overwrite {
			return fmt.Errorf("overwrite is not allowed by policy")
		}
		return writeExistingAt(f, rootIdx, comps, display, data, opts)
	}
	// os.IsNotExist does not unwrap fmt %w chains around syscall.Errno;
	// errors.Is does (Errno.Is handles fs.ErrNotExist).
	if !errors.Is(probeErr, fs.ErrNotExist) {
		return probeErr
	}
	if !opts.Create {
		return fmt.Errorf("create is not allowed by policy")
	}
	return writeNewAt(f, rootIdx, comps, display, data, opts)
}

func writeNewAt(f *FS, rootIdx int, comps []string, display string, data []byte, opts WriteOptions) error {
	if opts.Atomic {
		return atomicReplace(f, rootIdx, comps, data, 0o600, true)
	}
	fd, err := openFinalAt(f, rootIdx, comps, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	// No rollback on failure: unlinking here could delete a file another
	// writer created concurrently after our exclusive create. A partial
	// 0600 file is owner-only and safe to leave for the operator.
	return writeSyncClose(fd, display, data)
}

// existingMode returns the current file mode, or an error when absent.
func existingMode(f *FS, rootIdx int, comps []string) (uint32, error) {
	fd, err := openAtRoot(f.roots[rootIdx], comps, unix.O_RDONLY, 0, true)
	if err != nil {
		return 0, err
	}
	defer closeFd(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, err
	}
	return uint32(st.Mode & 0o777), nil
}

func writeExistingAt(f *FS, rootIdx int, comps []string, display string, data []byte, opts WriteOptions) error {
	if opts.Atomic {
		mode, err := existingMode(f, rootIdx, comps)
		if err != nil {
			return err
		}
		if mode == 0 {
			mode = 0o600
		}
		return atomicReplace(f, rootIdx, comps, data, mode, false)
	}
	fd, err := openFinalAt(f, rootIdx, comps, unix.O_WRONLY|unix.O_TRUNC, 0)
	if err != nil {
		return err
	}
	return writeSyncClose(fd, display, data)
}

// openFinalAt walks to the parent and opens the final component.
func openFinalAt(f *FS, rootIdx int, comps []string, flags int, mode uint32) (int, error) {
	dirFd, err := walkParent(f.roots[rootIdx], comps[:len(comps)-1])
	if err != nil {
		return -1, err
	}
	defer closeFd(dirFd)
	base := comps[len(comps)-1]
	if !validComponent(base) {
		return -1, fmt.Errorf("bad path component %q", base)
	}
	fd, err := openFinal(dirFd, base, flags, mode, true)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

// atomicReplace writes data to a temp file beside the target (O_EXCL) and
// publishes it, all relative to the walked parent dirfd.
//
// When exclusive is set (create-only grants), publication uses linkat:
// creating the hard link fails atomically with EEXIST if the target
// appeared concurrently, so a second writer can never overwrite the first.
// Otherwise the temp file renames over the target.
func atomicReplace(f *FS, rootIdx int, comps []string, data []byte, mode uint32, exclusive bool) error {
	dirFd, err := walkParent(f.roots[rootIdx], comps[:len(comps)-1])
	if err != nil {
		return fmt.Errorf("parent directory does not exist")
	}
	defer closeFd(dirFd)
	base := comps[len(comps)-1]
	if !validComponent(base) {
		return fmt.Errorf("bad path component %q", base)
	}
	if mode == 0 {
		mode = 0o600
	}
	var tmpFd int
	var tmpName string
	created := false
	for i := 0; i < 10 && !created; i++ {
		tmpName = ".catflap-write-" + randHex(8)
		fd, err := openFinal(dirFd, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, mode, true)
		if err == nil {
			tmpFd, created = fd, true
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	if !created {
		return fmt.Errorf("temp: could not create unique temp file")
	}
	failed := true
	defer func() {
		closeFd(tmpFd)
		if failed {
			_ = unlinkAt(dirFd, tmpName)
		}
	}()
	if err := writeAll(tmpFd, data); err != nil {
		return err
	}
	if err := unix.Fsync(tmpFd); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if exclusive {
		// Atomic no-overwrite publication: link fails EEXIST when the
		// target exists, including when a concurrent create won first.
		if err := unix.Linkat(dirFd, tmpName, dirFd, base, 0); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("target already exists (concurrent create; overwrite not allowed)")
			}
			return fmt.Errorf("link: %w", err)
		}
		if err := unlinkAt(dirFd, tmpName); err != nil {
			return fmt.Errorf("temp cleanup: %w", err)
		}
		failed = false
		return nil
	}
	if err := unix.Renameat(dirFd, tmpName, dirFd, base); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	failed = false
	return nil
}

func randHex(n int) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])[:n]
}

func unlinkAt(dirFd int, name string) error {
	return unix.Unlinkat(dirFd, name, 0)
}

func writeAll(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}
		data = data[n:]
	}
	return nil
}

func writeSyncClose(fd int, display string, data []byte) error {
	fh := os.NewFile(uintptr(fd), display)
	if _, err := fh.Write(data); err != nil {
		_ = fh.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := fh.Sync(); err != nil {
		_ = fh.Close()
		return fmt.Errorf("sync: %w", err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return nil
}
