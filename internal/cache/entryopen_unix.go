//go:build unix

package cache

import (
	"errors"
	"os"
	"syscall"
)

// openEntryRegular opens a cache entry for reading without ever blocking on,
// or following, a special file. O_NOFOLLOW makes a symlink open fail with
// ELOOP instead of following it, and O_NONBLOCK makes opening a FIFO with no
// writer return immediately instead of blocking forever, so a regular file
// swapped for a FIFO (or a symlink to one) between the Lstat pre-check in
// readEntry and this open can never hang a lock-free Get.
//
// The caller must still fstat the returned descriptor and verify it is a
// regular file before reading: on most platforms opening a FIFO read-only
// with O_NONBLOCK succeeds (with no writer), and only the stat of the opened
// descriptor can prove the object is a regular file. O_NONBLOCK does not
// affect reads of regular files.
func openEntryRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// isSpecialFileOpenError reports whether err means the open was refused
// because the path resolves to a special non-regular object: ELOOP (O_NOFOLLOW
// on a symlink) or ENXIO (a FIFO/device variant the platform refuses to open
// read-only). Such errors are classified as corrupt entries — a fast,
// non-blocking rejection that the normal self-healing removal path cleans up —
// rather than filesystem errors.
func isSpecialFileOpenError(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENXIO)
}
