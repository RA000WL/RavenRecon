//go:build !unix

package cache

import "os"

// openEntryRegular opens a cache entry for reading. Non-unix platforms (most
// notably Windows) have no POSIX FIFO semantics: named pipes are never opened
// read-only by an entry path (Windows refuses to open a pipe without a
// writer), and the platform's own reparse-point handling applies. The opened
// descriptor is still fstat-verified to be a regular file before anything is
// read, so non-regular objects are rejected by the same post-open check used
// on unix.
func openEntryRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

// isSpecialFileOpenError always reports false on platforms without the unix
// O_NOFOLLOW/O_NONBLOCK semantics: there is no ELOOP/ENXIO open-error class to
// map, and the opened-descriptor regular-file check is the single rejection
// mechanism.
func isSpecialFileOpenError(error) bool { return false }
