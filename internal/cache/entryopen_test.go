//go:build unix

package cache

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// openResult is the bounded-open helper's outcome.
type openResult struct {
	f   *os.File
	err error
}

// openWithin runs openEntryRegular with a watchdog, so tests can assert that
// opening a path that previously could block (a planted FIFO without a
// writer) returns promptly instead of hanging. It mirrors the getWithin
// pattern used for Get.
func openWithin(t *testing.T, path string, d time.Duration) (*os.File, error) {
	t.Helper()
	ch := make(chan openResult, 1)
	go func() { f, err := openEntryRegular(path); ch <- openResult{f, err} }()
	select {
	case r := <-ch:
		return r.f, r.err
	case <-time.After(d):
		t.Fatalf("openEntryRegular(%s) blocked longer than %s", path, d)
		return nil, nil
	}
}

// fifoSupported mirrors fifo_test.go's runtime.GOOS guard: syscall.Mkfifo is
// available on these platforms only.
func fifoSupported() bool {
	switch runtime.GOOS {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris":
		return true
	}
	return false
}

// TestOpenEntryRegularFifoDoesNotBlock is the TOCTOU-window regression test
// for the safe-open helper: a FIFO with no writer passed to openEntryRegular
// must return promptly (a plain os.Open on such a FIFO blocks forever), and
// whatever the platform returns, the object must be identifiable as
// non-regular without reading it — which is exactly what readEntry's
// opened-descriptor fstat check does with the helper's result.
func TestOpenEntryRegularFifoDoesNotBlock(t *testing.T) {
	if !fifoSupported() {
		t.Skipf("syscall.Mkfifo unsupported on %s", runtime.GOOS)
	}
	path := filepath.Join(t.TempDir(), "entry.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	f, err := openWithin(t, path, 5*time.Second)
	if err != nil {
		// Some platforms refuse the open outright (ENXIO-class); that is a
		// prompt, acceptable rejection.
		t.Logf("open of FIFO failed promptly: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("fstat opened FIFO descriptor: %v", err)
	}
	if fi.Mode().IsRegular() {
		t.Fatal("a FIFO opened through openEntryRegular must never fstat as a regular file")
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("opened descriptor mode %v, want a named pipe", fi.Mode())
	}
}

// TestOpenEntryRegularSymlinkRefused verifies O_NOFOLLOW semantics: a symlink
// at the entry path — even one pointing at a regular file — is refused with a
// prompt ELOOP-class error, never followed. This is the deterministic
// half of the swap-window guarantee (the FIFO case may legally succeed on
// some platforms, the symlink case must always fail).
func TestOpenEntryRegularSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "entry.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	f, err := openWithin(t, link, 5*time.Second)
	if f != nil {
		_ = f.Close()
		t.Fatal("openEntryRegular must not open a symlink")
	}
	if err == nil {
		t.Fatal("expected a prompt error for a symlink entry path")
	}
	if !isSpecialFileOpenError(err) {
		t.Fatalf("expected an ELOOP-class special-file error, got %v", err)
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("errors.Is(err, syscall.ELOOP) = false for %v", err)
	}
}

// TestOpenEntryRegularRegularFileControl is the positive control: the helpers
// must not disturb the common path — a regular file opens and fstats regular.
func TestOpenEntryRegularRegularFileControl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := openWithin(t, path, 5*time.Second)
	if err != nil {
		t.Fatalf("open regular file: %v", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("fstat: %v", err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("regular file fstat mode %v, want regular", fi.Mode())
	}
	if isSpecialFileOpenError(nil) {
		t.Fatal("nil error must never classify as a special-file error")
	}
}
