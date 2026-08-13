//go:build unix

package cache

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// TestFifoAtEntryPath verifies that a FIFO planted at an entry path yields a
// non-usable outcome quickly instead of blocking Get forever (opening a FIFO
// with no writer blocks), and is removed by self-healing. Creating a FIFO
// requires syscall.Mkfifo, which exists only on POSIX platforms; the file is
// build-tagged unix, and the runtime.GOOS guard skips any platform where
// Mkfifo is unavailable.
func TestFifoAtEntryPath(t *testing.T) {
	switch runtime.GOOS {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris":
		// syscall.Mkfifo is available on these platforms.
	default:
		t.Skipf("syscall.Mkfifo unsupported on %s", runtime.GOOS)
	}

	c, key := newTestFS(t)
	path, err := c.entryPath(key)
	if err != nil {
		t.Fatalf("entryPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir shard: %v", err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	o := getWithin(t, c, key, 5*time.Second)
	if o.State != StateCorrupt {
		t.Fatalf("expected StateCorrupt for FIFO at entry path, got %s", o.State)
	}
	if o.IsUsable() {
		t.Fatal("FIFO at entry path must not be usable")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("FIFO not self-healed (lstat err %v)", err)
	}
}
