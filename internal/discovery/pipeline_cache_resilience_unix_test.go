//go:build unix

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRunFifoAtEntryPathCompletes plants a FIFO at the entry path and asserts
// the discovery layer never blocks on it: the run returns results within the
// bound, surfaces a cache-get warning, the FIFO is self-healed (removed), and
// a second run completes as a hit. Creating a FIFO requires syscall.Mkfifo,
// which exists only on POSIX platforms; the file is build-tagged unix and the
// runtime.GOOS guard skips any platform where Mkfifo is unavailable (the same
// guard pattern as internal/cache's fifo_test.go).
func TestRunFifoAtEntryPathCompletes(t *testing.T) {
	switch runtime.GOOS {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris":
		// syscall.Mkfifo is available on these platforms.
	default:
		t.Skipf("syscall.Mkfifo unsupported on %s", runtime.GOOS)
	}

	target := mustDomain(t, "example.com")
	c := openTestCache(t)
	key := keyFor(t, target, "subfinder", "v2.6.3")
	path := rawEntryPath(c, key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir shard: %v", err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	r := newFakeRunner(t, fullScript())
	cfg := testConfig(r, newFakeLookup())
	cfg.Cache = c

	var rep Report
	var runErr error
	mustFinish(t, 30*time.Second, "run with a FIFO at the entry path", func() {
		rep, runErr = Run(context.Background(), target, cfg)
	})
	if runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	res := rep.Results[0]
	if res.Cached || res.Status != OutCompleted {
		t.Fatalf("subfinder = cached %t status %s, want a fresh completed execution", res.Cached, res.Status)
	}
	if len(res.Hosts) != 2 {
		t.Fatalf("subfinder hosts = %v, want the executed payload", names(res.Hosts))
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "cache get") {
		t.Fatalf("a problematic filesystem object must surface a cache-get warning, got %v", res.Err)
	}
	// The FIFO was classified corrupt, self-healed (removed), and replaced by
	// this run's stored regular record file at the same path — never read.
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("entry path must hold the stored regular record after self-heal (lstat err %v, mode %v)", err, fi.Mode())
	}
	// Second run completes as a hit.
	rep2 := mustRun(t, target, cfg)
	if !rep2.Results[0].Cached {
		t.Fatal("run 2 must hit the recomputed record")
	}
}
