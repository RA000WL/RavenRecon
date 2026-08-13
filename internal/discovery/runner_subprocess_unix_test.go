//go:build unix

package discovery

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// assertDescendantReaped reads the descendant pid written by the shell
// scripts in these tests and fails unless that process is gone. It proves
// the process-group kill actually reaped the pipe-holding descendant: a
// runner that only bounded the wait (the grace path) without killing the
// group would fail here, so the F1 regression test cannot be masked by the
// grace fallback.
func assertDescendantReaped(t *testing.T, pidFile string) {
	t.Helper()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read descendant pid file: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("parse descendant pid %q: %v", b, err)
	}
	err = syscall.Kill(pid, 0)
	if err == nil {
		t.Fatalf("descendant process %d is still alive: the process-group kill did not reap it", pid)
	}
	if err != syscall.ESRCH {
		t.Fatalf("probe descendant %d: %v", pid, err)
	}
}
