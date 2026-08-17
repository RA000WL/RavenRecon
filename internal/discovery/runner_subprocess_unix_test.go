//go:build unix

package discovery

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// probePidAlive reports whether a process with the given pid exists
// (kill(pid, 0)), without reaping anything. It is the patient probe used by
// the resource-freeze hardening tests; a Windows stub exists so the shared
// test files compile there (those tests skip before probing).
func probePidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// Descendant-reap probe bounds. Immediately after the process-group kill
// the descendant is either a zombie waiting for its new parent's reap
// (kill(pid, 0) reports zombies as alive) or still inside the
// signal-delivery window, and it clears within milliseconds — a single
// instant probe would race that window and flake. The probe therefore
// polls until the process is gone or descendantReapBound elapses.
const (
	descendantReapBound = 2 * time.Second
	descendantReapPoll  = 25 * time.Millisecond
)

// assertDescendantReaped reads the descendant pid written by the shell
// scripts in these tests and fails unless that process is gone. It proves
// the process-group kill actually reaped the pipe-holding descendant: a
// runner that only bounded the wait (the grace path) without killing the
// group would fail here, so the F1 regression test cannot be masked by the
// grace fallback.
func assertDescendantReaped(t *testing.T, pidFile string) {
	t.Helper()
	if err := descendantReaped(pidFile); err != nil {
		t.Fatal(err)
	}
}

// descendantReaped polls until the recorded descendant process is gone
// (kill(pid, 0) reports ESRCH) or descendantReapBound elapses. Polling
// does not weaken the assertion: a descendant that genuinely SURVIVED the
// group kill (the F1 regression this assertion pins) is a `sleep 3600`
// that stays alive indefinitely, so it is still detected at the bound —
// only the milliseconds-long zombie/signal-delivery window is absorbed.
func descendantReaped(pidFile string) error {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("read descendant pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("parse descendant pid %q: %w", b, err)
	}
	deadline := time.Now().Add(descendantReapBound)
	for {
		err = syscall.Kill(pid, 0)
		if err == syscall.ESRCH {
			return nil // gone: reaped (or never existed)
		}
		if err != nil && err != syscall.EPERM {
			return fmt.Errorf("probe descendant %d: %w", pid, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("descendant process %d is still alive: the process-group kill did not reap it", pid)
		}
		time.Sleep(descendantReapPoll)
	}
}

// TestDescendantReapedDetectsSurvivor pins the FAILURE side of the
// descendant-reap poll: a descendant that genuinely survived the kill must
// still be detected at the bound, so the poll can never mask the F1
// regression assertion. The sleeper is a real `sleep 3600` that outlives
// the probe bound by a wide margin; descendantReaped must report it alive.
func TestDescendantReapedDetectsSurvivor(t *testing.T) {
	skipOnWindows(t)
	cmd := exec.Command("sleep", "3600")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleeper: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	if err := descendantReaped(pidFile); err == nil {
		t.Fatal("a live descendant must be reported as alive")
	}
}
