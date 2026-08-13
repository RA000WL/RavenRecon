package discovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The hardening tests pin the resource-lifetime invariants of the
// self-owned-pipe ExecRunner: after Run returns, nothing it spawned may
// survive — no pipe-copy goroutine, no file descriptor, no live capture
// buffer — regardless of how hostile the child was. They use real
// subprocesses (POSIX shell scripts in t.TempDir; skipped on Windows) because
// the fake-runner seam can never mask process-lifecycle defects.

// mustFinish runs fn with a hard watchdog. fn must not fail the test itself:
// it only captures results; all assertions run after mustFinish returns, so
// t.Fatalf is always called from the test goroutine. Every dangerous
// operation in the hardening and resilience tests is invoked through it.
func mustFinish(t *testing.T, timeout time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("%s did not finish within %s", what, timeout)
	}
}

// waitForTrue polls cond until it holds or patience elapses. It is the
// "patience, no tight timing" primitive: leaks are asserted by giving the
// system time to prove them, never by measuring how fast something happened.
func waitForTrue(t *testing.T, patience time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(patience)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s did not hold within %s", what, patience)
}

// readPidFile parses a pid written by a test's shell script.
func readPidFile(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("parse pid %q: %v", b, err)
	}
	return pid
}

// TestExecRunnerResourceFreezeOnEscapedWriter is the resource-freeze
// regression test: an escaped-setsid descendant keeps WRITING into the
// captured pipes after the child was killed. Bounds asserted:
//
//  1. Run returns promptly with the cancellation mapped to
//     context.DeadlineExceeded.
//  2. The returned capture is a final snapshot: samples taken 100 ms apart
//     are identical (on the pre-fix design the leaked pipe-copy goroutine
//     kept growing the capture buffer after Run returned).
//  3. Closing the runner's read ends terminates the stream structurally: the
//     escaped writer's next write hits a pipe with no readers and the writer
//     dies (patience probe on its pid). On the pre-fix design the leaked copy
//     goroutine holds the read end open, so the writer survives.
//  4. No pipe descriptors are left behind in this process (Linux).
func TestExecRunnerResourceFreezeOnEscapedWriter(t *testing.T) {
	skipOnWindows(t)
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid (util-linux) not available")
	}
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	t.Setenv("RAVEN_PIDFILE", pidFile)
	// The escaped descendant writes 2 bytes every 10 ms for ~8 s. The child
	// (the wrapper's `wait`) is killed by the process-group kill; the
	// escaped writer survives the kill — only Run's own pipe teardown can
	// terminate it.
	script := writePosixScript(t, `setsid sh -c 'i=0; while [ "$i" -lt 800 ]; do echo x; i=$((i+1)); sleep 0.01; done' &
echo $! > "$RAVEN_PIDFILE"
wait`)

	baselineFD, fdTrackable := countOpenFDs()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var res RunResult
	var err error
	mustFinish(t, 10*time.Second, "Run", func() {
		res, err = (ExecRunner{}).Run(ctx, Cmd{Path: script, Args: nil}, Limits{MaxOutput: 64})
	})
	if err == nil {
		t.Fatal("an uncatchable pipe-holding descendant must produce an error, not a hang")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want errors.Is(err, context.DeadlineExceeded), got %v", err)
	}

	// The capture returned by Run is final: the buffers were quiescent when
	// Run read them, and nothing keeps writing into them afterwards.
	first := string(res.Stdout)
	for i := 0; i < 3; i++ {
		time.Sleep(100 * time.Millisecond)
		if got := string(res.Stdout); got != first {
			t.Fatalf("capture changed after Run returned (sample %d: %q vs %q): a pipe-copy goroutine is still writing",
				i, got, first)
		}
	}

	// Structural proof that the pipes (and therefore the copy goroutines)
	// died with Run: the escaped writer is terminated by its next write into
	// a pipe with no readers. Pre-fix, the leaked copy goroutine keeps the
	// read end open and the writer survives this probe.
	pid := readPidFile(t, pidFile)
	waitForTrue(t, 3*time.Second, "escaped writer termination after Run returned", func() bool {
		return !probePidAlive(pid)
	})

	if fdTrackable {
		waitForTrue(t, 3*time.Second, "open fd count settles to baseline", func() bool {
			n, _ := countOpenFDs()
			return n == baselineFD
		})
	}
}

// TestExecRunnerChildExitHeldStdoutDrainReturnsBounded is the pipeCopies
// drain-timer deadlock regression test (review finding: CRITICAL). It drives
// the NORMAL-EXIT path with a held pipe: the direct child EXITS 0 while a
// setsid-escaped background descendant still holds exactly ONE pipe write
// end. The descendant's stderr is redirected to /dev/null so only stdout is
// held — the two-pipe asymmetry is the point: it makes the drain timer
// deterministically fire with exactly one token already consumed (done==1).
//
// On the pre-fix code this hangs forever:
//
//  1. the child is reaped first, so waitCommand's waitCh arm runs drain();
//  2. the stderr copy finishes on EOF (its pipe closed when the child
//     exited) and consumes one token (done==1);
//  3. the stdout copy stays blocked — the escaped descendant keeps writing
//     for ~8 s, long past the 1 s copyDrainBound;
//  4. the drain timer fires at done==1 and calls finish(), which performs
//     TWO receives against the ONE send still outstanding: with the read
//     ends closed the blocked copy returns and its single token is
//     consumed, then the second receive blocks forever, so drain ->
//     waitCommand -> Run never return. The 30 s context does not rescue it:
//     the ctx select arm already lost and is never re-checked. PERMANENT
//     HANG.
//
// The reason every hostile test stayed green pre-fix: they all take the
// CANCELLATION path, where finish() runs with zero prior consumption, which
// is correct. This test is the first to drive the child-reaped-first path
// with a held pipe.
//
// The bug is platform-independent — it lives in the shared drain logic in
// runner.go and would deadlock identically on Windows — but setsid does not
// exist there, so the test is POSIX-only (runtime.GOOS guard); the Windows
// build exercises the same drain code through its own subprocess tests.
//
// Post-fix, the timer path closes the read ends and reaps EXACTLY the
// remaining tokens, so Run returns around copyDrainBound plus a tiny margin.
// The 30 s context guarantees the timer path fires rather than cancellation,
// and the 6 s watchdog is safe and non-flaky because the post-fix return
// lands near 1 s. The returned Stdout capture must be stable (frozen): no
// copy goroutine may still write into it after Run returns.
//
// The CANCELLATION-path counterpart with a held pipe is already covered by
// TestExecRunnerEscapedDescendantCannotPinRun,
// TestExecRunnerEscapedDescendantWriterBoundsCapture, and
// TestExecRunnerResourceFreezeOnEscapedWriter, so no companion test is
// added.
func TestExecRunnerChildExitHeldStdoutDrainReturnsBounded(t *testing.T) {
	skipOnWindows(t)
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid (util-linux) not available")
	}
	// The direct child exits 0 immediately (it never waits for the
	// background job), so its own write ends close with it. The
	// setsid-escaped descendant writes one "x" line per 10 ms for ~8 s into
	// stdout and sends its stderr to /dev/null: exactly ONE pipe write end
	// remains held, so the stderr copy finishes on EOF, the stdout copy
	// stays blocked, and the drain timer fires at done==1.
	script := writePosixScript(t, `setsid sh -c 'i=0; while [ "$i" -lt 800 ]; do echo x; i=$((i+1)); sleep 0.01; done' 2>/dev/null & exit 0`)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var res RunResult
	var err error
	mustFinish(t, 6*time.Second, "Run", func() {
		res, err = (ExecRunner{}).Run(ctx, Cmd{Path: script, Args: nil}, Limits{})
	})
	// Bounded return is the regression itself: pre-fix this never returns
	// (the timer branch's over-receive blocks forever) and mustFinish's
	// watchdog fails the test. The error value is deliberately not further
	// constrained — the child exited 0 and was reaped first, so Run must
	// return nil or a benign structured drain error, never a cancellation
	// classification (which would mean the wrong path ran).
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned a cancellation error on the child-reaped-first path (want the drain path): %v", err)
	}
	// The capture returned by Run is final: the copy goroutines were joined
	// before Run read the buffers, so nothing keeps writing into Stdout
	// after Run returns. Pre-fix (before the hang) the same quiescence was
	// guaranteed by the same join; this pins that the fixed timer path
	// preserves it.
	first := string(res.Stdout)
	if first == "" {
		t.Fatal("stdout must contain the lines written before the drain bound")
	}
	for i := 0; i < 3; i++ {
		time.Sleep(100 * time.Millisecond)
		if got := string(res.Stdout); got != first {
			t.Fatalf("capture changed after Run returned (sample %d: %q vs %q): a pipe-copy goroutine is still writing",
				i, got, first)
		}
	}
}

// TestExecRunnerRepeatedHostileExecutionsBoundResources runs ≥15 hostile
// executions (setsid-escaped writer + short-context cancellation) through
// ExecRunner and then proves nothing accumulates: every Run returns within
// its bound, the goroutine count settles back to the baseline, and (on
// Linux) the open-fd count settles back to the baseline. Pre-fix, each
// execution leaked the Wait goroutine AND both pipe-copy goroutines (plus
// their read ends) until the escaped writer exited, so both counts grew.
func TestExecRunnerRepeatedHostileExecutionsBoundResources(t *testing.T) {
	skipOnWindows(t)
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid (util-linux) not available")
	}
	// Each iteration's descendant ESCAPES the process group and outlives the
	// run (~8 s writer loop vs 150 ms deadline), so only Run's own pipe
	// teardown can terminate it. Pre-fix, every execution leaked the Wait
	// goroutine and both pipe-copy goroutines (plus their read ends) until
	// the writer exited long after the run, so counts accumulated.
	script := writePosixScript(t, `setsid sh -c 'i=0; while [ "$i" -lt 400 ]; do echo x; i=$((i+1)); sleep 0.02; done' &
wait`)

	runtime.GC()
	baselineG := runtime.NumGoroutine()
	baselineFD, fdTrackable := countOpenFDs()

	const iters = 15
	for i := 0; i < iters; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		var err error
		mustFinish(t, 10*time.Second, fmt.Sprintf("Run %d/%d", i+1, iters), func() {
			_, err = (ExecRunner{}).Run(ctx, Cmd{Path: script, Args: nil}, Limits{})
		})
		cancel()
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Run %d: want context.DeadlineExceeded, got %v", i, err)
		}
	}

	// Patience-only leak assertions: give transient runtime goroutines a
	// chance to park, then demand the counts settle. Tolerances cover
	// harness noise; the bounds themselves are what matter.
	runtime.GC()
	waitForTrue(t, 3*time.Second, "goroutine count settles", func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= baselineG+2
	})
	if fdTrackable {
		runtime.GC()
		waitForTrue(t, 3*time.Second, "open fd count settles", func() bool {
			n, _ := countOpenFDs()
			return n <= baselineFD
		})
	}
}
