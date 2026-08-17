package discovery

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/cache"
)

// The real-subprocess regression tests exercise ExecRunner (and the pipeline
// through it) with actual child processes: POSIX shell scripts written into
// t.TempDir. The fake-runner seam used by the pipeline tests can never mask
// process-lifecycle defects, so the two production defects found in review —
// a cancelled run whose descendant keeps Cmd.Wait blocked on pipe EOF (F1),
// and the killed-child classification that never mapped to the context error
// (F2) — are pinned here with real processes. Tests that need POSIX shell
// semantics skip on Windows (runtime.GOOS guard); they still compile there.

// writePosixScript writes an executable POSIX shell script into a fresh
// t.TempDir directory and returns its path.
func writePosixScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tool.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return p
}

// skipOnWindows marks tests whose subprocess semantics (sh, setsid, POSIX
// signal/kill behavior) do not exist on Windows.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell subprocess semantics are not available on windows")
	}
}

// assertPromptReturn fails the test when the measurement reaches bound. The
// bounds are intentionally generous: these tests assert boundedness (a hang
// is a failure), not latency precision, so they must not be flaky on slow
// machines.
func assertPromptReturn(t *testing.T, start time.Time, bound time.Duration, what string) {
	t.Helper()
	if elapsed := time.Since(start); elapsed >= bound {
		t.Fatalf("%s took %s to return; want completion within %s", what, elapsed, bound)
	}
}

// TestExecRunnerCancelledKillsDescendant is the F1 regression test: a
// wrapper script (documented Bin-override / PATH-shim configuration) spawns a
// background child that inherits stdout/stderr and ignores TERM/INT. Without
// the process-group kill, killing only the direct child leaves the
// descendant holding the captured pipe write-ends and exec.Cmd.Wait blocks in
// awaitGoroutines forever; the worker would be stuck and the pool shutdown
// could never complete. With the fix the whole group is killed and Run
// returns a context error promptly after the deadline fires. The descendant's
// pid is captured through $RAVEN_PIDFILE and probed (with a short bounded
// poll, see assertDescendantReaped) after Run returns: the
// group kill must have actually reaped it — a runner that only bounded the
// wait (returning an error even when the descendant survives) must not be
// able to pass this test.
func TestExecRunnerCancelledKillsDescendant(t *testing.T) {
	skipOnWindows(t)
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	t.Setenv("RAVEN_PIDFILE", pidFile)
	script := writePosixScript(t, `trap "" TERM INT
sleep 3600 &
echo $! > "$RAVEN_PIDFILE"
wait`)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	_, err := (ExecRunner{}).Run(ctx, Cmd{Path: script, Args: nil}, Limits{})
	assertPromptReturn(t, start, 10*time.Second, "Run")
	if err == nil {
		t.Fatal("a cancelled run must return an error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want errors.Is(err, context.DeadlineExceeded), got %v", err)
	}
	assertDescendantReaped(t, pidFile)
}

// TestExecRunnerEscapedDescendantCannotPinRun exercises the self-owned-pipe
// teardown: a descendant that ESCAPES the process group (setsid) while
// holding the captured pipes cannot be killed by the group kill, yet Run
// must still return promptly with the structured cancellation error. The
// pipes are the runner's own (see pipeCopies): the read ends are force-closed
// and the copy goroutines joined before Cmd.Wait is awaited, so an escaped
// pipe-holder can no longer pin Cmd.Wait or Run. The waitGrace bound now
// covers only the residual case of a child that cannot be killed at all (an
// unkillable D-state process) and does not fire here. The escaped `sleep`
// process is transient by design — the whole point is that nothing can kill
// it — so it exits on its own (after at most 10 s) and the test leaves only
// a short-lived orphan behind.
func TestExecRunnerEscapedDescendantCannotPinRun(t *testing.T) {
	skipOnWindows(t)
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid (util-linux) not available")
	}
	// The descendant must outlive the 1 s deadline by a wide margin so the
	// cancellation path deterministically fires while it still holds the
	// pipes.
	script := writePosixScript(t, `setsid sleep 10 &
wait`)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err := (ExecRunner{}).Run(ctx, Cmd{Path: script, Args: nil}, Limits{})
	assertPromptReturn(t, start, 10*time.Second, "Run")
	if err == nil {
		t.Fatal("an uncatchable pipe-holding descendant must produce an error, not a hang")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want errors.Is(err, context.DeadlineExceeded), got %v", err)
	}
}

// TestExecRunnerEscapedDescendantWriterBoundsCapture pins the capture
// bounds under a hostile writer: a descendant that ESCAPES the process group
// (setsid) while holding the captured pipes AND KEEPS WRITING cannot be
// killed by the group kill, yet Run must return promptly with the
// cancellation mapped to context.DeadlineExceeded and a final, capped
// snapshot of the output. The capture buffers are quiescent when Run reads
// them — the runner's own pipe teardown force-closes the read ends and joins
// the copy goroutines before Cmd.Wait is awaited — so the limitedBuffer
// mutex (see runner.go) is defense-in-depth rather than the pre-fix
// data-race guard; running this test under -race proves that quiescence. On
// the old os/exec-internal-pipe design, the same scenario left a pipe-copy
// goroutine writing into the buffers while Run read them (the race this
// regression originally pinned), which is why the mutex exists.
//
// The escaped descendant is bounded by its own lifetime (a ~6 s write loop,
// one 2-byte write per 10 ms) so nothing needs to kill it: the 1 s deadline
// lands well inside the loop, while the descendant is actively writing, and
// the orphan exits on its own afterwards (its next write hits a pipe with no
// readers). A small capture cap forces the truncation flag to be written on
// every subsequent write, pinning the truncation behavior.
func TestExecRunnerEscapedDescendantWriterBoundsCapture(t *testing.T) {
	skipOnWindows(t)
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid (util-linux) not available")
	}
	script := writePosixScript(t, `setsid sh -c 'i=0; while [ "$i" -lt 600 ]; do echo x; i=$((i+1)); sleep 0.01; done' &
wait`)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	res, err := (ExecRunner{}).Run(ctx, Cmd{Path: script, Args: nil}, Limits{MaxOutput: 64})
	assertPromptReturn(t, start, 10*time.Second, "Run")
	if err == nil {
		t.Fatal("an uncatchable pipe-holding descendant must produce an error, not a hang")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want errors.Is(err, context.DeadlineExceeded), got %v", err)
	}
	// Reading the result is the point of this test: under -race without the
	// limitedBuffer mutex, the still-alive pipe-copy goroutine's writes
	// (contents and the truncation flag) race these reads.
	if !res.StdoutTruncated {
		t.Fatalf("stdout must be truncated under the %d-byte cap while the descendant keeps writing", 64)
	}
	if len(res.Stdout) > 64 {
		t.Fatalf("stdout is %d bytes, exceeding the 64-byte cap", len(res.Stdout))
	}
	for _, b := range res.Stdout {
		if b != 'x' && b != '\n' {
			t.Fatalf("stdout contains unexpected byte %q", b)
		}
	}
}

// TestExecRunnerCancelledMidRunMapsToCanceled is the F2 regression test for
// a cancelled context: Go reports a child killed by CommandContext as
// "signal: killed", which errors.Is does not match against context.Canceled.
// The runner must join the context error so callers classify the outcome as
// cancelled — never as a clean exit-code failure (ExitCode -1 was being
// cached as failed/incomplete before the fix).
func TestExecRunnerCancelledMidRunMapsToCanceled(t *testing.T) {
	skipOnWindows(t)
	script := writePosixScript(t, `sleep 30`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	res, err := (ExecRunner{}).Run(ctx, Cmd{Path: script, Args: nil}, Limits{})
	assertPromptReturn(t, start, 10*time.Second, "Run")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want errors.Is(err, context.Canceled), got %v", err)
	}
	// The kill happens mid-run; any capture must be bounded and the exit
	// code must not be surfaced as a "clean" code (it is meaningless when
	// the process never ran to completion).
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d on a cancelled run; want 0 (meaningless, never a clean failure)", res.ExitCode)
	}
}

// TestExecRunnerDeadlineMidRunMapsToDeadlineExceeded is the F2 regression
// test for the per-job deadline path: the same killed-child classification
// must map to context.DeadlineExceeded so the pipeline reports and stores
// StatusCancelled instead of failed.
func TestExecRunnerDeadlineMidRunMapsToDeadlineExceeded(t *testing.T) {
	skipOnWindows(t)
	script := writePosixScript(t, `sleep 30`)
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := (ExecRunner{}).Run(ctx, Cmd{Path: script, Args: nil}, Limits{})
	assertPromptReturn(t, start, 10*time.Second, "Run")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want errors.Is(err, context.DeadlineExceeded), got %v", err)
	}
}

// TestRunBinOverrideWrapperDeadlineIsBoundedAndCancelled drives the F1 and
// F2 fixes through the whole pipeline with a REAL subprocess: the subfinder
// Bin override is a wrapper script that spawns a descendant holding
// stdout/stderr (the documented wrapper-shim configuration). The per-job
// deadline must trigger the process-group kill, the run must finish promptly
// (no hang through pool shutdown), and the outcome must be cancelled — never
// a failed or partial exit-code classification — so StatusCancelled is what
// gets stored.
func TestRunBinOverrideWrapperDeadlineIsBoundedAndCancelled(t *testing.T) {
	skipOnWindows(t)
	script := writePosixScript(t, `if [ "$1" = "-version" ]; then
	echo "Current Version: v2.6.3"
	exit 0
fi
trap "" TERM INT
sleep 3600 &
echo $! > "$RAVEN_PIDFILE"
wait`)
	cfg := DefaultConfig()
	cfg.Sources = []string{"subfinder"}
	cfg.Bin = map[string]string{"subfinder": script}
	cfg.Timeout = 3 * time.Second
	cfg.Cache = openTestCache(t)
	target := mustDomain(t, "example.com")
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	t.Setenv("RAVEN_PIDFILE", pidFile)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	done := make(chan struct{})
	var rep Report
	var runErr error
	go func() {
		rep, runErr = Run(ctx, target, cfg)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("pipeline run did not return within 20s; the wrapper descendant wedged shutdown")
	}
	if runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	if len(rep.Results) != 1 || rep.Results[0].Source != "subfinder" {
		t.Fatalf("results = %+v, want exactly subfinder", rep.Results)
	}
	res := rep.Results[0]
	if res.Status != OutCancelled {
		t.Fatalf("subfinder outcome = %s, want cancelled (a deadline-killed wrapper must never classify as failed or partial)", res.Status)
	}
	det := res.Detection
	k := keyFor(t, target, "subfinder", det.Version)
	out := cfg.Cache.Get(context.Background(), k)
	if out.IsHit() {
		t.Fatal("a cancelled record must never be a hit")
	}
	if out.State != cache.StateIncomplete || out.Record.Status != cache.StatusCancelled {
		t.Fatalf("state = %s record status = %q, want incomplete/cancelled for a real killed process", out.State, out.Record.Status)
	}
	assertDescendantReaped(t, pidFile)
	assertPromptReturn(t, start, 15*time.Second, "pipeline run")
}
