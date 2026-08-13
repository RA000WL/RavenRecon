package discovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// ErrExecutableNotFound is returned (wrapped with context) when a tool
// executable does not exist. It is separate from ordinary execution failures
// so callers can distinguish "not installed" from "installed but broken"
// without parsing messages.
var ErrExecutableNotFound = errors.New("discovery: executable not found")

// DefaultMaxOutput is the default per-stream capture cap in bytes applied to
// stdout and stderr of every tool invocation. It bounds memory regardless of
// how much output a tool produces; overflow is truncated and diagnosed, never
// buffered. It is deliberately well below the cache's MaxRecordSize so a
// stored result never approaches the cache size limit.
const DefaultMaxOutput int64 = 4 << 20 // 4 MiB per stream

// Limits bounds one external execution. Every execution is bounded: output
// beyond the caps is discarded, so a runaway tool cannot exhaust memory.
type Limits struct {
	// MaxOutput caps each captured stream (stdout and stderr) in bytes.
	// Zero means DefaultMaxOutput.
	MaxOutput int64
}

// cap returns the effective per-stream cap.
func (l Limits) cap() int64 {
	if l.MaxOutput <= 0 {
		return DefaultMaxOutput
	}
	return l.MaxOutput
}

// Cmd describes one external invocation. Args are passed as separate argv
// values; they are never interpreted by a shell.
type Cmd struct {
	// Path is the executable (absolute path, or a bare name resolved through
	// exec.LookPath).
	Path string

	// Args are the argument vector after the executable. Target-derived
	// strings are never composed into shell syntax; they only ever appear as
	// individual argv elements.
	Args []string
}

// RunResult is the bounded capture of one execution.
type RunResult struct {
	// Stdout and Stderr hold the captured output, each at most the configured
	// cap.
	Stdout []byte
	Stderr []byte

	// StdoutTruncated reports that stdout exceeded the cap and was cut.
	StdoutTruncated bool
	// StderrTruncated reports that stderr exceeded the cap and was cut.
	StderrTruncated bool

	// ExitCode is the process exit code. It is only meaningful when Run
	// returned nil (the process executed and exited); a process that never
	// ran to completion reports its failure through the error instead.
	ExitCode int
}

// Runner executes external commands. The real implementation (ExecRunner)
// wraps exec.CommandContext; tests inject fake runners that return canned
// stdout, stderr, and exit codes, so the discovery tests never require the
// external tools to be installed and never touch the network.
//
// Contracts:
//
//   - Run returns a nil error whenever the process executed and exited,
//     regardless of its exit code (RunResult.ExitCode carries a non-zero
//     code).
//   - Run returns a non-nil error when the process never ran to completion:
//     executable missing or unrunnable (errors.Is with ErrExecutableNotFound
//     distinguishes "not found"), the context was cancelled or its deadline
//     elapsed (context errors, inspect with errors.Is), or an internal
//     failure.
//   - Run must return promptly when ctx is done: implementations must honor
//     context cancellation and kill the child process. ExecRunner kills the
//     child's whole process group on unix; on Windows only the direct child
//     is killed.
//   - Run's resource lifetime is bounded by Run itself: the pipe-copy
//     goroutines it spawns and their file descriptors are terminated before
//     Run returns on every path (normal exit, non-zero exit, and
//     cancellation), so a descendant that escaped the process group while
//     holding the output pipes can pin no goroutine or descriptor once Run
//     has returned. The short grace period that follows a kill covers only
//     the residual case of a process that cannot be killed at all (an
//     unkillable D-state child), where the Wait goroutine itself remains
//     parked until the process is reaped.
type Runner interface {
	Run(ctx context.Context, cmd Cmd, limits Limits) (RunResult, error)
}

// ExecRunner is the production Runner. It executes commands with the standard
// library only: exec.CommandContext, arguments as separate values, never a
// shell, bounded capture of stdout and stderr, and — on unix — process-group
// kill on cancellation (see runner_unix.go / runner_windows.go for the
// platform halves). Captured streams flow through pipes the runner owns
// itself (see pipeCopies), so Run's resource lifetime is bounded by Run's
// own termination of its goroutines and descriptors.
type ExecRunner struct{}

var _ Runner = ExecRunner{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, cmd Cmd, limits Limits) (RunResult, error) {
	if ctx == nil {
		return RunResult{}, fmt.Errorf("discovery: context must not be nil")
	}
	if cmd.Path == "" {
		return RunResult{}, fmt.Errorf("discovery: command path must not be empty")
	}
	out := &limitedBuffer{max: limits.cap()}
	errBuf := &limitedBuffer{max: limits.cap()}

	// Self-owned pipes: the runner creates the pipes, hands the write ends
	// to the child as its stdio, and copies the read ends into the capture
	// buffers itself. With plain io.Writer sinks os/exec spawns its OWN
	// internal pipe-copy goroutines that stay alive until pipe EOF — which
	// can be arbitrarily long after Run returns when a descendant escaped
	// the process group while holding the write ends (see pipeCopies). Our
	// read ends are under our control, so the copies can always be
	// terminated before Run returns.
	outR, outW, err := os.Pipe()
	if err != nil {
		return RunResult{}, fmt.Errorf("discovery: create stdout pipe: %w", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return RunResult{}, fmt.Errorf("discovery: create stderr pipe: %w", err)
	}
	c := exec.CommandContext(ctx, cmd.Path, cmd.Args...)
	c.Stdout = outW
	c.Stderr = errW
	configureProcessGroup(c)
	if err := c.Start(); err != nil {
		// Start failures are the "never ran" class: the executable was
		// unrunnable, or the context was already done and Start returned
		// the context error without forking. No copy goroutines exist yet;
		// all four pipe ends are closed here and nothing is left behind.
		_ = outR.Close()
		_ = outW.Close()
		_ = errR.Close()
		_ = errW.Close()
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return RunResult{}, fmt.Errorf("%w: %s", ErrExecutableNotFound, cmd.Path)
		}
		return RunResult{}, fmt.Errorf("discovery: execute %s: %w", cmd.Path, err)
	}
	// The child duplicated the write ends into its stdio at fork; the
	// parent's copies must be closed so the pipes reach EOF when the child
	// (and any pipe-holding descendant) exits.
	_ = outW.Close()
	_ = errW.Close()

	pipes := &pipeCopies{outR: outR, errR: errR, copied: make(chan struct{}, 2)}
	pipes.start(out, errBuf)

	// waitCommand terminates the copies on every path before returning, so
	// the buffers below are quiescent when they are read: no goroutine can
	// be writing into them, and the capture is final.
	runErr := waitCommand(ctx, c, pipes)
	res := RunResult{
		Stdout:          out.bytes(),
		Stderr:          errBuf.bytes(),
		StdoutTruncated: out.trunc(),
		StderrTruncated: errBuf.trunc(),
	}
	if runErr == nil {
		res.ExitCode = 0
		return res, nil
	}
	// Context cancellation takes priority over exit classification. A child
	// killed because its context was cancelled or its deadline elapsed must
	// be classified by the context error, never as a clean non-zero exit:
	// exec.CommandContext reports "signal: killed" for a killed child,
	// which errors.Is cannot match against context.Canceled, so the context
	// error is joined explicitly. Genuine non-zero exits with an untouched
	// context are unaffected.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, fmt.Errorf("discovery: execute %s: %w", cmd.Path, errors.Join(runErr, ctxErr))
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		// The process executed and exited non-zero; the capture is still
		// valid and callers decide how to treat the exit code.
		res.ExitCode = ee.ExitCode()
		return res, nil
	}
	return res, fmt.Errorf("discovery: execute %s: %w", cmd.Path, runErr)
}

// waitGrace bounds the only wait that can outlive the pipe copies: c.Wait()
// itself. Since the runner's own copies are terminated before this wait
// begins, the process group kill makes Wait return as soon as the direct
// child is reaped. The single residual case is a child that cannot be
// killed at all — an unkillable D-state process — whose waitpid never
// returns. When that happens, exactly the Wait goroutine (plus
// exec.CommandContext's own kill-watcher goroutine, both inherent to the
// standard library and parked until the process is reaped) remains: no
// pipe-copy goroutine, file descriptor, or capture buffer outlives Run.
const waitGrace = 2 * time.Second

// copyDrainBound gives the pipe-copy goroutines a bounded chance to finish
// draining on EOF after the child was reaped, before their read ends are
// force-closed. On the benign path the child's exit closed the write ends, so
// the remaining bytes and EOF are already in the pipe and the copies finish
// on their own within microseconds; force-closing first could discard a
// small residual buffer on arbitrarily loaded machines. On the hostile path
// — a descendant that escaped the process group still holds the write ends —
// the bound expires and the read ends are closed, terminating the copies.
// The bound is deliberately generous: expiring it means a hostile pipe
// holder, not a slow machine.
const copyDrainBound = 1 * time.Second

// pipeCopies owns the two stdout/stderr pipe-copy goroutines and their read
// ends. Every copy goroutine terminates before Run reads the capture
// buffers: on the normal path they finish on EOF (or are force-closed after
// the drain bound); on the cancellation path they are force-closed and
// joined immediately after the process-group kill. A pipe-holding descendant
// that escaped the process group can therefore pin no goroutine, descriptor,
// or capture buffer past Run's own return.
type pipeCopies struct {
	outR, errR *os.File
	// copied receives one token per terminated copy goroutine (capacity 2,
	// so a finished copy never blocks on its own termination signal).
	copied chan struct{}
}

// start launches the two copy goroutines: io.Copy from each read end into
// the corresponding capture sink. limitedBuffer always reports full
// consumption, so the copies never block on the sinks and the pipes never
// back up; overflow is truncated inside the sinks.
func (p *pipeCopies) start(out, errSink *limitedBuffer) {
	copyOne := func(r *os.File, sink *limitedBuffer) {
		go func() {
			_, _ = io.Copy(sink, r)
			// Benign-path EOF case: the copy closes its own read end. The
			// force-close in finish() and in drain's timer branch is
			// idempotent with this (os.File.Close is safe for concurrent
			// use and double close is harmless).
			_ = r.Close()
			p.copied <- struct{}{}
		}()
	}
	copyOne(p.outR, out)
	copyOne(p.errR, errSink)
}

// finish force-closes both read ends (unblocking any pending Read) and joins
// both copy goroutines. After it returns, the capture buffers are quiescent:
// no goroutine can write into them anymore, and no pipe descriptor is open.
//
// It is safe to call only after both copies started AND on a path where no
// token has been consumed yet: it receives exactly two tokens, matching the
// two sends each copy goroutine performs. In this runner that is exactly the
// cancellation path (waitCommand's ctx arm calls finish() directly, so drain
// never ran). The child-reaped-first path must use drain instead, which
// reaps only the still-outstanding tokens after closing the read ends —
// calling finish() from drain's timer branch would over-receive when one
// token was already consumed: a third receive against only two sends, which
// blocks forever.
func (p *pipeCopies) finish() {
	_ = p.outR.Close()
	_ = p.errR.Close()
	<-p.copied
	<-p.copied
}

// drain waits a short bounded interval for the copies to finish on EOF, then
// forces them closed if they did not. Postconditions are identical to
// finish: buffers quiescent, read ends closed, no goroutine or descriptor
// left behind.
//
// Exactly one of drain and finish runs per waitCommand (they are the two
// arms of its select), and each copy goroutine sends exactly one token, so
// the total number of receives across the chosen path must be exactly two.
// drain's timer branch therefore closes the read ends first — which
// guarantees both copies return — and then reaps EXACTLY the remaining
// tokens; it never delegates to finish, whose unconditional two receives
// would over-consume (and block forever) when one token was already
// received before the timer fired.
func (p *pipeCopies) drain() {
	timer := time.NewTimer(copyDrainBound)
	defer timer.Stop()
	done := 0
	for done < 2 {
		select {
		case <-p.copied:
			done++
		case <-timer.C:
			// The child was reaped but a descendant still holds a pipe
			// write end, so a copy cannot finish on EOF. Force-close the
			// read ends (unblocking any pending Read), then await only the
			// outstanding sends: with the read ends closed both copies must
			// return, and their tokens are all that remain (each copy sends
			// exactly once, and the channel has capacity 2, so sends never
			// block). This loop cannot over-receive and cannot block.
			_ = p.outR.Close()
			_ = p.errR.Close()
			for done < 2 {
				<-p.copied
				done++
			}
			return
		}
	}
}

// waitCommand runs c to completion. If ctx fires first, the child's process
// group is killed (unix; the direct child is always killed, and on Windows
// that is the only kill available).
//
// On every path the pipe copies are terminated BEFORE this function returns:
//
//   - child reaped first: the copies finish on EOF, with the bounded drain
//     (copyDrainBound) as the only allowance for a still-writing escaped
//     descendant, after which their read ends are force-closed. The caller
//     then reads quiescent buffers.
//   - ctx done first: the process group is killed, then the read ends are
//     force-closed and both copies joined, and only then is c.Wait itself
//     awaited — bounded by waitGrace, which covers exclusively the residual
//     case of a child that cannot be killed (a D-state process). On that
//     path exactly the Wait goroutine (and CommandContext's inherent kill
//     watcher) remains parked until the process is reaped; no pipe-copy
//     goroutine, file descriptor, or capture buffer outlives this function.
func waitCommand(ctx context.Context, c *exec.Cmd, pipes *pipeCopies) error {
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- c.Wait()
	}()
	select {
	case err := <-waitCh:
		// The child was reaped; its exit closed its write ends. Drain the
		// remaining bytes, bounded, then force-close if a descendant still
		// holds the pipes. Whichever way the copies end, they are finished
		// before this function returns.
		pipes.drain()
		return err
	case <-ctx.Done():
		killProcessGroup(c)
		pipes.finish()
		select {
		case err := <-waitCh:
			return err
		case <-time.After(waitGrace):
			return fmt.Errorf("process %s did not finish within %s of cancellation (an unkillable process: only its Wait goroutine remains, parked until it is reaped)", c.Path, waitGrace)
		}
	}
}

// limitedBuffer is a Write sink that retains at most max bytes. It always
// reports that it consumed everything it was given, so a child process
// writing to a full pipe never blocks on us; overflow is truncated and
// diagnosed via the truncated flag instead.
//
// Every method is mutex-guarded. Under the self-owned-pipe design the
// pipe-copy goroutines are joined before Run reads the result on every path,
// so the buffers are quiescent at read time; the mutex is defense-in-depth
// against a copy goroutine still finishing a final write while the read ends
// are force-closed.
type limitedBuffer struct {
	mu        sync.Mutex
	max       int64
	truncated bool
	buf       bytes.Buffer
}

// Write implements io.Writer.
func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.max - int64(b.buf.Len())
	if remaining > 0 {
		n := int64(len(p))
		if n > remaining {
			n = remaining
		}
		b.buf.Write(p[:n])
		if n < int64(len(p)) {
			b.truncated = true
		}
	} else {
		b.truncated = true
	}
	return len(p), nil
}

// bytes returns a snapshot copy of the retained bytes. It is a copy, not a
// view of the backing array: the copy goroutines are joined before Run reads
// the result on every path (see pipeCopies), so a view would be safe today,
// but returning a copy keeps this method safe against a copy goroutine
// finishing a final write during force-close and under future refactors.
func (b *limitedBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

// trunc reports whether output was discarded for exceeding the cap.
func (b *limitedBuffer) trunc() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}
