package discovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
//     child's whole process group on unix — so a wrapper script or PATH shim
//     that spawned a descendant holding the captured pipes cannot keep
//     Cmd.Wait blocked on pipe EOF — and bounds the post-kill pipe drain by
//     a short grace period. On Windows only the direct child is killed.
type Runner interface {
	Run(ctx context.Context, cmd Cmd, limits Limits) (RunResult, error)
}

// ExecRunner is the production Runner. It executes commands with the standard
// library only: exec.CommandContext, arguments as separate values, never a
// shell, bounded capture of stdout and stderr, and — on unix — process-group
// kill on cancellation with a bounded post-kill drain (see runner_unix.go /
// runner_windows.go for the platform halves).
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
	c := exec.CommandContext(ctx, cmd.Path, cmd.Args...)
	out := &limitedBuffer{max: limits.cap()}
	errBuf := &limitedBuffer{max: limits.cap()}
	c.Stdout = out
	c.Stderr = errBuf
	configureProcessGroup(c)
	if err := c.Start(); err != nil {
		// Start failures are the "never ran" class: the executable was
		// unrunnable, or the context was already done and Start returned
		// the context error without forking.
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return RunResult{}, fmt.Errorf("%w: %s", ErrExecutableNotFound, cmd.Path)
		}
		return RunResult{}, fmt.Errorf("discovery: execute %s: %w", cmd.Path, err)
	}
	runErr := waitCommand(ctx, c)
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

// waitGrace bounds the post-cancellation pipe drain inside exec.Cmd.Wait.
// Once the process group has been killed, Wait must finish as soon as the OS
// closes the captured pipes; the only way it cannot is a descendant that
// escaped the process group while still holding the output pipes' write ends.
// That pathological case is bounded here instead of hanging the caller.
const waitGrace = 2 * time.Second

// waitCommand runs c to completion. If ctx fires first, the child's process
// group is killed (unix; the direct child is always killed, and on Windows
// that is the only kill available) and Wait is bounded by waitGrace: a
// wrapper script or PATH shim that spawned a pipe-holding descendant can no
// longer wedge the caller beyond the grace period. When Wait completes, its
// error says whether the child was killed; Run joins the context error to
// make the cancellation classification explicit.
//
// The Wait goroutine is bounded by construction: it ends when Wait returns,
// which the group kill (or the descendant's own exit) guarantees in practice;
// the grace path only covers the caller, never blocking the pipeline on the
// pipe-copy goroutines. On the grace path those copy goroutines stay ALIVE
// until the escaped descendant exits and keeps writing into the capture
// buffers; limitedBuffer is mutex-guarded so that concurrent writing can
// never race the caller's reads of the result (see limitedBuffer).
func waitCommand(ctx context.Context, c *exec.Cmd) error {
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- c.Wait()
	}()
	select {
	case err := <-waitCh:
		return err
	case <-ctx.Done():
		killProcessGroup(c)
		select {
		case err := <-waitCh:
			return err
		case <-time.After(waitGrace):
			return fmt.Errorf("process %s did not finish within %s of cancellation (a descendant may still hold its output pipes)", c.Path, waitGrace)
		}
	}
}

// limitedBuffer is a Write sink that retains at most max bytes. It always
// reports that it consumed everything it was given, so a child process
// writing to a full pipe never blocks on us; overflow is truncated and
// diagnosed via the truncated flag instead.
//
// Every method is mutex-guarded. This matters on the waitGrace path: when an
// escaped descendant (setsid, or any wrapper-spawned child on Windows) still
// holds the captured pipes after cancellation, os/exec's pipe-copy goroutine
// is still alive — it keeps reading the pipe and writing into this buffer
// until the descendant exits, which can be long after Run has returned its
// result. The mutex serializes those concurrent writer writes against the
// caller's reads (bytes and the truncation flag), so the documented
// "Wait goroutine leaks until the descendant exits" behavior is race-free.
// On Windows, where only the direct child can be killed, this is the only
// protection the caller has against that concurrent writer.
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
// view of the backing array: the pipe-copy goroutine may still be writing
// into the buffer (grace path), and a view would alias memory the writer
// keeps mutating after this method returns.
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
