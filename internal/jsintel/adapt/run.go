// Adapter execution: one tool against one target, producing a jsintel.Source
// over the bounded stdout capture. The source yields one
// Item{Kind: ItemLine, Line: <raw line>} per output line; stderr is never
// parsed for content (house rule); the stream is bounded by construction
// (the runner's capture cap) and honors context cancellation.
package adapt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/jsintel"
)

// maxRawLineBytes is the ingest-boundary line cap: a raw stdout line longer
// than this is skipped and counted (overlong), never emitted as an Item. It
// mirrors urlintel's maxRawURLLen boundary cap (32 KiB). The jsintel engine
// seam has no line cap of its own in this pass, so the cap lives here and
// the count is exposed for the future orchestration to fold into the
// engine's Malformed accounting.
const maxRawLineBytes = 32 << 10 // 32 KiB

// Run executes tool t against target (a declared URL such as
// "https://example.com/") and returns a jsintel.Source yielding one
// Item{Kind: ItemLine, Line: <raw stdout line>} per output line of the
// bounded capture. Execution goes through the discovery Runner (the r
// seam; nil means the production ExecRunner): exec.CommandContext,
// arguments as separate argv values — never a shell, never concatenation —
// bounded per-stream capture (Limits.MaxOutput, default 4 MiB), and
// process-group kill on cancellation (unix). The runner enforces the
// context/timeout/output limits: the caller's context deadline is the
// execution deadline (the python tools have no HTTP timeout of their own —
// SecretFinder in particular must be bounded by the caller's deadline).
//
// The returned source is non-nil whenever the process executed and exited —
// its bounded stdout capture is valid regardless of the exit code — and nil
// when the process never ran (resolution or execution failure). A non-zero
// exit code is reported as a structured error on Run's return; the source
// remains streamable, so callers that keep partial output stream it and
// classify the slot themselves (partial vs failed), mirroring the
// urlintel/adapt classification. Cancelled and timed-out executions are
// classified per the house contract: the returned error wraps ctx.Err() for
// the caller to distinguish via errors.Is.
//
// Executable resolution (the wrapper model): the command's Path is the
// per-run override-map value when present (keys "subjs", "linkfinder.py",
// "SecretFinder.py" — a value is executed verbatim), else the tool's bare
// name. For the python pair the SCRIPT IS the executable: "linkfinder.py"
// and "SecretFinder.py" must be on PATH as wrappers with a shebang (or a
// symlink to the real script), or overridden per run. There is no
// python3-interpreter split, and the adapter NEVER resolves executables
// itself: PATH lookup and missing-executable classification
// (discovery.ErrExecutableNotFound, wrapped with context) are the RUNNER's
// job, so a missing executable is a structured error, never a panic.
//
// Per-tool invocation forms (pinned by test):
//
//	subjs:       Path "subjs" (or override). A temp file (0600, created in
//	             os.TempDir, containing exactly the target URL — no
//	             trailing newline) is written and the tool runs with argv
//	             exactly ["-c", "1", "-t", "15", "-i", <tmpfile>]; the temp
//	             file is removed on every path (success and failure). -c 1
//	             pins the tool's internal worker count for determinism
//	             (moot for a single input URL).
//	linkfinder:  Path "linkfinder.py" (or override), argv exactly
//	             ["-i", <target>, "-o", "cli"] — "cli" prints to stdout;
//	             never -d (stdout pollution) and never -o without "cli"
//	             (writes output.html and spawns xdg-open).
//	secretfinder: Path "SecretFinder.py" (or override), argv exactly
//	             ["-i", <target>, "-o", "cli"]. -H is never passed (broken
//	             in the tool: crashes with an AttributeError).
func Run(ctx context.Context, r *discovery.Runner, t Tool, target string, overrides map[string]string) (src jsintel.Source, err error) {
	if ctx == nil {
		return nil, fmt.Errorf("adapt: context must not be nil")
	}
	if !t.Valid() {
		return nil, fmt.Errorf("adapt: unknown tool %q", t.Name)
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("adapt: %s: target must not be empty", t.Name)
	}
	if strings.ContainsAny(target, "\r\n") {
		// A multi-line target would become multiple input lines for subjs
		// and a broken argument for the python tools.
		return nil, fmt.Errorf("adapt: %s: target must be a single line (no CR/LF)", t.Name)
	}
	e := env{runner: runnerOf(r), overrides: overrides}.sanitized()

	// Panic containment: a panicking runner (hostile seam) must fail the
	// call with a structured error, never crash the process.
	defer func() {
		if r := recover(); r != nil {
			src = nil
			err = fmt.Errorf("adapt: %s execution panicked: %v", t.Name, r)
		}
	}()

	// The command's Path: the override value when present, else the bare
	// name. The adapter does no LookPath — the runner resolves and
	// classifies (ErrExecutableNotFound) a missing executable.
	path := e.pathFor(t.binName())

	// subjs has no positional-argument or -u input: its target goes into a
	// temp file passed via -i. The file is created 0600, holds exactly the
	// target (subjs reads it as its single input line), and is removed on
	// every path — success, execution failure, and cancellation.
	tmp := ""
	if t.targetFile() {
		f, terr := os.CreateTemp("", "ravenrecon-subjs-*.txt")
		if terr != nil {
			return nil, fmt.Errorf("adapt: %s: create target file: %w", t.Name, terr)
		}
		tmp = f.Name()
		defer func() { _ = os.Remove(tmp) }()
		if _, werr := f.WriteString(target); werr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("adapt: %s: write target file: %w", t.Name, werr)
		}
		if cerr := f.Close(); cerr != nil {
			return nil, fmt.Errorf("adapt: %s: close target file: %w", t.Name, cerr)
		}
	}

	rres, rerr := e.runner.Run(ctx, discovery.Cmd{Path: path, Args: t.buildArgv(target, tmp)}, e.limits)
	if rerr != nil {
		// The process never ran to completion. Context classification
		// takes priority: cancellation and deadline-elapse are never tool
		// failures.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("adapt: %s %s: %w", t.Name, target, ctxErr)
		}
		if errors.Is(rerr, discovery.ErrExecutableNotFound) {
			return nil, fmt.Errorf("adapt: %s: %w (%s)", t.Name, discovery.ErrExecutableNotFound, path)
		}
		return nil, fmt.Errorf("adapt: %s %s could not be executed: %w", t.Name, target, rerr)
	}

	// The process executed and exited; its bounded stdout capture is valid
	// regardless of the exit code.
	src = newToolSource(rres)
	if rres.ExitCode != 0 {
		return src, fmt.Errorf("adapt: %s %s: exited with code %d", t.Name, target, rres.ExitCode)
	}
	return src, nil
}

// toolSource is the jsintel.Source over one tool's bounded stdout capture.
// The adapter stream is raw: lines are trimmed (CRLF and surrounding
// whitespace stripped), blank lines are skipped, lines over maxRawLineBytes
// are skipped and counted (overlong — the engine seam has no line cap of its
// own in this pass), and EVERYTHING else passes through unchanged as one
// ItemLine per line. Canonical-boundary rejection (non-URLs, the
// "[ + ] URL: <u>" progress form, "name\t->\tvalue" secret lines, garbage
// preamble) is the engine's accounting — never the adapter's — so noisy tool
// output is counted by the engine, never fatal and never silently dropped.
// Tool output is never trusted as a URL until the engine has canonicalized
// it.
//
// The underlying capture is already bounded by the runner (Limits.MaxOutput),
// so the stream is bounded by construction. Not safe for concurrent use: the
// engine reads a source sequentially by design.
type toolSource struct {
	data     []byte
	pos      int
	lines    int
	overlong int
	code     int
	trunc    bool
}

// newToolSource wraps a bounded stdout capture and carries the execution
// metadata (exit code, stdout truncation) for the orchestrator's slot
// classification.
func newToolSource(r discovery.RunResult) *toolSource {
	return &toolSource{data: r.Stdout, code: r.ExitCode, trunc: r.StdoutTruncated}
}

// Next implements jsintel.Source. It returns io.EOF at end of stream and
// honors ctx cancellation (returning ctx.Err()).
func (s *toolSource) Next(ctx context.Context) (jsintel.Item, error) {
	if err := ctx.Err(); err != nil {
		return jsintel.Item{}, err
	}
	for s.pos < len(s.data) {
		start := s.pos
		if nl := bytes.IndexByte(s.data[start:], '\n'); nl >= 0 {
			s.pos = start + nl + 1
		} else {
			s.pos = len(s.data)
		}
		line := strings.TrimSpace(string(s.data[start:s.pos]))
		if line == "" {
			continue
		}
		if len(line) > maxRawLineBytes {
			s.overlong++
			continue
		}
		s.lines++
		return jsintel.Item{Kind: jsintel.ItemLine, Line: line}, nil
	}
	return jsintel.Item{}, io.EOF
}

// lineCount reports how many non-blank lines were streamed. It is final once
// the source is exhausted (the engine reads to EOF or to cancellation).
func (s *toolSource) lineCount() int { return s.lines }

// overlongCount reports how many lines were skipped for exceeding
// maxRawLineBytes. It is final once the source is exhausted; the future
// orchestration folds this count into the engine's Malformed accounting.
func (s *toolSource) overlongCount() int { return s.overlong }

// exitCode reports the process exit code of the executed tool.
func (s *toolSource) exitCode() int { return s.code }

// truncated reports whether stdout exceeded the runner's capture cap (the
// captured set is incomplete by definition).
func (s *toolSource) truncated() bool { return s.trunc }
