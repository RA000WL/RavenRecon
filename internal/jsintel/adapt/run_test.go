package adapt

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/jsintel"
)

// runWith runs Run over the fake seams and returns the source and error.
func runWith(runner discovery.Runner, t Tool, target string, overrides map[string]string) (jsintel.Source, error) {
	r := discovery.Runner(runner)
	return Run(context.Background(), &r, t, target, overrides)
}

// drainItems streams a source to EOF and returns the items.
func drainItems(t *testing.T, src jsintel.Source) []jsintel.Item {
	t.Helper()
	var items []jsintel.Item
	for {
		it, err := src.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return items
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		items = append(items, it)
	}
}

// requireLines asserts the item lines exactly.
func requireLines(t *testing.T, got []jsintel.Item, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("items = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Kind != jsintel.ItemLine {
			t.Fatalf("item %d kind = %v, want ItemLine", i, got[i].Kind)
		}
		if got[i].Line != want[i] {
			t.Fatalf("item %d line = %q, want %q", i, got[i].Line, want[i])
		}
	}
}

const testTarget = "https://example.com/"

// TestRunSubjsArgvAndTempFile: subjs runs with the exact pinned argv and a
// temp file that exists DURING the call with mode 0600 and exactly the
// target URL; the file is removed after success.
func TestRunSubjsArgvAndTempFile(t *testing.T) {
	inter := &subjsInterceptor{}
	src, err := runWith(inter, Tools["subjs"], testTarget, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"-c", "1", "-t", "15", "-i", inter.cmd.Args[5]}
	if len(inter.cmd.Args) != 6 {
		t.Fatalf("argv = %v, want 6 elements", inter.cmd.Args)
	}
	for i := range want {
		if inter.cmd.Args[i] != want[i] {
			t.Fatalf("argv = %v, want %v", inter.cmd.Args, want)
		}
	}
	if !inter.existed {
		t.Fatal("temp file did not exist during the execution call")
	}
	if inter.mode != 0o600 {
		t.Fatalf("temp file mode = %o, want 0600", inter.mode)
	}
	if string(inter.content) != testTarget {
		t.Fatalf("temp file content = %q, want exactly %q", inter.content, testTarget)
	}
	// Removed after success.
	if _, err := os.Stat(inter.cmd.Args[5]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp file still exists after Run: %v", err)
	}
	// The capture streams as ItemLine items.
	requireLines(t, drainItems(t, src), "https://example.com/app.js")
}

// TestRunSubjsTempFileRemovedOnFailure: the temp file is removed when the
// process never ran to completion.
func TestRunSubjsTempFileRemovedOnFailure(t *testing.T) {
	runner := newFakeRunner(runStep{runErr: errors.New("boom")})
	_, err := runWith(runner, Tools["subjs"], testTarget, nil)
	if err == nil {
		t.Fatal("Run returned nil error for an execution failure")
	}
	path := runner.argsOf(0)[5]
	if _, serr := os.Stat(path); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("temp file %s still exists after failed Run: %v", path, serr)
	}
}

// TestRunSubjsTempFileRemovedOnNonZeroExit: the temp file is removed when
// the process executed but exited non-zero.
func TestRunSubjsTempFileRemovedOnNonZeroExit(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("https://example.com/app.js\n"), code: 1})
	src, err := runWith(runner, Tools["subjs"], testTarget, nil)
	if err == nil {
		t.Fatal("Run returned nil error for a non-zero exit")
	}
	if !strings.Contains(err.Error(), "code 1") {
		t.Fatalf("error = %v, want exit-code diagnosis", err)
	}
	path := runner.argsOf(0)[5]
	if _, serr := os.Stat(path); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("temp file %s still exists after non-zero-exit Run: %v", path, serr)
	}
	// The capture stays streamable (partial semantics).
	requireLines(t, drainItems(t, src), "https://example.com/app.js")
}

// TestRunLinkfinderArgv: linkfinder runs with the exact pinned argv; the
// script IS the executable (Path = the bare name, resolved by the runner).
func TestRunLinkfinderArgv(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("/api/v1/users\n")})
	src, err := runWith(runner, Tools["linkfinder"], testTarget, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := runner.pathOf(0); got != "linkfinder.py" {
		t.Fatalf("path = %q, want linkfinder.py (bare name; the runner resolves it)", got)
	}
	want := []string{"-i", testTarget, "-o", "cli"}
	got := runner.argsOf(0)
	if len(got) != len(want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv = %v, want %v", got, want)
		}
	}
	requireLines(t, drainItems(t, src), "/api/v1/users")
}

// TestRunSecretfinderArgvAndRawPassThrough: secretfinder runs with the exact
// pinned argv and its raw lines — progress lines and "name\t->\tvalue"
// secret lines — pass through untouched as ItemLine items.
func TestRunSecretfinderArgvAndRawPassThrough(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte(
		"[ + ] URL: https://example.com/app.js\r\n" +
			"google_api\t->\tAIzaSyDummySyntheticKey\n" +
			"json_web_token\t->\teyJhbGciOiJIUzI1NiJ9.example\n")})
	src, err := runWith(runner, Tools["secretfinder"], testTarget, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"-i", testTarget, "-o", "cli"}
	got := runner.argsOf(0)
	if len(got) != len(want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv = %v, want %v", got, want)
		}
	}
	if got := runner.pathOf(0); got != "SecretFinder.py" {
		t.Fatalf("path = %q, want SecretFinder.py (bare name; the runner resolves it)", got)
	}
	requireLines(t, drainItems(t, src),
		"[ + ] URL: https://example.com/app.js",
		"google_api\t->\tAIzaSyDummySyntheticKey",
		"json_web_token\t->\teyJhbGciOiJIUzI1NiJ9.example")
}

// TestRunBinOverride: the executable override replaces the LookPath
// resolution for the binary tool.
func TestRunBinOverride(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("https://example.com/app.js\n")})
	src, err := runWith(runner, Tools["subjs"], testTarget, map[string]string{"subjs": "/opt/bin/subjs"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := runner.pathOf(0); got != "/opt/bin/subjs" {
		t.Fatalf("path = %q, want /opt/bin/subjs", got)
	}
	requireLines(t, drainItems(t, src), "https://example.com/app.js")
}

// TestRunScriptOverride: the per-run executable override replaces the bare
// name as the command's Path. With the wrapper model the script name IS the
// executable name, so the override is keyed by it directly — no interpreter
// key exists.
func TestRunScriptOverride(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("/api\n")})
	overrides := map[string]string{
		"linkfinder.py": "/opt/tools/linkfinder.py",
	}
	src, err := runWith(runner, Tools["linkfinder"], testTarget, overrides)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := runner.pathOf(0); got != "/opt/tools/linkfinder.py" {
		t.Fatalf("path = %q, want /opt/tools/linkfinder.py", got)
	}
	want := []string{"-i", testTarget, "-o", "cli"}
	got := runner.argsOf(0)
	if len(got) != len(want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv = %v, want %v", got, want)
		}
	}
	requireLines(t, drainItems(t, src), "/api")
}

// TestRunLookPathFailure: an unresolvable executable is a structured error
// wrapping discovery.ErrExecutableNotFound — never a panic. Resolution is
// the RUNNER's job: the fake runner scripts the ErrExecutableNotFound
// response for the unresolvable Path (mirroring how urlintel/adapt tests
// script runner failures), and Run must classify it via errors.Is without
// doing any adapter-side LookPath.
func TestRunLookPathFailure(t *testing.T) {
	tool := Tool{Name: "subjs", Bin: "/definitely/not/a/real/ravenrecon-adapt-binary"}
	runner := newFakeRunner(runStep{runErr: discovery.ErrExecutableNotFound})
	_, err := runWith(runner, tool, testTarget, nil)
	if err == nil {
		t.Fatal("Run returned nil error for an unresolvable executable")
	}
	if !errors.Is(err, discovery.ErrExecutableNotFound) {
		t.Fatalf("error = %v, want ErrExecutableNotFound classification", err)
	}
	if got := runner.pathOf(0); got != tool.Bin {
		t.Fatalf("path = %q, want the unresolvable path %q passed to the runner", got, tool.Bin)
	}
}

// TestRunToolLookPathFailure: an unresolvable python tool (the script IS the
// executable under the wrapper model) is the same structured
// ErrExecutableNotFound classification, scripted by the runner.
func TestRunToolLookPathFailure(t *testing.T) {
	tool := Tool{Name: "linkfinder", Bin: "/definitely/not/a/real/linkfinder.py", ProbeKind: ProbeExistence}
	runner := newFakeRunner(runStep{runErr: discovery.ErrExecutableNotFound})
	_, err := runWith(runner, tool, testTarget, nil)
	if err == nil {
		t.Fatal("Run returned nil error for an unresolvable tool executable")
	}
	if !errors.Is(err, discovery.ErrExecutableNotFound) {
		t.Fatalf("error = %v, want ErrExecutableNotFound classification", err)
	}
	if got := runner.pathOf(0); got != tool.Bin {
		t.Fatalf("path = %q, want the unresolvable script path %q passed to the runner", got, tool.Bin)
	}
}

// TestRunBadToolName: an unknown tool name is refused up front.
func TestRunBadToolName(t *testing.T) {
	runner := newFakeRunner()
	_, err := runWith(runner, Tool{Name: "katana"}, testTarget, nil)
	if err == nil {
		t.Fatal("Run accepted an unknown tool")
	}
	if runner.callCount() != 0 {
		t.Fatalf("unknown tool executed %d runner calls; want 0", runner.callCount())
	}
}

// TestRunNilContext: a nil context is refused.
func TestRunNilContext(t *testing.T) {
	r := discovery.Runner(newFakeRunner())
	if _, err := Run(nil, &r, Tools["subjs"], testTarget, nil); err == nil {
		t.Fatal("Run with nil context returned nil error")
	}
}

// TestRunEmptyTarget: an empty (or whitespace-only) target is refused.
func TestRunEmptyTarget(t *testing.T) {
	for _, target := range []string{"", "   "} {
		if _, err := runWith(newFakeRunner(), Tools["subjs"], target, nil); err == nil {
			t.Fatalf("Run accepted empty target %q", target)
		}
	}
}

// TestRunMultiLineTarget: a target containing a newline is refused — it
// would become multiple input lines for subjs.
func TestRunMultiLineTarget(t *testing.T) {
	_, err := runWith(newFakeRunner(), Tools["subjs"], "https://example.com/\nhttps://evil.example/", nil)
	if err == nil {
		t.Fatal("Run accepted a multi-line target")
	}
}

// TestRunCancelledBeforeStart: an already-cancelled context is classified
// per the house contract (the error wraps the context error).
func TestRunCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := discovery.Runner(newFakeRunner(runStep{block: true}))
	if _, err := Run(ctx, &r, Tools["subjs"], testTarget, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

// TestRunTimeoutKillsHangingTool: a tool that hangs past the caller's
// deadline is classified timed-out per the house contract (the error wraps
// context.DeadlineExceeded).
func TestRunTimeoutKillsHangingTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := discovery.Runner(newFakeRunner(runStep{block: true}))
	if _, err := Run(ctx, &r, Tools["linkfinder"], testTarget, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

// TestRunTruncatedOutput: stdout cut at the runner's capture cap is reported
// on the source (the captured set is incomplete by definition), with a clean
// exit still yielding a nil error.
func TestRunTruncatedOutput(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("https://example.com/app.js\n"), trunc: true})
	src, err := runWith(runner, Tools["subjs"], testTarget, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ts, ok := src.(*toolSource)
	if !ok {
		t.Fatalf("source type = %T, want *toolSource", src)
	}
	if !ts.truncated() {
		t.Fatal("source did not report stdout truncation")
	}
	if ts.exitCode() != 0 {
		t.Fatalf("exit code = %d, want 0", ts.exitCode())
	}
	requireLines(t, drainItems(t, src), "https://example.com/app.js")
}

// TestRunPanicContained: a panicking runner call is converted into a
// structured error — never a crash.
func TestRunPanicContained(t *testing.T) {
	runner := newFakeRunner(runStep{panics: true})
	_, err := runWith(runner, Tools["subjs"], testTarget, nil)
	if err == nil {
		t.Fatal("Run returned nil error for a panicking runner")
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("error = %v, want panic diagnosis", err)
	}
}

// TestToolSourceTrimsSkipsBlanksAndCaps pins the adapter stream contract:
// lines are trimmed (CRLF and surrounding whitespace), blank lines skipped,
// overlong lines (> maxRawLineBytes) skipped and counted, everything else
// passes through unchanged, and the stream honors cancellation.
func TestToolSourceTrimsSkipsBlanksAndCaps(t *testing.T) {
	overlong := strings.Repeat("a", maxRawLineBytes+1)
	src := newToolSource(discovery.RunResult{Stdout: []byte(
		"\r\n  https://example.com/a  \r\n" +
			"\t\n" +
			"https://example.com/b\n" +
			"[ + ] URL: https://example.com/c\n" +
			"google_api\t->\tAIzaSyDummySyntheticKey\n" +
			overlong + "\n" +
			"https://example.com/d\n")})
	var got []string
	for {
		it, err := src.Next(context.Background())
		if err != nil {
			if errors.Is(err, context.Canceled) {
				t.Fatal("unexpected cancellation")
			}
			break // io.EOF
		}
		got = append(got, it.Line)
	}
	want := []string{
		"https://example.com/a",
		"https://example.com/b",
		"[ + ] URL: https://example.com/c",
		"google_api\t->\tAIzaSyDummySyntheticKey",
		"https://example.com/d",
	}
	requireLines(t, itemsFrom(got), want...)
	if src.lineCount() != len(want) {
		t.Fatalf("lineCount = %d, want %d", src.lineCount(), len(want))
	}
	if src.overlongCount() != 1 {
		t.Fatalf("overlongCount = %d, want 1", src.overlongCount())
	}

	// Cancellation mid-stream surfaces ctx.Err().
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Next after cancellation = %v, want context.Canceled", err)
	}
}

// itemsFrom converts raw lines to ItemLine items (helper for assertions).
func itemsFrom(lines []string) []jsintel.Item {
	items := make([]jsintel.Item, len(lines))
	for i, l := range lines {
		items[i] = jsintel.Item{Kind: jsintel.ItemLine, Line: l}
	}
	return items
}

// TestRunCompletedEmpty: a clean exit with no output is a legitimate
// completed-empty result — the tool found nothing.
func TestRunCompletedEmpty(t *testing.T) {
	src, err := runWith(newFakeRunner(runStep{}), Tools["subjs"], testTarget, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := drainItems(t, src); len(got) != 0 {
		t.Fatalf("items = %v, want none", got)
	}
}
