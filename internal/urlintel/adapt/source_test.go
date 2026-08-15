package adapt

import (
	"context"
	"errors"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/urlintel"
)

var (
	urlA = "https://example.com/a?q=1"
	urlB = "https://example.com/b"
)

// urlLines returns a canned two-URL stdout capture.
func urlLines() []byte {
	return []byte(urlA + "\r\n" + urlB + "\n")
}

// TestRunCompletedSingleTool is the happy path: one tool, one target, clean
// exit, both URLs ingested with endpoints, parameters, and relationships.
func TestRunCompletedSingleTool(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines()})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()
	cfg.Metrics = &urlintel.Metrics{}

	rep := runOnce(t, cfg)

	if len(rep.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(rep.Results))
	}
	r := rep.Results[0]
	if r.Tool != "gau" || r.Status != ResultCompleted || r.Lines != 2 || r.Err != nil {
		t.Fatalf("result = %+v, want gau/completed/2 lines/no err", r)
	}
	requireEqualStrings(t, "entries", entryStrings(rep.Report), []string{urlA, urlB})
	// The real invocation must carry the typed argv: probe first, then the
	// positional target as its own argument.
	if got := runner.argsOf(0); len(got) != 1 || got[0] != "-version" {
		t.Fatalf("call 0 argv = %v, want [-version]", got)
	}
	if got := runner.argsOf(1); len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("call 1 argv = %v, want [example.com]", got)
	}

	e := findEntry(t, rep.Report, urlA)
	if len(e.Endpoints) != 1 || e.Endpoints[0].Method != "GET" {
		t.Fatalf("entry endpoints = %+v, want one GET endpoint", e.Endpoints)
	}
	if len(e.Parameters) != 1 || e.Parameters[0].Name != "q" {
		t.Fatalf("entry parameters = %+v, want [q]", e.Parameters)
	}
	if len(e.Relationships) == 0 {
		t.Fatal("entry has no relationships")
	}
	if rep.Metrics.Lines != 2 || rep.Metrics.Extracted != 2 || rep.Metrics.Malformed != 0 {
		t.Fatalf("metrics = %+v, want 2 lines / 2 extracted / 0 malformed", rep.Metrics)
	}
}

// TestRunCompletedEmpty: clean exit with no output is a legitimate
// completed-empty result — the tool found nothing.
func TestRunCompletedEmpty(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	rep := runOnce(t, cfg)
	if rep.Results[0].Status != ResultCompleted || rep.Results[0].Lines != 0 {
		t.Fatalf("result = %+v, want completed with 0 lines", rep.Results[0])
	}
	if len(rep.Report.Entries) != 0 || rep.Report.Malformed != 0 {
		t.Fatalf("report = %+v, want empty", rep.Report)
	}
}

// TestRunCrossToolMerge: the same URL observed by two tools is ONE report
// entry with unioned sources (the engine's two-level merge at emit time).
func TestRunCrossToolMerge(t *testing.T) {
	// Both tools emit identical captures; the concurrent execution order is
	// nondeterministic, which is exactly why the assertions must not depend
	// on it. gau probes first (one call); both real calls then consume the
	// shared capture.
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines()})
	cfg := testConfig([]Tool{Gau(), Waybackurls()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	rep := runOnce(t, cfg)

	if len(rep.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(rep.Results))
	}
	for _, r := range rep.Results {
		if r.Status != ResultCompleted {
			t.Fatalf("result = %+v, want completed", r)
		}
	}
	requireEqualStrings(t, "entries", entryStrings(rep.Report), []string{urlA, urlB})
	for _, u := range []string{urlA, urlB} {
		e := findEntry(t, rep.Report, u)
		if len(e.Sources) != 2 {
			t.Fatalf("entry %s sources = %v, want both tools", u, e.Sources)
		}
		if got := sortedStrings(e.Sources); got[0] != "gau" || got[1] != "waybackurls" {
			t.Fatalf("entry %s sources = %v, want {gau, waybackurls}", u, e.Sources)
		}
	}
}

// TestRunResultsDeterministicOrder: one slot per (tool, target), tool-major,
// targets in input order, regardless of the concurrent execution order.
func TestRunResultsDeterministicOrder(t *testing.T) {
	targets := []asset.Host{mustHost(t, "example.com"), mustHost(t, "api.example.com")}
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines()})
	cfg := testConfig([]Tool{Gau(), Waybackurls()}, targets)
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	rep := runOnce(t, cfg)

	if len(rep.Results) != 4 {
		t.Fatalf("results = %d, want 4", len(rep.Results))
	}
	want := []struct{ tool, target string }{
		{"gau", "example.com"},
		{"gau", "api.example.com"},
		{"waybackurls", "example.com"},
		{"waybackurls", "api.example.com"},
	}
	for i, w := range want {
		if rep.Results[i].Tool != w.tool || rep.Results[i].Target.Name != w.target {
			t.Fatalf("results[%d] = %s/%s, want %s/%s",
				i, rep.Results[i].Tool, rep.Results[i].Target.Name, w.tool, w.target)
		}
	}
	// Determinism: two identical runs produce identical reports and results.
	rep2 := runOnce(t, cfg)
	if len(rep2.Results) != len(rep.Results) {
		t.Fatalf("second run results = %d, want %d", len(rep2.Results), len(rep.Results))
	}
	for i := range rep.Results {
		if rep.Results[i].Status != rep2.Results[i].Status {
			t.Fatalf("results[%d] status differs between runs", i)
		}
	}
	requireEqualStrings(t, "entries", entryStrings(rep2.Report), entryStrings(rep.Report))
}

// TestRunPartialNonZeroExit: a non-zero exit with usable output keeps the
// captured URLs and reports partial.
func TestRunPartialNonZeroExit(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines(), code: 3})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	rep := runOnce(t, cfg)
	r := rep.Results[0]
	if r.Status != ResultPartial {
		t.Fatalf("result = %+v, want partial", r)
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "exited with code 3") {
		t.Fatalf("result err = %v, want exit-code diagnosis", r.Err)
	}
	// The captured URLs are kept, never discarded.
	requireEqualStrings(t, "entries", entryStrings(rep.Report), []string{urlA, urlB})
}

// TestRunPartialTruncated: stdout cut at the capture cap is partial — the
// captured set is incomplete by definition, even with a clean exit.
func TestRunPartialTruncated(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines(), trunc: true})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	rep := runOnce(t, cfg)
	r := rep.Results[0]
	if r.Status != ResultPartial {
		t.Fatalf("result = %+v, want partial", r)
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "capture cap") {
		t.Fatalf("result err = %v, want truncation diagnosis", r.Err)
	}
	requireEqualStrings(t, "entries", entryStrings(rep.Report), []string{urlA, urlB})
}

// TestRunFailedNonZeroExitEmpty: a non-zero exit with no usable output is
// failed, without poisoning the report.
func TestRunFailedNonZeroExitEmpty(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{code: 1})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	rep := runOnce(t, cfg)
	r := rep.Results[0]
	if r.Status != ResultFailed {
		t.Fatalf("result = %+v, want failed", r)
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no usable output") {
		t.Fatalf("result err = %v, want no-usable-output diagnosis", r.Err)
	}
	if len(rep.Report.Entries) != 0 {
		t.Fatalf("report entries = %v, want none", entryStrings(rep.Report))
	}
}

// TestRunFailedExecutionError: a runner failure (process never ran to
// completion) that is not a cancellation is failed.
func TestRunFailedExecutionError(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{runErr: discovery.ErrExecutableNotFound})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	rep := runOnce(t, cfg)
	r := rep.Results[0]
	if r.Status != ResultFailed {
		t.Fatalf("result = %+v, want failed", r)
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "not found") {
		t.Fatalf("result err = %v, want not-found diagnosis", r.Err)
	}
}

// TestRunExecutableVanishesBetweenDetectAndRun: detection found the
// executable, but execution-time lookup fails — failed, never skipped.
func TestRunExecutableVanishesBetweenDetectAndRun(t *testing.T) {
	lookup := newFakeLookup()
	lookup.Add("gau", "/fake/bin/gau")
	lookup.AddErr("gau", errors.New("gone"))
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines()})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = lookup.asFunc()

	rep := runOnce(t, cfg)
	r := rep.Results[0]
	if r.Status != ResultFailed || r.Err == nil {
		t.Fatalf("result = %+v, want failed with a diagnosis", r)
	}
	// The executable vanished between the detection lookup and the
	// execution lookup: exactly two lookups happened, and the runner never
	// executed the real call.
	if len(lookup.requested()) != 2 {
		t.Fatalf("lookups = %v, want 2", lookup.requested())
	}
	if runner.callCount() != 1 {
		t.Fatalf("runner calls = %d, want 1 (probe only)", runner.callCount())
	}
}

// TestRunSkippedWhenToolMissing: a MISSING tool is skipped — never an error,
// never an execution attempt.
func TestRunSkippedWhenToolMissing(t *testing.T) {
	lookup := newFakeLookup()
	lookup.AddErr("gau", errors.New("not found"))
	runner := newFakeRunner()
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = lookup.asFunc()

	rep := runOnce(t, cfg)
	r := rep.Results[0]
	if r.Status != ResultSkipped {
		t.Fatalf("result = %+v, want skipped", r)
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "not found") {
		t.Fatalf("result err = %v, want missing reason", r.Err)
	}
	if runner.callCount() != 0 {
		t.Fatalf("skipped tool executed %d runner calls; want 0", runner.callCount())
	}
}

// TestRunMixedMissingAndPresent: a missing tool is skipped while a present
// one still runs — a broken install never aborts the run.
func TestRunMixedMissingAndPresent(t *testing.T) {
	lookup := newFakeLookup()
	lookup.AddErr("gau", errors.New("not found"))
	runner := newFakeRunner(runStep{out: urlLines()})
	cfg := testConfig([]Tool{Gau(), Waybackurls()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = lookup.asFunc()

	rep := runOnce(t, cfg)
	if len(rep.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(rep.Results))
	}
	if rep.Results[0].Tool != "gau" || rep.Results[0].Status != ResultSkipped {
		t.Fatalf("results[0] = %+v, want skipped gau", rep.Results[0])
	}
	if rep.Results[1].Tool != "waybackurls" || rep.Results[1].Status != ResultCompleted {
		t.Fatalf("results[1] = %+v, want completed waybackurls", rep.Results[1])
	}
	requireEqualStrings(t, "entries", entryStrings(rep.Report), []string{urlA, urlB})
}

// TestRunCancelledMidExecution: cancelling the run context mid-flight reports
// cancelled (never failed, never success), keeps the lines consumed so far in
// the report, and returns without hanging.
func TestRunCancelledMidExecution(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{block: true})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var rep RunReport
	var runErr error
	go func() {
		rep, runErr = Run(ctx, cfg)
		close(done)
	}()
	// Detection probe (call 0) then the blocking real call (call 1).
	waitUntil(t, "tool execution starts", testTimeout, func() bool {
		return runner.callCount() >= 2
	})
	cancel()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after cancellation")
	}
	if runErr != nil {
		t.Fatalf("Run error = %v, want nil (cancellation is reported per slot)", runErr)
	}
	if rep.Results[0].Status != ResultCancelled || rep.Results[0].Err == nil {
		t.Fatalf("result = %+v, want cancelled with a cause", rep.Results[0])
	}
}

// TestRunTimedOut: the outer per-job deadline elapsing during execution is
// timed-out, never failed and never cancelled.
func TestRunTimedOut(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{block: true})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()
	cfg.Timeout = 200 * time.Millisecond

	rep := runOnce(t, cfg)
	r := rep.Results[0]
	if r.Status != ResultTimedOut {
		t.Fatalf("result = %+v, want timed-out", r)
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "deadline") {
		t.Fatalf("result err = %v, want deadline diagnosis", r.Err)
	}
}

// TestRunCancelledBeforeStart: an already-cancelled context is refused up
// front.
func TestRunCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	if _, err := Run(ctx, cfg); err == nil {
		t.Fatal("Run with cancelled context returned nil error")
	}
}

// TestRunNilContext: a nil context is refused.
func TestRunNilContext(t *testing.T) {
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	if _, err := Run(nil, cfg); err == nil {
		t.Fatal("Run with nil context returned nil error")
	}
}

// TestRunRejectsNonCanonicalTarget: a hand-built non-canonical Host must be
// refused at the boundary — defense-in-depth before argv construction.
func TestRunRejectsNonCanonicalTarget(t *testing.T) {
	cfg := testConfig([]Tool{Gau()}, []asset.Host{{Name: "Example.COM"}})
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("Run accepted a non-canonical target")
	}
}

// TestRunRejectsNoTargets: at least one target is required.
func TestRunRejectsNoTargets(t *testing.T) {
	cfg := testConfig([]Tool{Gau()}, nil)
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("Run accepted an empty target list")
	}
}

// TestRunRejectsNamelessTool: a nameless tool would collide on the engine's
// adapter key and provenance; it is refused.
func TestRunRejectsNamelessTool(t *testing.T) {
	cfg := testConfig([]Tool{{ProbeKind: ProbeExistence}}, []asset.Host{mustHost(t, "example.com")})
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("Run accepted a nameless tool")
	}
}

// TestRunDeduplicatesTools: the same tool selected twice collapses to one
// slot per target — no double execution, no double report.
func TestRunDeduplicatesTools(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines()})
	cfg := testConfig([]Tool{Gau(), Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	rep := runOnce(t, cfg)
	if len(rep.Results) != 1 {
		t.Fatalf("results = %d, want 1 (deduplicated)", len(rep.Results))
	}
	if runner.callCount() != 2 {
		t.Fatalf("runner calls = %d, want 2 (probe + one run)", runner.callCount())
	}
}

// TestRunPanickingJob: a panicking runner call fails its slot and never
// crashes the run; sibling slots still complete.
func TestRunPanickingJob(t *testing.T) {
	// Call order: gau probe (version), gau run (panics), waybackurls run
	// (clean capture). Concurrency 1 makes the order deterministic: the
	// scripted runner steps are consumed serially, so the panicking step
	// cannot be grabbed by the sibling job (a parallel race that made this
	// test flaky under -race).
	runner := newFakeRunner(
		runStep{out: []byte("gau 2.1.1\n")},
		runStep{panics: true},
		runStep{out: urlLines()},
	)
	cfg := testConfig([]Tool{Gau(), Waybackurls()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()
	cfg.Concurrency = 1

	rep := runOnce(t, cfg)
	if rep.Results[0].Tool != "gau" || rep.Results[0].Status != ResultFailed {
		t.Fatalf("results[0] = %+v, want failed gau", rep.Results[0])
	}
	if rep.Results[0].Err == nil || !strings.Contains(rep.Results[0].Err.Error(), "panicked") {
		t.Fatalf("results[0].Err = %v, want panic diagnosis", rep.Results[0].Err)
	}
	if rep.Results[1].Status != ResultCompleted {
		t.Fatalf("results[1] = %+v, want completed waybackurls", rep.Results[1])
	}
}

// TestRunParseParametersDisabled: the flag passes through to the engine and
// controls extraction.
func TestRunParseParametersDisabled(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines()})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()
	cfg.ParseParameters = false

	rep := runOnce(t, cfg)
	e := findEntry(t, rep.Report, urlA)
	if len(e.Parameters) != 0 {
		t.Fatalf("parameters = %v, want none with extraction disabled", e.Parameters)
	}
}

// TestRunCacheSecondRunZeroWork: with a real filesystem-backed cache, the
// first run extracts and stores; the second run serves every URL from cache
// with ZERO extraction and ZERO store work (the per-(URL, adapter)
// cache-before-execute wiring).
func TestRunCacheSecondRunZeroWork(t *testing.T) {
	open := func(t *testing.T) *cache.FS {
		c, err := cache.Open(t.TempDir())
		if err != nil {
			t.Fatalf("cache.Open: %v", err)
		}
		return c
	}
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines()})
	cfg.LookPath = newFakeLookup().asFunc()

	// First run: extract and store.
	cfg.Cache = open(t)
	cfg.Metrics = &urlintel.Metrics{}
	rep1 := runOnce(t, cfg)
	if rep1.Metrics.Extracted != 2 || rep1.Metrics.Stored != 2 {
		t.Fatalf("run 1 metrics = %+v, want 2 extracted / 2 stored", rep1.Metrics)
	}

	// Second run against the SAME cache: every URL is a hit, zero work.
	cfg.Metrics = &urlintel.Metrics{}
	rep2 := runOnce(t, cfg)
	if rep2.Metrics.Extracted != 0 || rep2.Metrics.Stored != 0 {
		t.Fatalf("run 2 metrics = %+v, want 0 extracted / 0 stored", rep2.Metrics)
	}
	if rep2.Metrics.Reads != 2 {
		t.Fatalf("run 2 cache reads = %d, want 2", rep2.Metrics.Reads)
	}
	if rep2.Metrics.Lines != 2 {
		t.Fatalf("run 2 lines = %d, want 2", rep2.Metrics.Lines)
	}
	requireEqualStrings(t, "entries", entryStrings(rep2.Report), entryStrings(rep1.Report))
	for _, u := range []string{urlA, urlB} {
		if !findEntry(t, rep2.Report, u).Cached {
			t.Fatalf("entry %s was not served from cache", u)
		}
	}
	if rep2.Results[0].Status != ResultCompleted {
		t.Fatalf("result = %+v, want completed (cache-held)", rep2.Results[0])
	}
}

// TestToolSourceTrimsAndSkipsBlanks pins the adapter stream contract: lines
// are trimmed (CRLF and surrounding whitespace), blank lines are skipped,
// everything else passes through unchanged, and the stream honors
// cancellation.
func TestToolSourceTrimsAndSkipsBlanks(t *testing.T) {
	src := newToolSource([]byte(
		"\r\n  " + urlA + "  \r\n" +
			"\t\n" +
			urlB + "\n" +
			"https://example.com/c with space\n" +
			"\n"))
	got := []string{}
	for {
		line, err := src.Next(context.Background())
		if errors.Is(err, context.Canceled) {
			t.Fatal("unexpected cancellation")
		}
		if err != nil {
			break // io.EOF
		}
		got = append(got, line)
	}
	want := []string{urlA, urlB, "https://example.com/c with space"}
	requireEqualStrings(t, "lines", got, want)
	if src.lineCount() != len(want) {
		t.Fatalf("lineCount = %d, want %d", src.lineCount(), len(want))
	}

	// Cancellation mid-stream surfaces ctx.Err().
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Next after cancellation = %v, want context.Canceled", err)
	}
}

// TestRunCancelledMidSubmitPopulatesAllSlots pins that EVERY results slot —
// including slots whose jobs were never submitted because cancellation
// stopped the submit loop — carries its tool and target identity: the init
// pass fills Tool and Target per slot in the deterministic tools×targets
// order, so a cancelled placeholder is never a zero-valued entry.
//
// Concurrency 1 + queue 1 force the scenario deterministically: the first
// execution call blocks the only worker, one pending job fills the queue,
// and every later Submit blocks on backpressure. Cancelling the run context
// releases the blocked Submit with an error, so the LAST slot(s) are never
// submitted at all and keep their initialized cancelled placeholders; the
// queued job is dropped by the pool's forced shutdown without running — so
// no job body populates any of those slots.
func TestRunCancelledMidSubmitPopulatesAllSlots(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{block: true})
	cfg := testConfig([]Tool{Gau(), Waybackurls()},
		[]asset.Host{mustHost(t, "example.com"), mustHost(t, "api.example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()
	cfg.Concurrency = 1
	cfg.QueueSize = 1

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var rep RunReport
	var runErr error
	go func() {
		rep, runErr = Run(ctx, cfg)
		close(done)
	}()
	// Detection probe (call 0), then the first execution call (call 1),
	// which blocks the only worker forever (until cancellation).
	waitUntil(t, "tool execution starts", testTimeout, func() bool {
		return runner.callCount() >= 2
	})
	cancel()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after cancellation")
	}
	if runErr != nil {
		t.Fatalf("Run error = %v, want nil (cancellation is reported per slot)", runErr)
	}
	// Only the probe and the one blocked execution ever ran: the queued and
	// never-submitted slots were populated by the init pass alone.
	if got := runner.callCount(); got != 2 {
		t.Fatalf("runner calls = %d, want 2 (probe + one blocked execution)", got)
	}
	if len(rep.Results) != 4 {
		t.Fatalf("results = %d, want 4", len(rep.Results))
	}
	want := []struct{ tool, target string }{
		{"gau", "example.com"},
		{"gau", "api.example.com"},
		{"waybackurls", "example.com"},
		{"waybackurls", "api.example.com"},
	}
	for i, w := range want {
		r := rep.Results[i]
		if r.Tool != w.tool {
			t.Fatalf("results[%d].Tool = %q, want %q", i, r.Tool, w.tool)
		}
		if r.Target.Name != w.target {
			t.Fatalf("results[%d].Target = %q, want %q (non-zero target identity)", i, r.Target.Name, w.target)
		}
		if r.Status != ResultCancelled {
			t.Fatalf("results[%d].Status = %s, want cancelled", i, r.Status)
		}
	}
}

// TestRunNoGoroutineLeakAfterShutdown: Run leaves no goroutines behind after
// a clean completion (the outer pool and every inner ingest pool unwound).
func TestRunNoGoroutineLeakAfterShutdown(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{out: urlLines()})
	cfg := testConfig([]Tool{Gau(), Waybackurls()},
		[]asset.Host{mustHost(t, "example.com"), mustHost(t, "api.example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	baseline := goruntime.NumGoroutine()
	runOnce(t, cfg)
	waitForGoroutines(t, baseline, testTimeout)
}

// TestRunNoGoroutineLeakAfterCancellation: a cancelled run unwinds the outer
// pool, the blocking runner call, and every inner pool without leaks.
func TestRunNoGoroutineLeakAfterCancellation(t *testing.T) {
	runner := newFakeRunner(runStep{out: []byte("gau 2.1.1\n")}, runStep{block: true})
	cfg := testConfig([]Tool{Gau()}, []asset.Host{mustHost(t, "example.com")})
	cfg.Runner = runner
	cfg.LookPath = newFakeLookup().asFunc()

	baseline := goruntime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = Run(ctx, cfg)
		close(done)
	}()
	waitUntil(t, "tool execution starts", testTimeout, func() bool {
		return runner.callCount() >= 2
	})
	cancel()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after cancellation")
	}
	waitForGoroutines(t, baseline, testTimeout)
}
