package adapt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// urlintel tests are hermetic: no public internet, no real executables —
// every tool invocation is scripted through the package's shared fakeRunner
// (keyed by "path arg1 arg2 ...", discovery_test.go) and the lookPath seam
// (fakeLookup / missingLookup). The engine's per-URL work runs on the
// bounded pool configured from in.Bounds (DefaultStageConfig: 4 workers,
// 64-queue), so each test exercises the real IngestInto path deterministically.
//
// The urlintelParametersTruncated sticky flag is the adapter's mapping of the
// engine's OWN truncation signal — URLEntry.Overflow (parameters dropped at
// urlintel's per-URL cap, maxParametersPerURL = 256) — and is preserved
// end-to-end (record → cache → merge → report; AGENTS §0.6 names "urlintel's
// Overflow" as a carve-out chain). Runner-level capture truncation
// (RunResult.StdoutTruncated) is deliberately NOT flagged: it folds the
// domain partial, because the captured set is incomplete by definition and
// partial is the honest vocabulary for that cut (adapt/doc.go). The
// constructor seams (runner, lookPath) are the ONLY test plumbing: StageParams
// is operator configuration, never test injection.

// urlintelInput builds a StageInput for the urlintel stage with the resolved
// default bounds (through the runner these are never zero — the engine's own
// validation requires positive Concurrency/QueueSize) and the deterministic
// fixed clock the package's dns tests share.
func urlintelInput(target asset.Domain, domains []asset.Domain, params map[string]string, c cache.Cache) pipeline.StageInput {
	return pipeline.StageInput{
		Target:  target,
		Domains: domains,
		Bounds:  pipeline.DefaultStageConfig(),
		Config:  params,
		Clock:   fixedClock{now: fixedTime},
		Cache:   c,
	}
}

// urlStrings renders canonical URL assets as strings for deterministic
// assertions.
func urlStrings(urls []asset.URL) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		out = append(out, u.String())
	}
	return out
}

// missingLookup resolves no executable, as if nothing were on PATH.
func missingLookup(name string) (string, error) {
	return "", fmt.Errorf("executable %q not found", name)
}

// recordingCache is a hermetic cache.Cache that always misses, records every
// Get key, and counts Puts — proving both the cache-before-execute flow and
// which config the engine derived keys from.
type recordingCache struct {
	mu   sync.Mutex
	gets []cache.Key
	puts int
}

func (c *recordingCache) Get(ctx context.Context, key cache.Key) cache.Outcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets = append(c.gets, key)
	return cache.Outcome{State: cache.StateMiss}
}

func (c *recordingCache) Put(ctx context.Context, key cache.Key, record cache.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.puts++
	return nil
}

func (c *recordingCache) Delete(ctx context.Context, key cache.Key) error { return nil }
func (c *recordingCache) Clear(ctx context.Context) error                 { return nil }

func (c *recordingCache) getKeys() []cache.Key {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]cache.Key, len(c.gets))
	copy(out, c.gets)
	return out
}

func (c *recordingCache) putCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.puts
}

// stateErrorCache is a hermetic cache.Cache whose Get always returns a
// diagnosed state error — exercising the engine's cache-diagnostic path
// (recordCacheDiagnostic) through the stage: the engine surfaces the joined
// diagnostics as its run error while still merging the fresh extraction into
// the report.
type stateErrorCache struct{}

func (stateErrorCache) Get(ctx context.Context, key cache.Key) cache.Outcome {
	return cache.Outcome{State: cache.StateError, Err: errors.New("synthetic cache read failure")}
}

func (stateErrorCache) Put(ctx context.Context, key cache.Key, record cache.Record) error {
	return nil
}

func (stateErrorCache) Delete(ctx context.Context, key cache.Key) error { return nil }
func (stateErrorCache) Clear(ctx context.Context) error                 { return nil }

// gauLines scripts the gau invocation for one domain to emit the given raw
// lines.
func gauLines(domain string, lines ...string) map[string]func(discovery.Cmd) (discovery.RunResult, error) {
	return map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"gau " + domain: func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte(strings.Join(lines, "\n") + "\n")}, nil
		},
	}
}

func TestURLIntelStageName(t *testing.T) {
	s := NewURLIntelStage(nil, nil)
	if got := s.Name(); got != pipeline.StageURLIntel {
		t.Fatalf("Name() = %q, want %q", got, pipeline.StageURLIntel)
	}
}

func TestURLIntelStageHappyPath(t *testing.T) {
	target := mustDomain(t, "example.com")
	domain := mustDomain(t, "api.example.com")
	runner := newFakeRunner(gauLines("example.com",
		"https://example.com/a",
		"https://example.com/c",
		"https://example.com/b",
	))
	runner.script["gau api.example.com"] = func(discovery.Cmd) (discovery.RunResult, error) {
		return discovery.RunResult{Stdout: []byte("https://api.example.com/x\n")}, nil
	}

	s := NewURLIntelStage(runner, fakeLookup)
	res, err := s.Run(context.Background(), urlintelInput(target, []asset.Domain{domain}, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	// The engine merges both domains' observations into one deterministic,
	// sorted report; the adapter boundary-filters against the target.
	requireEqualStrings(t, "Additions.URLs", urlStrings(res.Additions.URLs), []string{
		"https://api.example.com/x",
		"https://example.com/a",
		"https://example.com/b",
		"https://example.com/c",
	})
	if len(res.Additions.Domains) != 0 || len(res.Additions.Hosts) != 0 {
		t.Fatalf("Additions carry corpus kinds the stage must not produce: domains=%d hosts=%d",
			len(res.Additions.Domains), len(res.Additions.Hosts))
	}
	if res.ItemsProcessed != 4 {
		t.Fatalf("ItemsProcessed = %d, want 4 (one entry per distinct canonical URL)", res.ItemsProcessed)
	}
	if res.ItemsFailed != 0 {
		t.Fatalf("ItemsFailed = %d, want 0", res.ItemsFailed)
	}
	if !runner.called("gau example.com") || !runner.called("gau api.example.com") {
		t.Fatal("the stage must query every declared domain through the selected tool")
	}
}

func TestURLIntelStageClockBridge(t *testing.T) {
	// The clock bridge (Now = in.Clock.Now) must surface exactly the
	// injected fixed instant as every entry's provenance timestamp.
	target := mustDomain(t, "example.com")
	runner := newFakeRunner(gauLines("example.com", "https://example.com/a"))
	s := NewURLIntelStage(runner, fakeLookup)

	res, err := s.Run(context.Background(), urlintelInput(target, nil, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	if len(res.Additions.URLs) != 1 {
		t.Fatalf("Additions.URLs = %d entries, want 1", len(res.Additions.URLs))
	}
}

func TestURLIntelStageToolSelection(t *testing.T) {
	// The tool parameter selects the built-in descriptor; argv is typed and
	// canonical per tool (adapt/tool.go).
	target := mustDomain(t, "example.com")
	tests := []struct {
		params map[string]string
		key    string
	}{
		{nil, "gau example.com"},
		{map[string]string{}, "gau example.com"},
		{map[string]string{"tool": "gau"}, "gau example.com"},
		{map[string]string{"tool": "waybackurls"}, "waybackurls example.com"},
		{map[string]string{"tool": "waymore"}, "waymore -i example.com -mode U"},
		// Unknown StageParams keys are ignored (defensive reading).
		{map[string]string{"tool": "gau", "unrelated": "x"}, "gau example.com"},
		{map[string]string{"unrelated": "x"}, "gau example.com"},
		{map[string]string{"tool": "  waybackurls  "}, "waybackurls example.com"},
	}
	for _, tt := range tests {
		// Script whichever tool the case selects: "path arg1 arg2 ...".
		script := map[string]func(discovery.Cmd) (discovery.RunResult, error}{
			tt.key: func(discovery.Cmd) (discovery.RunResult, error) {
				return discovery.RunResult{Stdout: []byte("https://example.com/a\n")}, nil
			},
		}
		runner := newFakeRunner(script)
		s := NewURLIntelStage(runner, fakeLookup)
		res, err := s.Run(context.Background(), urlintelInput(target, nil, tt.params, nil))
		if err != nil {
			t.Fatalf("params %v: Run: %v", tt.params, err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("params %v: Outcome = %q, want completed", tt.params, res.Outcome)
		}
		if !runner.called(tt.key) {
			t.Fatalf("params %v: tool %q not invoked (calls: %v)", tt.params, tt.key, runner.calls)
		}
	}
}

func TestURLIntelStageInvalidToolParam(t *testing.T) {
	target := mustDomain(t, "example.com")
	runner := newFakeRunner(gauLines("example.com", "https://example.com/a"))
	s := NewURLIntelStage(runner, fakeLookup)

	res, err := s.Run(context.Background(), urlintelInput(target, nil, map[string]string{"tool": "katana"}, nil))
	if err == nil {
		t.Fatal("Run: nil error, want the structured unknown-tool error")
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
	if !strings.Contains(err.Error(), "stage urlintel") || !strings.Contains(err.Error(), "katana") {
		t.Fatalf("error = %q, want stage name and tool name", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner invoked %d times for an invalid tool, want 0", len(runner.calls))
	}
}

func TestURLIntelStageParseParametersParam(t *testing.T) {
	target := mustDomain(t, "example.com")
	s := NewURLIntelStage(newFakeRunner(gauLines("example.com", "https://example.com/a")), fakeLookup)

	// Invalid values are structured errors mapped to failed.
	for _, v := range []string{"maybe", "1", ""} {
		res, err := s.Run(context.Background(), urlintelInput(target, nil, map[string]string{"parse_parameters": v}, nil))
		if err == nil {
			t.Fatalf("parse_parameters %q: nil error, want the structured error", v)
		}
		if res.Outcome != pipeline.OutcomeFailed {
			t.Fatalf("parse_parameters %q: Outcome = %q, want failed", v, res.Outcome)
		}
		if !strings.Contains(err.Error(), "parse_parameters") {
			t.Fatalf("parse_parameters %q: error = %q, want the key named", v, err)
		}
	}

	// Values are trimmed and case-insensitive; true and false both run.
	for _, v := range []string{"true", "TRUE", " false ", "False"} {
		res, err := s.Run(context.Background(), urlintelInput(target, nil, map[string]string{"parse_parameters": v}, nil))
		if err != nil {
			t.Fatalf("parse_parameters %q: Run: %v", v, err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("parse_parameters %q: Outcome = %q, want completed", v, res.Outcome)
		}
	}
}

func TestURLIntelStageParseParametersEntersCacheKey(t *testing.T) {
	// ParseParameters is result-relevant: it must enter the engine's per-URL
	// cache keys, so a record written with extraction enabled is never served
	// to a run that disabled it (urlintel urlKey; AGENTS §11).
	target := mustDomain(t, "example.com")
	lines := "https://example.com/a?q=1"

	for _, enabled := range []bool{true, false} {
		runner := newFakeRunner(gauLines("example.com", lines))
		rec := &recordingCache{}
		s := NewURLIntelStage(runner, fakeLookup)
		params := map[string]string{}
		if !enabled {
			params["parse_parameters"] = "false"
		}
		res, err := s.Run(context.Background(), urlintelInput(target, nil, params, rec))
		if err != nil {
			t.Fatalf("parse_parameters=%v: Run: %v", enabled, err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("parse_parameters=%v: Outcome = %q, want completed", enabled, res.Outcome)
		}
		keys := rec.getKeys()
		if len(keys) != 1 {
			t.Fatalf("parse_parameters=%v: Get calls = %d, want 1", enabled, len(keys))
		}
	}
	// The two runs derived different keys for the same URL and adapter: the
	// parameter-extraction flag is inside the key.
	runnerA := newFakeRunner(gauLines("example.com", lines))
	recA := &recordingCache{}
	if _, err := NewURLIntelStage(runnerA, fakeLookup).Run(context.Background(), urlintelInput(target, nil, nil, recA)); err != nil {
		t.Fatalf("run A: %v", err)
	}
	runnerB := newFakeRunner(gauLines("example.com", lines))
	recB := &recordingCache{}
	if _, err := NewURLIntelStage(runnerB, fakeLookup).Run(context.Background(), urlintelInput(target, nil, map[string]string{"parse_parameters": "false"}, recB)); err != nil {
		t.Fatalf("run B: %v", err)
	}
	if len(recA.getKeys()) != 1 || len(recB.getKeys()) != 1 {
		t.Fatalf("expected one Get per run, got %d and %d", len(recA.getKeys()), len(recB.getKeys()))
	}
	if recA.getKeys()[0] == recB.getKeys()[0] {
		t.Fatalf("cache keys identical across parse_parameters true/false: %s", recA.getKeys()[0])
	}
}

func TestURLIntelStageOutOfDomainFiltered(t *testing.T) {
	target := mustDomain(t, "example.com")
	runner := newFakeRunner(gauLines("example.com",
		"https://example.com/a",
		"http://evil.com/x",
		"http://example.org/y",
		"https://sub.example.com/b",
	))
	s := NewURLIntelStage(runner, fakeLookup)

	res, err := s.Run(context.Background(), urlintelInput(target, nil, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	requireEqualStrings(t, "Additions.URLs", urlStrings(res.Additions.URLs), []string{
		"https://example.com/a",
		"https://sub.example.com/b",
	})
}

func TestURLIntelStageMalformedCounted(t *testing.T) {
	target := mustDomain(t, "example.com")
	runner := newFakeRunner(gauLines("example.com",
		"not-a-url",
		"https://",
		"https://example.com/ok?q=1",
		"https://example.com/bad\x00url",
	))
	s := NewURLIntelStage(runner, fakeLookup)

	res, err := s.Run(context.Background(), urlintelInput(target, nil, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	// Raw tool lines the engine rejected at the ingest boundary are counted
	// as failed items, never silently dropped and never fatal.
	if res.ItemsFailed != 3 {
		t.Fatalf("ItemsFailed = %d, want 3 (malformed raw lines)", res.ItemsFailed)
	}
	requireEqualStrings(t, "Additions.URLs", urlStrings(res.Additions.URLs), []string{
		"https://example.com/ok?q=1",
	})
}

func TestURLIntelStageMergeAcrossDomains(t *testing.T) {
	target := mustDomain(t, "example.com")
	domain := mustDomain(t, "api.example.com")
	runner := newFakeRunner(gauLines("example.com",
		"https://example.com/shared",
		"https://example.com/target-only",
	))
	runner.script["gau api.example.com"] = func(discovery.Cmd) (discovery.RunResult, error) {
		return discovery.RunResult{Stdout: []byte("https://example.com/shared\nhttps://api.example.com/api-only\n")}, nil
	}
	s := NewURLIntelStage(runner, fakeLookup)

	res, err := s.Run(context.Background(), urlintelInput(target, []asset.Domain{domain}, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	// The shared accumulator merges across domains: one entry per distinct
	// canonical URL, counted once.
	requireEqualStrings(t, "Additions.URLs", urlStrings(res.Additions.URLs), []string{
		"https://api.example.com/api-only",
		"https://example.com/shared",
		"https://example.com/target-only",
	})
	if res.ItemsProcessed != 3 {
		t.Fatalf("ItemsProcessed = %d, want 3 (distinct canonical URLs)", res.ItemsProcessed)
	}
}

func TestURLIntelStageTruncationFlag(t *testing.T) {
	// 257 distinct query parameters exceed the engine's per-URL cap
	// (maxParametersPerURL = 256): the entry is flagged Overflow — the
	// engine's documented truncation marker — and the adapter must never
	// swallow it (AGENTS §0.6 carve-out: completed + sticky flag).
	target := mustDomain(t, "example.com")
	var b strings.Builder
	b.WriteString("https://example.com/p?")
	for i := 0; i < 257; i++ {
		if i > 0 {
			b.WriteString("&")
		}
		b.WriteString(fmt.Sprintf("p%d=v%d", i, i))
	}
	runner := newFakeRunner(gauLines("example.com", b.String()))
	s := NewURLIntelStage(runner, fakeLookup)

	res, err := s.Run(context.Background(), urlintelInput(target, nil, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q (the overflow entry is engine-completed)", res.Outcome, pipeline.OutcomeCompleted)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true (parameters dropped past the per-URL cap)")
	}
	if !res.StickyFlags[urlintelParametersTruncated] {
		t.Fatalf("StickyFlags[%q] unset, want true", urlintelParametersTruncated)
	}
}

func TestURLIntelStageAllDomainsFailed(t *testing.T) {
	// The executable is missing: every domain's tool source cannot be
	// constructed. The failure is counted honestly as failed items — never a
	// silent skip (the run-level fold reports failed).
	target := mustDomain(t, "example.com")
	domain := mustDomain(t, "api.example.com")
	s := NewURLIntelStage(newFakeRunner(nil), missingLookup)

	res, err := s.Run(context.Background(), urlintelInput(target, []asset.Domain{domain}, nil, nil))
	if err != nil {
		t.Fatalf("Run returned a Go error for source-construction failures: %v", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
	if res.ItemsFailed != 2 {
		t.Fatalf("ItemsFailed = %d, want 2 (target + domain with no usable tool source)", res.ItemsFailed)
	}
	if len(res.Additions.URLs) != 0 {
		t.Fatalf("Additions.URLs = %d entries, want 0", len(res.Additions.URLs))
	}
}

func TestURLIntelStagePartial(t *testing.T) {
	target := mustDomain(t, "example.com")

	// Non-zero exit with usable output: the captured set is incomplete by
	// definition — partial, never completed, never silently truncated.
	runner := newFakeRunner(map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"gau example.com": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("https://example.com/a\n"), ExitCode: 1}, nil
		},
	})
	s := NewURLIntelStage(runner, fakeLookup)
	res, err := s.Run(context.Background(), urlintelInput(target, nil, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("non-zero exit: Outcome = %q, want %q", res.Outcome, pipeline.OutcomePartial)
	}
	if !runner.called("gau example.com") {
		t.Fatal("the tool must run even when its exit is non-zero")
	}

	// Capture cut at the runner's capture cap: StdoutTruncated folds the
	// domain partial (the retained URL set is incomplete; the sticky flag is
	// reserved for the engine's own Overflow marker — documented in the
	// package doc comment).
	runner = newFakeRunner(map[string]func(discovery.Cmd) (discovery.RunResult, error){
		"gau example.com": func(discovery.Cmd) (discovery.RunResult, error) {
			return discovery.RunResult{Stdout: []byte("https://example.com/a\n"), StdoutTruncated: true}, nil
		},
	})
	s = NewURLIntelStage(runner, fakeLookup)
	res, err = s.Run(context.Background(), urlintelInput(target, nil, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("capture-capped: Outcome = %q, want %q", res.Outcome, pipeline.OutcomePartial)
	}
	if res.Truncated {
		t.Fatal("Truncated = true for a capture-capped run, want false (the partial outcome already marks the set incomplete)")
	}
}

func TestURLIntelStageAdditionsPreservedOnEngineError(t *testing.T) {
	// A diagnosed cache-read failure surfaces as the engine's joined run
	// error; the fresh extraction is still merged into the report, and the
	// stage must propagate those additions even though it reports failed
	// (the runner merges a failed stage's honest retained output).
	target := mustDomain(t, "example.com")
	runner := newFakeRunner(gauLines("example.com", "https://example.com/a"))
	s := NewURLIntelStage(runner, fakeLookup)

	res, err := s.Run(context.Background(), urlintelInput(target, nil, nil, stateErrorCache{}))
	if err == nil {
		t.Fatal("Run: nil error, want the engine's joined cache diagnostic")
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
	if !strings.Contains(err.Error(), "stage urlintel") || !strings.Contains(err.Error(), "cache get") {
		t.Fatalf("error = %q, want stage name and the engine diagnostic", err)
	}
	requireEqualStrings(t, "Additions.URLs", urlStrings(res.Additions.URLs), []string{
		"https://example.com/a",
	})
}

func TestURLIntelStageCancellation(t *testing.T) {
	target := mustDomain(t, "example.com")
	domain := mustDomain(t, "api.example.com")

	// Pre-cancelled: no tool runs; the stage reports cancelled with the
	// context error, never failed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := newFakeRunner(gauLines("example.com", "https://example.com/a"))
	s := NewURLIntelStage(runner, fakeLookup)
	res, err := s.Run(ctx, urlintelInput(target, []asset.Domain{domain}, nil, nil))
	if err == nil {
		t.Fatal("Run: nil error for a pre-cancelled run, want the context error")
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCancelled)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("Err = %v, want context.Canceled", res.Err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner invoked %d times for a pre-cancelled run, want 0", len(runner.calls))
	}

	// Mid-run cancellation: the second domain's tool run fires the cancel;
	// the engine surfaces the context error, the stage reports cancelled,
	// and the FIRST domain's honest observations still propagate.
	ctx, cancel = context.WithCancel(context.Background())
	runner = newFakeRunner(gauLines("example.com", "https://example.com/a"))
	runner.script["gau api.example.com"] = func(discovery.Cmd) (discovery.RunResult, error) {
		cancel()
		return discovery.RunResult{Stdout: []byte("https://api.example.com/y\n")}, nil
	}
	s = NewURLIntelStage(runner, fakeLookup)
	res, err = s.Run(ctx, urlintelInput(target, []asset.Domain{domain}, nil, nil))
	if err == nil {
		t.Fatal("Run: nil error for a mid-run cancellation, want the context error")
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCancelled)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("Err = %v, want context.Canceled", res.Err)
	}
	requireEqualStrings(t, "Additions.URLs", urlStrings(res.Additions.URLs), []string{
		"https://example.com/a",
	})
}

func TestURLIntelStageCachePassThrough(t *testing.T) {
	// Nil cache: the engine's caching is disabled and the run completes.
	target := mustDomain(t, "example.com")
	s := NewURLIntelStage(newFakeRunner(gauLines("example.com", "https://example.com/a")), fakeLookup)
	res, err := s.Run(context.Background(), urlintelInput(target, nil, nil, nil))
	if err != nil {
		t.Fatalf("Run (nil cache): %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}

	// A non-nil cache reaches the engine's cache-before-execute path: each
	// processed URL is read (miss) and stored.
	runner := newFakeRunner(gauLines("example.com", "https://example.com/a", "https://example.com/b"))
	rec := &recordingCache{}
	s = NewURLIntelStage(runner, fakeLookup)
	res, err = s.Run(context.Background(), urlintelInput(target, nil, nil, rec))
	if err != nil {
		t.Fatalf("Run (with cache): %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	if got := len(rec.getKeys()); got != 2 {
		t.Fatalf("cache Gets = %d, want 2 (one per processed URL)", got)
	}
	if got := rec.putCount(); got != 2 {
		t.Fatalf("cache Puts = %d, want 2 (one completed record per processed URL)", got)
	}
}

func TestURLIntelStageNilContext(t *testing.T) {
	target := mustDomain(t, "example.com")
	s := NewURLIntelStage(newFakeRunner(nil), fakeLookup)
	res, err := s.Run(nil, urlintelInput(target, nil, nil, nil))
	if err == nil {
		t.Fatal("Run(nil ctx): nil error, want the structured guard error")
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
}

func TestURLIntelStageNonCanonicalTarget(t *testing.T) {
	// A non-canonical target is rejected through the single normalization
	// point (asset.NewDomain), never queried in a non-canonical form.
	bad := asset.Domain{Name: "Example.COM"}
	s := NewURLIntelStage(newFakeRunner(nil), fakeLookup)
	res, err := s.Run(context.Background(), urlintelInput(bad, nil, nil, nil))
	if err == nil {
		t.Fatal("Run(non-canonical target): nil error, want the structured guard error")
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
}

func TestURLIntelStageDeduplicatesDeclaredDomains(t *testing.T) {
	// The query set dedups by asset.Identity with the target first: a domain
	// already declared as the target is queried once.
	target := mustDomain(t, "example.com")
	runner := newFakeRunner(gauLines("example.com", "https://example.com/a"))
	s := NewURLIntelStage(runner, fakeLookup)

	res, err := s.Run(context.Background(), urlintelInput(target, []asset.Domain{target}, nil, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeCompleted)
	}
	// "gau example.com" ran once: the duplicate in.Domains entry was deduped.
	if got := len(runner.calls); got != 1 {
		t.Fatalf("runner invocations = %d, want 1 (target deduped against Domains)", got)
	}
}
