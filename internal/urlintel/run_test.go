package urlintel

import (
	"context"
	"errors"
	"fmt"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestIngestBasic covers one canonical URL through the whole pipeline: typed
// endpoint, extracted parameters, graph edges, provenance, and metrics.
func TestIngestBasic(t *testing.T) {
	cfg := testConfig()
	cfg.Metrics = &Metrics{}
	rep := runIngest(t, cfg, []string{"http://example.com/p?a=1&b=2"})

	if rep.Malformed != 0 {
		t.Fatalf("Malformed = %d, want 0", rep.Malformed)
	}
	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(rep.Entries))
	}
	e := rep.Entries[0]
	if e.URL.String() != "http://example.com/p?a=1&b=2" {
		t.Fatalf("URL = %q", e.URL.String())
	}
	if e.Status != StatusCompleted {
		t.Fatalf("status = %q, want completed", e.Status)
	}
	if e.Cached {
		t.Fatal("Cached = true on a fresh extraction")
	}
	if e.Err != nil {
		t.Fatalf("Err = %v, want nil", e.Err)
	}
	requireEqualStrings(t, "sources", e.Sources, []string{"test-adapter"})
	if !e.FirstSeen.Equal(fixedTime) || !e.LastSeen.Equal(fixedTime) {
		t.Fatalf("FirstSeen/LastSeen = %v/%v, want %v", e.FirstSeen, e.LastSeen, fixedTime)
	}
	if e.Host.String() != "example.com" {
		t.Fatalf("Host = %q, want example.com", e.Host.String())
	}

	// Exactly one endpoint: GET on the canonical URL, provenance from the
	// injected clock.
	if len(e.Endpoints) != 1 {
		t.Fatalf("endpoints = %d, want 1", len(e.Endpoints))
	}
	ep := e.Endpoints[0]
	if ep.Method != "GET" || ep.URL.String() != e.URL.String() {
		t.Fatalf("endpoint = %s %s", ep.Method, ep.URL.String())
	}
	if ep.Prov.Source != "test-adapter" || !ep.Prov.DiscoveredAt.Equal(fixedTime) {
		t.Fatalf("endpoint provenance = %+v", ep.Prov)
	}

	// Two parameters, values as-observed in first-seen order.
	requireEqualStrings(t, "parameter IDs", paramIDs(e), []string{
		"parameter:query:a", "parameter:query:b",
	})
	if len(e.Parameters) != 2 || len(e.Parameters[0].ObservedValues) != 1 || len(e.Parameters[1].ObservedValues) != 1 {
		t.Fatalf("parameters = %+v", e.Parameters)
	}

	// Graph: host->url, url->endpoint, url->parameter x2,
	// endpoint->parameter x2. relationIDs sorts by edge identity, so the
	// want-list is in sorted order (endpoint:... < host:... < url:...).
	wantRels := []string{
		"endpoint:GET http://example.com/p?a=1&b=2" + "endpoint_to_parameter\x00" + "parameter:query:a",
		"endpoint:GET http://example.com/p?a=1&b=2" + "endpoint_to_parameter\x00" + "parameter:query:b",
		"host:example.com" + "host_to_url\x00" + "url:http://example.com/p?a=1&b=2",
		"url:http://example.com/p?a=1&b=2" + "url_to_endpoint\x00" + "endpoint:GET http://example.com/p?a=1&b=2",
		"url:http://example.com/p?a=1&b=2" + "url_to_parameter\x00" + "parameter:query:a",
		"url:http://example.com/p?a=1&b=2" + "url_to_parameter\x00" + "parameter:query:b",
	}
	requireEqualStrings(t, "relationships", relationIDs(e), wantRels)

	// URL asset provenance (the canonical URL's Original still carries the
	// raw line).
	if e.URL.Prov.Source != "test-adapter" || !e.URL.Prov.DiscoveredAt.Equal(fixedTime) {
		t.Fatalf("URL provenance = %+v", e.URL.Prov)
	}
	if e.URL.Original != "http://example.com/p?a=1&b=2" {
		t.Fatalf("URL Original = %q", e.URL.Original)
	}

	// Work counters: one line read, canonicalized, extracted; no cache.
	snap := cfg.Metrics.Snapshot()
	if snap.Lines != 1 || snap.Canonicalized != 1 || snap.Extracted != 1 ||
		snap.Stored != 0 || snap.Reads != 0 || snap.Malformed != 0 {
		t.Fatalf("metrics = %+v", snap)
	}
}

// TestIngestCanonicalizationDedup pins that raw lines canonicalizing to the
// same Phase 2 URL identity merge into one entry: host case, default port,
// and query-key ordering — while a distinct raw query form stays distinct.
func TestIngestCanonicalizationDedup(t *testing.T) {
	rep := runIngest(t, testConfig(), []string{
		"HTTP://EXAMPLE.COM:80/p?b=2&a=1",
		"http://example.com/p?a=1&b=2",
		"http://example.com/p?x=a b", // raw space escapes to %20: distinct query
	})
	requireEqualStrings(t, "entries", entryStrings(rep), []string{
		"http://example.com/p?a=1&b=2",
		"http://example.com/p?x=a%20b",
	})

	e := findEntry(t, rep, "http://example.com/p?a=1&b=2")
	if len(e.Parameters) != 2 {
		t.Fatalf("parameters = %d, want 2", len(e.Parameters))
	}
	got := map[string][]string{}
	for _, p := range e.Parameters {
		got[p.Name] = p.ObservedValues
	}
	if len(got["a"]) != 1 || got["a"][0] != "1" || len(got["b"]) != 1 || got["b"][0] != "2" {
		t.Fatalf("parameter values = %v", got)
	}
}

// TestIngestMalformedLines pins the ingest boundary: schema-less lines,
// host-less lines, oversized lines, and control-character garbage are
// counted as malformed, never become entries, and never stop the run.
func TestIngestMalformedLines(t *testing.T) {
	cfg := testConfig()
	cfg.Metrics = &Metrics{}
	lines := []string{
		"not-a-url", // all-garbage: rejected by the parse
		"https://",  // missing host
		"http://example.com/" + strings.Repeat("a", maxRawURLLen), // oversized line: parses fine under the cap, rejected ONLY by the length check
		"http://example.com/bad\x00url",                           // control character
		"http://example.com/ok?q=1",                               // valid: must still process
	}
	rep := runIngest(t, cfg, lines)

	if rep.Malformed != 4 {
		t.Fatalf("Malformed = %d, want 4", rep.Malformed)
	}
	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (the valid line)", len(rep.Entries))
	}
	if e := rep.Entries[0]; e.URL.String() != "http://example.com/ok?q=1" || e.Status != StatusCompleted {
		t.Fatalf("valid entry = %+v", e)
	}
	snap := cfg.Metrics.Snapshot()
	if snap.Lines != 5 || snap.Canonicalized != 1 || snap.Malformed != 4 {
		t.Fatalf("metrics = %+v", snap)
	}
}

// TestIngestEmptySource covers the degenerate run: no lines, no entries, no
// error.
func TestIngestEmptySource(t *testing.T) {
	rep := runIngest(t, testConfig(), nil)
	if len(rep.Entries) != 0 || rep.Malformed != 0 {
		t.Fatalf("report = %+v, want empty", rep)
	}
}

// TestIngestConfigValidation pins the public API contract: nil arguments and
// invalid configuration are rejected with descriptive errors.
func TestIngestConfigValidation(t *testing.T) {
	ctx := context.Background()
	src := SliceSource(nil)

	cases := []struct {
		name string
		run  func() error
		want string
	}{
		{"nil context", func() error {
			_, err := Ingest(nil, testConfig(), src)
			return err
		}, "context must not be nil"},
		{"nil source", func() error {
			_, err := Ingest(ctx, testConfig(), nil)
			return err
		}, "source must not be nil"},
		{"nil accumulator", func() error {
			return IngestInto(ctx, testConfig(), src, nil)
		}, "accumulator must not be nil"},
		{"zero concurrency", func() error {
			cfg := Config{Concurrency: 0, QueueSize: 1, Adapter: "a"}
			_, err := Ingest(ctx, cfg, src)
			return err
		}, "concurrency must be positive"},
		{"zero queue", func() error {
			cfg := Config{Concurrency: 1, QueueSize: 0, Adapter: "a"}
			_, err := Ingest(ctx, cfg, src)
			return err
		}, "queue size must be positive"},
		{"negative timeout", func() error {
			cfg := Config{Concurrency: 1, QueueSize: 1, Timeout: -1, Adapter: "a"}
			_, err := Ingest(ctx, cfg, src)
			return err
		}, "timeout must not be negative"},
		{"empty adapter", func() error {
			cfg := testConfig()
			cfg.Adapter = ""
			_, err := Ingest(ctx, cfg, src)
			return err
		}, "adapter must not be empty"},
		{"oversized adapter", func() error {
			cfg := testConfig()
			cfg.Adapter = strings.Repeat("a", 129)
			_, err := Ingest(ctx, cfg, src)
			return err
		}, "adapter is longer than 128 bytes"},
		{"cancelled context", func() error {
			cctx, cancel := context.WithCancel(ctx)
			cancel()
			_, err := Ingest(cctx, testConfig(), src)
			return err
		}, "context canceled"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

// TestIngestCrossAdapterMerge covers the two-level emit design: two
// IngestInto runs (one per adapter) over a shared accumulator produce one
// entry per canonical URL with unioned sources in first-observation order,
// min/max timestamps, and merged parameter sources.
func TestIngestCrossAdapterMerge(t *testing.T) {
	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Clock = clk

	acc := NewAccumulator()
	cfg.Adapter = "adapter-a"
	if err := IngestInto(context.Background(), cfg,
		SliceSource([]string{"http://example.com/p?a=1&b=3"}), acc); err != nil {
		t.Fatalf("IngestInto (a): %v", err)
	}
	clk.advance(2 * time.Hour)
	cfg.Adapter = "adapter-b"
	if err := IngestInto(context.Background(), cfg,
		SliceSource([]string{"http://example.com/p?a=1&b=3", "http://other.example/x"}), acc); err != nil {
		t.Fatalf("IngestInto (b): %v", err)
	}

	rep := acc.Report()
	requireEqualStrings(t, "entries", entryStrings(rep), []string{
		"http://example.com/p?a=1&b=3",
		"http://other.example/x",
	})

	e := findEntry(t, rep, "http://example.com/p?a=1&b=3")
	requireEqualStrings(t, "sources", e.Sources, []string{"adapter-a", "adapter-b"})
	if !e.FirstSeen.Equal(fixedTime) || !e.LastSeen.Equal(fixedTime.Add(2*time.Hour)) {
		t.Fatalf("FirstSeen/LastSeen = %v/%v", e.FirstSeen, e.LastSeen)
	}
	// Parameter sources unioned; values unchanged (same canonical URL).
	for _, p := range e.Parameters {
		if p.Name != "a" && p.Name != "b" {
			t.Fatalf("unexpected parameter %q", p.Name)
		}
		requireEqualStrings(t, "parameter sources of "+p.Name, p.Sources, []string{"adapter-a", "adapter-b"})
	}
	// Every edge is deduplicated across the two observations.
	if len(e.Relationships) != 6 {
		t.Fatalf("relationships = %d, want 6 (deduplicated across adapters)", len(e.Relationships))
	}

	// The URL observed by only one adapter carries only that source.
	other := findEntry(t, rep, "http://other.example/x")
	requireEqualStrings(t, "other sources", other.Sources, []string{"adapter-b"})
}

// TestIngestEmitHook pins the incremental emit hook: called once per
// processed observation from worker goroutines.
func TestIngestEmitHook(t *testing.T) {
	var mu sync.Mutex
	emitted := map[string]int{}
	cfg := testConfig()
	cfg.Emit = func(_ context.Context, e URLEntry) error {
		mu.Lock()
		emitted[e.URL.String()]++
		mu.Unlock()
		return nil
	}
	lines := []string{
		"http://example.com/a",
		"http://example.com/b",
		"http://example.com/a", // duplicate observation of /a
	}
	rep := runIngest(t, cfg, lines)

	if len(rep.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(rep.Entries))
	}
	mu.Lock()
	defer mu.Unlock()
	if emitted["http://example.com/a"] != 2 || emitted["http://example.com/b"] != 1 {
		t.Fatalf("emitted = %v", emitted)
	}
}

// TestIngestEmitErrorRecordedNotFatal pins that an Emit failure is recorded
// on the run's returned error but does not abort the pipeline.
func TestIngestEmitErrorRecordedNotFatal(t *testing.T) {
	cfg := testConfig()
	cfg.Emit = func(_ context.Context, e URLEntry) error {
		if e.URL.String() == "http://example.com/a" {
			return errors.New("consumer exploded")
		}
		return nil
	}
	_, err := Ingest(context.Background(), cfg,
		SliceSource([]string{"http://example.com/a", "http://example.com/b"}))
	if err == nil || !strings.Contains(err.Error(), "urlintel: emit") ||
		!strings.Contains(err.Error(), "consumer exploded") {
		t.Fatalf("err = %v, want the emit failure surfaced", err)
	}
}

// TestIngestEmitPanicContained pins that a panicking Emit hook is contained
// at the call site: the entry is merged into the report BEFORE the hook runs
// (so the observation survives), the panic is converted into a run
// diagnostic (never a job error, never a crash), and no goroutine leaks.
func TestIngestEmitPanicContained(t *testing.T) {
	cfg := testConfig()
	cfg.Emit = func(_ context.Context, e URLEntry) error {
		panic("consumer exploded")
	}
	goruntime.GC()
	baseline := goruntime.NumGoroutine()

	rep, err := Ingest(context.Background(), cfg,
		SliceSource([]string{"http://example.com/a?q=1"}))
	if err == nil || !strings.Contains(err.Error(), "emit hook panicked") ||
		!strings.Contains(err.Error(), "consumer exploded") {
		t.Fatalf("err = %v, want the panic surfaced as an emit diagnostic", err)
	}
	// The merged observation predates the emit call: the report keeps it.
	if len(rep.Entries) != 1 || rep.Entries[0].URL.String() != "http://example.com/a?q=1" ||
		rep.Entries[0].Status != StatusCompleted {
		t.Fatalf("report = %+v, want the merged completed entry despite the panic", rep)
	}
	waitForGoroutines(t, baseline, 5*time.Second)
}

// blockingSource yields its fixed lines, then parks in Next until the run
// context is cancelled: the deterministic cancellation-at-EOF probe.
type blockingSource struct {
	lines []string
	i     int
}

// Next implements LineSource.
func (s *blockingSource) Next(ctx context.Context) (string, error) {
	if s.i < len(s.lines) {
		line := s.lines[s.i]
		s.i++
		return line, nil
	}
	<-ctx.Done()
	return "", ctx.Err()
}

// TestIngestCancellationAtEndOfStream pins that a source returning ctx.Err()
// ends the run: every consumed line is completed, and the run surfaces the
// source error.
func TestIngestCancellationAtEndOfStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &blockingSource{lines: []string{
		"http://example.com/a", "http://example.com/b", "http://example.com/c",
	}}
	cfg := testConfig()
	cfg.Metrics = &Metrics{}

	done := make(chan struct{})
	var rep Report
	var rerr error
	go func() {
		rep, rerr = Ingest(ctx, cfg, src)
		close(done)
	}()

	// All three lines are processed before the source parks (the metrics
	// are the live observable; rep is only assigned when Ingest returns).
	waitUntil(t, "all three extractions to complete", 2*time.Second, func() bool {
		return cfg.Metrics.Snapshot().Extracted == 3
	})
	cancel() // release the parked source
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Ingest did not finish after cancellation")
	}
	if rerr == nil || !strings.Contains(rerr.Error(), "context canceled") {
		t.Fatalf("err = %v, want the source cancellation surfaced", rerr)
	}
	for _, e := range rep.Entries {
		if e.Status != StatusCompleted {
			t.Fatalf("entry %s status = %s, want completed", e.URL.String(), e.Status)
		}
	}
}

// TestIngestCancellationMidStream pins the honest-status contract: when the
// run is cancelled mid-stream, every line consumed before the cancellation
// is represented as completed or cancelled (never failed), the completed
// observation is still persisted, and the run returns no error (cancellation
// is surfaced through entry statuses, not the error).
//
// The rate limiter makes the completed count exact: Burst 1 with a frozen
// clock means exactly ONE extraction ever happens (the first job); every
// later job parks on the limiter without executing. The exact number of
// lines consumed before cancellation is scheduling-dependent (the reader
// races the observer), so only the contract is asserted: all consumed lines
// are represented, none failed, and the one completed observation was
// persisted. The exact cancelled-entry accounting (one completed + one
// cancelled) is pinned deterministically by TestIngestRateLimiterGates.
func TestIngestCancellationMidStream(t *testing.T) {
	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Clock = clk
	cfg.Cache = openTestCache(t, clk, 0)
	cfg.Metrics = &Metrics{}
	cfg.Concurrency = 1
	cfg.QueueSize = 8
	cfg.Rate = 1
	cfg.Burst = 1
	cfg.Timeout = 0 // no real deadline: only cancellation releases the parked jobs

	lines := make([]string, 50)
	for i := range lines {
		lines[i] = fmt.Sprintf("http://example.com/p%d", i)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var rep Report
	var rerr error
	go func() {
		rep, rerr = Ingest(ctx, cfg, SliceSource(lines))
		close(done)
	}()

	// Cancel once the first extraction has demonstrably completed: exactly
	// one token was ever granted, so nothing else can have run.
	waitUntil(t, "the first extraction to complete", 2*time.Second, func() bool {
		return cfg.Metrics.Snapshot().Extracted >= 1
	})
	if snap := cfg.Metrics.Snapshot(); snap.Extracted != 1 {
		t.Fatalf("extracted = %d, want exactly 1 (burst=1, frozen clock)", snap.Extracted)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Ingest did not finish after cancellation")
	}
	if rerr != nil {
		t.Fatalf("err = %v, want nil (cancellation is surfaced via statuses)", rerr)
	}

	completed := 0
	for _, e := range rep.Entries {
		switch e.Status {
		case StatusCompleted:
			completed++
			if e.Err != nil {
				t.Fatalf("completed entry %s carries Err %v", e.URL.String(), e.Err)
			}
		case StatusCancelled:
		default:
			t.Fatalf("entry %s status = %s, want completed or cancelled", e.URL.String(), e.Status)
		}
	}
	if completed != 1 {
		t.Fatalf("completed = %d, want exactly 1 (only one token was ever granted)", completed)
	}
	// The completed observation was persisted even though the run was
	// cancelled (detached, bounded store context).
	if snap := cfg.Metrics.Snapshot(); snap.Stored != 1 {
		t.Fatalf("stored = %d, want exactly 1 completed entry persisted", snap.Stored)
	}
}

// TestIngestRateLimiterGates pins the job-start rate limiter with a frozen
// clock: with Burst 1, exactly one URL may ever be processed — every later
// job blocks on the limiter until its job deadline. Deterministic: the fake
// clock never advances, so tokens can never refill.
func TestIngestRateLimiterGates(t *testing.T) {
	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Clock = clk
	cfg.Metrics = &Metrics{}
	cfg.Rate = 1
	cfg.Burst = 1
	cfg.Timeout = 500 * time.Millisecond // jobs give up fast on the frozen limiter

	rep := runIngest(t, cfg, []string{"http://a.example/p", "http://b.example/p"})
	if snap := cfg.Metrics.Snapshot(); snap.Extracted != 1 {
		t.Fatalf("extracted = %d, want exactly 1 (burst=1, clock frozen)", snap.Extracted)
	}
	completed, cancelled := 0, 0
	for _, e := range rep.Entries {
		switch e.Status {
		case StatusCompleted:
			completed++
		case StatusCancelled:
			cancelled++
		default:
			t.Fatalf("entry %s status = %s", e.URL.String(), e.Status)
		}
	}
	if completed != 1 || cancelled != 1 {
		t.Fatalf("completed/cancelled = %d/%d, want 1/1", completed, cancelled)
	}
}

// TestIngestRateLimiterReleasesOnToken pins that the limiter gates but does
// not deadlock: with no real job deadline, a parked job's token wait is
// observable as a registered fake-clock timer, and advancing the clock
// releases the token and completes the run.
func TestIngestRateLimiterReleasesOnToken(t *testing.T) {
	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Clock = clk
	cfg.Metrics = &Metrics{}
	cfg.Rate = 1
	cfg.Burst = 1
	cfg.Timeout = 0 // no real deadline: the fake clock alone gates token release

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var rep Report
	var rerr error
	go func() {
		rep, rerr = Ingest(ctx, cfg, SliceSource([]string{"http://a.example/p", "http://b.example/p"}))
		close(done)
	}()

	// The second job's token wait becomes observable as a registered
	// fake-clock timer; exactly one extraction has happened so far.
	waitUntil(t, "the second job's token wait to register", 2*time.Second, func() bool {
		return clk.waiterCount() >= 1
	})
	if snap := cfg.Metrics.Snapshot(); snap.Extracted != 1 {
		t.Fatalf("extracted = %d before token release, want exactly 1", snap.Extracted)
	}
	clk.advance(time.Second) // release one token
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Ingest did not finish after the token release")
	}
	if rerr != nil {
		t.Fatalf("err = %v", rerr)
	}
	if snap := cfg.Metrics.Snapshot(); snap.Extracted != 2 {
		t.Fatalf("extracted = %d, want 2", snap.Extracted)
	}
	if len(rep.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(rep.Entries))
	}
	for _, e := range rep.Entries {
		if e.Status != StatusCompleted {
			t.Fatalf("entry %s status = %s, want completed", e.URL.String(), e.Status)
		}
	}
}

// TestIngestRateLimiterDisabled pins that Rate <= 0 disables pacing: every
// URL processes immediately.
func TestIngestRateLimiterDisabled(t *testing.T) {
	cfg := testConfig() // Rate 0 from testConfig
	rep := runIngest(t, cfg, []string{"http://a.example/p", "http://b.example/p"})
	if len(rep.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(rep.Entries))
	}
	for _, e := range rep.Entries {
		if e.Status != StatusCompleted {
			t.Fatalf("entry %s status = %s, want completed", e.URL.String(), e.Status)
		}
	}
}

// TestIngestIPLiteralNoHost pins the Phase 2 scope rule: an IP-literal URL
// carries no host asset and no host_to_url edge.
func TestIngestIPLiteralNoHost(t *testing.T) {
	rep := runIngest(t, testConfig(), []string{"http://192.0.2.1/p?q=1"})
	e := findEntry(t, rep, "http://192.0.2.1/p?q=1")
	if !hostIsZero(e.Host) {
		t.Fatalf("Host = %+v, want zero for an IP-literal URL", e.Host)
	}
	for _, r := range e.Relationships {
		if r.Kind == "host_to_url" {
			t.Fatalf("unexpected host_to_url edge: %+v", r)
		}
	}
	if got := len(e.Relationships); got != 3 {
		t.Fatalf("relationships = %d, want 3 (url->endpoint, url->param, endpoint->param)", got)
	}
	if hosts := rep.AllHosts(); len(hosts) != 0 {
		t.Fatalf("AllHosts = %v, want none", hosts)
	}
}

// TestIngestParameterExtractionPin pins the Phase 6A parameter semantics at
// the pipeline level: names and values stay exactly as observed (escaped
// forms never unescape, distinct raw forms stay distinct identities),
// repeated names merge within one URL, value-less keys are skipped, and the
// raw-space escape merges forms the URL model equates.
func TestIngestParameterExtractionPin(t *testing.T) {
	rep := runIngest(t, testConfig(), []string{
		"http://example.com/p?x=a%20b",       // escaped space
		"http://example.com/p?x=a+b",         // plus form: DISTINCT identity
		"http://example.com/p?x=a%20b&flag",  // value-less key skipped
		"http://example.com/p?x=a%20b&x=2nd", // repeated name merges
		"http://example.com/p?x=a b",         // raw space: same identity as %20
		"http://example.com/p?x=café",        // raw non-ASCII as-observed
	})

	// Six raw lines, five canonical URLs: the two %20 lines canonicalize
	// together, the + form stays distinct, and the flag/2nd variants are
	// their own URLs. The canonical query sorts keys by decoded name, so
	// the value-less flag key sorts before x.
	requireEqualStrings(t, "entries", entryStrings(rep), []string{
		"http://example.com/p?flag&x=a%20b",
		"http://example.com/p?x=a%20b",
		"http://example.com/p?x=a%20b&x=2nd",
		"http://example.com/p?x=a+b",
		"http://example.com/p?x=café",
	})

	values := func(canonical string) []string {
		e := findEntry(t, rep, canonical)
		if len(e.Parameters) != 1 {
			t.Fatalf("%s: parameters = %d, want 1", canonical, len(e.Parameters))
		}
		return e.Parameters[0].ObservedValues
	}
	requireEqualStrings(t, "x values (escaped space)", values("http://example.com/p?x=a%20b"), []string{"a%20b"})
	requireEqualStrings(t, "x values (flag variant)", values("http://example.com/p?flag&x=a%20b"), []string{"a%20b"})
	requireEqualStrings(t, "x values (2nd variant)", values("http://example.com/p?x=a%20b&x=2nd"), []string{"a%20b", "2nd"})
	requireEqualStrings(t, "x values (plus)", values("http://example.com/p?x=a+b"), []string{"a+b"})
	requireEqualStrings(t, "x values (raw non-ASCII)", values("http://example.com/p?x=café"), []string{"café"})
}

// TestIngestParameterOverflow pins the per-URL parameter cap: distinct
// parameters beyond maxParametersPerURL are dropped and the entry is flagged
// Overflow but still completed.
func TestIngestParameterOverflow(t *testing.T) {
	var b strings.Builder
	b.WriteString("http://example.com/p?")
	for i := 0; i < maxParametersPerURL+10; i++ {
		if i > 0 {
			b.WriteByte('&')
		}
		fmt.Fprintf(&b, "p%d=v", i)
	}
	rep := runIngest(t, testConfig(), []string{b.String()})
	e := rep.Entries[0]
	if e.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed (overflowed records stay completed)", e.Status)
	}
	if !e.Overflow {
		t.Fatal("Overflow = false, want true")
	}
	if len(e.Parameters) != maxParametersPerURL {
		t.Fatalf("parameters = %d, want %d retained", len(e.Parameters), maxParametersPerURL)
	}
}

// TestIngestParameterValueTruncation pins the per-parameter value cap: more
// distinct values than the Phase 2 model retains are dropped with the
// parameter's Truncated flag set, never fatal.
func TestIngestParameterValueTruncation(t *testing.T) {
	var b strings.Builder
	b.WriteString("http://example.com/p?")
	for i := 1; i <= maxObservedValues+1; i++ {
		if i > 1 {
			b.WriteByte('&')
		}
		fmt.Fprintf(&b, "x=%d", i)
	}
	rep := runIngest(t, testConfig(), []string{b.String()})
	e := rep.Entries[0]
	if e.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", e.Status)
	}
	if e.Overflow {
		t.Fatal("Overflow = true, want false (only one distinct parameter)")
	}
	if len(e.Parameters) != 1 {
		t.Fatalf("parameters = %d, want 1", len(e.Parameters))
	}
	p := e.Parameters[0]
	if !p.Truncated {
		t.Fatal("Truncated = false, want true")
	}
	if len(p.ObservedValues) != maxObservedValues {
		t.Fatalf("values = %d, want %d retained", len(p.ObservedValues), maxObservedValues)
	}
	if p.ObservedValues[0] != "1" || p.ObservedValues[maxObservedValues-1] != "1024" {
		t.Fatalf("first/last value = %q/%q, want 1/1024", p.ObservedValues[0], p.ObservedValues[maxObservedValues-1])
	}
}

// TestIngestDeterminism pins the report contract: the same source processed
// twice (different concurrency, second run cache-backed) produces identical
// reports.
func TestIngestDeterminism(t *testing.T) {
	clk := newFakeClock(fixedTime)
	lines := []string{
		"http://example.com/a?q=1&x=2",
		"http://example.com/b?q=3",
		"http://example.com/a?q=1&x=2",
		"http://192.0.2.1/c?q=4",
		"http://EXAMPLE.com:80/a?x=2&q=1",
	}

	cfg1 := testConfig()
	cfg1.Clock = clk
	cfg1.Concurrency = 1
	rep1 := runIngest(t, cfg1, lines)

	clk2 := newFakeClock(fixedTime)
	cfg2 := testConfig()
	cfg2.Clock = clk2
	cfg2.Concurrency = 8
	cfg2.Cache = openTestCache(t, clk2, 0)
	rep2 := runIngest(t, cfg2, lines)

	if fp1, fp2 := reportFingerprint(rep1), reportFingerprint(rep2); fp1 != fp2 {
		t.Fatalf("reports differ across runs:\n%s\nvs\n%s", fp1, fp2)
	}
}

// TestIngestNoGoroutineLeak pins the shutdown contract: after Ingest returns,
// every pool-owned goroutine has terminated.
func TestIngestNoGoroutineLeak(t *testing.T) {
	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Clock = clk
	cfg.Cache = openTestCache(t, clk, 0)

	lines := make([]string, 20)
	for i := range lines {
		lines[i] = fmt.Sprintf("http://example.com/p%d?q=%d", i, i)
	}

	goruntime.GC()
	baseline := goruntime.NumGoroutine()

	runIngest(t, cfg, lines)
	waitForGoroutines(t, baseline, 5*time.Second)
}

// reportFingerprint renders a report's entries deterministically: one line
// per entry with its URL, status, sources, and the sorted identities of its
// endpoints, parameters (with values), and relationships.
func reportFingerprint(rep Report) string {
	var b strings.Builder
	for _, e := range rep.Entries {
		fmt.Fprintf(&b, "%s|%s|%v", e.URL.String(), e.Status, e.Sources)
		for i := range e.Endpoints {
			b.WriteString("|ep:" + e.Endpoints[i].Identity().String())
		}
		for i := range e.Parameters {
			p := e.Parameters[i]
			fmt.Fprintf(&b, "|prm:%s=%v", p.ID(), p.ObservedValues)
		}
		for i := range e.Relationships {
			b.WriteString("|rel:" + e.Relationships[i].ID())
		}
		b.WriteString("\n")
	}
	return b.String()
}
