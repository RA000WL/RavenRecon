package techintel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

func TestIngestConfigValidation(t *testing.T) {
	ctx := context.Background()
	src := &SliceObservationSource{newObs(t, "https://ok.example/")}

	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"zero concurrency", func(c *Config) { c.Concurrency = 0 }, "Concurrency"},
		{"zero queue", func(c *Config) { c.QueueSize = 0 }, "QueueSize"},
		{"negative timeout", func(c *Config) { c.Timeout = -1 }, "Timeout"},
		{"negative tech cap", func(c *Config) { c.MaxTechnologiesPerObservation = -1 }, "MaxTechnologiesPerObservation"},
		{"negative indicator cap", func(c *Config) { c.MaxIndicatorsPerObservation = -1 }, "MaxIndicatorsPerObservation"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t)
			tt.mut(&cfg)
			_, err := Ingest(ctx, cfg, src)
			if err == nil {
				t.Fatal("invalid config must be rejected")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}

	if _, err := Ingest(ctx, testConfig(t), nil); err == nil ||
		!strings.Contains(err.Error(), "nil observation source") {
		t.Errorf("nil source error = %v", err)
	}
}

func TestIngestPreCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := testConfig(t)
	cfg.Metrics = &Metrics{}

	rep, err := Ingest(ctx, cfg, &SliceObservationSource{newObs(t, "https://ok.example/")})
	if err != nil {
		t.Fatalf("pre-cancelled run must not error: %v", err)
	}
	if rep.Observations.Completed != 0 || rep.Observations.Cancelled != 0 ||
		rep.Observations.Malformed != 0 {
		t.Errorf("counts = %+v", rep.Observations)
	}
	if len(rep.Technologies) != 0 || len(rep.Evidence) != 0 {
		t.Errorf("report must be empty: %d techs, %d evidence", len(rep.Technologies), len(rep.Evidence))
	}
	if got := cfg.Metrics.Snapshot(); got.Observations != 0 || got.Analyzed != 0 {
		t.Errorf("metrics = %+v", got)
	}
}

func TestIngestFreshThenCached(t *testing.T) {
	obs := newObs(t, "https://ok.example/")
	obs.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
	obs.Body = "It works!"

	emit1 := &entrySink{}
	cfg := testConfig(t)
	cfg.Emit = emit1.Fn()
	cfg.Metrics = &Metrics{}

	rep1, err := Ingest(context.Background(), cfg, &SliceObservationSource{obs})
	if err != nil {
		t.Fatalf("fresh run: %v", err)
	}
	if rep1.Observations.Completed != 1 {
		t.Errorf("completed = %d, want 1", rep1.Observations.Completed)
	}
	if got := cfg.Metrics.Snapshot(); got.Observations != 1 || got.Analyzed != 1 || got.Stored != 1 || got.Reads != 1 {
		t.Errorf("metrics = %+v", got)
	}
	if len(emit1.entries) != 1 || emit1.entries[0].Cached {
		t.Errorf("emit = %+v, want one uncached entry", emit1.entries)
	}
	if len(rep1.Technologies) != 2 { // nginx + apache (It works!)
		t.Errorf("technologies = %d, want 2", len(rep1.Technologies))
	}
	nginxTech := (*asset.Technology)(nil)
	for i := range rep1.Technologies {
		if rep1.Technologies[i].Name == "nginx" {
			nginxTech = &rep1.Technologies[i]
		}
	}
	if nginxTech == nil {
		t.Errorf("nginx missing: %v", rep1.Technologies)
	}

	// Second run over the same cache: the hit serves the stored result with
	// ZERO analysis.
	emit2 := &entrySink{}
	cfg2 := cfg
	cfg2.Emit = emit2.Fn()
	cfg2.Metrics = &Metrics{}

	rep2, err := Ingest(context.Background(), cfg2, &SliceObservationSource{obs})
	if err != nil {
		t.Fatalf("cached run: %v", err)
	}
	if got := cfg2.Metrics.Snapshot(); got.Reads != 1 || got.Analyzed != 0 || got.Stored != 0 {
		t.Errorf("cached metrics = %+v", got)
	}
	if len(emit2.entries) != 1 || !emit2.entries[0].Cached {
		t.Errorf("cached emit = %+v, want one cached entry", emit2.entries)
	}
	if !reflect.DeepEqual(rep1.Technologies, rep2.Technologies) {
		t.Errorf("technologies diverged: %v vs %v", rep1.Technologies, rep2.Technologies)
	}
	if !reflect.DeepEqual(rep1.Evidence, rep2.Evidence) || rep1.Conflicts != rep2.Conflicts {
		t.Errorf("report diverged: evidence %v vs %v, conflicts %d vs %d",
			rep1.Evidence, rep2.Evidence, rep1.Conflicts, rep2.Conflicts)
	}
}

func TestIngestMalformedCounted(t *testing.T) {
	valid := newObs(t, "https://ok.example/")
	valid.Headers = []HeaderEntry{{Name: "Server", Value: "nginx"}}
	broken := Observation{Source: "test", ObservedAt: fixedTime} // zero URL

	cfg := testConfig(t)
	cfg.Metrics = &Metrics{}
	rep, err := Ingest(context.Background(), cfg, &SliceObservationSource{valid, broken})
	if err == nil || !strings.Contains(err.Error(), "malformed observation") {
		t.Errorf("run error = %v, want malformed diagnostic", err)
	}
	if rep.Observations.Completed != 1 || rep.Observations.Malformed != 1 {
		t.Errorf("counts = %+v", rep.Observations)
	}
	if got := cfg.Metrics.Snapshot(); got.Observations != 1 || got.Malformed != 1 {
		t.Errorf("metrics = %+v", got)
	}
}

func TestIngestEmitDiagnosticsContained(t *testing.T) {
	obs := newObs(t, "https://ok.example/")
	obs.Headers = []HeaderEntry{{Name: "Server", Value: "nginx"}}

	t.Run("emit error", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.Emit = func(context.Context, Observation, ReportEntry) error {
			return errors.New("emit boom")
		}
		rep, err := Ingest(context.Background(), cfg, &SliceObservationSource{obs})
		if err == nil || !strings.Contains(err.Error(), "emit") || !strings.Contains(err.Error(), "emit boom") {
			t.Errorf("run error = %v, want emit diagnostic", err)
		}
		if rep.Observations.Completed != 1 {
			t.Errorf("completed = %d, want 1 (emit errors are not fatal)", rep.Observations.Completed)
		}
	})

	t.Run("emit panic", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.Emit = func(context.Context, Observation, ReportEntry) error {
			panic("kaboom")
		}
		rep, err := Ingest(context.Background(), cfg, &SliceObservationSource{obs})
		if err == nil || !strings.Contains(err.Error(), "emit hook panicked") {
			t.Errorf("run error = %v, want panic diagnostic", err)
		}
		if rep.Observations.Completed != 1 {
			t.Errorf("completed = %d, want 1 (emit panics are not fatal)", rep.Observations.Completed)
		}
	})
}

// blockGetCache is a cache whose first Get blocks until the run context is
// cancelled; it deterministically wedges one worker so queued jobs and the
// reader backpressure can be observed.
type blockGetCache struct {
	reached chan struct{}
	unlock  chan struct{}
	once    sync.Once
}

func (c *blockGetCache) Get(ctx context.Context, key cache.Key) cache.Outcome {
	c.once.Do(func() { close(c.reached) })
	select {
	case <-c.unlock:
	case <-ctx.Done():
	}
	return cache.Outcome{State: cache.StateMiss}
}

func (c *blockGetCache) Put(ctx context.Context, key cache.Key, record cache.Record) error {
	return nil
}
func (c *blockGetCache) Delete(ctx context.Context, key cache.Key) error { return nil }
func (c *blockGetCache) Clear(ctx context.Context) error                 { return nil }

var _ cache.Cache = (*blockGetCache)(nil)

func TestIngestCancellationHonestStatuses(t *testing.T) {
	cg := &blockGetCache{reached: make(chan struct{}), unlock: make(chan struct{})}
	cfg := testConfig(t)
	cfg.Concurrency = 1
	cfg.QueueSize = 2
	cfg.Cache = cg
	cfg.Metrics = &Metrics{}

	ctx, cancel := context.WithCancel(context.Background())
	var rep Report
	var runErr error
	done := make(chan struct{})
	go func() {
		rep, runErr = Ingest(ctx, cfg, &SliceObservationSource{
			newObs(t, "https://a.example/"),
			newObs(t, "https://b.example/"),
			newObs(t, "https://c.example/"),
		})
		close(done)
	}()

	// Wait until the single worker is stuck in its cache Get, then cancel:
	// the reader is blocked submitting the third observation, the remaining
	// jobs are queued, and everything drains with honest cancelled
	// statuses.
	select {
	case <-cg.reached:
	case <-time.After(testTimeout):
		t.Fatal("worker never reached the blocking Get")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("ingest did not return after cancellation")
	}
	if runErr != nil {
		t.Errorf("run error = %v, want nil", runErr)
	}
	if rep.Observations.Completed != 0 || rep.Observations.Cancelled != 3 {
		t.Errorf("counts = %+v, want 0 completed / 3 cancelled", rep.Observations)
	}
	if len(rep.Technologies) != 0 {
		t.Errorf("cancelled run must not report technologies: %v", rep.Technologies)
	}
	got := cfg.Metrics.Snapshot()
	if got.Observations != 3 || got.Reads != 1 || got.Analyzed != 0 || got.Stored != 0 {
		t.Errorf("metrics = %+v", got)
	}
}

func TestIngestMegaRoundTrip(t *testing.T) {
	obs := megaObs(t)
	cfg := testConfig(t)
	cfg.Metrics = &Metrics{}

	rep1, err := Ingest(context.Background(), cfg, &SliceObservationSource{obs})
	if err != nil {
		t.Fatalf("mega run: %v", err)
	}
	if rep1.Observations.Completed != 1 || rep1.Observations.Malformed != 0 {
		t.Errorf("counts = %+v", rep1.Observations)
	}
	if len(rep1.Technologies) > 128 || len(rep1.Evidence) > 512 {
		t.Errorf("caps exceeded: %d technologies, %d evidence", len(rep1.Technologies), len(rep1.Evidence))
	}

	// The fixture must fire the documented marker technologies.
	for _, want := range []string{"nginx", "apache", "cloudflare", "wordpress", "drupal",
		"php", "react", "angular", "graphql"} {
		found := false
		for _, t0 := range rep1.Technologies {
			if t0.Name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("technology %q did not fire", want)
		}
	}
	techByName := func(name string) *asset.Technology {
		for i := range rep1.Technologies {
			if rep1.Technologies[i].Name == name {
				return &rep1.Technologies[i]
			}
		}
		return nil
	}
	if nginx := techByName("nginx"); nginx == nil || nginx.Version != "1.25.3" {
		t.Errorf("nginx = %v, want version 1.25.3", nginx)
	}
	if wp := techByName("wordpress"); wp == nil || wp.Version != "6.4.2" {
		t.Errorf("wordpress = %v, want version 6.4.2", wp)
	}
	if ng := techByName("angular"); ng == nil || ng.Version != "17.0.0" {
		t.Errorf("angular = %v, want version 17.0.0", ng)
	}

	// Second run over the same cache must reproduce the report exactly with
	// zero analysis.
	cfg2 := cfg
	cfg2.Metrics = &Metrics{}
	rep2, err := Ingest(context.Background(), cfg2, &SliceObservationSource{obs})
	if err != nil {
		t.Fatalf("cached mega run: %v", err)
	}
	if cfg2.Metrics.Snapshot().Analyzed != 0 {
		t.Errorf("cached run analyzed, want 0")
	}
	if !reflect.DeepEqual(rep1.Technologies, rep2.Technologies) {
		t.Errorf("mega technologies diverged")
	}
	if !reflect.DeepEqual(rep1.Evidence, rep2.Evidence) ||
		!reflect.DeepEqual(rep1.Relationships, rep2.Relationships) ||
		rep1.Conflicts != rep2.Conflicts || rep1.Truncated != rep2.Truncated {
		t.Errorf("mega report diverged")
	}
}

func TestIngestHitServedFromStubCache(t *testing.T) {
	obs := newObs(t, "https://ok.example/")
	obs.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
	mask := sourcesMask(obs)

	db, err := fingerprints.Load()
	if err != nil {
		t.Fatal(err)
	}
	prov := asset.Provenance{Source: obs.Source, DiscoveredAt: obs.ObservedAt}
	entry := completedEntry(obs, analyze(obs, db.Fingerprints(), 128, 512, prov), prov)
	rec, err := encodeStoredTech(obs, entry, mask, fixedTime)
	if err != nil {
		t.Fatal(err)
	}

	emit := &entrySink{}
	cfg := testConfig(t)
	cfg.Cache = &stubCache{outcome: cache.Outcome{State: cache.StateHit, Record: &rec}}
	cfg.DB = db
	cfg.Emit = emit.Fn()
	cfg.Metrics = &Metrics{}

	rep, err := Ingest(context.Background(), cfg, &SliceObservationSource{obs})
	if err != nil {
		t.Fatalf("hit run: %v", err)
	}
	if got := cfg.Metrics.Snapshot(); got.Analyzed != 0 || got.Stored != 0 || got.Reads != 1 {
		t.Errorf("metrics = %+v, want zero analysis on a hit", got)
	}
	if len(emit.entries) != 1 || !emit.entries[0].Cached {
		t.Errorf("emit = %+v, want one cached entry", emit.entries)
	}
	if len(rep.Technologies) != 1 || rep.Technologies[0].Name != "nginx" {
		t.Errorf("technologies = %v, want canned nginx", rep.Technologies)
	}
}

func TestMetricsNilSafety(t *testing.T) {
	var m *Metrics
	m.addObservations()
	m.addAnalyzed()
	m.addStored()
	m.addReads()
	m.addMalformed()
	if got := m.Snapshot(); got != (MetricsSnapshot{}) {
		t.Errorf("nil snapshot = %+v, want zero", got)
	}
}

func TestSliceObservationSource(t *testing.T) {
	a := newObs(t, "https://a.example/")
	b := newObs(t, "https://b.example/")
	src := SliceObservationSource{a, b}

	o1, err := src.Next(context.Background())
	if err != nil || !o1.identity().Equal(a.identity()) {
		t.Errorf("Next 1 = %v/%v", o1, err)
	}
	o2, err := src.Next(context.Background())
	if err != nil || !o2.identity().Equal(b.identity()) {
		t.Errorf("Next 2 = %v/%v", o2, err)
	}
	if _, err := src.Next(context.Background()); err != io.EOF {
		t.Errorf("Next 3 = %v, want io.EOF", err)
	}
}

// TestIngestFreshVsCachedEvidenceIdentical is the H1 cache regression test:
// a fresh run and a cached re-run over the SAME cache must produce IDENTICAL
// evidence identities — including HTML-derived evidence whose value sits
// after a non-ASCII (case-folding-shrinking) body prefix. The old
// folded-index bug tore such evidence values, so fresh and cached runs
// diverged; the cache round-trip proves the stored values are the observed
// original spans and the identities cover exactly those bytes.
func TestIngestFreshVsCachedEvidenceIdentical(t *testing.T) {
	obs := newObs(t, "https://ok.example/")
	obs.Headers = []HeaderEntry{
		{Name: "Server", Value: "nginx/1.25.3"},
		{Name: "Set-Cookie", Value: "sid=abc; HttpOnly"},
	}
	obs.Body = "\u0130\u1E9E<div class=\"CF-ERROR-DETAILS\">It works! webpackChunk</div>"

	cfg := testConfig(t)
	cfg.Metrics = &Metrics{}

	rep1, err := Ingest(context.Background(), cfg, &SliceObservationSource{obs})
	if err != nil {
		t.Fatalf("fresh run: %v", err)
	}
	if got := cfg.Metrics.Snapshot(); got.Analyzed != 1 || got.Stored != 1 {
		t.Fatalf("fresh metrics = %+v, want a full analysis + store", got)
	}

	cfg2 := cfg
	cfg2.Metrics = &Metrics{}
	rep2, err := Ingest(context.Background(), cfg2, &SliceObservationSource{obs})
	if err != nil {
		t.Fatalf("cached run: %v", err)
	}
	if got := cfg2.Metrics.Snapshot(); got.Analyzed != 0 || got.Stored != 0 || got.Reads != 1 {
		t.Fatalf("cached metrics = %+v, want zero analysis on the hit", got)
	}

	ids := func(evs []asset.Evidence) map[string]bool {
		out := make(map[string]bool, len(evs))
		for _, ev := range evs {
			out[ev.ID()] = true
		}
		return out
	}
	fresh := ids(rep1.Evidence)
	cached := ids(rep2.Evidence)
	if len(fresh) == 0 || len(fresh) != len(cached) {
		t.Fatalf("evidence identity counts: fresh %d cached %d, want identical non-empty sets", len(fresh), len(cached))
	}
	for id := range fresh {
		if !cached[id] {
			t.Errorf("evidence identity %q present in the fresh run but missing from the cached run", id)
		}
	}
	// Byte-for-byte evidence values too (the identities cover stored bytes,
	// so identical identities imply identical values — this pins both).
	if !reflect.DeepEqual(rep1.Evidence, rep2.Evidence) {
		t.Errorf("evidence diverged between fresh and cached runs:\nfresh:\n%+v\ncached:\n%+v", rep1.Evidence, rep2.Evidence)
	}
	// The HTML-derived evidence must carry the original observed marker
	// (byte-for-byte, upper-cased as observed), never a folded or torn span.
	found := false
	for _, ev := range rep1.Evidence {
		if ev.Indicator == "html_substring:cf-error-details" {
			found = true
			if ev.Value != "CF-ERROR-DETAILS" {
				t.Errorf("html evidence value = %q, want the original observed span %q", ev.Value, "CF-ERROR-DETAILS")
			}
		}
	}
	if !found {
		t.Errorf("html_substring evidence missing from %v", rep1.Evidence)
	}
	if !reflect.DeepEqual(rep1.Technologies, rep2.Technologies) || rep1.Conflicts != rep2.Conflicts {
		t.Errorf("technologies/conflicts diverged between runs")
	}
}

// waitForGoroutines patience-waits until the goroutine count returns to at
// most baseline+2 (bounded patience, never timing-fragile: it only fails on
// a genuine leak).
func waitForGoroutines(t *testing.T, baseline int, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		runtime.GC()
		if n := runtime.NumGoroutine(); n <= baseline+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	n := runtime.NumGoroutine()
	t.Fatalf("goroutines = %d after run (baseline %d); possible leak", n, baseline)
}

// TestIngestNoGoroutineLeakAfterShutdown verifies that a completed run
// leaves no goroutines behind: Ingest's Shutdown is the join point — it
// drains the queue and in-flight jobs and returns only after every
// pool-owned goroutine (the workers and the reader) has terminated. This
// test proves the pool is fully drained BEFORE the goroutine count is
// taken (the runtime guarantee on the pool's Shutdown, pinned end-to-end
// here).
func TestIngestNoGoroutineLeakAfterShutdown(t *testing.T) {
	cfg := testConfig(t)
	cfg.Concurrency = 8

	mkObs := func(i int) Observation {
		o := newObs(t, fmt.Sprintf("https://h%d.example/", i))
		o.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
		o.Body = "It works!"
		return o
	}

	// Warm up so runtime internals (test framework, caches, GC) are
	// settled before the baseline is taken.
	mustFinish(t, "warm-up Ingest", func() {
		if _, err := Ingest(context.Background(), cfg, &SliceObservationSource{mkObs(0)}); err != nil {
			t.Fatalf("warm-up Ingest: %v", err)
		}
	})
	runtime.GC()
	baseline := runtime.NumGoroutine()

	src := &SliceObservationSource{}
	for i := 0; i < 64; i++ {
		*src = append(*src, mkObs(i))
	}
	mustFinish(t, "Ingest", func() {
		if _, err := Ingest(context.Background(), cfg, src); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	})
	waitForGoroutines(t, baseline, 5*time.Second)
}

// TestIngestNoGoroutineLeakAfterCancellation verifies the same guarantee on
// the cancellation path: a run cancelled mid-flight (one worker wedged in a
// cache Get) unwinds the reader, the pool, and the drain completely and
// leaves no goroutines behind.
func TestIngestNoGoroutineLeakAfterCancellation(t *testing.T) {
	cg := &blockGetCache{reached: make(chan struct{}), unlock: make(chan struct{})}
	cfg := testConfig(t)
	cfg.Concurrency = 1
	cfg.QueueSize = 2
	cfg.Cache = cg

	runtime.GC()
	baseline := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	var runErr error
	done := make(chan struct{})
	ing := func() {
		_, runErr = Ingest(ctx, cfg, &SliceObservationSource{
			newObs(t, "https://a.example/"),
			newObs(t, "https://b.example/"),
			newObs(t, "https://c.example/"),
		})
		close(done)
	}
	mustFinish(t, "Ingest start", func() { go ing() })

	// Wait until the single worker is stuck in its cache Get, then cancel:
	// the reader and the queued jobs unwind through the bounded drain.
	select {
	case <-cg.reached:
	case <-time.After(testTimeout):
		t.Fatal("worker never reached the blocking Get")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("ingest did not return after cancellation")
	}
	if runErr != nil {
		t.Errorf("run error = %v, want nil", runErr)
	}
	waitForGoroutines(t, baseline, 5*time.Second)
}

// TestIngestRecordCreatedAtIsStoreTime is the L3 regression test: a record's
// CreatedAt is stamped from the RUN clock at STORE time, never from the
// observation's ObservedAt. TTL is measured from CreatedAt, so a stale
// ObservedAt must not expire a fresh record instantly, and a future
// ObservedAt must not make it immortal.
func TestIngestRecordCreatedAtIsStoreTime(t *testing.T) {
	obs := newObs(t, "https://ok.example/")
	obs.Headers = []HeaderEntry{{Name: "Server", Value: "nginx"}}
	obs.ObservedAt = fixedTime.Add(-48 * time.Hour) // stale observation time

	cfg := testConfig(t) // fake clock frozen at fixedTime
	cfg.Metrics = &Metrics{}
	if _, err := Ingest(context.Background(), cfg, &SliceObservationSource{obs}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	key, err := techKey(obs, fingerprints.SchemaVersion, techDigest(t))
	if err != nil {
		t.Fatal(err)
	}
	out := cfg.Cache.Get(context.Background(), key)
	if out.State != cache.StateHit {
		t.Fatalf("state = %v, want a stored hit", out.State)
	}
	if got := out.Record.CreatedAt; !got.Equal(fixedTime) {
		t.Errorf("record CreatedAt = %v, want the run clock's store time %v (never ObservedAt %v)", got, fixedTime, obs.ObservedAt)
	}
	// The observation's own time stays in the payload, untouched.
	if got := out.Record.Target; got != obs.identity().String() {
		t.Errorf("record target = %q, want %q", got, obs.identity().String())
	}
}

// TestIngestRecordCreatedAtIsStoreTimeFutureObservedAt is the future-time
// twin of TestIngestRecordCreatedAtIsStoreTime: an observation stamped 1h
// in the FUTURE must not make its record immortal. CreatedAt is stamped
// from the run clock at store time, TTL is measured from CreatedAt, so the
// record expires exactly within the configured TTL window from the store
// time — a Get just past store time + TTL must report the record expired,
// even though the observation's own timestamp is still in the future.
func TestIngestRecordCreatedAtIsStoreTimeFutureObservedAt(t *testing.T) {
	obs := newObs(t, "https://ok.example/")
	obs.Headers = []HeaderEntry{{Name: "Server", Value: "nginx"}}
	obs.ObservedAt = fixedTime.Add(1 * time.Hour) // future observation time

	// The cache's clock is a separate, advanceable seam from the engine's
	// fake clock: the store happens at fixedTime, and the TTL evaluation at
	// Get time uses this cache clock.
	ttl := 1 * time.Hour
	cacheNow := fixedTime
	db, err := cache.Open(t.TempDir(), cache.WithTTL(ttl), cache.WithClock(func() time.Time { return cacheNow }))
	if err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(t) // fake engine clock frozen at fixedTime (the store clock)
	cfg.Cache = db
	cfg.Metrics = &Metrics{}
	if _, err := Ingest(context.Background(), cfg, &SliceObservationSource{obs}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	key, err := techKey(obs, fingerprints.SchemaVersion, techDigest(t))
	if err != nil {
		t.Fatal(err)
	}
	out := db.Get(context.Background(), key)
	if out.State != cache.StateHit {
		t.Fatalf("state = %v, want a stored hit", out.State)
	}
	if got := out.Record.CreatedAt; !got.Equal(fixedTime) {
		t.Errorf("record CreatedAt = %v, want the run clock's store time %v (never ObservedAt %v)", got, fixedTime, obs.ObservedAt)
	}

	// Exactly at store time + TTL: still fresh (expiry requires strictly
	// greater elapsed time).
	cacheNow = fixedTime.Add(ttl)
	if out := db.Get(context.Background(), key); !out.IsHit() {
		t.Fatalf("state = %v, want a hit exactly at the TTL boundary", out.State)
	}
	// Just past store time + TTL: expired — the record is NOT immortal
	// despite the still-future ObservedAt.
	cacheNow = fixedTime.Add(ttl + time.Nanosecond)
	if out := db.Get(context.Background(), key); out.State != cache.StateExpired {
		t.Errorf("state = %v, want expired within the TTL window from store time", out.State)
	}
}

// entrySink records entries passed to an Emit hook.
type entrySink struct {
	mu      sync.Mutex
	entries []ReportEntry
}

func (s *entrySink) Fn() func(context.Context, Observation, ReportEntry) error {
	return func(_ context.Context, _ Observation, e ReportEntry) error {
		s.mu.Lock()
		s.entries = append(s.entries, e)
		s.mu.Unlock()
		return nil
	}
}
