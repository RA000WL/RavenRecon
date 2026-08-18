package urlintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// stubCache is a scriptable cache.Cache for cancellation and diagnostics
// tests: Get returns a canned outcome, and Put/Delete/Clear are no-ops (the
// pipeline treats them as silent success). It carries no mutable state:
// jobs may call it concurrently.
type stubCache struct {
	getOutcome cache.Outcome
}

func (c *stubCache) Get(ctx context.Context, key cache.Key) cache.Outcome {
	return c.getOutcome
}

func (c *stubCache) Put(ctx context.Context, key cache.Key, record cache.Record) error {
	return nil
}

func (c *stubCache) Delete(ctx context.Context, key cache.Key) error {
	return nil
}

func (c *stubCache) Clear(ctx context.Context) error { return nil }

// TestIngestCacheGetCancellationNotSurfaced pins that a cache.Get failing
// with an error that wraps a cancellation or deadline error is never
// recorded as a run diagnostic: cancellation is surfaced through entry
// statuses only (see doc.go, "Cancellation"), never as a spurious run
// error. The observation falls through to a fresh extraction and the run
// completes cleanly.
func TestIngestCacheGetCancellationNotSurfaced(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{"context canceled", fmt.Errorf("cache get: %w", context.Canceled)},
		{"deadline exceeded", fmt.Errorf("cache get: %w", context.DeadlineExceeded)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stub := &stubCache{getOutcome: cache.Outcome{State: cache.StateError, Err: tt.err}}
			cfg := testConfig()
			cfg.Cache = stub

			rep, rerr := Ingest(context.Background(), cfg,
				SliceSource([]string{"http://example.com/a?q=1"}))
			if rerr != nil {
				t.Fatalf("Ingest returned %v, want nil (cancellation inside Get must not surface)", rerr)
			}
			// The observation was recomputed fresh, never served, never
			// misclassified.
			if len(rep.Entries) != 1 || rep.Entries[0].Status != StatusCompleted || rep.Entries[0].Cached {
				t.Fatalf("report = %+v, want one fresh completed entry", rep)
			}
		})
	}
}

// TestIngestRunErrDiagnosticsBounded pins the run-diagnostic cap: a run with
// more than maxRunDiagnostics diagnostics (here a cache whose Get fails on
// every read) surfaces at most maxRunDiagnostics individual diagnostics plus
// one count line. The error string stays bounded regardless of how many
// diagnostics were recorded.
func TestIngestRunErrDiagnosticsBounded(t *testing.T) {
	stub := &stubCache{getOutcome: cache.Outcome{
		State: cache.StateError,
		Err:   errors.New("synthetic cache failure"),
	}}
	cfg := testConfig()
	cfg.Cache = stub

	const lines = maxRunDiagnostics + 8 // 40 diagnostics: 32 retained + 8 counted
	src := make([]string, lines)
	for i := range src {
		src[i] = fmt.Sprintf("http://example.com/p%d?q=1", i)
	}
	_, rerr := Ingest(context.Background(), cfg, SliceSource(src))
	if rerr == nil {
		t.Fatal("Ingest returned nil, want the bounded diagnostics surfaced")
	}
	msg := rerr.Error()
	if len(msg) >= 64<<10 {
		t.Fatalf("error string is %d bytes, want < 64 KiB (diagnostics must be bounded)", len(msg))
	}
	if !strings.Contains(msg, "synthetic cache failure") {
		t.Fatalf("error does not retain the first diagnostics: %q", msg)
	}
	if !strings.Contains(msg, "and 8 more diagnostic") {
		t.Fatalf("error does not carry the overflow count line: %q", msg)
	}
}

// TestURLKeyComposition pins the Phase 3 key derivation: the key contains
// the operation, the canonical URL identity (never raw input), the adapter,
// and the result-relevant ParseParameters flag — and nothing else. Two
// logically identical observations produce identical keys.
func TestURLKeyComposition(t *testing.T) {
	u := mustURL(t, "http://example.com/p?a=1")

	k1, err := urlKey(u, "adapter-a", true)
	if err != nil {
		t.Fatalf("urlKey: %v", err)
	}
	k2, err := urlKey(u, "adapter-b", true)
	if err != nil {
		t.Fatalf("urlKey: %v", err)
	}
	k3, err := urlKey(u, "adapter-a", false)
	if err != nil {
		t.Fatalf("urlKey: %v", err)
	}
	k4, err := urlKey(u, "adapter-a", true)
	if err != nil {
		t.Fatalf("urlKey: %v", err)
	}
	if k1 == k2 || k1 == k3 {
		t.Fatalf("keys must differ across adapters and flags: %q %q %q", k1, k2, k3)
	}
	if k1 != k4 {
		t.Fatalf("identical observations must produce identical keys: %q vs %q", k1, k4)
	}

	// The key is derived from the canonical identity, so a differently
	// spelled raw line for the same canonical URL yields the same key.
	raw := mustURL(t, "HTTP://example.com:80/p?a=1")
	k5, err := urlKey(raw, "adapter-a", true)
	if err != nil {
		t.Fatalf("urlKey: %v", err)
	}
	if k5 != k1 {
		t.Fatalf("canonical-equivalent observations must share a key: %q vs %q", k1, k5)
	}

	// The key payload carries the operation, target, and configuration.
	k, err := cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    u.Identity().String(),
		Config: map[string]string{
			"adapter":          "adapter-a",
			"parse_parameters": "true",
		},
	})
	if err != nil {
		t.Fatalf("cache.NewKey: %v", err)
	}
	if k1 != k {
		t.Fatalf("key %q does not match the documented composition %q", k1, k)
	}
}

// TestIngestCacheMissThenHit verifies cache-before-execute: the first run
// extracts and stores completed per-(URL, adapter) records; the second run
// performs ZERO extraction work, serves every entry from cache, and
// reproduces the identical observation (URL, host, endpoints, parameters,
// relationships, sources, timestamps).
func TestIngestCacheMissThenHit(t *testing.T) {
	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Clock = clk
	cfg.Cache = openTestCache(t, clk, 0)
	cfg.Metrics = &Metrics{}

	lines := []string{
		"http://example.com/a?q=1",
		"http://example.com/b?q=2&x=3",
		"http://192.0.2.1/c?q=4",
	}
	rep1 := runIngest(t, cfg, lines)

	snap := cfg.Metrics.Snapshot()
	if snap.Lines != 3 || snap.Canonicalized != 3 || snap.Extracted != 3 ||
		snap.Stored != 3 || snap.Reads != 3 || snap.Malformed != 0 {
		t.Fatalf("first-run metrics = %+v", snap)
	}

	// Second run over the same source: every observation is a cache hit.
	cfg.Metrics = &Metrics{}
	rep2 := runIngest(t, cfg, lines)
	snap = cfg.Metrics.Snapshot()
	if snap.Extracted != 0 || snap.Stored != 0 || snap.Reads != 3 {
		t.Fatalf("second-run metrics = %+v (want 0 extracted, 0 stored, 3 reads)", snap)
	}
	for _, e := range rep2.Entries {
		if !e.Cached {
			t.Fatalf("entry %s: Cached = false, want true", e.URL.String())
		}
	}

	// The cached observations reproduce the identical merged view.
	if fp1, fp2 := reportFingerprint(rep1), reportFingerprint(rep2); fp1 != fp2 {
		t.Fatalf("cached report differs from the fresh one:\n%s\nvs\n%s", fp1, fp2)
	}
	for _, e := range rep2.Entries {
		if e.Status != StatusCompleted {
			t.Fatalf("entry %s status = %s, want completed", e.URL.String(), e.Status)
		}
		if !e.FirstSeen.Equal(fixedTime) || !e.LastSeen.Equal(fixedTime) {
			t.Fatalf("entry %s FirstSeen/LastSeen = %v/%v", e.URL.String(), e.FirstSeen, e.LastSeen)
		}
	}
}

// TestIngestCachePerAdapterSeparation pins that observations of the same URL
// from different adapters are stored under different keys: adapter-b's run
// misses adapter-a's record, extracts fresh, and stores its own; adapter-a's
// record remains servable afterwards.
func TestIngestCachePerAdapterSeparation(t *testing.T) {
	clk := newFakeClock(fixedTime)
	line := []string{"http://example.com/p?q=1"}

	cfgA := testConfig()
	cfgA.Clock = clk
	cfgA.Adapter = "adapter-a"
	cfgA.Cache = openTestCache(t, clk, 0)
	cfgA.Metrics = &Metrics{}
	runIngest(t, cfgA, line)

	cfgB := testConfig()
	cfgB.Clock = newFakeClock(fixedTime)
	cfgB.Adapter = "adapter-b"
	cfgB.Cache = cfgA.Cache // same cache, different adapter
	cfgB.Metrics = &Metrics{}
	repB := runIngest(t, cfgB, line)
	if snap := cfgB.Metrics.Snapshot(); snap.Extracted != 1 || snap.Stored != 1 {
		t.Fatalf("adapter-b metrics = %+v, want a fresh extraction and store", snap)
	}
	requireEqualStrings(t, "adapter-b sources", repB.Entries[0].Sources, []string{"adapter-b"})

	// Adapter-a's record is still servable: a third run with adapter-a
	// performs zero extraction work.
	cfgA.Metrics = &Metrics{}
	runIngest(t, cfgA, line)
	if snap := cfgA.Metrics.Snapshot(); snap.Extracted != 0 || snap.Stored != 0 {
		t.Fatalf("adapter-a re-run metrics = %+v, want a pure cache hit", snap)
	}
}

// TestIngestCacheParseParametersFlag pins that ParseParameters is
// result-relevant and therefore part of the key: a run with extraction
// disabled is never served a record written with it enabled, and vice versa.
func TestIngestCacheParseParametersFlag(t *testing.T) {
	clk := newFakeClock(fixedTime)
	line := []string{"http://example.com/p?q=1&x=2"}

	withParams := testConfig()
	withParams.Clock = clk
	withParams.ParseParameters = true
	withParams.Cache = openTestCache(t, clk, 0)
	withParams.Metrics = &Metrics{}
	rep1 := runIngest(t, withParams, line)
	if len(rep1.Entries[0].Parameters) != 2 {
		t.Fatalf("parameters = %d, want 2", len(rep1.Entries[0].Parameters))
	}

	// Disabled: a different key, so a fresh extraction WITHOUT parameters.
	noParams := testConfig()
	noParams.Clock = newFakeClock(fixedTime)
	noParams.ParseParameters = false
	noParams.Cache = withParams.Cache
	noParams.Metrics = &Metrics{}
	rep2 := runIngest(t, noParams, line)
	if snap := noParams.Metrics.Snapshot(); snap.Extracted != 1 {
		t.Fatalf("no-params metrics = %+v, want a fresh extraction (different key)", snap)
	}
	if len(rep2.Entries[0].Parameters) != 0 {
		t.Fatalf("parameters = %d, want 0 with ParseParameters disabled", len(rep2.Entries[0].Parameters))
	}

	// Enabled again: served from the original record (zero extraction).
	withParams.Metrics = &Metrics{}
	rep3 := runIngest(t, withParams, line)
	if snap := withParams.Metrics.Snapshot(); snap.Extracted != 0 {
		t.Fatalf("params re-run metrics = %+v, want a pure cache hit", snap)
	}
	if len(rep3.Entries[0].Parameters) != 2 {
		t.Fatalf("parameters = %d, want 2 from the cached record", len(rep3.Entries[0].Parameters))
	}
}

// TestIngestCacheExpiry pins TTL semantics: once the cache's clock passes
// the record's TTL, the observation is re-extracted and re-stored.
func TestIngestCacheExpiry(t *testing.T) {
	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Clock = clk
	cfg.Cache = openTestCache(t, clk, time.Hour)
	cfg.Metrics = &Metrics{}

	line := []string{"http://example.com/p?q=1"}
	runIngest(t, cfg, line)
	if snap := cfg.Metrics.Snapshot(); snap.Extracted != 1 || snap.Stored != 1 {
		t.Fatalf("first-run metrics = %+v", snap)
	}

	clk.advance(2 * time.Hour) // past the TTL
	cfg.Metrics = &Metrics{}
	runIngest(t, cfg, line)
	if snap := cfg.Metrics.Snapshot(); snap.Extracted != 1 || snap.Stored != 1 {
		t.Fatalf("post-TTL metrics = %+v, want a fresh extraction and store", snap)
	}
}

// decodeCase mutates a valid stored payload for the validation table.
type decodeCase struct {
	name   string
	mutate func(s *storedURL)
	want   string // substring of the expected decode error
}

// TestDecodeStoredURLValidation pins that a corrupt, tampered, or
// inconsistent stored record is never served as a hit: every identity field
// is re-validated through the Phase 2 model, and every payload is bounded.
func TestDecodeStoredURLValidation(t *testing.T) {
	u := mustURL(t, "http://example.com/p?a=1")
	adapter := "test-adapter"
	entry := extractURL(u, adapter, true, fixedTime)
	valid := entryToStored(entry, adapter)

	cases := []decodeCase{
		{"wrong target", func(s *storedURL) { s.Target = "url:http://evil.example/" }, "does not match"},
		{"wrong adapter", func(s *storedURL) { s.Adapter = "other-adapter" }, "does not match"},
		{"different URL", func(s *storedURL) { s.URL = mustURL(t, "http://other.example/p") }, "does not match"},
		{"non-canonical URL", func(s *storedURL) {
			s.URL = asset.URL{Scheme: "http", HostPort: "EXAMPLE.com", Path: "/p"}
		}, "not in canonical form"},
		{"too many endpoints", func(s *storedURL) { s.Endpoints = []asset.Endpoint{entry.Endpoints[0], entry.Endpoints[0]} }, "cap 1"},
		{"non-GET endpoint", func(s *storedURL) {
			ep := entry.Endpoints[0]
			ep.Method = "POST"
			s.Endpoints = []asset.Endpoint{ep}
		}, "not GET"},
		{"endpoint URL mismatch", func(s *storedURL) {
			ep := entry.Endpoints[0]
			ep.URL = mustURL(t, "http://other.example/p")
			s.Endpoints = []asset.Endpoint{ep}
		}, "does not match"},
		{"endpoint original carries credentials", func(s *storedURL) {
			// Canonical fields untouched (String() stays canonical, so all
			// pre-existing checks pass): only the decode-time credential
			// defense can refuse this.
			ep := s.Endpoints[0]
			ep.URL.Original = "http://user:pass@example.com/p?a=1"
			s.Endpoints = []asset.Endpoint{ep}
		}, "credentials"},
		{"url original carries credentials", func(s *storedURL) {
			// Same, on the record's own URL asset.
			s.URL.Original = "http://user:pass@example.com/p?a=1"
		}, "credentials"},
		{"endpoint original carries credentials in an unparseable form", func(s *storedURL) {
			// The canonical fields are untouched (String() stays canonical,
			// so every parse- and identity-based check passes): only the
			// canonical-form refusal can catch this. url.Parse fails on the
			// raw control byte, so a parse-based userinfo check alone would
			// let the credential-bearing Original through to the report.
			ep := s.Endpoints[0]
			ep.URL.Original = "http://user:pass@example.com/\x01"
			s.Endpoints = []asset.Endpoint{ep}
		}, "credentials"},
		{"parameter location not query", func(s *storedURL) {
			s.Parameters[0].Location = "path"
		}, "not query"},
		{"parameter without values", func(s *storedURL) {
			s.Parameters[0].ObservedValues = nil
		}, "has no observed values"},
		{"parameter with too many values", func(s *storedURL) {
			vs := make([]string, maxObservedValues+1)
			for i := range vs {
				vs[i] = "v"
			}
			s.Parameters[0].ObservedValues = vs
		}, "cap"},
		{"oversized first value", func(s *storedURL) {
			s.Parameters[0].ObservedValues = []string{strings.Repeat("v", 8193)}
		}, "invalid"},
		{"oversized later value", func(s *storedURL) {
			s.Parameters[0].ObservedValues = []string{"v1", strings.Repeat("v", 8193)}
		}, "value invalid"},
		{"oversized name", func(s *storedURL) {
			s.Parameters[0].Name = strings.Repeat("n", 513)
		}, "invalid"},
		{"no sources", func(s *storedURL) { s.Sources = nil }, "no sources"},
		{"empty source", func(s *storedURL) { s.Sources = []string{""} }, "empty source"},
		{"oversized source", func(s *storedURL) {
			s.Sources = []string{strings.Repeat("s", 129)}
		}, "longer than 128"},
		{"zero first seen", func(s *storedURL) { s.FirstSeen = time.Time{} }, "timestamps are incomplete"},
		{"zero last seen", func(s *storedURL) { s.LastSeen = time.Time{} }, "timestamps are incomplete"},
		{"last before first", func(s *storedURL) {
			s.LastSeen = s.FirstSeen.Add(-time.Hour)
		}, "before first_seen"},
	}

	// Positive control: the unmutated payload decodes.
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := decodeStoredURL(raw, u, adapter); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// A fresh extraction per case: the mutate closures write into
			// slice elements, so sharing the payload across cases would
			// cascade.
			entry := extractURL(u, adapter, true, fixedTime)
			s := entryToStored(entry, adapter)
			tt.mutate(&s)
			raw, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			_, derr := decodeStoredURL(raw, u, adapter)
			if derr == nil {
				t.Fatalf("tampered payload accepted: %+v", s)
			}
			if !strings.Contains(derr.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", derr, tt.want)
			}
		})
	}

	// Garbage JSON is rejected.
	if _, err := decodeStoredURL(json.RawMessage(`{"broken":`), u, adapter); err == nil {
		t.Fatal("garbage JSON accepted")
	}
}

// TestIngestCacheSelfHealing pins the corruption contract: a record that
// fails validation (unusable payload or mismatched identity fields) is
// deleted, the observation is recomputed in the same run, the discard is
// surfaced as a diagnostic on the run, and the NEXT run is served the healed
// record.
func TestIngestCacheSelfHealing(t *testing.T) {
	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Clock = clk
	cfg.Cache = openTestCache(t, clk, 0)
	cfg.Metrics = &Metrics{}

	line := []string{"http://example.com/p?q=1"}
	runIngest(t, cfg, line) // write a valid record

	u := mustURL(t, "http://example.com/p?q=1")
	key, err := urlKey(u, cfg.Adapter, cfg.ParseParameters)
	if err != nil {
		t.Fatalf("urlKey: %v", err)
	}

	t.Run("unusable payload", func(t *testing.T) {
		// Valid JSON that fails decodeStoredURL's identity validation (a
		// structurally corrupt payload cannot even be stored: the cache
		// record JSON-encodes Data).
		rec := cache.Record{
			Operation: Operation,
			Target:    u.Identity().String(),
			Status:    cache.StatusCompleted,
			Meta:      map[string]string{"adapter": cfg.Adapter},
			Data:      json.RawMessage(`{}`),
		}
		if err := cfg.Cache.Put(context.Background(), key, rec); err != nil {
			t.Fatalf("cache.Put: %v", err)
		}

		cfg.Metrics = &Metrics{}
		rep, rerr := Ingest(context.Background(), cfg, SliceSource(line))
		if rerr == nil || !strings.Contains(rerr.Error(), "discarded unusable cached result") {
			t.Fatalf("err = %v, want the discard diagnostic", rerr)
		}
		if snap := cfg.Metrics.Snapshot(); snap.Extracted != 1 || snap.Stored != 1 {
			t.Fatalf("metrics = %+v, want recomputation in the same run", snap)
		}
		e := rep.Entries[0]
		if e.Status != StatusCompleted || e.Cached {
			t.Fatalf("entry = status %s cached %v, want completed fresh", e.Status, e.Cached)
		}

		// The record was repaired: the next run is a pure hit.
		cfg.Metrics = &Metrics{}
		if _, err := Ingest(context.Background(), cfg, SliceSource(line)); err != nil {
			t.Fatalf("healed re-run: %v", err)
		}
		if snap := cfg.Metrics.Snapshot(); snap.Extracted != 0 {
			t.Fatalf("healed re-run extracted = %d, want 0", snap.Extracted)
		}
	})

	t.Run("mismatched identity", func(t *testing.T) {
		// A fully valid payload stored under a different operation: the
		// identity check must fire before the payload is even decoded.
		validData, err := json.Marshal(entryToStored(entryFor("http://example.com/p?q=1", cfg.Adapter, fixedTime), cfg.Adapter))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rec := cache.Record{
			Operation: "other.op",
			Target:    u.Identity().String(),
			Status:    cache.StatusCompleted,
			Meta:      map[string]string{"adapter": cfg.Adapter},
			Data:      validData,
		}
		if err := cfg.Cache.Put(context.Background(), key, rec); err != nil {
			t.Fatalf("cache.Put: %v", err)
		}

		cfg.Metrics = &Metrics{}
		_, rerr := Ingest(context.Background(), cfg, SliceSource(line))
		if rerr == nil || !strings.Contains(rerr.Error(), "discarded cached record with mismatched identity") {
			t.Fatalf("err = %v, want the mismatch diagnostic", rerr)
		}
		if snap := cfg.Metrics.Snapshot(); snap.Extracted != 1 {
			t.Fatalf("extracted = %d, want recomputation", snap.Extracted)
		}
	})

	t.Run("credentials in stored original", func(t *testing.T) {
		// A fully valid payload whose endpoint URL's Original carries
		// userinfo: the canonical checks all pass (String() is untouched),
		// so only the decode-time credential defense can refuse it — a
		// tampered credential-bearing Original must never be served into
		// the report. The record is deleted, the observation recomputed in
		// the same run, and the healed record carries no userinfo.
		st := entryToStored(entryFor("http://example.com/p?q=1", cfg.Adapter, fixedTime), cfg.Adapter)
		ep := st.Endpoints[0]
		ep.URL.Original = "http://user:pass@example.com/p?q=1"
		st.Endpoints = []asset.Endpoint{ep}
		data, err := json.Marshal(st)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rec := cache.Record{
			Operation: Operation,
			Target:    u.Identity().String(),
			Status:    cache.StatusCompleted,
			Meta:      map[string]string{"adapter": cfg.Adapter},
			Data:      data,
		}
		if err := cfg.Cache.Put(context.Background(), key, rec); err != nil {
			t.Fatalf("cache.Put: %v", err)
		}

		cfg.Metrics = &Metrics{}
		rep, rerr := Ingest(context.Background(), cfg, SliceSource(line))
		if rerr == nil || !strings.Contains(rerr.Error(), "discarded unusable cached result") ||
			!strings.Contains(rerr.Error(), "credentials") {
			t.Fatalf("err = %v, want the credential discard diagnostic", rerr)
		}
		if snap := cfg.Metrics.Snapshot(); snap.Extracted != 1 || snap.Stored != 1 {
			t.Fatalf("metrics = %+v, want recomputation in the same run", snap)
		}
		e := rep.Entries[0]
		if e.Status != StatusCompleted || e.Cached {
			t.Fatalf("entry = status %s cached %v, want completed fresh", e.Status, e.Cached)
		}
		if len(e.Endpoints) != 1 {
			t.Fatalf("endpoints = %d, want 1", len(e.Endpoints))
		}
		if strings.Contains(e.Endpoints[0].URL.Original, "user:pass") {
			t.Fatalf("endpoint URL.Original leaks the credential: %q", e.Endpoints[0].URL.Original)
		}
		if e.Endpoints[0].URL.Original != e.Endpoints[0].URL.String() {
			t.Fatalf("endpoint URL.Original = %q, want the canonical form %q",
				e.Endpoints[0].URL.Original, e.Endpoints[0].URL.String())
		}

		// The record was repaired: the next run is a pure hit.
		cfg.Metrics = &Metrics{}
		if _, err := Ingest(context.Background(), cfg, SliceSource(line)); err != nil {
			t.Fatalf("healed re-run: %v", err)
		}
		if snap := cfg.Metrics.Snapshot(); snap.Extracted != 0 {
			t.Fatalf("healed re-run extracted = %d, want 0", snap.Extracted)
		}
	})
}
