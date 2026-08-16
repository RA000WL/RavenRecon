package jsintel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Benchmarks exercise the pipeline hermetically: synthetic deterministic
// scripts, loopback HTTP servers behind the fetch transport seam (every
// request keeps its canonical host while the transport dials the resolved
// loopback address), and a real filesystem-backed Phase 3 cache rooted at a
// b.TempDir() directory (no public Internet). They are command-gated
// (-bench only) and reuse the fetch tests' transport helpers (transportFor,
// countingRT, mustURL) — there is no second execution path to harden.
//
// The hit-path contract is pinned the house way: every cache-hit benchmark
// asserts ZERO round trips through a counting transport, and the full-pipeline
// benchmark additionally asserts zero parses and zero fetch dispatches
// through the engine's own Metrics counters.
//
// Timing reality (measured 2026-08-16 on the benchmark machine — an AMD
// Ryzen 5 8645HS, 12 threads, ext4 root filesystem, default -benchtime):
// the parse and analyzer benchmarks are pure CPU (ParseSmall ≈40 µs per
// 1.5 KiB script, ParseLargeBundle ≈27 ms per 1 MiB bundle, the extractors
// ≈3.5–4.6 ms per parsed 64 KiB bundle); the fetch benchmarks are
// fsync-bound (BenchmarkFetchMiss ≈73 ms per 1 MiB miss / ≈16 MB/s
// including the serialized cache write; BenchmarkFetchHit ≈33 ms per
// validated 1 MiB record decode); the full-pipeline hit pass measures
// ≈1.8 ms per 9-script run (≈0.2 ms per script). Every benchmark
// completes in well under 5 s at the default -benchtime. Numbers are
// machine-dependent (the 5C precedent): variance is environment-dependent
// and reported, not hidden.

// benchSink consumes benchmark outputs so the compiler cannot eliminate the
// timed work.
var (
	benchSinkParsed Parsed
	benchSinkInt    int
	benchSinkStr    string
)

// benchSmallScript returns a deterministic typical small script (~1.5 KiB):
// a few imports, endpoint-ish strings, a source map reference, and filler.
func benchSmallScript() []byte {
	var b strings.Builder
	b.WriteString("import{render}from\"./ui/render.js\";\n")
	b.WriteString("import data from\"../data.js\";\n")
	b.WriteString("const API=\"/api/v1/status\";\n")
	b.WriteString("const WS=\"wss://example.com/socket\";\n")
	b.WriteString("const CDN=\"https://cdn.example.net/lib/core.js\";\n")
	b.WriteString("function load(u){return fetch(u,{headers:{\"X-Trace\":\"bench\"}});}\n")
	b.WriteString("export function boot(){return load(API).then(r=>r.status);}\n")
	for b.Len() < 1536 {
		b.WriteString("const v=1;")
	}
	b.WriteString("\n//# sourceMappingURL=app.js.map\n")
	return []byte(b.String())
}

// genLargeBundle generates a deterministic minified-style bundle of at least
// 1 MiB on a SINGLE line: many static and dynamic imports, hundreds of
// string literals, numeric filler, and a trailing source map reference. The
// generation stays deliberately below every parser cap (imports < 1024,
// strings — literals plus import specifiers — < 8192, retained values
// < 4096 bytes, tokens far below 1 Mi), so a parse of the bundle must
// complete un-truncated; the benchmark asserts exactly that.
func genLargeBundle() []byte {
	var b strings.Builder
	b.WriteString("(function(){\"use strict\";")
	for i := 0; i < 480; i++ {
		fmt.Fprintf(&b, "import{e%d as t%d}from\"./m%d.js\";", i, i, i)
		if i%40 == 0 {
			fmt.Fprintf(&b, "import(\"./dyn%d.js\");", i)
		}
	}
	for i := 0; i < 900; i++ {
		fmt.Fprintf(&b, "\"/api/v%d/users/%d?session=%s&state=%d\",", i, i, strings.Repeat("a", 64), i)
	}
	for i := 0; b.Len() < 1<<20; i++ {
		fmt.Fprintf(&b, "var v%d=%d;", i, i)
	}
	b.WriteString("//# sourceMappingURL=bundle.js.map")
	return []byte(b.String())
}

// genMediumBundle generates a deterministic ~64 KiB script whose literals
// exercise both analyzers: endpoint candidates (relative paths, absolute
// http(s) URLs on a different host, ws/wss URLs, graphql and SSE shapes) and
// synthetic secret candidates (documentation-style values, never real
// credentials), plus skipped junk (whitespace candidates, dynamic templates).
func genMediumBundle() []byte {
	var b strings.Builder
	b.WriteString("(function(){\n")
	for i := 0; b.Len() < 64<<10; i++ {
		fmt.Fprintf(&b, "const u%d=\"/api/v%d/items/%d\";", i, i%8, i)
		fmt.Fprintf(&b, "s%d=\"https://cdn%d.example.net/assets/f%d.js\";", i, i%4, i)
		if i%16 == 0 {
			fmt.Fprintf(&b, "w%d=\"wss://sync%d.example.com/socket\";", i, i%2)
		}
		if i%64 == 0 {
			b.WriteString("g=\"/graphql\";e=\"/events\";")
			b.WriteString("j=\"not a url\";t=`/api/t/${i}`;")
		}
		switch i % 8 {
		case 0:
			b.WriteString("k=\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiZW5jaCJ9.SFlKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\";")
		case 1:
			b.WriteString("k=\"AKIAIOSFODNN7EXAMPLE\";")
		case 2:
			b.WriteString("k=\"ghp_benchbenchbenchbenchbenchbenchbench\" + \"benchbench\";")
		case 3:
			b.WriteString("k=\"sk_test_benchbenchbenchbenchbench\";")
		}
		fmt.Fprintf(&b, "n%d=%d;", i, i)
	}
	b.WriteString("})();\n")
	return []byte(b.String())
}

// BenchmarkParseSmall measures one Parse of a typical small script
// (~1.5 KiB, imports + strings) through the public NewParser().
func BenchmarkParseSmall(b *testing.B) {
	src := benchSmallScript()
	p := NewParser()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsed, err := p.Parse(src)
		if err != nil {
			b.Fatalf("Parse: %v", err)
		}
		if len(parsed.Imports) == 0 || len(parsed.Strings) == 0 {
			b.Fatal("Parse extracted no observations")
		}
		benchSinkParsed = parsed
	}
}

// BenchmarkParseLargeBundle measures one Parse of a generated ~1 MiB
// minified-style single-line bundle. The post-loop assertions pin the
// completion contract: no error, no Truncated flag (the bundle is
// deliberately below every parser cap — no silent truncation), and the
// expected observation classes were extracted.
func BenchmarkParseLargeBundle(b *testing.B) {
	src := genLargeBundle()
	if len(src) < 1<<20 {
		b.Fatalf("bundle is %d bytes, want at least 1 MiB", len(src))
	}
	if strings.ContainsRune(string(src), '\n') {
		b.Fatal("bundle must be a single line")
	}
	p := NewParser()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsed, err := p.Parse(src)
		if err != nil {
			b.Fatalf("Parse: %v", err)
		}
		if parsed.Truncated {
			b.Fatal("Parse truncated the bundle; want a complete parse (bundle is below every cap)")
		}
		if len(parsed.Imports) == 0 || len(parsed.Strings) == 0 {
			b.Fatal("Parse extracted no observations")
		}
		benchSinkParsed = parsed
	}
	b.StopTimer()
	parsed, err := p.Parse(src)
	if err != nil || parsed.Truncated {
		b.Fatalf("verification parse: err=%v truncated=%v", err, parsed.Truncated)
	}
	benchSinkInt = len(parsed.Imports)
	benchSinkStr = parsed.SourceMapRef
}

// BenchmarkFetchMiss measures the full cache-miss fetch operation for one
// canonical URL — key derivation, cache lookup (miss), one bounded HTTP GET
// of a 1 MiB body through the loopback transport seam, and the fsync-bound
// cache store — exactly the engine's cache-before-execute miss path. Every
// iteration fetches a DISTINCT URL, so every iteration is a true miss
// regardless of -benchtime. b.SetBytes reports the retained body throughput
// (MB/s) of the whole miss path, cache write included.
func BenchmarkFetchMiss(b *testing.B) {
	body := []byte(strings.Repeat("var b=1;", (1<<20)/7+1))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(body)
	}))
	b.Cleanup(srv.Close)

	rt := &countingRT{inner: transportFor(b, srv)}
	cfg := FetchConfig{Transport: rt, RequestTimeout: 10 * time.Second}
	c, err := cache.Open(b.TempDir())
	if err != nil {
		b.Fatalf("cache.Open: %v", err)
	}
	ctx := context.Background()
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u := mustURL(b, fmt.Sprintf("http://example.com/app%d.js", i))
		lookup := lookupFetch(ctx, u, cfg, c, wallClock{}, "bench")
		if lookup.Err != nil {
			b.Fatalf("lookup: %v", lookup.Err)
		}
		if lookup.Hit {
			b.Fatal("unexpected cache hit on a distinct URL")
		}
		res := Fetch(ctx, cfg, u)
		if res.Status != FetchCompleted || res.Reason != ReasonNone {
			b.Fatalf("fetch: status=%s reason=%s err=%v", res.Status, res.Reason, res.Err)
		}
		if !strings.EqualFold(res.ContentType, "application/javascript") || res.Size != int64(len(body)) {
			b.Fatalf("fetch: content-type=%q size=%d", res.ContentType, res.Size)
		}
		now := time.Now().UTC()
		if err := storeFetch(ctx, cfg, c, wallClock{}, res, []string{"bench"}, now, now); err != nil {
			b.Fatalf("store: %v", err)
		}
	}
	b.StopTimer()
	if got := rt.calls(); got != int64(b.N) {
		b.Fatalf("miss pass round trips = %d, want exactly one per iteration (%d)", got, b.N)
	}
}

// BenchmarkFetchHit measures the cache-hit lookup path for one canonical
// URL: the js.fetch key derivation and the validated record decode, with
// zero network work. The untimed warm-up performs the single miss that
// populates the record; the timed loop is pure hits. The counting transport
// assertion fails the benchmark if a request ever fires on the hit path.
func BenchmarkFetchHit(b *testing.B) {
	body := []byte(strings.Repeat("var h=2;", (1<<20)/7+1))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(body)
	}))
	b.Cleanup(srv.Close)

	rt := &countingRT{inner: transportFor(b, srv)}
	cfg := FetchConfig{Transport: rt, RequestTimeout: 10 * time.Second}
	c, err := cache.Open(b.TempDir())
	if err != nil {
		b.Fatalf("cache.Open: %v", err)
	}
	ctx := context.Background()
	u := mustURL(b, "http://example.com/app.js")

	b.ResetTimer()
	// Untimed warm-up: one miss + store, so the timed loop is pure hits.
	b.StopTimer()
	res := Fetch(ctx, cfg, u)
	if res.Status != FetchCompleted {
		b.Fatalf("warm-up fetch: status=%s err=%v", res.Status, res.Err)
	}
	now := time.Now().UTC()
	if err := storeFetch(ctx, cfg, c, wallClock{}, res, []string{"bench"}, now, now); err != nil {
		b.Fatalf("warm-up store: %v", err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		lookup := lookupFetch(ctx, u, cfg, c, wallClock{}, "bench")
		if lookup.Err != nil {
			b.Fatalf("lookup: %v", lookup.Err)
		}
		if !lookup.Hit {
			b.Fatal("cache miss on the hit path")
		}
		if lookup.Result.Status != FetchCompleted || lookup.Result.Size != int64(len(body)) {
			b.Fatalf("hit result: status=%s size=%d", lookup.Result.Status, lookup.Result.Size)
		}
	}
	b.StopTimer()
	if got := rt.calls(); got != 1 {
		b.Fatalf("hit pass round trips = %d, want 1 (the warm-up only; the hit path must issue zero)", got)
	}
}

// benchScriptSet is the AnalyzeCacheHit workload: one HTML observation
// referencing 8 scripts, each importing one shared module — 9 candidate URLs
// per run. The scripts carry endpoint literals so the analysis is real work.
const (
	benchPageScripts = 8
	benchAllScripts  = benchPageScripts + 1 // + shared.js
)

// benchHTMLItem builds the pipeline input: one ItemHTML whose body references
// /s0.js../s7.js.
func benchHTMLItem(b *testing.B) Item {
	b.Helper()
	var body strings.Builder
	body.WriteString("<!doctype html><html><head>")
	for i := 0; i < benchPageScripts; i++ {
		fmt.Fprintf(&body, "<script src=\"/s%d.js\"></script>", i)
	}
	body.WriteString("</head><body></body></html>")
	return Item{
		Kind: ItemHTML,
		URL:  mustURL(b, "http://example.com/"),
		Body: body.String(),
	}
}

// BenchmarkAnalyzeCacheHit measures the FULL pipeline (engine Run) over the
// HTML item + its scripts on a warm cache: the timed iterations perform zero
// HTTP round trips (counting transport), zero fetch dispatches, and zero
// parses (the engine's own Metrics), because both the js.fetch and the
// js.analyze records are served as validated hits. One op = one full Run
// over 9 scripts (8 page scripts + shared.js): the per-script cost is
// ns/op ÷ 9.
func BenchmarkAnalyzeCacheHit(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		var body string
		switch {
		case r.URL.Path == "/shared.js":
			body = "const health=\"/health\";const gql=\"/graphql\";"
		case strings.HasPrefix(r.URL.Path, "/s"):
			var i int
			fmt.Sscanf(r.URL.Path, "/s%d.js", &i)
			body = fmt.Sprintf("import\"./shared.js\";const list=\"/api/v%d/items\";const page=\"/api/v%d/list?page=%d\";", i, i, i)
		default:
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	b.Cleanup(srv.Close)

	rt := &countingRT{inner: transportFor(b, srv)}
	cfg := DefaultConfig()
	cfg.Concurrency = 16
	cfg.QueueSize = 256
	cfg.Timeout = 0 // no per-job deadline: the loopback server never blocks
	cfg.Rate = 0    // pacing disabled: the benchmark measures raw throughput
	cfg.Transport = rt
	c, err := cache.Open(b.TempDir())
	if err != nil {
		b.Fatalf("cache.Open: %v", err)
	}
	cfg.Cache = c
	item := benchHTMLItem(b)
	ctx := context.Background()

	b.ResetTimer()
	// Untimed warm-up: one cold Run populates the js.fetch and js.analyze
	// records so every timed iteration is a pure hit.
	b.StopTimer()
	rep, err := Run(ctx, cfg, SliceSource([]Item{item}))
	if err != nil {
		b.Fatalf("warm-up Run: %v", err)
	}
	if len(rep.Entries) != benchAllScripts {
		b.Fatalf("warm-up entries = %d, want %d", len(rep.Entries), benchAllScripts)
	}
	warmCalls := rt.calls()
	if warmCalls != benchAllScripts {
		b.Fatalf("warm-up round trips = %d, want %d", warmCalls, benchAllScripts)
	}
	snap := rep.Metrics()
	if snap.Parses != benchAllScripts || snap.Fetches != benchAllScripts {
		b.Fatalf("warm-up metrics = %+v, want %d parses and fetches", snap, benchAllScripts)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		rep, err = Run(ctx, cfg, SliceSource([]Item{item}))
		if err != nil {
			b.Fatalf("Run: %v", err)
		}
		if len(rep.Entries) != benchAllScripts {
			b.Fatalf("entries = %d, want %d", len(rep.Entries), benchAllScripts)
		}
		snap := rep.Metrics()
		if snap.Fetches != 0 || snap.Parses != 0 || snap.Stores != 0 {
			b.Fatalf("hit pass performed work: %+v; want zero fetches, parses, stores", snap)
		}
		for _, e := range rep.Entries {
			if !e.Cached || e.Status != StatusCompleted || e.JS == nil {
				b.Fatalf("entry %s: cached=%v status=%s js=%v", e.URL.String(), e.Cached, e.Status, e.JS != nil)
			}
		}
	}
	b.StopTimer()
	if got := rt.calls(); got != warmCalls {
		b.Fatalf("hit pass round trips = %d, want zero beyond the warm-up's %d", got, warmCalls)
	}
}

// BenchmarkExtractEndpoints measures the endpoint/URL analyzer's throughput
// on one parsed ~64 KiB bundle (mixed relative, absolute different-host, and
// ws/wss candidates). The parse happens once outside the timed loop; the
// timed work is extractEndpoints alone.
func BenchmarkExtractEndpoints(b *testing.B) {
	parsed, err := NewParser().Parse(genMediumBundle())
	if err != nil {
		b.Fatalf("Parse: %v", err)
	}
	if parsed.Truncated {
		b.Fatal("medium bundle truncated the parser")
	}
	js := asset.JavaScript{
		URL:  mustURL(b, "http://example.com/app.js"),
		Prov: asset.Provenance{Source: "bench", DiscoveredAt: time.Now().UTC()},
	}
	cfg := Config{Source: "bench", Clock: wallClock{}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := extractEndpoints(js, parsed, cfg)
		if len(out.endpoints) == 0 || len(out.urls) == 0 {
			b.Fatalf("endpoints=%d urls=%d, want non-empty", len(out.endpoints), len(out.urls))
		}
		benchSinkInt = len(out.endpoints)
	}
}

// BenchmarkExtractSecrets measures the secret-candidate analyzer's
// throughput on the same parsed ~64 KiB bundle (synthetic documentation-style
// values only — detection, never verification). The parse happens once
// outside the timed loop; the timed work is extractSecrets alone.
func BenchmarkExtractSecrets(b *testing.B) {
	parsed, err := NewParser().Parse(genMediumBundle())
	if err != nil {
		b.Fatalf("Parse: %v", err)
	}
	js := asset.JavaScript{
		URL:  mustURL(b, "http://example.com/app.js"),
		Prov: asset.Provenance{Source: "bench", DiscoveredAt: time.Now().UTC()},
	}
	cfg := Config{Source: "bench", Clock: wallClock{}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := extractSecrets(js, parsed, cfg)
		if len(out.secrets) == 0 {
			b.Fatal("secrets empty, want non-empty")
		}
		benchSinkInt = len(out.secrets)
	}
}
