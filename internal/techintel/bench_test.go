package techintel

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

// Benchmarks exercise the technology detection engine hermetically:
// synthetic observations, the REAL compiled fingerprint database
// (fingerprints.Load), a real bounded runtime.Pool, and a real
// filesystem-backed Phase 3 cache (no public Internet). They are
// command-gated (-bench only).
//
// Timing reality (measured 2026-08-15 on the benchmark machine — an AMD
// Ryzen 5 8645HS, 12 threads, WSL2 over an ext4 root filesystem,
// -benchtime=1x): the pure-CPU micro-benchmarks measure ≈50 µs/op
// (AnalyzeHeaders — one header-only observation through the full analyzer),
// ≈1.5 ms/op (AnalyzeFull — headers, cookies, and a 64 KiB HTML body),
// ≈79 µs/op (HeaderAnalysis — every header indicator matched over a
// 24-entry corpus), ≈855 µs/op (HTMLParse — a 256 KiB page corpus build and
// single-pass scan), and ≈23 µs/op (ConfidenceMerge — 24 results folded
// into 22). The Ingest cold passes measure ≈87 ms (10), ≈0.60 s (100),
// ≈4.9 s (1k), and ≈56 s (10k; a second standalone run measured ≈47 s — the
// pass is fsync-bound and disk-noise-sensitive, expect roughly 50–60 s;
// ≈1 min wall including harness overhead). The full set (all nine
// benchmarks) measured 63 s of test time / 64 s wall — run it with
// -benchtime=1x and allow ≈1.5 minutes (the harness re-caches and re-times
// each workload). The cold passes are fsync-bound —
// one serialized cache write per observation (see internal/cache) — so the
// 10k figure is disk-dependent; the per-pass pipeline cost also shows up as
// ≈950 MB allocated across ≈11.2 M allocs for the 10k pass. Under
// `go test -short` (the CI-style default) the 10k workload is skipped
// entirely (its skip message names this measured duration), keeping the
// suite bounded; the 10/100/1k workloads and the pure-CPU micro-benchmarks
// still run.
//
// The Ingest cold workloads must be run with -benchtime=1x: the cold pass
// reuses ONE cache across iterations, so only iteration 1 of a workload is
// truly cold — iterations 2..N are pure cache hits. The post-loop metrics
// assertion pins exactly that shape (exactly one cold pass happened, every
// later iteration hit) regardless of b.N, so a higher -benchtime does not
// silently mix hit iterations into the "cold" figure; it just makes the
// reported per-op number a hits-dominated average. All timings are
// machine-dependent: the cold passes are dominated by the filesystem's
// fsync cost (one serialized cache write per observation, see
// internal/cache), so expect different numbers on different disks and
// filesystems. Under `go test -short` (the CI-style default) the 10k
// workload is skipped entirely, keeping the suite bounded; the 10/100/1k
// workloads and the pure-CPU micro-benchmarks still run.

// benchFixedTime is the deterministic provenance timestamp shared by every
// benchmark observation, so all results are reproducible.
var benchFixedTime = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

// benchProv returns the deterministic provenance for a benchmark source.
func benchProv(source string) asset.Provenance {
	return asset.Provenance{Source: source, DiscoveredAt: benchFixedTime}
}

// benchDB loads the REAL fingerprint database once (untimed hoisting) and
// returns it together with the deep-copied fingerprint list the engine's
// env holds. A load failure is fatal: silently continuing would benchmark
// against an empty database and invalidate every measurement.
func benchDB(b *testing.B) (*fingerprints.DB, []fingerprints.Fingerprint) {
	b.Helper()
	db, err := fingerprints.Load()
	if err != nil {
		b.Fatalf("fingerprints.Load: %v", err)
	}
	return db, db.Fingerprints()
}

// benchObservation assembles one synthetic observation from a constant
// canonical URL (benchmark fixtures; a parse failure is a programming
// error and panics, mirroring the DNS benchmark harness).
func benchObservation(raw string, headers []HeaderEntry, cookies []CookieEntry, body string) Observation {
	u, err := asset.ParseURL(raw, asset.Provenance{})
	if err != nil {
		panic(err)
	}
	return Observation{
		URL:        u,
		Headers:    headers,
		Cookies:    cookies,
		Body:       body,
		Source:     "bench",
		ObservedAt: benchFixedTime,
	}
}

// hasResultName reports whether the retained technologies contain name.
func hasResultName(ts []TechnologyResult, name string) bool {
	for i := range ts {
		if ts[i].Technology.Name == name {
			return true
		}
	}
	return false
}

// benchFillerUnit is repeated inside <p> tags to pad benchmark bodies to
// their exact target size. The text is deliberately free of every
// fingerprint match string (checked against the DB tables), so padding
// never fires indicators.
const benchFillerUnit = "lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "

// paddedHTML returns a page of exactly size bytes: prefix, paragraph filler,
// suffix. The scanner tolerates a filler chunk cut mid-tag at the boundary.
func paddedHTML(prefix, suffix string, size int) string {
	body := prefix
	for len(body) < size-len(suffix) {
		chunk := "<p>" + benchFillerUnit + "</p>"
		if len(body)+len(chunk) > size-len(suffix) {
			chunk = chunk[:size-len(suffix)-len(body)]
		}
		body += chunk
	}
	return body + suffix
}

// benchFullHead is the marker-rich head+body-open of the full-page fixture:
// generator metas, script tags, stylesheet links, and framework attributes,
// every marker taken from the production fingerprint tables.
func benchFullHead() string {
	return `<html lang="en" ng-app="app" ng-version="17.2.0">` +
		`<head>` +
		`<meta name="generator" content="WordPress 6.4.2">` +
		`<meta name="generator" content="Astro v4.0.0">` +
		`<meta name="generator" content="Hugo 0.120.0">` +
		`<meta name="csrf-token" content="t0k3n">` +
		`<link rel="stylesheet" href="/wp-content/themes/t/style.css">` +
		`<link rel="stylesheet" href="/app.css">` +
		`<script id="__NEXT_DATA__" type="application/json">{}</script>` +
		`<script src="https://cdn.example.com/static/js/react.js"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/vue.runtime.global.js"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/angular.min.js"></script>` +
		`<script src="/js/svelte.min.js"></script>` +
		`<script src="/js/solid.min.js"></script>` +
		`<script src="/js/qwik.core.js"></script>` +
		`<script src="/_next/static/chunks/main.js"></script>` +
		`<script src="/_nuxt/entry.js"></script>` +
		`<script src="/@vite/client"></script>` +
		`<script src="/build/entry.client.js"></script>` +
		`<script src="/page-data/app-data.json"></script>` +
		`<script src="https://www.google-analytics.com/analytics.js"></script>` +
		`<script src="https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/react-relay@0.1/relay.js"></script>` +
		`<script src="https://cdn.jsdelivr.net/npm/system.min.js"></script>` +
		`<script src="/js/require.js"></script>` +
		`</head>` +
		`<body>` +
		`<div id="root" data-reactroot>` +
		`<div id="___gatsby" q:version="1.5.0" q:base="/build/">` +
		`<div data-astro-island="">`
}

// benchFullObservation is the full-path analyzer fixture: headers, cookies,
// and a 64 KiB HTML body.
func benchFullObservation(b *testing.B) Observation {
	head := benchFullHead()
	body := paddedHTML(head, "</div></div></div></body></html>", 64<<10)
	if len(body) != 64<<10 {
		b.Fatalf("full fixture body = %d bytes, want %d", len(body), 64<<10)
	}
	o := benchObservation("https://h0.example.com/blog/post-1",
		[]HeaderEntry{
			{Name: "Server", Value: "nginx/1.25.3"},
			{Name: "X-Powered-By", Value: "Express"},
			{Name: "Set-Cookie", Value: "session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/"},
			{Name: "X-Request-Id", Value: "req-0001"},
			{Name: "Via", Value: "1.1 varnish"},
		},
		[]CookieEntry{
			{Name: "phx_session", Value: "abc123"},
			{Name: "grafana_session", Value: "deadbeef"},
		},
		body)
	return o
}

// analyze is exercised at the DefaultConfig caps (128 technologies, 512
// indicators) throughout.

// BenchmarkAnalyzeHeaders measures one header-only observation (the nginx
// Server banner) through the full analyzer against the REAL compiled
// database: corpus extraction, every fingerprint indicator match, evidence
// assembly, confidence scoring, and deterministic retention.
func BenchmarkAnalyzeHeaders(b *testing.B) {
	_, fps := benchDB(b)
	o := benchObservation("https://h0.example.com/",
		[]HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}, nil, "")
	prov := benchProv("bench")

	// Sanity (hoisted, untimed): the fixture must actually fire nginx — a
	// benchmark that analyzes nothing measures nothing.
	first := analyze(o, fps, 128, 512, prov)
	if !hasResultName(first.technologies, "nginx") || len(first.evidence) == 0 {
		b.Fatalf("header-only fixture fired %d technologies / %d evidence, want nginx with evidence",
			len(first.technologies), len(first.evidence))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if out := analyze(o, fps, 128, 512, prov); len(out.evidence) == 0 {
			b.Fatal("analysis produced no evidence")
		}
	}
}

// BenchmarkAnalyzeFull measures the full analyzer path on a realistic
// observation: headers, cookies (caller-provided plus Set-Cookie parsing
// with session flags), and a 64 KiB HTML body carrying generator metas,
// script tags, stylesheet links, and framework attributes.
func BenchmarkAnalyzeFull(b *testing.B) {
	_, fps := benchDB(b)
	o := benchFullObservation(b)
	prov := benchProv("bench")

	// Sanity (hoisted): both the header channel (nginx, spoofable) and the
	// body channel (wordpress's generator, structural) must fire.
	first := analyze(o, fps, 128, 512, prov)
	if !hasResultName(first.technologies, "nginx") || !hasResultName(first.technologies, "wordpress") {
		b.Fatalf("full fixture fired %d technologies (nginx=%v wordpress=%v), want both",
			len(first.technologies), hasResultName(first.technologies, "nginx"), hasResultName(first.technologies, "wordpress"))
	}
	if len(first.evidence) < 10 {
		b.Fatalf("full fixture produced only %d evidence records, want a rich set", len(first.evidence))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if out := analyze(o, fps, 128, 512, prov); len(out.evidence) == 0 {
			b.Fatal("analysis produced no evidence")
		}
	}
}

// BenchmarkHeaderAnalysis isolates the header-matching inner loop: every
// header-kind indicator of the real DB matched against a fixed 24-entry
// header corpus. The corpus construction is hoisted (untimed); the timed
// loop runs only matchIndicator.
func BenchmarkHeaderAnalysis(b *testing.B) {
	_, fps := benchDB(b)
	corpus := benchHeaderCorpus()
	inds := benchHeaderIndicators(fps)
	if len(inds) < 20 {
		b.Fatalf("only %d header indicators in the DB, want a meaningful inner loop", len(inds))
	}

	// Sanity (hoisted): the nginx banner indicator must fire on the corpus.
	nginxFired := false
	for _, ind := range inds {
		if ind.Match == "server: nginx" && len(matchIndicator(ind, &corpus)) > 0 {
			nginxFired = true
		}
	}
	if !nginxFired {
		b.Fatal("header corpus must fire the nginx server-banner indicator")
	}

	b.ResetTimer()
	first := -1
	for i := 0; i < b.N; i++ {
		total := 0
		for _, ind := range inds {
			total += len(matchIndicator(ind, &corpus))
		}
		if first < 0 {
			first = total
		} else if total != first {
			b.Fatalf("match total changed between iterations: %d then %d (nondeterministic matching)", first, total)
		}
	}
	if first <= 0 {
		b.Fatal("header inner loop matched nothing")
	}
}

// benchHeaderCorpus builds the fixed 24-entry header corpus in matchable
// form (the analyzer's headerLine shape), hoisted out of the timed loop.
func benchHeaderCorpus() obsCorpus {
	c := obsCorpus{}
	entries := []HeaderEntry{
		{Name: "Server", Value: "nginx/1.25.3"},
		{Name: "Date", Value: "Sat, 15 Aug 2026 12:00:00 GMT"},
		{Name: "Content-Type", Value: "text/html; charset=utf-8"},
		{Name: "Content-Length", Value: "65536"},
		{Name: "Connection", Value: "keep-alive"},
		{Name: "Cache-Control", Value: "public, max-age=3600"},
		{Name: "X-Frame-Options", Value: "SAMEORIGIN"},
		{Name: "X-Content-Type-Options", Value: "nosniff"},
		{Name: "Strict-Transport-Security", Value: "max-age=31536000"},
		{Name: "Referrer-Policy", Value: "strict-origin-when-cross-origin"},
		{Name: "Permissions-Policy", Value: "camera=(), microphone=()"},
		{Name: "Accept-Ranges", Value: "bytes"},
		{Name: "ETag", Value: `"abc123"`},
		{Name: "Vary", Value: "Accept-Encoding"},
		{Name: "Content-Encoding", Value: "gzip"},
		{Name: "X-Powered-By", Value: "Express"},
		{Name: "Set-Cookie", Value: "session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/"},
		{Name: "Cookie", Value: "theme=dark; lang=en"},
		{Name: "X-Request-Id", Value: "req-0001"},
		{Name: "X-Envoy-Upstream-Service-Time", Value: "12"},
		{Name: "Via", Value: "1.1 varnish"},
		{Name: "X-Amz-Bucket-Region", Value: "us-east-1"},
		{Name: "X-Served-By", Value: "cache-lax"},
		{Name: "Alt-Svc", Value: `h3=":443"; ma=86400`},
	}
	c.headers = make([]headerLine, 0, len(entries))
	for _, h := range entries {
		line := h.Name + ": " + h.Value
		c.headers = append(c.headers, headerLine{name: h.Name, value: h.Value, line: line, lower: strings.ToLower(line)})
	}
	return c
}

// benchHeaderIndicators collects every header-kind indicator of the real
// DB, in DB order.
func benchHeaderIndicators(fps []fingerprints.Fingerprint) []fingerprints.Indicator {
	var out []fingerprints.Indicator
	for _, fp := range fps {
		for _, ind := range fp.Indicators {
			if ind.Kind == fingerprints.IndicatorHeader {
				out = append(out, ind)
			}
		}
	}
	return out
}

// BenchmarkHTMLParse measures the body-corpus build: one lowercase copy and
// ONE single-pass tag scan (scripts, css, metas, attributes, sourcemap
// tokens) over a 256 KiB synthetic HTML page. The page is built once
// (hoisted); the timed loop runs only the corpus build and scan.
func BenchmarkHTMLParse(b *testing.B) {
	// No DB needed: the corpus build is database-independent.
	head := benchFullHead()
	body := paddedHTML(head, "</div></div></div></body></html>", 256<<10)
	if len(body) != 256<<10 {
		b.Fatalf("parse fixture body = %d bytes, want %d", len(body), 256<<10)
	}
	o := benchObservation("https://h0.example.com/", nil, nil, body)

	// Sanity (hoisted): the single pass must extract candidate material.
	first := buildCorpus(o)
	if len(first.scripts) == 0 || len(first.metas) == 0 || len(first.attrs) == 0 {
		b.Fatalf("corpus extraction found scripts=%d metas=%d attrs=%d, want all non-empty",
			len(first.scripts), len(first.metas), len(first.attrs))
	}
	if len(first.body) != 256<<10 || len(first.bodyLower) != 256<<10 {
		b.Fatalf("corpus body/lower sizes = %d/%d, want %d/%d",
			len(first.body), len(first.bodyLower), 256<<10, 256<<10)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := buildCorpus(o)
		if len(c.scripts) == 0 {
			b.Fatal("corpus extraction found no scripts")
		}
	}
}

// benchmarkMergeInputs builds the two populated technology-result lists the
// merge benchmark folds together: 12 results each, 10 distinct identities,
// overlapping on nginx and wordpress so the deterministic tie-break chain
// is exercised (equal scores with different versions and ObservedAt).
type benchMergeInputsResult struct {
	a, b []TechnologyResult
}

func buildBenchMergeInputs(b *testing.B) benchMergeInputsResult {
	provA := benchProv("bench-a")
	provB := benchProv("bench-b") // strictly later ObservedAt
	mk := func(name string, cat asset.TechnologyCategory, version string, score float64, level ConfidenceLevel, p asset.Provenance) TechnologyResult {
		t, err := asset.NewTechnology(name, cat, p)
		if err != nil {
			b.Fatalf("NewTechnology(%q): %v", name, err)
		}
		if version != "" {
			if t, err = asset.WithVersion(t, version); err != nil {
				b.Fatalf("WithVersion(%q): %v", version, err)
			}
		}
		return TechnologyResult{Technology: t, Score: score, Level: level}
	}
	a := []TechnologyResult{
		mk("nginx", asset.CategoryServer, "1.25.3", 0.9, LevelHigh, provA),
		mk("cloudflare", asset.CategoryCDN, "", 0.83, LevelHigh, provA),
		mk("wordpress", asset.CategoryCMS, "6.4.2", 0.9, LevelHigh, provA),
		mk("react", asset.CategoryFramework, "", 0.9, LevelHigh, provA),
		mk("vue", asset.CategoryFramework, "", 0.85, LevelHigh, provA),
		mk("express", asset.CategoryFramework, "", 0.81, LevelHigh, provA),
		mk("php", asset.CategoryLanguage, "8.2.12", 0.8, LevelHigh, provA),
		mk("node.js", asset.CategoryRuntime, "20.11.1", 0.77, LevelMedium, provA),
		mk("webpack", asset.CategoryBuildTool, "", 0.75, LevelMedium, provA),
		mk("auth0", asset.CategoryAuthentication, "", 0.7, LevelMedium, provA),
		mk("aws", asset.CategoryCloudProvider, "", 0.6, LevelMedium, provA),
		mk("angular", asset.CategoryFramework, "17.2.0", 0.6, LevelMedium, provA),
	}
	bl := []TechnologyResult{
		mk("nginx", asset.CategoryServer, "", 0.9, LevelHigh, provB), // score tie: a's version must survive
		mk("wordpress", asset.CategoryCMS, "6.4.3", 0.9, LevelHigh, provB),
		mk("gatsby", asset.CategoryCMS, "", 0.85, LevelHigh, provB),
		mk("drupal", asset.CategoryCMS, "10.1.0", 0.82, LevelHigh, provB),
		mk("svelte", asset.CategoryFramework, "", 0.8, LevelHigh, provB),
		mk("solid", asset.CategoryFramework, "", 0.79, LevelMedium, provB),
		mk("s3", asset.CategoryStorage, "", 0.7, LevelMedium, provB),
		mk("kubernetes", asset.CategoryOrchestration, "", 0.65, LevelMedium, provB),
		mk("docker", asset.CategoryContainer, "", 0.6, LevelMedium, provB),
		mk("graphql", asset.CategoryGraphQL, "", 0.55, LevelMedium, provB),
		mk("postgresql", asset.CategoryDatabase, "15.4", 0.5, LevelMedium, provB),
		mk("elasticsearch", asset.CategorySearchEngine, "", 0.45, LevelLow, provB),
	}
	return benchMergeInputsResult{a: a, b: bl}
}

// BenchmarkConfidenceMerge measures the deterministic merge of two
// populated per-observation technology lists (the merge-at-emit path): 24
// results, 10 distinct identities, equal-score ties resolved by the
// version/earliest/source/ordinal/version-text/level chain.
func BenchmarkConfidenceMerge(b *testing.B) {
	in := buildBenchMergeInputs(b)

	// Sanity (hoisted): the merge keeps every distinct identity (22 of 24
	// inputs) and the equal-score nginx tie resolves deterministically.
	first := mergeTechnologyResults(in.a, in.b)
	if len(first) != 22 {
		b.Fatalf("merged = %d technologies, want 22", len(first))
	}
	for i := range first {
		if first[i].Technology.Name == "nginx" && first[i].Technology.Version != "1.25.3" {
			b.Fatalf("nginx tie-break lost the version: %q", first[i].Technology.Version)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		merged := mergeTechnologyResults(in.a, in.b)
		if len(merged) != 22 {
			b.Fatalf("merged = %d technologies, want 22", len(merged))
		}
	}
}

// bench10kDuration is the measured wall duration of one 10,000-observation
// cold Ingest pass on the benchmark machine (see the file header); it is
// named by the -short skip message so the skip is honest about cost.
const bench10kDuration = "50–60 s"

// benchWorkload is one Ingest cold-pass sizing.
type benchWorkload struct {
	name string
	obs  int
}

var benchWorkloads = []benchWorkload{
	{"10", 10},
	{"100", 100},
	{"1000", 1000},
	{"10000", 10000},
}

// benchObservations builds n deterministic distinct observations: one per
// host, each carrying a Server banner and a small generator-marked HTML
// body, so a real multi-channel analysis happens per observation.
func benchObservations(n int) []Observation {
	obs := make([]Observation, 0, n)
	for i := 0; i < n; i++ {
		u, err := asset.ParseURL(fmt.Sprintf("https://h%d.example.com/", i), asset.Provenance{})
		if err != nil {
			panic(err) // constant-shaped input; cannot fail
		}
		obs = append(obs, Observation{
			URL:        u,
			Headers:    []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}},
			Body:       fmt.Sprintf(`<html><head><title>site %d</title><meta name="generator" content="WordPress 6.4.2"></head><body><p>page %d</p></body></html>`, i, i),
			Source:     "bench",
			ObservedAt: benchFixedTime,
		})
	}
	return obs
}

// benchConfig returns the fixed benchmark configuration: DefaultConfig with
// benchmark tuning (16 workers, no per-job deadline, no rate limiting —
// throughput measurement, mirroring the DNS and URL intelligence benchmark
// harnesses), the REAL fingerprint database injected (the compile-once load
// is hoisted out of the timed region), and the real FS cache rooted at dir.
// A cache open failure is fatal for the benchmark: silently proceeding
// would turn every cold pass into an uncached run and invalidate the
// measurements.
func benchConfig(b *testing.B, dir string, db *fingerprints.DB) Config {
	cfg := DefaultConfig()
	cfg.Concurrency = 16
	cfg.QueueSize = 256
	cfg.Timeout = 0 // no per-job deadline: local work never blocks
	cfg.Rate = 0    // pacing disabled: the benchmark measures raw throughput
	cfg.DB = db
	cfg.Metrics = &Metrics{}
	c, err := cache.Open(dir)
	if err != nil {
		b.Fatalf("cache.Open: %v", err)
	}
	cfg.Cache = c
	return cfg
}

// benchIngest runs one workload's full cold Ingest pass: n distinct
// observations, n cache misses + n cache writes per iteration. The cache is
// REUSED across iterations, so only iteration 1 is truly cold — run with
// -benchtime=1x (the required usage; see the file header). The post-loop
// metrics assertion pins exactly one cold pass regardless of b.N: reads
// accumulate per iteration (n per pass), while analyzed/stored stay at
// exactly n — every iteration beyond the first must be pure cache hits with
// ZERO analysis. Malformed must stay zero: a malformed observation would
// mean the fixture drifted from the canonical model.
func benchIngest(b *testing.B, wl benchWorkload) {
	// The 10k workload takes ≈50–60 s per pass (measured; see the file
	// header); under -short it is skipped so CI-style runs stay bounded.
	if testing.Short() && wl.obs >= 10000 {
		b.Skip(fmt.Sprintf("the %d-observation cold pass takes ≈%s; skipped under -short", wl.obs, bench10kDuration))
	}

	db, _ := benchDB(b)
	obs := benchObservations(wl.obs)
	cfg := benchConfig(b, b.TempDir(), db)
	ctx := context.Background()

	b.ResetTimer()
	var rep Report
	for i := 0; i < b.N; i++ {
		// Fresh source per iteration: Next consumes the slice, so reuse a
		// copy of the slice HEADER only — the observations themselves are
		// built once, outside the timed loop.
		src := &SliceObservationSource{}
		*src = obs
		var err error
		rep, err = Ingest(ctx, cfg, src)
		if err != nil {
			b.Fatalf("Ingest: %v", err)
		}
	}
	b.StopTimer()

	if rep.Observations.Completed != wl.obs {
		b.Fatalf("completed observations = %d, want %d", rep.Observations.Completed, wl.obs)
	}
	snap := cfg.Metrics.Snapshot()
	if snap.Reads != b.N*wl.obs {
		b.Fatalf("cache reads = %d, want %d (one per observation per iteration)", snap.Reads, b.N*wl.obs)
	}
	if snap.Analyzed != wl.obs || snap.Stored != wl.obs {
		b.Fatalf("analyzed/stored = %d/%d, want exactly one cold pass (%d); iterations 2..N must be pure cache hits",
			snap.Analyzed, snap.Stored, wl.obs)
	}
	if snap.Malformed != 0 {
		b.Fatalf("malformed = %d, want 0", snap.Malformed)
	}
}

func BenchmarkIngestCold10(b *testing.B)    { benchIngest(b, benchWorkloads[0]) }
func BenchmarkIngestCold100(b *testing.B)   { benchIngest(b, benchWorkloads[1]) }
func BenchmarkIngestCold1000(b *testing.B)  { benchIngest(b, benchWorkloads[2]) }
func BenchmarkIngestCold10000(b *testing.B) { benchIngest(b, benchWorkloads[3]) }
