package urlintel

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Benchmarks exercise the full ingest path hermetically: synthetic raw URL
// lines, a real bounded runtime.Pool, and a real filesystem-backed Phase 3
// cache (no public Internet). They are command-gated (-bench only).
//
// Timing reality (measured 2026-08-15 on the benchmark machine — an AMD
// Ryzen 5 8645HS, 12 threads, ext4 root filesystem, -benchtime=1x): the
// 10/100/1k cold passes measure ≈82 ms, ≈0.56 s, ≈5.3 s; the 10k cold pass
// is ≈56 s and the hit pass's UNTIMED warm-up costs the same ≈56 s again
// before its ≈0.5 s timed iteration — run the 10/100/1k/10k cold+hit set
// with -benchtime=1x and allow ≈2.5 minutes. The 100k cold spot measures
// ≈9 minutes. The million-line cold pass measures ≈50 minutes (2,982 s,
// 1.0e9-line-stream wall; fsync-bound: one serialized cache write per URL)
// — run it only with -benchtime=1x and on a quiet machine. Under
// `go test -short` (the CI-style default) the 10k, 100k, and million-line
// workloads are skipped entirely, keeping the suite bounded; the 10/100/1k
// workloads and the pure-CPU micro-benchmarks still run.
//
// Each workload ingests n distinct canonical URLs: n cache misses + n cache
// writes (fsync-bound, serialized by the cache's mutation lock) on the cold
// pass, and n pure cache hits on the hit pass — the hit pass's zero-work
// assertion (via the engine's Metrics counters) pins that no extraction or
// store happens in the timed loop.

// benchWorkload is one benchmark sizing.
type benchWorkload struct {
	name string
	urls int
}

var benchWorkloads = []benchWorkload{
	{"10", 10},
	{"100", 100},
	{"1000", 1000},
	{"10000", 10000},
}

// benchLines builds n deterministic raw URL lines (h0..hN-1.example.com),
// each canonicalizing to a distinct Phase 2 URL identity.
func benchLines(n int) []string {
	lines := make([]string, 0, n)
	for i := 0; i < n; i++ {
		lines = append(lines, fmt.Sprintf("http://h%d.example.com/p?a=%d&b=%d", i, i, i))
	}
	return lines
}

// benchConfig returns the fixed benchmark configuration: DefaultConfig with
// benchmark tuning (16 workers, no per-job deadline, no rate limiting —
// throughput measurement, mirroring the DNS and HTTP probing benchmark
// harnesses) and the real FS cache rooted at dir. A cache open failure is
// fatal for the benchmark: silently proceeding would turn every cold pass
// into an uncached run and invalidate the measurements.
func benchConfig(b *testing.B, dir string) Config {
	cfg := DefaultConfig()
	cfg.Concurrency = 16
	cfg.QueueSize = 256
	cfg.Timeout = 0 // no per-job deadline: local work never blocks
	cfg.Rate = 0    // pacing disabled: the benchmark measures raw throughput
	c, err := cache.Open(dir)
	if err != nil {
		b.Fatalf("cache.Open: %v", err)
	}
	cfg.Cache = c
	return cfg
}

// benchIngest runs one workload's ingest for the benchmark. When hitPass is
// false the cold pass is timed (n cache misses + n cache writes per
// iteration, all misses on the first iteration); when true an untimed
// warm-up pass populates the cache BEFORE the timed loop starts, so every
// timed iteration (all b.N of them) is a pure cache hit — the timed loop is
// never mixed with warm-up work, and the post-loop zero-work assertion
// checks the whole timed loop after it finishes through the engine's
// Metrics counters (no extraction, no store, exactly n reads per iteration).
//
// NOTE the cold pass reuses one cache across b.N iterations: only the FIRST
// iteration is truly cold — iterations 2..N are hits (read-only). Run the
// cold workloads with -benchtime=1x (the required usage) so the reported
// number is the true cold pass; a higher -benchtime silently mixes hit
// iterations into the "cold" figure. The million-line benchmark avoids the
// ambiguity by asserting a full cold pass per iteration, which is also why
// it must be run at -benchtime=1x.
func benchIngest(b *testing.B, wl benchWorkload, hitPass bool) {
	// The 10k and larger workloads take minutes per pass; under -short they
	// are skipped so CI-style runs stay bounded (see the file header).
	if testing.Short() && wl.urls >= 10000 {
		b.Skip(fmt.Sprintf("%d-line workloads take minutes each; skipped under -short", wl.urls))
	}

	lines := benchLines(wl.urls)
	cfg := benchConfig(b, b.TempDir())
	ctx := context.Background()

	b.ResetTimer()
	if hitPass {
		// Untimed warm-up: populate the cache so the timed iterations below
		// are all pure hits. StopTimer excludes this cold pass from the
		// measurement; the zero-work assertion after the loop proves it.
		b.StopTimer()
		if _, err := Ingest(ctx, cfg, SliceSource(lines)); err != nil {
			b.Fatalf("warm-up Ingest: %v", err)
		}
		// Fresh counters for the timed loop only: the warm-up's reads and
		// stores must not leak into the assertion.
		cfg.Metrics = &Metrics{}
		b.StartTimer()
	}

	var rep Report
	var err error
	if hitPass {
		for i := 0; i < b.N; i++ {
			rep, err = Ingest(ctx, cfg, SliceSource(lines))
			if err != nil {
				b.Fatalf("Ingest: %v", err)
			}
		}
		// Every timed iteration must be a pure cache hit: zero extraction,
		// zero stores, and exactly one cache read per line.
		snap := cfg.Metrics.Snapshot()
		if snap.Extracted != 0 || snap.Stored != 0 {
			b.Fatalf("hit pass performed extraction/store work: %+v; want zero (pure cache hits)", snap)
		}
		if snap.Reads != b.N*wl.urls {
			b.Fatalf("hit pass cache reads = %d, want %d", snap.Reads, b.N*wl.urls)
		}
	} else {
		for i := 0; i < b.N; i++ {
			rep, err = Ingest(ctx, cfg, SliceSource(lines))
			if err != nil {
				b.Fatalf("Ingest: %v", err)
			}
		}
	}
	b.StopTimer()

	if len(rep.Entries) != wl.urls {
		b.Fatalf("entries = %d, want %d", len(rep.Entries), wl.urls)
	}
}

func BenchmarkIngestCold10(b *testing.B)    { benchIngest(b, benchWorkloads[0], false) }
func BenchmarkIngestCold100(b *testing.B)   { benchIngest(b, benchWorkloads[1], false) }
func BenchmarkIngestCold1000(b *testing.B)  { benchIngest(b, benchWorkloads[2], false) }
func BenchmarkIngestCold10000(b *testing.B) { benchIngest(b, benchWorkloads[3], false) }
func BenchmarkIngestHit10(b *testing.B)     { benchIngest(b, benchWorkloads[0], true) }
func BenchmarkIngestHit100(b *testing.B)    { benchIngest(b, benchWorkloads[1], true) }
func BenchmarkIngestHit1000(b *testing.B)   { benchIngest(b, benchWorkloads[2], true) }
func BenchmarkIngestHit10000(b *testing.B)  { benchIngest(b, benchWorkloads[3], true) }

// BenchmarkIngestCold100000 is the 100k-sized cold spot used for the
// run-level seen-set decision: it measures the plain pipeline's cold
// throughput at 100k distinct URLs (100k fsync-bound cache writes) so the
// per-line filesystem cost can be isolated from the pure-CPU micro-bench
// costs (see BenchmarkNormalize / BenchmarkMergeParams). Short-gated like
// every workload at or beyond 10k.
func BenchmarkIngestCold100000(b *testing.B) {
	benchIngest(b, benchWorkload{name: "100000", urls: 100000}, false)
}

// genSource is a counting LineSource: it streams n deterministic raw URL
// lines without materializing them. The million-line benchmark's source —
// streaming is the point (no pre-built 1M-element slice).
type genSource struct {
	n int
	i int
}

// Next implements LineSource.
func (g *genSource) Next(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if g.i >= g.n {
		return "", io.EOF
	}
	i := g.i
	g.i++
	return fmt.Sprintf("http://h%d.example.com/p?a=%d", i, i), nil
}

// BenchmarkIngestMillion runs one full cold pass of a synthetic
// 1,000,000-line stream (1M distinct URLs) through the real pipeline: 1M
// parses, extractions, cache misses, and fsync-bound cache writes, with
// wall throughput and allocations reported (-benchmem). It takes ≈50
// minutes — run with -benchtime=1x on a quiet machine; under -short it is
// skipped (see the file header for the measured duration).
func BenchmarkIngestMillion(b *testing.B) {
	if testing.Short() {
		b.Skip("the 1M-line cold pass takes ≈50 minutes; skipped under -short")
	}
	const n = 1_000_000
	cfg := benchConfig(b, b.TempDir())
	ctx := context.Background()

	for i := 0; i < b.N; i++ {
		// Fresh counters per iteration: the assertion below must describe
		// exactly this iteration's pass.
		cfg.Metrics = &Metrics{}
		b.ResetTimer()
		rep, err := Ingest(ctx, cfg, &genSource{n: n})
		b.StopTimer()
		if err != nil {
			b.Fatalf("Ingest: %v", err)
		}
		if len(rep.Entries) != n {
			b.Fatalf("entries = %d, want %d", len(rep.Entries), n)
		}
		snap := cfg.Metrics.Snapshot()
		if snap.Lines != n || snap.Canonicalized != n || snap.Extracted != n ||
			snap.Stored != n || snap.Reads != n || snap.Malformed != 0 {
			b.Fatalf("metrics = %+v, want a full cold pass (1M read/extracted/stored)", snap)
		}
	}
}

// BenchmarkNormalize measures the ingest-boundary parse: one raw string
// canonicalized into a Phase 2 URL asset through asset.ParseURL (no cache).
func BenchmarkNormalize(b *testing.B) {
	const raw = "HTTP://Example.COM:80/p?a=1&b=2"
	prov := asset.Provenance{Source: "bench", DiscoveredAt: time.Now().UTC()}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := asset.ParseURL(raw, prov); err != nil {
			b.Fatalf("ParseURL: %v", err)
		}
	}
}

// BenchmarkMergeParams measures asset.MergeParameters on two populated
// parameters: two observations of the same query parameter with distinct
// value histories merged via the Phase 2 merge primitive.
func BenchmarkMergeParams(b *testing.B) {
	now := time.Now().UTC()
	prov := asset.Provenance{Source: "bench", DiscoveredAt: now}
	a, err := asset.NewParameter("q", "query", "v1", "bench", now, prov)
	if err != nil {
		b.Fatalf("NewParameter: %v", err)
	}
	for _, v := range []string{"v2", "v3", "v4"} {
		if a, err = asset.WithValue(a, v, "bench", now); err != nil {
			b.Fatalf("WithValue: %v", err)
		}
	}
	c, err := asset.NewParameter("q", "query", "v3", "bench", now, prov)
	if err != nil {
		b.Fatalf("NewParameter: %v", err)
	}
	for _, v := range []string{"v4", "v5", "v6"} {
		if c, err = asset.WithValue(c, v, "bench", now); err != nil {
			b.Fatalf("WithValue: %v", err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := asset.MergeParameters(a, c); err != nil {
			b.Fatalf("MergeParameters: %v", err)
		}
	}
}
