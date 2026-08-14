package dns

import (
	"context"
	"fmt"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Benchmarks exercise the full resolution path hermetically: a fake
// resolver, a real bounded runtime.Pool, and a real filesystem-backed Phase
// 3 cache (no public Internet). They are command-gated (-bench only).
//
// Timing reality: the 10/100/1k workloads plus spot checks run in seconds;
// the 10k workloads take several minutes EACH — run them with
// -benchtime=1x and allow ~10 minutes for the full 10k set. Under
// `go test -short` (the CI-style default) the 10k workloads are skipped
// entirely, keeping the suite bounded; the 1k concurrency sweep still runs.
//
// Each host resolves A/AAAA/CNAME plus its direct CNAME target's A/AAAA
// (depth 1): five queries per host, five cache records per host on the cold
// pass, and five cache hits per host on the second pass.

// benchWorkload is one benchmark sizing.
type benchWorkload struct {
	name  string
	hosts int
}

var benchWorkloads = []benchWorkload{
	{"10", 10},
	{"100", 100},
	{"1000", 1000},
	{"10000", 10000},
}

// benchHosts builds n deterministic in-scope hosts (h0..hN-1.example.com).
func benchHosts(n int) []asset.Host {
	hosts := make([]asset.Host, 0, n)
	for i := 0; i < n; i++ {
		h, err := asset.NewHost(fmt.Sprintf("h%d.example.com", i), asset.Provenance{})
		if err != nil {
			panic(err)
		}
		hosts = append(hosts, h)
	}
	return hosts
}

// benchFake populates a fake resolver for n hosts: two A records, one AAAA
// record, and a CNAME to cN.example.net (which itself resolves to two A and
// one AAAA) — five answers per host, all in documentation ranges.
func benchFake(f *fakeResolver, n int) {
	for i := 0; i < n; i++ {
		h := fmt.Sprintf("h%d.example.com", i)
		c := fmt.Sprintf("c%d.example.net", i)
		f.set(h, TypeA, "192.0.2.1", "192.0.2.2")
		f.set(h, TypeAAAA, "2001:db8::1")
		f.set(h, TypeCNAME, c)
		f.set(c, TypeA, "198.51.100.1", "198.51.100.2")
		f.set(c, TypeAAAA, "2001:db8::2")
	}
}

// benchConfigAt returns the fixed benchmark configuration: real pool at the
// given concurrency, no rate limiting (throughput measurement), and the real
// FS cache rooted at dir. A cache open failure is fatal for the benchmark:
// silently proceeding would turn every cold pass into an uncached run and
// invalidate the measurements.
func benchConfigAt(b *testing.B, dir string, res Resolver, concurrency int) Config {
	cfg := DefaultConfig()
	cfg.Concurrency = concurrency
	cfg.QueueSize = 256
	cfg.Timeout = 0 // no per-job deadline: the fake resolver never blocks
	cfg.Rate = 0    // pacing disabled: the benchmark measures raw throughput
	cfg.Resolver = res
	c, err := cache.Open(dir)
	if err != nil {
		b.Fatalf("cache.Open: %v", err)
	}
	cfg.Cache = c
	return cfg
}

// benchConfig returns the fixed benchmark configuration at the default
// concurrency (16) shared by the fixed-concurrency passes.
func benchConfig(b *testing.B, dir string, res Resolver) Config {
	return benchConfigAt(b, dir, res, 16)
}

// benchResolve runs the resolution for one workload at one concurrency.
// When hitPass is false the cold pass is timed (50k queries for 10k hosts,
// all misses); when true an untimed warm-up pass populates the cache BEFORE
// the timed loop starts, so every timed iteration (all b.N of them) is a
// pure cache hit — the timed loop is never mixed with warm-up work, and the
// zero-query assertion checks the whole timed loop after it finishes.
func benchResolveAt(b *testing.B, wl benchWorkload, hitPass bool, concurrency int) {
	// The 10k workloads take minutes per pass; under -short they are
	// skipped so CI-style runs stay bounded (see the file header).
	if testing.Short() && wl.hosts >= 10000 {
		b.Skip("10k workloads take minutes each; skipped under -short")
	}

	hosts := benchHosts(wl.hosts)
	f := newFakeResolver()
	benchFake(f, wl.hosts)
	cfg := benchConfigAt(b, b.TempDir(), f, concurrency)
	domain := mustDomain(b, "example.com")
	ctx := context.Background()

	b.ResetTimer()
	if hitPass {
		// Untimed warm-up: populate the cache so the timed iterations below
		// are all pure hits. StopTimer excludes this cold pass from the
		// measurement; the zero-query assertion after the loop proves it.
		b.StopTimer()
		if _, err := Resolve(ctx, domain, hosts, cfg); err != nil {
			b.Fatalf("warm-up Resolve: %v", err)
		}
		b.StartTimer()
	}

	var rep Report
	var err error
	if hitPass {
		calls := f.callCount()
		for i := 0; i < b.N; i++ {
			rep, err = Resolve(ctx, domain, hosts, cfg)
			if err != nil {
				b.Fatalf("Resolve: %v", err)
			}
		}
		// Every timed iteration must be a pure cache hit: zero queries.
		if got := f.callCount(); got != calls {
			b.Fatalf("hit pass issued %d queries; want zero", got-calls)
		}
	} else {
		for i := 0; i < b.N; i++ {
			rep, err = Resolve(ctx, domain, hosts, cfg)
			if err != nil {
				b.Fatalf("Resolve: %v", err)
			}
		}
	}
	b.StopTimer()

	if len(rep.Results) != wl.hosts {
		b.Fatalf("results = %d, want %d", len(rep.Results), wl.hosts)
	}
}

// benchResolve runs one workload at the default benchmark concurrency (16).
func benchResolve(b *testing.B, wl benchWorkload, hitPass bool) {
	benchResolveAt(b, wl, hitPass, 16)
}

func BenchmarkResolveCold10(b *testing.B)    { benchResolve(b, benchWorkloads[0], false) }
func BenchmarkResolveCold100(b *testing.B)   { benchResolve(b, benchWorkloads[1], false) }
func BenchmarkResolveCold1000(b *testing.B)  { benchResolve(b, benchWorkloads[2], false) }
func BenchmarkResolveCold10000(b *testing.B) { benchResolve(b, benchWorkloads[3], false) }
func BenchmarkResolveHit10(b *testing.B)     { benchResolve(b, benchWorkloads[0], true) }
func BenchmarkResolveHit100(b *testing.B)    { benchResolve(b, benchWorkloads[1], true) }
func BenchmarkResolveHit1000(b *testing.B)   { benchResolve(b, benchWorkloads[2], true) }
func BenchmarkResolveHit10000(b *testing.B)  { benchResolve(b, benchWorkloads[3], true) }

// BenchmarkResolveColdConcurrency sweeps the resolver concurrency dimension
// (F6): the fixed cold workload at 1/4/16/64 workers — measurement only, no
// optimization. Sizing: 1,000 hosts per point was measured first (≈26 s per
// point at every concurrency — the per-type cache writes are fsync-bound and
// fully serialized, so wall time is concurrency-independent); the sweep pins
// 400 hosts (2,000 queries) so each point is ≈10 s and the whole sweep stays
// ≈40 s even at -benchtime=1x, under the ≤60 s added-time budget. The sweep
// runs under -short too: 400 is below the 10k short-mode gate.
func BenchmarkResolveColdConcurrency(b *testing.B) {
	var sweepWorkload = benchWorkload{name: "sweep", hosts: 400}
	for _, c := range []int{1, 4, 16, 64} {
		c := c
		b.Run(fmt.Sprintf("Concurrency%d", c), func(b *testing.B) {
			benchResolveAt(b, sweepWorkload, false, c)
		})
	}
}
