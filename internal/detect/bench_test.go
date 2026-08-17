package detect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// benchRules builds n rules: a dependency chain of depth n/10 plus a wide
// fan of independent rules — both graph shapes the scheduler must handle
// without quadratic behavior.
func benchRules(b *testing.B, n int) []Rule {
	b.Helper()
	// The scheduler benchmark measures orchestration, not finding
	// generation: its rules find nothing (a legitimate rule outcome).
	noFindings := func(context.Context, *Context) ([]asset.Finding, error) { return nil, nil }
	rules := make([]Rule, 0, n)
	chain := n / 10
	if chain == 0 {
		chain = 1
	}
	for i := 0; i < chain; i++ {
		id := fmt.Sprintf("chain.%04d", i)
		var deps []string
		if i > 0 {
			deps = []string{fmt.Sprintf("chain.%04d", i-1)}
		}
		rules = append(rules, makeRule(b, id, &ruleOptions{deps: deps, detector: noFindings}))
	}
	for i := chain; i < n; i++ {
		rules = append(rules, makeRule(b, fmt.Sprintf("wide.%04d", i), &ruleOptions{detector: noFindings}))
	}
	return rules
}

// benchSnapshot builds a corpus with k assets of each core kind.
func benchSnapshot(b *testing.B, k int) Snapshot {
	b.Helper()
	snap := Snapshot{Assets: make([]asset.Identity, 0, k)}
	prov := asset.Provenance{Source: "bench"}
	for i := 0; i < k; i++ {
		host := fmt.Sprintf("host%04d.example.com", i)
		if h, err := asset.NewHost(host, prov); err == nil {
			snap.Assets = append(snap.Assets, h.Identity())
		}
		if u, err := asset.ParseURL(fmt.Sprintf("https://%s/app", host), prov); err == nil {
			snap.Assets = append(snap.Assets, u.Identity())
		}
	}
	return snap
}

func BenchmarkRuleScheduler100(b *testing.B)  { benchmarkRuleScheduler(b, 100) }
func BenchmarkRuleScheduler500(b *testing.B)  { benchmarkRuleScheduler(b, 500) }
func BenchmarkRuleScheduler1000(b *testing.B) { benchmarkRuleScheduler(b, 1000) }

// benchmarkRuleScheduler measures the full cold-run orchestration path.
// Registration happens INSIDE the timed loop (after ResetTimer): the
// reported cost deliberately includes registry construction and rule
// registration alongside dependency-level scheduling and execution —
// BenchmarkRegistration isolates the registration share for comparison.
func benchmarkRuleScheduler(b *testing.B, n int) {
	rules := benchRules(b, n)
	snap := benchSnapshot(b, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg := NewRegistry()
		for _, r := range rules {
			if err := reg.Register(r); err != nil {
				b.Fatalf("register: %v", err)
			}
		}
		rep, err := Run(context.Background(), DefaultEngineConfig(reg), snap)
		if err != nil {
			b.Fatalf("Run: %v", err)
		}
		if rep.Completed != n {
			b.Fatalf("completed %d, want %d", rep.Completed, n)
		}
	}
}

func BenchmarkRegistration(b *testing.B) {
	rules := benchRules(b, 1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg := NewRegistry()
		for _, r := range rules {
			if err := reg.Register(r); err != nil {
				b.Fatalf("register: %v", err)
			}
		}
	}
}

func BenchmarkFindingGeneration(b *testing.B) {
	detector := func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		out := make([]asset.Finding, 0, 8)
		for i := 0; i < 8; i++ {
			f, err := testFinding(dctx, "bench.rule", "Bench rule", CategoryInformation, i)
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
		return out, nil
	}
	rule := makeRule(b, "bench.rule", &ruleOptions{detector: detector})
	snap := testSnapshot(b)
	reg := NewRegistry()
	if err := reg.Register(rule); err != nil {
		b.Fatalf("register: %v", err)
	}
	cfg := DefaultEngineConfig(reg)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Run(context.Background(), cfg, snap); err != nil {
			b.Fatalf("Run: %v", err)
		}
	}
}

func BenchmarkCacheHitPath(b *testing.B) {
	dir := b.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		b.Fatalf("cache.Open: %v", err)
	}
	reg := NewRegistry()
	if err := reg.Register(makeRule(b, "bench.rule", nil)); err != nil {
		b.Fatalf("register: %v", err)
	}
	snap := testSnapshot(b)
	cfg := DefaultEngineConfig(reg)
	cfg.Cache = fs
	// Warm the cache once.
	if _, err := Run(context.Background(), cfg, snap); err != nil {
		b.Fatalf("warm Run: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep, err := Run(context.Background(), cfg, snap)
		if err != nil {
			b.Fatalf("Run: %v", err)
		}
		if rep.CacheHits != 1 {
			b.Fatalf("expected a cache hit")
		}
	}
}

func BenchmarkMetricsRecord(b *testing.B) {
	m := &Metrics{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.recordExecution("bench.rule", 100*time.Microsecond, 2)
		m.recordCache("bench.rule", true)
	}
	if sn := m.Snapshot(); sn.Executions != b.N {
		b.Fatalf("executions %d, want %d", sn.Executions, b.N)
	}
}
