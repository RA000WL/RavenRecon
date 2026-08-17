package report

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// benchContext builds a canonical input with n hosts, n URLs, and n/10
// findings — a proportional corpus at the documented performance targets
// (100 / 1,000 / 10,000 / 100,000 assets).
func benchContext(b *testing.B, n int) Context {
	b.Helper()
	c := Context{
		Target:    "example.com",
		StartedAt: fixedTime,
		EndedAt:   fixedTime.Add(90 * time.Second),
		Hosts:     make([]asset.Host, 0, n),
		URLs:      make([]asset.URL, 0, n),
		Findings:  make([]asset.Finding, 0, n/10),
	}
	for i := 0; i < n; i++ {
		c.Hosts = append(c.Hosts, hostAssetB(b, fmt.Sprintf("host%06d.example.com", i)))
		u, err := asset.ParseURL(fmt.Sprintf("https://host%06d.example.com/path/%d?i=%d", i, i, i), fixedProv("bench"))
		if err != nil {
			b.Fatalf("url: %v", err)
		}
		c.URLs = append(c.URLs, u)
	}
	for i := 0; i < n/10; i++ {
		c.Findings = append(c.Findings, findingFixtureB(b, fmt.Sprintf("rule-%03d", i%8), fmt.Sprintf("host%06d.example.com", i)))
	}
	return c
}

func benchModel(b *testing.B, n int) *Model {
	b.Helper()
	m, err := NewModel(benchContext(b, n))
	if err != nil {
		b.Fatalf("model: %v", err)
	}
	return m
}

func hostAssetB(b *testing.B, name string) asset.Host {
	b.Helper()
	h, err := asset.NewHost(name, fixedProv("bench"))
	if err != nil {
		b.Fatalf("host: %v", err)
	}
	return h
}

func findingFixtureB(b *testing.B, ruleID, hostName string) asset.Finding {
	b.Helper()
	subject := hostAssetB(b, hostName).Identity()
	ev, err := asset.NewEvidence(asset.MethodDetection, "detect:"+ruleID, "observed", subject, fixedProv("bench"))
	if err != nil {
		b.Fatalf("evidence: %v", err)
	}
	f, err := asset.NewFinding(asset.Finding{
		RuleID: ruleID, RuleName: ruleID + " rule", Category: "exposure",
		Subject: subject, Confidence: 0.8, Evidence: []asset.Evidence{ev},
		Priority: "medium", Status: "open", Created: fixedTime,
	})
	if err != nil {
		b.Fatalf("finding: %v", err)
	}
	return f
}

func builtinB(b *testing.B, id string) Reporter {
	b.Helper()
	reg, err := NewDefaultRegistry()
	if err != nil {
		b.Fatalf("registry: %v", err)
	}
	rep, ok := reg.Get(id)
	if !ok {
		b.Fatalf("reporter %q missing", id)
	}
	return rep
}

// benchmarkModelBuild measures the one-time canonical model build
// (validation, merge, sort, statistics, digest).
func benchmarkModelBuild(b *testing.B, n int) {
	b.Helper()
	c := benchContext(b, n)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NewModel(c); err != nil {
			b.Fatalf("model: %v", err)
		}
	}
}

// benchmarkRender measures one renderer over one model into a memory sink
// (the write-path cost without filesystem noise).
func benchmarkRender(b *testing.B, id string, m *Model) {
	b.Helper()
	rep := builtinB(b, id)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink := newMemSink()
		if err := rep.Render(ctx, m, sink); err != nil {
			b.Fatalf("render: %v", err)
		}
	}
}

func BenchmarkModelBuild100(b *testing.B)    { benchmarkModelBuild(b, 100) }
func BenchmarkModelBuild1000(b *testing.B)   { benchmarkModelBuild(b, 1_000) }
func BenchmarkModelBuild10000(b *testing.B)  { benchmarkModelBuild(b, 10_000) }
func BenchmarkModelBuild100000(b *testing.B) { benchmarkModelBuild(b, 100_000) }

func BenchmarkJSON100(b *testing.B)    { benchmarkRender(b, "json", benchModel(b, 100)) }
func BenchmarkJSON1000(b *testing.B)   { benchmarkRender(b, "json", benchModel(b, 1_000)) }
func BenchmarkJSON10000(b *testing.B)  { benchmarkRender(b, "json", benchModel(b, 10_000)) }
func BenchmarkJSON100000(b *testing.B) { benchmarkRender(b, "json", benchModel(b, 100_000)) }

func BenchmarkCSV100(b *testing.B)    { benchmarkRender(b, "csv", benchModel(b, 100)) }
func BenchmarkCSV1000(b *testing.B)   { benchmarkRender(b, "csv", benchModel(b, 1_000)) }
func BenchmarkCSV10000(b *testing.B)  { benchmarkRender(b, "csv", benchModel(b, 10_000)) }
func BenchmarkCSV100000(b *testing.B) { benchmarkRender(b, "csv", benchModel(b, 100_000)) }

func BenchmarkMarkdown100(b *testing.B)    { benchmarkRender(b, "markdown", benchModel(b, 100)) }
func BenchmarkMarkdown1000(b *testing.B)   { benchmarkRender(b, "markdown", benchModel(b, 1_000)) }
func BenchmarkMarkdown10000(b *testing.B)  { benchmarkRender(b, "markdown", benchModel(b, 10_000)) }
func BenchmarkMarkdown100000(b *testing.B) { benchmarkRender(b, "markdown", benchModel(b, 100_000)) }

func BenchmarkHTML100(b *testing.B)    { benchmarkRender(b, "html", benchModel(b, 100)) }
func BenchmarkHTML1000(b *testing.B)   { benchmarkRender(b, "html", benchModel(b, 1_000)) }
func BenchmarkHTML10000(b *testing.B)  { benchmarkRender(b, "html", benchModel(b, 10_000)) }
func BenchmarkHTML100000(b *testing.B) { benchmarkRender(b, "html", benchModel(b, 100_000)) }
