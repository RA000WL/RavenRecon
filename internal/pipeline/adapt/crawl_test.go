package adapt

import (
	"context"
	"reflect"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/crawl"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// fakeCrawlSource is the hermetic crawl seam for tests.
type fakeCrawlSource struct {
	fn func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error)
}

func (f *fakeCrawlSource) Crawl(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
	return f.fn(ctx, domain, hosts, cfg)
}

func mustDomainCrawl(t *testing.T, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain %q: %v", name, err)
	}
	return d
}
func mustHostCrawl(t *testing.T, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost %q: %v", name, err)
	}
	return h
}
func mustURLCrawl(t *testing.T, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL %q: %v", raw, err)
	}
	return u
}

func TestCrawlStageAddsURLs(t *testing.T) {
	src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
		return crawl.Result{
			URLs: []asset.URL{mustURLCrawl(t, "https://example.com/api/a"), mustURLCrawl(t, "https://example.com/api/b")},
		}, nil
	}}
	st := NewCrawlStage(src)
	in := pipeline.StageInput{
		Target: mustDomainCrawl(t, "example.com"),
		Hosts:  []asset.Host{mustHostCrawl(t, "www.example.com")},
		Bounds: pipeline.StageConfig{MaxCorpusSize: 100000, MaxOutput: 100000, MaxConcurrency: 4, QueueSize: 8},
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	if len(res.Additions.URLs) != 2 {
		t.Fatalf("URLs = %d, want 2", len(res.Additions.URLs))
	}
	got := []string{res.Additions.URLs[0].String(), res.Additions.URLs[1].String()}
	// Deterministic sorted order enforced by crawl engine; adapt preserves it.
	if !(contains(got, "https://example.com/api/a") && contains(got, "https://example.com/api/b")) {
		t.Errorf("URLs = %v, want both a and b", got)
	}
	if len(res.Results.IPs) != 0 || len(res.Documents) != 0 {
		t.Errorf("crawl should only produce Additions.URLs, got Results %+v Documents %d", res.Results, len(res.Documents))
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestCrawlStagePipelineIntegration(t *testing.T) {
	src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
		return crawl.Result{
			URLs: []asset.URL{mustURLCrawl(t, "https://example.com/crawl1"), mustURLCrawl(t, "https://example.com/crawl2")},
		}, nil
	}}
	seed := &t3dFakeStage{name: pipeline.StageDiscover, res: pipeline.StageResult{
		Outcome: pipeline.OutcomeCompleted,
		Additions: pipeline.StageAdditions{
			Hosts: []asset.Host{mustHostCrawl(t, "www.example.com")},
		},
	}}
	crawlSt := NewCrawlStage(src)
	cfg := pipeline.ScanConfig{
		Target: mustDomainCrawl(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDiscover, pipeline.StageCrawl},
	}
	clk := fixedClock{now: fixedTime}
	rep, err := pipeline.Run(context.Background(), cfg, nil, clk, []pipeline.Stage{seed, crawlSt})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.URLs) != 2 {
		t.Fatalf("RunReport.URLs = %d, want 2 crawl URLs", len(rep.URLs))
	}
	if rep.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", rep.Outcome)
	}
	// Deterministic DeepEqual second run.
	rep2, err := pipeline.Run(context.Background(), cfg, nil, clk, []pipeline.Stage{seed, NewCrawlStage(src)})
	if err != nil {
		t.Fatalf("Run2: %v", err)
	}
	if !reflect.DeepEqual(rep.URLs, rep2.URLs) {
		t.Fatalf("deterministic URLs differ: %v vs %v", rep.URLs, rep2.URLs)
	}
}

func TestCrawlStageTruncationFlag(t *testing.T) {
	// Generate many URLs to exceed MaxTotalURLs via fake source.
	var many []asset.URL
	for i := 0; i < 5; i++ {
		many = append(many, mustURLCrawl(t, "https://example.com/api/"+itoaCrawl(i)))
	}
	src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
		// Simulate crawl engine truncated output.
		return crawl.Result{URLs: many, Truncated: true}, nil
	}}
	st := NewCrawlStage(src)
	in := pipeline.StageInput{
		Target: mustDomainCrawl(t, "example.com"),
		Hosts:  []asset.Host{mustHostCrawl(t, "www.example.com")},
		Bounds: pipeline.StageConfig{MaxOutput: 100000},
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Truncated {
		t.Errorf("Truncated = false, want true")
	}
	if !res.StickyFlags["crawl_truncated"] {
		t.Errorf("StickyFlags = %v, want crawl_truncated", res.StickyFlags)
	}
}

func TestCrawlStageScopeFilter(t *testing.T) {
	src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
		return crawl.Result{
			URLs: []asset.URL{
				mustURLCrawl(t, "https://example.com/in"),
				mustURLCrawl(t, "https://evil.com/out"),
				mustURLCrawl(t, "https://192.168.1.1/ip"),
			},
		}, nil
	}}
	st := NewCrawlStage(src)
	in := pipeline.StageInput{
		Target: mustDomainCrawl(t, "example.com"),
		Hosts:  []asset.Host{mustHostCrawl(t, "www.example.com")},
		Bounds: pipeline.StageConfig{MaxOutput: 100000},
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Additions.URLs) != 1 || res.Additions.URLs[0].String() != "https://example.com/in" {
		t.Errorf("URLs = %v, want only in-domain", res.Additions.URLs)
	}
}

func itoaCrawl(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

func TestCrawlStageNoHostsShortCircuit(t *testing.T) {
	called := false
	src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
		called = true
		return crawl.Result{}, nil
	}}
	st := NewCrawlStage(src)
	in := pipeline.StageInput{
		Target: mustDomainCrawl(t, "example.com"),
		Hosts:  nil,
		URLs:   nil,
		Bounds: pipeline.StageConfig{MaxOutput: 100000},
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if called {
		t.Errorf("source should not be called when no hosts")
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", res.Outcome)
	}
}
