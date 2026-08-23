package adapt

import (
	"context"
	"errors"
	"reflect"
	"strings"
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

// --- crawl-adapter honesty: failed hosts are never completed=len(hosts) ---

// TestCrawlStageAllHostsFailedReportsIncomplete pins the honesty contract:
// when the crawl ENGINE signals that every host's katana invocation failed
// (Result.FailedHosts = len(hosts), e.g. katana missing from PATH), the
// stage must report incomplete with honest counters, never
// completed=len(hosts). The signal is explicit engine data (NEW-85) — the
// stage never infers failure from diagnostics presence.
func TestCrawlStageAllHostsFailedReportsIncomplete(t *testing.T) {
	src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
		return crawl.Result{
			Diagnostics: []string{"katana not found: exec: \"katana\": executable file not found in $PATH"},
			FailedHosts: 2,
		}, nil
	}}
	st := NewCrawlStage(src)
	in := pipeline.StageInput{
		Target: mustDomainCrawl(t, "example.com"),
		Hosts:  []asset.Host{mustHostCrawl(t, "www.example.com"), mustHostCrawl(t, "api.example.com")},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeIncomplete {
		t.Fatalf("Outcome = %q, want incomplete when every host's crawl failed", res.Outcome)
	}
	if res.ItemsProcessed != 0 || res.ItemsFailed != 2 {
		t.Fatalf("ItemsProcessed/ItemsFailed = %d/%d, want 0/2", res.ItemsProcessed, res.ItemsFailed)
	}
}

// TestCrawlStageLinklessSuccessWithBenignDiagnosticStaysCompleted pins
// NEW-85: a genuinely linkless success that emitted only a benign diagnostic
// (e.g. skipped malformed lines) carries FailedHosts=0 from the engine and
// must report completed with ItemsFailed=0 — diagnostics presence alone is
// never read as failure.
func TestCrawlStageLinklessSuccessWithBenignDiagnosticStaysCompleted(t *testing.T) {
	src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
		return crawl.Result{Diagnostics: []string{"malformed lines: 3"}}, nil
	}}
	st := NewCrawlStage(src)
	in := pipeline.StageInput{
		Target: mustDomainCrawl(t, "example.com"),
		Hosts:  []asset.Host{mustHostCrawl(t, "www.example.com")},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed for a linkless success with a benign diagnostic", res.Outcome)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 0 {
		t.Fatalf("ItemsProcessed/ItemsFailed = %d/%d, want 1/0", res.ItemsProcessed, res.ItemsFailed)
	}
}

// TestCrawlStageFailedHostsReportsPartial pins the FailedHosts contract's
// mixed case: some hosts crawled (URLs exist), some failed outright — the
// stage reports partial with honest counters.
func TestCrawlStageFailedHostsReportsPartial(t *testing.T) {
	src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
		return crawl.Result{
			URLs:        []asset.URL{mustURLCrawl(t, "https://example.com/a")},
			FailedHosts: 1,
		}, nil
	}}
	st := NewCrawlStage(src)
	in := pipeline.StageInput{
		Target: mustDomainCrawl(t, "example.com"),
		Hosts:  []asset.Host{mustHostCrawl(t, "www.example.com"), mustHostCrawl(t, "api.example.com")},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("Outcome = %q, want partial when a host failed but URLs were crawled", res.Outcome)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 1 {
		t.Fatalf("ItemsProcessed/ItemsFailed = %d/%d, want 1/1", res.ItemsProcessed, res.ItemsFailed)
	}
}

// TestCrawlStageLegitimateEmptyAndDiagnosticsStayCompleted guards the
// contract's other side: a genuinely linkless host (zero URLs, zero
// diagnostics) stays completed, and diagnostics beside real URLs do not
// downgrade the outcome.
func TestCrawlStageLegitimateEmptyAndDiagnosticsStayCompleted(t *testing.T) {
	t.Run("legitimately empty crawl", func(t *testing.T) {
		src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
			return crawl.Result{}, nil
		}}
		st := NewCrawlStage(src)
		in := pipeline.StageInput{
			Target: mustDomainCrawl(t, "example.com"),
			Hosts:  []asset.Host{mustHostCrawl(t, "www.example.com")},
		}
		res, err := st.Run(context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted || res.ItemsProcessed != 1 {
			t.Fatalf("Outcome/ItemsProcessed = %q/%d, want completed/1 for an empty-but-successful crawl", res.Outcome, res.ItemsProcessed)
		}
	})
	t.Run("diagnostics beside URLs keep completed", func(t *testing.T) {
		src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
			return crawl.Result{
				URLs:        []asset.URL{mustURLCrawl(t, "https://example.com/a")},
				Diagnostics: []string{"host api.example.com exited 1"},
			}, nil
		}}
		st := NewCrawlStage(src)
		in := pipeline.StageInput{
			Target: mustDomainCrawl(t, "example.com"),
			Hosts:  []asset.Host{mustHostCrawl(t, "www.example.com")},
		}
		res, err := st.Run(context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = %q, want completed when URLs were produced", res.Outcome)
		}
		if res.ItemsProcessed != 1 || res.ItemsFailed != 0 {
			t.Fatalf("ItemsProcessed/ItemsFailed = %d/%d, want 1/0", res.ItemsProcessed, res.ItemsFailed)
		}
	})
}

// TestCrawlStageCancelledKeepsJoinedErrorAndPartialURLs is the NEW-73
// regression: when the engine returns BOTH partial URLs and an error while
// the stage context is cancelled, the adapter must not collapse to a bare
// ctx.Err() — the joined engine detail stays attached to the cancelled
// result AND the in-scope captured URLs are retained as additions (the
// runner merges additions regardless of outcome, so a mid-crawl
// cancellation never silently discards what was already crawled).
func TestCrawlStageCancelledKeepsJoinedErrorAndPartialURLs(t *testing.T) {
	src := &fakeCrawlSource{fn: func(ctx context.Context, domain asset.Domain, hosts []asset.Host, cfg crawl.Config) (crawl.Result, error) {
		urls := []asset.URL{mustURLCrawl(t, "https://example.com/partial")}
		return crawl.Result{URLs: urls},
			errors.Join(context.Canceled, errors.New("katana host scan aborted"))
	}}
	st := NewCrawlStage(src)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the stage context is already fired when Run begins
	in := pipeline.StageInput{
		Target: mustDomainCrawl(t, "example.com"),
		Hosts:  []asset.Host{mustHostCrawl(t, "www.example.com")},
		Bounds: pipeline.StageConfig{MaxOutput: 100000},
		Clock:  fixedClock{now: fixedTime},
	}
	res, runErr := st.Run(ctx, in)
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("Outcome = %q, want cancelled", res.Outcome)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("Err = %v, want a wrapped context.Canceled", res.Err)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "katana host scan aborted") {
		t.Fatalf("Err = %v, want the engine's joined detail retained alongside the cancellation", res.Err)
	}
	if runErr == nil || !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Run error = %v, want the joined cancellation error returned", runErr)
	}
	if len(res.Additions.URLs) != 1 || res.Additions.URLs[0].String() != "https://example.com/partial" {
		t.Fatalf("Additions.URLs = %v, want the partially captured in-scope URL retained on the cancelled result", res.Additions.URLs)
	}
}
