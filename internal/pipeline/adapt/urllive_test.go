package adapt

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

func mustDomainUrllive(t testing.TB, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain %q: %v", name, err)
	}
	return d
}
func mustURLUrllive(t testing.TB, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL %q: %v", raw, err)
	}
	return u
}

// urlLiveTransport is a hermetic transport for urllive stage tests.
type urlLiveTransport struct {
	mu    sync.Mutex
	byURL map[string]int // URL string -> status
	count int
}

func (t *urlLiveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.count++
	t.mu.Unlock()
	status := 200
	if s, ok := t.byURL[req.URL.String()]; ok {
		status = s
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func TestUrlliveStageName(t *testing.T) {
	if got := NewUrlliveStage(nil).Name(); got != pipeline.StageURLLive {
		t.Fatalf("Name = %q, want urllive", got)
	}
}

func TestUrlliveStageAddsLiveRecords(t *testing.T) {
	tr := &urlLiveTransport{byURL: map[string]int{
		"http://example.com/a": 200,
		"http://example.com/b": 404,
		"http://example.com/c": 500,
	}}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs: []asset.URL{
			mustURLUrllive(t, "http://example.com/a"),
			mustURLUrllive(t, "http://example.com/b"),
			mustURLUrllive(t, "http://example.com/c"),
		},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	if len(res.Results.LiveRecords) != 3 {
		t.Fatalf("LiveRecords = %d, want 3", len(res.Results.LiveRecords))
	}
	// Deterministic sorted order
	want := []string{"http://example.com/a", "http://example.com/b", "http://example.com/c"}
	for i, r := range res.Results.LiveRecords {
		if r.URL.String() != want[i] {
			t.Errorf("LiveRecords[%d] = %s, want %s", i, r.URL.String(), want[i])
		}
	}
	if tr.count != 3 {
		t.Fatalf("requests = %d, want 3", tr.count)
	}
}

func TestUrlliveStagePipelineIntegration(t *testing.T) {
	tr := &urlLiveTransport{byURL: map[string]int{
		"http://example.com/a": 200,
		"http://example.com/b": 200,
	}}
	seed := &t3dFakeStage{name: pipeline.StageDiscover, res: pipeline.StageResult{
		Outcome: pipeline.OutcomeCompleted,
		Additions: pipeline.StageAdditions{
			URLs: []asset.URL{mustURLUrllive(t, "http://example.com/a"), mustURLUrllive(t, "http://example.com/b")},
		},
	}}
	urlliveSt := NewUrlliveStage(tr)
	cfg := pipeline.ScanConfig{
		Target: mustDomainUrllive(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDiscover, pipeline.StageURLLive},
	}
	clk := fixedClock{now: fixedTime}
	rep, err := pipeline.Run(context.Background(), cfg, nil, clk, []pipeline.Stage{seed, urlliveSt})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Results.LiveRecords) != 2 {
		t.Fatalf("RunReport LiveRecords = %d, want 2", len(rep.Results.LiveRecords))
	}
	if rep.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", rep.Outcome)
	}
	// Deterministic second run
	rep2, err := pipeline.Run(context.Background(), cfg, nil, clk, []pipeline.Stage{seed, NewUrlliveStage(tr)})
	if err != nil {
		t.Fatalf("Run2: %v", err)
	}
	if !reflect.DeepEqual(rep.Results.LiveRecords, rep2.Results.LiveRecords) {
		t.Fatalf("deterministic live records differ")
	}
}

func TestUrlliveStageEmptyInputShortCircuit(t *testing.T) {
	called := false
	tr := &countingRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
	}}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   nil,
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if called {
		t.Error("transport should not be called for empty input")
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed", res.Outcome)
	}
	if len(res.Results.LiveRecords) != 0 {
		t.Errorf("LiveRecords = %d, want 0", len(res.Results.LiveRecords))
	}
}

type countingRoundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (c *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.fn(req)
}

func TestUrlliveStageTruncationFlag(t *testing.T) {
	// Header overflow via many headers
	tr := &headerOverflowTransport{}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/trunc")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true")
	}
	if !res.StickyFlags[UrlliveStickyFlag] {
		t.Errorf("StickyFlags = %v, want %s", res.StickyFlags, UrlliveStickyFlag)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Errorf("Outcome = %q, want completed (truncated is a completed-with-flag carve-out per AGENTS §0.6)", res.Outcome)
	}
}

type headerOverflowTransport struct{}

func (t *headerOverflowTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h := make(http.Header)
	for i := 0; i < 130; i++ {
		h.Set("X-Test-"+pad3urllive(i), "v")
	}
	return &http.Response{StatusCode: 200, Header: h, Body: http.NoBody, Request: req}, nil
}

func pad3urllive(i int) string {
	return string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}

func TestUrlliveStageNilContext(t *testing.T) {
	st := NewUrlliveStage(nil)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/a")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	_, err := st.Run(nil, in)
	if err == nil {
		t.Fatal("want error for nil context")
	}
}

func TestUrlliveStageNonCanonicalTarget(t *testing.T) {
	tr := &urlLiveTransport{}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: asset.Domain{Name: "Example.com"},
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/a")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err == nil {
		t.Fatal("want error for non-canonical target")
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want failed", res.Outcome)
	}
}

func TestUrlliveStageCacheHit(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir, cache.WithClock(fixedClock{now: fixedTime}.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	tr := &urlLiveTransport{byURL: map[string]int{"http://example.com/a": 200}}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/a")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
		Cache:  c,
	}
	res1, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if len(res1.Results.LiveRecords) != 1 || res1.Results.LiveRecords[0].Status != 200 {
		t.Fatalf("first run status = %d, want 200", res1.Results.LiveRecords[0].Status)
	}
	if tr.count != 1 {
		t.Fatalf("first requests = %d, want 1", tr.count)
	}
	// Second run with failing transport — cache should serve without calling transport
	tr2Fail := &failingTransport{err: errorf("should not be called")}
	st2 := NewUrlliveStage(tr2Fail)
	in2 := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/a")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
		Cache:  c,
	}
	res2, err := st2.Run(context.Background(), in2)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if len(res2.Results.LiveRecords) != 1 || res2.Results.LiveRecords[0].Status != 200 {
		t.Fatalf("second run status = %d, want 200 (cache hit)", res2.Results.LiveRecords[0].Status)
	}
	if !reflect.DeepEqual(res1.Results.LiveRecords, res2.Results.LiveRecords) {
		t.Fatalf("cache hit records differ: %+v vs %+v", res1.Results.LiveRecords, res2.Results.LiveRecords)
	}
	_ = tr
}

type failingTransport struct{ err error }

func (t *failingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, t.err
}

func errorf(s string) error { return &fakeError{s} }

type fakeError struct{ s string }

func (e *fakeError) Error() string { return e.s }

func TestUrlliveStageCancellation(t *testing.T) {
	tr := &blockingTransport{block: make(chan struct{})}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/a")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := st.Run(ctx, in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("Outcome = %q, want cancelled", res.Outcome)
	}
}

type blockingTransport struct{ block chan struct{} }

func (t *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-t.block:
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
	}
}

func TestUrlliveStageOutOfDomainFiltered(t *testing.T) {
	tr := &urlLiveTransport{byURL: map[string]int{}}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs: []asset.URL{
			mustURLUrllive(t, "http://example.com/in"),
			mustURLUrllive(t, "http://evil.com/out"),
		},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Results.LiveRecords) != 1 || res.Results.LiveRecords[0].URL.String() != "http://example.com/in" {
		t.Fatalf("LiveRecords = %+v, want only in-domain", res.Results.LiveRecords)
	}
}

func TestUrlliveStageCacheBeforePipelineMerge(t *testing.T) {
	// Pipeline-level test: seed URLs, urllive produces 3, pipeline caps at 2
	dir := t.TempDir()
	_ = dir
	tr := &urlLiveTransport{byURL: map[string]int{
		"http://example.com/a": 200,
		"http://example.com/b": 200,
		"http://example.com/c": 200,
	}}
	seed := &t3dFakeStage{name: pipeline.StageDiscover, res: pipeline.StageResult{
		Outcome: pipeline.OutcomeCompleted,
		Additions: pipeline.StageAdditions{
			URLs: []asset.URL{
				mustURLUrllive(t, "http://example.com/a"),
				mustURLUrllive(t, "http://example.com/b"),
				mustURLUrllive(t, "http://example.com/c"),
			},
		},
	}}
	urlliveSt := NewUrlliveStage(tr)
	cfg := pipeline.ScanConfig{
		Target: mustDomainUrllive(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDiscover, pipeline.StageURLLive},
		StageBounds: map[pipeline.StageName]pipeline.StageConfig{
			pipeline.StageURLLive: {MaxOutput: 2},
		},
	}
	clk := fixedClock{now: fixedTime}
	rep, err := pipeline.Run(context.Background(), cfg, nil, clk, []pipeline.Stage{seed, urlliveSt})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Results.LiveRecords) != 2 {
		t.Fatalf("LiveRecords = %d, want 2 (capped)", len(rep.Results.LiveRecords))
	}
	if !rep.Truncated || !rep.StickyFlags["live_records_truncated"] {
		t.Fatalf("want live_records_truncated flag and Truncated, got %v %v", rep.Truncated, rep.StickyFlags)
	}
}
