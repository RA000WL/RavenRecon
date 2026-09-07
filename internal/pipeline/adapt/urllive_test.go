package adapt

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/triage"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
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
	// A cut-short triage must be marked truncated (AGENTS §0.6): the
	// retained records are an incomplete set.
	if !res.Truncated {
		t.Fatal("Truncated = false, want true for a cancelled triage")
	}
	if !res.StickyFlags[UrlliveStickyFlag] {
		t.Fatalf("StickyFlags = %v, want %q set", res.StickyFlags, UrlliveStickyFlag)
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

// echoLiveTransport answers every request by echoing decoded query values
// into the body (reflected-unencoded) unless staticBody is set, in which
// case it serves the static page (not-reflected). It records request URLs.
type echoLiveTransport struct {
	mu         sync.Mutex
	requests   []string
	staticBody *string
}

func (t *echoLiveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requests = append(t.requests, req.URL.String())
	t.mu.Unlock()
	body := ""
	if t.staticBody != nil {
		body = *t.staticBody
	} else {
		q, _ := url.ParseQuery(req.URL.RawQuery)
		var vals []string
		for _, vs := range q {
			vals = append(vals, vs...)
		}
		body = "<html>" + strings.Join(vals, "|") + "</html>"
	}
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func (t *echoLiveTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.requests)
}

// reflectEvidenceIndex indexes reflection evidence by source URL identity
// string → param → verdict value.
func reflectEvidenceIndex(t testing.TB, evs []asset.Evidence) map[string]map[string]string {
	t.Helper()
	out := make(map[string]map[string]string)
	for _, ev := range evs {
		param, verdict, ok := httpprobe.ParseReflectEvidence(ev)
		if !ok {
			t.Fatalf("non-reflection evidence in urllive reflection output: %+v", ev)
		}
		src := ev.Source.String()
		if out[src] == nil {
			out[src] = make(map[string]string)
		}
		out[src][param] = string(verdict)
	}
	return out
}

func TestUrlliveStageReflectsParams(t *testing.T) {
	tr := &echoLiveTransport{}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs: []asset.URL{
			mustURLUrllive(t, "http://example.com/search?q=term&page=2"),
			mustURLUrllive(t, "http://example.com/about"),
		},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (reflection is additive)", res.Outcome)
	}
	if len(res.Results.LiveRecords) != 2 {
		t.Fatalf("LiveRecords = %d, want 2 (liveness untouched)", len(res.Results.LiveRecords))
	}
	idx := reflectEvidenceIndex(t, res.Results.Evidence)
	got, ok := idx["url:http://example.com/search?page=2&q=term"]
	if !ok {
		t.Fatalf("no reflection evidence for the parameterized URL: %v", idx)
	}
	for _, p := range []string{"q", "page"} {
		if got[p] != string(httpprobe.ReflectUnencoded) {
			t.Errorf("param %q verdict = %q, want reflected-unencoded", p, got[p])
		}
	}
	if _, ok := idx["url:http://example.com/about"]; ok {
		t.Errorf("param-less URL must produce no reflection evidence: %v", idx)
	}
	// One liveness GET per URL plus one reflection GET for the single
	// parameterized URL.
	if tr.count() != 3 {
		t.Errorf("requests = %d, want 3 (2 live + 1 reflection)", tr.count())
	}
}

func TestUrlliveStageReflectionSilentEndpoint(t *testing.T) {
	static := "<html><body>static, no echo</body></html>"
	tr := &echoLiveTransport{staticBody: &static}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/search?q=term")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	idx := reflectEvidenceIndex(t, res.Results.Evidence)
	got := idx["url:http://example.com/search?q=term"]
	if got["q"] != string(httpprobe.ReflectAbsent) {
		t.Errorf("param q verdict = %q, want not-reflected (triage needs it to drop)", got["q"])
	}
}

func TestUrlliveStageReflectionDisabled(t *testing.T) {
	tr := &echoLiveTransport{}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/search?q=term")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
		Config: map[string]string{"urllive_reflection": "false"},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Results.Evidence) != 0 {
		t.Fatalf("Evidence = %d, want 0 (reflection disabled)", len(res.Results.Evidence))
	}
	if len(res.Results.LiveRecords) != 1 {
		t.Fatalf("LiveRecords = %d, want 1 (liveness intact)", len(res.Results.LiveRecords))
	}
	if tr.count() != 1 {
		t.Errorf("requests = %d, want 1 (liveness only)", tr.count())
	}
}

func TestUrlliveStageReflectionOverflowFlag(t *testing.T) {
	tr := &echoLiveTransport{}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs: []asset.URL{
			mustURLUrllive(t, "http://example.com/a?x=1"),
			mustURLUrllive(t, "http://example.com/b?x=1"),
			mustURLUrllive(t, "http://example.com/c?x=1"),
		},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
		Config: map[string]string{"urllive_reflect_max_urls": "2"},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (overflow rides the flag, not the outcome)", res.Outcome)
	}
	if !res.StickyFlags[UrlliveReflectOverflowFlag] {
		t.Fatalf("flags = %v, want %q (the cut tail is honestly flagged)", res.StickyFlags, UrlliveReflectOverflowFlag)
	}
	if !res.Truncated {
		t.Fatalf("Truncated = false, want true alongside %q (§0.6: the flag never rides alone)", UrlliveReflectOverflowFlag)
	}
	idx := reflectEvidenceIndex(t, res.Results.Evidence)
	if len(idx) != 2 {
		t.Fatalf("reflected URLs = %d, want 2 (sorted head)", len(idx))
	}
	if _, ok := idx["url:http://example.com/a?x=1"]; !ok {
		t.Errorf("sorted-head cut must keep /a: %v", idx)
	}
	if _, ok := idx["url:http://example.com/b?x=1"]; !ok {
		t.Errorf("sorted-head cut must keep /b: %v", idx)
	}
}

func TestUrlliveStageReflectionSkipsDeadCorpus(t *testing.T) {
	// Dead parameterized URLs (liveness transport failure) are never
	// reflected: only the liveness requests run, zero reflection
	// requests, zero evidence, liveness intact.
	deadTr := &failLiveTransport{}
	st := NewUrlliveStage(deadTr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs: []asset.URL{
			mustURLUrllive(t, "http://example.com/a?x=1"),
			mustURLUrllive(t, "http://example.com/b?x=1"),
		},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Liveness issued exactly 2 requests; any reflection request would
	// push the count past it (shared transport).
	if got := deadTr.count(); got != 2 {
		t.Fatalf("requests = %d, want 2 (liveness only, zero reflection on a dead corpus)", got)
	}
	if len(res.Results.Evidence) != 0 {
		t.Fatalf("evidence = %d, want 0 (dead corpus is never reflected)", len(res.Results.Evidence))
	}
	if len(res.Results.LiveRecords) != 2 {
		t.Fatalf("LiveRecords = %d, want 2 (liveness intact)", len(res.Results.LiveRecords))
	}
	if res.StickyFlags[UrlliveReflectOverflowFlag] || res.StickyFlags[UrlliveReflectTruncatedFlag] {
		t.Fatalf("flags = %v, want no reflection flags (reflection never ran)", res.StickyFlags)
	}
}

func TestUrlliveStageReflectionCached(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	urls := []asset.URL{mustURLUrllive(t, "http://example.com/search?q=term")}
	cold := NewUrlliveStage(&echoLiveTransport{})
	coldRes, err := cold.Run(context.Background(), pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   urls,
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
		Cache:  c,
	})
	if err != nil {
		t.Fatalf("cold Run: %v", err)
	}
	fail := &failLiveTransport{}
	warm := NewUrlliveStage(fail)
	warmRes, err := warm.Run(context.Background(), pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   urls,
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
		Cache:  c,
	})
	if err != nil {
		t.Fatalf("warm Run: %v", err)
	}
	if fail.count() != 0 {
		t.Fatalf("warm requests = %d, want 0 (live + reflection both cached)", fail.count())
	}
	if len(coldRes.Results.Evidence) != len(warmRes.Results.Evidence) {
		t.Fatalf("warm evidence = %d, cold = %d (must match)", len(warmRes.Results.Evidence), len(coldRes.Results.Evidence))
	}
	for i := range coldRes.Results.Evidence {
		if coldRes.Results.Evidence[i].Identity() != warmRes.Results.Evidence[i].Identity() {
			t.Fatalf("warm evidence[%d] = %s, cold = %s", i, warmRes.Results.Evidence[i].ID(), coldRes.Results.Evidence[i].ID())
		}
	}
}

// failLiveTransport fails every request (warm-run proof: any request is a
// cache miss).
type failLiveTransport struct {
	mu sync.Mutex
	n  int
}

func (t *failLiveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.n++
	t.mu.Unlock()
	return nil, errors.New("must not be called: cache hit expected")
}

func (t *failLiveTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

// TestUrlliveReflectionFeedsTriageGate is the NEW-120 end-to-end proof
// across the package seam: urllive reflection evidence flows through the
// results channel into a triage detect run, where a reflecting endpoint
// keeps its finding (with cited verdicts) and a silent endpoint loses
// it. It pins the evidence identity contract (URL-identity source) so
// format drift fails loudly instead of degrading silently to fail-open.
func TestUrlliveReflectionFeedsTriageGate(t *testing.T) {
	raw := "http://example.com/search?q=term"
	runGate := func(tr http.RoundTripper) []asset.Finding {
		t.Helper()
		st := NewUrlliveStage(tr)
		res, err := st.Run(context.Background(), pipeline.StageInput{
			Target: mustDomainUrllive(t, "example.com"),
			URLs:   []asset.URL{mustURLUrllive(t, raw)},
			Bounds: pipeline.DefaultStageConfig(),
			Clock:  fixedClock{now: fixedTime},
		})
		if err != nil {
			t.Fatalf("urllive Run: %v", err)
		}
		ep, err := asset.NewEndpoint("GET", raw, asset.Provenance{Source: "test"})
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		rules, err := triage.Rules()
		if err != nil {
			t.Fatalf("triage.Rules: %v", err)
		}
		reg := detect.NewRegistry()
		for _, r := range rules {
			if err := reg.Register(r); err != nil {
				t.Fatalf("Register: %v", err)
			}
		}
		if err := reg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		reg.Seal()
		cfg := detect.DefaultEngineConfig(reg)
		rep, err := detect.Run(context.Background(), cfg, detect.Snapshot{
			Endpoints: []asset.Endpoint{ep},
			Evidence:  res.Results.Evidence,
		})
		if err != nil {
			t.Fatalf("detect.Run: %v", err)
		}
		return rep.Findings
	}

	reflecting := runGate(&echoLiveTransport{})
	var kept *asset.Finding
	for i, f := range reflecting {
		if strings.HasPrefix(f.RuleID, "triage.") {
			kept = &reflecting[i]
			break
		}
	}
	if kept == nil {
		t.Fatalf("reflecting endpoint lost all triage findings: %+v", reflecting)
	}
	if !strings.Contains(kept.Metadata["reflection"], "q:reflected-unencoded") {
		t.Errorf("kept finding reflection meta = %q, want the cited verdict", kept.Metadata["reflection"])
	}

	static := "<html><body>static, no echo</body></html>"
	silent := runGate(&echoLiveTransport{staticBody: &static})
	for _, f := range silent {
		if strings.HasPrefix(f.RuleID, "triage.") {
			t.Fatalf("silent endpoint kept triage finding %s (must drop on not-reflected): %+v", f.RuleID, f)
		}
	}
}

// TestUrlliveStageReflectionTransportErrorFlag pins the review-wave
// honesty fix: a reflection record carrying a transport error (no
// verdicts reachable) marks the evidence set truncated — unknown
// verdicts are never silently completed.
func TestUrlliveStageReflectionTransportErrorFlag(t *testing.T) {
	tr := &echoLiveTransport{}
	// Fail exactly the canary-substituted requests (encoded ':' present
	// only after substitution); liveness requests pass through.
	failTr := &failOnCanaryTransport{inner: tr}
	st := NewUrlliveStage(failTr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/search?q=term")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.StickyFlags[UrlliveReflectTruncatedFlag] {
		t.Fatalf("flags = %v, want %q (errored reflection is an incomplete set)", res.StickyFlags, UrlliveReflectTruncatedFlag)
	}
	if !res.Truncated {
		t.Fatalf("Truncated = false, want true alongside %q (§0.6: the flag never rides alone)", UrlliveReflectTruncatedFlag)
	}
	if len(res.Results.Evidence) != 0 {
		t.Fatalf("evidence = %d, want 0 (errors yield no verdicts)", len(res.Results.Evidence))
	}
	if len(res.Results.LiveRecords) != 1 {
		t.Fatalf("LiveRecords = %d, want 1 (liveness intact)", len(res.Results.LiveRecords))
	}
}

// failOnCanaryTransport fails requests whose query carries a substituted
// canary (percent-encoded ':'), passing everything else through.
type failOnCanaryTransport struct {
	inner *echoLiveTransport
}

func (t *failOnCanaryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.RawQuery, "%3A") {
		return nil, errors.New("synthetic reflection transport failure")
	}
	return t.inner.RoundTrip(req)
}

// TestFoldUrlliveOutcomesTable is the M-9 / NEW-72 regression table: the
// fold implements the unified mapping (adapt/doc.go) — cancelled >
// failed-with-no-completions > all-completed > partial — so a mixed
// success/failure report folds to PARTIAL, never completed.
func TestFoldUrlliveOutcomesTable(t *testing.T) {
	ok := httpprobe.LiveRecord{URL: mustURLUrllive(t, "http://example.com/ok"), Status: 200}
	bad := httpprobe.LiveRecord{URL: mustURLUrllive(t, "http://example.com/bad"), Err: errors.New("connection refused")}
	cancelled := httpprobe.LiveRecord{URL: mustURLUrllive(t, "http://example.com/cx"), Err: context.Canceled}
	truncated := httpprobe.LiveRecord{URL: mustURLUrllive(t, "http://example.com/trunc"), Truncated: true}

	cases := []struct {
		name string
		recs []httpprobe.LiveRecord
		want pipeline.Outcome
	}{
		{"no records", nil, pipeline.OutcomeCompleted},
		{"all success", []httpprobe.LiveRecord{ok}, pipeline.OutcomeCompleted},
		{"all failed", []httpprobe.LiveRecord{bad}, pipeline.OutcomeFailed},
		{"mixed success and failure", []httpprobe.LiveRecord{ok, bad}, pipeline.OutcomePartial},
		{"cancelled only", []httpprobe.LiveRecord{cancelled}, pipeline.OutcomeCancelled},
		{"cancelled beats failure", []httpprobe.LiveRecord{cancelled, bad}, pipeline.OutcomeCancelled},
		{"truncated counts as completion", []httpprobe.LiveRecord{truncated}, pipeline.OutcomeCompleted},
		{"truncated plus failure is partial", []httpprobe.LiveRecord{truncated, bad}, pipeline.OutcomePartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := foldUrlliveOutcomes(httpprobe.LiveReport{Records: tc.recs})
			if got != tc.want {
				t.Fatalf("foldUrlliveOutcomes = %q, want %q", got, tc.want)
			}
		})
	}
}

// postUrlliveTransport distinguishes liveness GETs (no canary in the
// query) from reflection GETs (substituted canary carries ':'), and
// records every POST with its content type and body. liveCT is served on
// liveness responses; getMode/postMode ("echo"/"encode"/"silent") drive
// reflection answers over the decoded values. Reflection answers serve
// text/html, pinning that the probes ignore response Content-Types.
type postUrlliveTransport struct {
	mu       sync.Mutex
	total    int
	posts    int
	postCTs  []string
	liveCT   string
	getMode  string
	postMode string
	bigPost  bool
}

func (t *postUrlliveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.total++
	isPost := req.Method == http.MethodPost
	if isPost {
		t.posts++
		t.postCTs = append(t.postCTs, req.Header.Get("Content-Type"))
	}
	t.mu.Unlock()
	if isPost {
		data, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if t.bigPost {
			return postHTMLResponse(t.liveCTOfReflection(), strings.Repeat("z", 128<<10+1024)), nil
		}
		return t.answerMode(t.postMode, postBodyValues(req.Header.Get("Content-Type"), string(data))), nil
	}
	if strings.Contains(req.URL.RawQuery, "%3A") {
		q, _ := url.ParseQuery(req.URL.RawQuery)
		var vals []string
		for _, vs := range q {
			vals = append(vals, vs...)
		}
		return t.answerMode(t.getMode, vals), nil
	}
	return postHTMLResponse(t.liveCT, "<html><body>liveness static</body></html>"), nil
}

func (t *postUrlliveTransport) liveCTOfReflection() string { return "text/html" }

func postHTMLResponse(ct, body string) *http.Response {
	if ct == "" {
		ct = "text/html"
	}
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{ct}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func (t *postUrlliveTransport) answerMode(mode string, vals []string) *http.Response {
	switch mode {
	case "echo":
		return postHTMLResponse("", "<html>"+strings.Join(vals, "|")+"</html>")
	case "encode":
		enc := make([]string, 0, len(vals))
		for _, v := range vals {
			enc = append(enc, url.QueryEscape(v))
		}
		return postHTMLResponse("", "<html>"+strings.Join(enc, "|")+"</html>")
	default:
		return postHTMLResponse("", "<html>static, no echo</html>")
	}
}

// postBodyValues decodes a POST body per its content type into values.
func postBodyValues(ct, body string) []string {
	if strings.HasPrefix(ct, "application/json") {
		var m map[string]string
		if err := json.Unmarshal([]byte(body), &m); err == nil {
			var vals []string
			for _, v := range m {
				vals = append(vals, v)
			}
			return vals
		}
		return nil
	}
	q, err := url.ParseQuery(body)
	if err != nil {
		return nil
	}
	var vals []string
	for _, vs := range q {
		vals = append(vals, vs...)
	}
	return vals
}

func (t *postUrlliveTransport) counts() (total, posts int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total, t.posts
}

// postEvidenceByScope indexes stage evidence by source URL identity,
// asserting every record carries a queryable reflection scope.
func postEvidenceByScope(t testing.TB, evs []asset.Evidence) map[string]map[string]string {
	t.Helper()
	out := make(map[string]map[string]string)
	for _, ev := range evs {
		scope, ok := httpprobe.ReflectEvidenceScope(ev)
		if !ok {
			t.Fatalf("evidence without a reflection scope in POST output: %+v", ev)
		}
		param, verdict, ok := httpprobe.ParseReflectEvidence(ev)
		if ok {
			if scope != httpprobe.ReflectScopeQueryGET {
				t.Fatalf("GET-shaped evidence carries scope %q: %+v", scope, ev)
			}
			m := out[ev.Source.String()]
			if m == nil {
				m = make(map[string]string)
				out[ev.Source.String()] = m
			}
			m["get:"+param] = string(verdict)
			continue
		}
		param = postEvidenceParam(t, ev, scope)
		m := out[ev.Source.String()]
		if m == nil {
			m = make(map[string]string)
			out[ev.Source.String()] = m
		}
		m[string(scope)+":"+param] = ev.Value
	}
	return out
}

func postEvidenceParam(t testing.TB, ev asset.Evidence, scope httpprobe.ReflectScope) string {
	t.Helper()
	var prefix string
	switch scope {
	case httpprobe.ReflectScopePostForm:
		prefix = httpprobe.ReflectPostFormIndicatorPrefix
	case httpprobe.ReflectScopePostJSON:
		prefix = httpprobe.ReflectPostJSONIndicatorPrefix
	default:
		t.Fatalf("unexpected scope %q for %+v", scope, ev)
	}
	param, ok := strings.CutPrefix(ev.Indicator, prefix)
	if !ok || param == "" {
		t.Fatalf("POST evidence indicator %q lacks its scope prefix", ev.Indicator)
	}
	return param
}

// TestUrlliveStageReflectsPostForm is the GET-clean + POST-reflected pair:
// one URL, GET-silent, POST-echoing — both verdicts present with distinct
// scopes, and exactly one POST issued as form-urlencoded.
func TestUrlliveStageReflectsPostForm(t *testing.T) {
	tr := &postUrlliveTransport{liveCT: "application/x-www-form-urlencoded", getMode: "silent", postMode: "echo"}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/search?q=term&page=2")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (POST reflection is additive)", res.Outcome)
	}
	idx := postEvidenceByScope(t, res.Results.Evidence)
	got, ok := idx["url:http://example.com/search?page=2&q=term"]
	if !ok {
		t.Fatalf("no reflection evidence for the parameterized URL: %v", idx)
	}
	// GET-clean: both params verdict not-reflected under query-get-only.
	for _, p := range []string{"q", "page"} {
		if got["get:"+p] != string(httpprobe.ReflectAbsent) {
			t.Errorf("GET param %q = %q, want not-reflected", p, got["get:"+p])
		}
		if got["post-form:"+p] != string(httpprobe.ReflectUnencoded) {
			t.Errorf("POST param %q = %q, want reflected-unencoded", p, got["post-form:"+p])
		}
	}
	total, posts := tr.counts()
	if total != 3 {
		t.Errorf("requests = %d, want 3 (1 live + 1 GET reflection + 1 POST)", total)
	}
	if posts != 1 {
		t.Errorf("POST requests = %d, want exactly 1", posts)
	}
	tr.mu.Lock()
	ct := ""
	if len(tr.postCTs) == 1 {
		ct = tr.postCTs[0]
	}
	tr.mu.Unlock()
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("POST Content-Type = %q, want the form type", ct)
	}
}

// TestUrlliveStageReflectsPostJSON pins JSON discovery through a
// parameterized content type with mixed case: the POST mirrors the
// advertised type and verdicts carry post-json scope.
func TestUrlliveStageReflectsPostJSON(t *testing.T) {
	tr := &postUrlliveTransport{liveCT: "Application/JSON; charset=UTF-8", getMode: "silent", postMode: "echo"}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/api?q=term")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	idx := postEvidenceByScope(t, res.Results.Evidence)
	got, ok := idx["url:http://example.com/api?q=term"]
	if !ok {
		t.Fatalf("no reflection evidence: %v", idx)
	}
	if got["post-json:q"] != string(httpprobe.ReflectUnencoded) {
		t.Errorf("POST param q = %q, want reflected-unencoded", got["post-json:q"])
	}
	total, posts := tr.counts()
	if total != 3 || posts != 1 {
		t.Errorf("requests = %d/%d POST, want 3/1", total, posts)
	}
	tr.mu.Lock()
	ct := ""
	if len(tr.postCTs) == 1 {
		ct = tr.postCTs[0]
	}
	tr.mu.Unlock()
	if ct != "application/json" {
		t.Errorf("POST Content-Type = %q, want the JSON type", ct)
	}
}

// TestUrlliveStagePostDiscoverySkipsNonBody pins the discovery rule: an
// endpoint answering text/html gets no POST probe even though a POST
// would reflect — zero POST requests, GET verdicts untouched.
func TestUrlliveStagePostDiscoverySkipsNonBody(t *testing.T) {
	tr := &postUrlliveTransport{liveCT: "text/html", getMode: "echo", postMode: "echo"}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/search?q=term")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	total, posts := tr.counts()
	if posts != 0 {
		t.Fatalf("POST requests = %d, want 0 (text/html advertises no body acceptance)", posts)
	}
	if total != 2 {
		t.Fatalf("requests = %d, want 2 (liveness + GET reflection only)", total)
	}
	for _, ev := range res.Results.Evidence {
		if scope, ok := httpprobe.ReflectEvidenceScope(ev); ok && scope != httpprobe.ReflectScopeQueryGET {
			t.Fatalf("non-GET evidence on a text/html endpoint: %+v", ev)
		}
	}
	idx := reflectEvidenceIndex(t, res.Results.Evidence)
	if idx["url:http://example.com/search?q=term"]["q"] != string(httpprobe.ReflectUnencoded) {
		t.Errorf("GET verdict missing or wrong: %v", idx)
	}
}

// TestReflectPostKindTable pins the discovery rule mapping unit by unit,
// including the deliberate non-matches (multipart is not re-sent as a
// urlencoded form; HTML/text never probe).
func TestReflectPostKindTable(t *testing.T) {
	cases := []struct {
		ct    string
		scope httpprobe.ReflectScope
		ok    bool
	}{
		{"application/x-www-form-urlencoded", httpprobe.ReflectScopePostForm, true},
		{"application/x-www-form-urlencoded; charset=UTF-8", httpprobe.ReflectScopePostForm, true},
		{"Application/X-Www-Form-Urlencoded", httpprobe.ReflectScopePostForm, true},
		{"application/json", httpprobe.ReflectScopePostJSON, true},
		{"Application/JSON; charset=utf-8", httpprobe.ReflectScopePostJSON, true},
		{"application/hal+json", httpprobe.ReflectScopePostJSON, true},
		{"application/problem+json; charset=utf-8", httpprobe.ReflectScopePostJSON, true},
		{"text/html", "", false},
		{"text/html; charset=utf-8", "", false},
		{"text/plain", "", false},
		{"multipart/form-data; boundary=xyz", "", false},
		{"", "", false},
		{"not a type", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.ct, func(t *testing.T) {
			scope, ok := reflectPostKind(tc.ct)
			if ok != tc.ok || scope != tc.scope {
				t.Fatalf("reflectPostKind(%q) = %q/%v, want %q/%v", tc.ct, scope, ok, tc.scope, tc.ok)
			}
		})
	}
}

// TestUrlliveStagePostBudgetGetFirst pins the split policy: the budget
// selects URLs for GET exactly as before POST; POST probes only ride
// already-selected URLs, so the second URL gets neither GET nor POST
// evidence while overflow is flagged.
func TestUrlliveStagePostBudgetGetFirst(t *testing.T) {
	tr := &postUrlliveTransport{liveCT: "application/x-www-form-urlencoded", getMode: "echo", postMode: "echo"}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs: []asset.URL{
			mustURLUrllive(t, "http://example.com/a?x=1"),
			mustURLUrllive(t, "http://example.com/b?x=1"),
		},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
		Config: map[string]string{"urllive_reflect_max_urls": "1"},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.StickyFlags[UrlliveReflectOverflowFlag] {
		t.Fatalf("flags = %v, want %q", res.StickyFlags, UrlliveReflectOverflowFlag)
	}
	idx := postEvidenceByScope(t, res.Results.Evidence)
	a, ok := idx["url:http://example.com/a?x=1"]
	if !ok {
		t.Fatalf("budgeted URL /a has no evidence: %v", idx)
	}
	if a["get:x"] != string(httpprobe.ReflectUnencoded) || a["post-form:x"] != string(httpprobe.ReflectUnencoded) {
		t.Errorf("/a verdicts = %v, want GET+POST unencoded", a)
	}
	if _, ok := idx["url:http://example.com/b?x=1"]; ok {
		t.Errorf("cut URL /b has evidence (POST must never widen the GET head): %v", idx)
	}
	_, posts := tr.counts()
	if posts != 1 {
		t.Errorf("POST requests = %d, want 1 (only the budgeted URL)", posts)
	}
}

// TestUrlliveStagePostTruncatedFlag pins POST truncation honesty: an
// over-cap POST body marks the evidence set truncated while GET verdicts
// and liveness stand.
func TestUrlliveStagePostTruncatedFlag(t *testing.T) {
	tr := &postUrlliveTransport{liveCT: "application/x-www-form-urlencoded", getMode: "echo", postMode: "echo", bigPost: true}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/search?q=term")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (truncation rides the flag, not the outcome)", res.Outcome)
	}
	if !res.StickyFlags[UrlliveReflectTruncatedFlag] {
		t.Fatalf("flags = %v, want %q (POST body-cap hit is an incomplete set)", res.StickyFlags, UrlliveReflectTruncatedFlag)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true alongside the flag (§0.6: the flag never rides alone)")
	}
	idx := postEvidenceByScope(t, res.Results.Evidence)
	got := idx["url:http://example.com/search?q=term"]
	if got["get:q"] != string(httpprobe.ReflectUnencoded) {
		t.Errorf("GET verdict = %q, want unencoded (GET stands through POST truncation)", got["get:q"])
	}
	if _, ok := got["post-form:q"]; ok {
		t.Errorf("POST verdict present despite truncation (unknown carries no evidence): %v", got)
	}
	if len(res.Results.LiveRecords) != 1 {
		t.Fatalf("LiveRecords = %d, want 1 (liveness intact)", len(res.Results.LiveRecords))
	}
}

// TestUrlliveStagePostReflectionDisabled pins that disabling reflection
// disables POST too: liveness only, zero POST requests.
func TestUrlliveStagePostReflectionDisabled(t *testing.T) {
	tr := &postUrlliveTransport{liveCT: "application/x-www-form-urlencoded", getMode: "echo", postMode: "echo"}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs:   []asset.URL{mustURLUrllive(t, "http://example.com/search?q=term")},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
		Config: map[string]string{"urllive_reflection": "false"},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	total, posts := tr.counts()
	if posts != 0 {
		t.Fatalf("POST requests = %d, want 0 (reflection disabled)", posts)
	}
	if total != 1 {
		t.Fatalf("requests = %d, want 1 (liveness only)", total)
	}
	if len(res.Results.Evidence) != 0 {
		t.Fatalf("Evidence = %d, want 0", len(res.Results.Evidence))
	}
}

// TestUrlliveStagePostSkipsDeadCorpus pins that dead parameterized URLs
// get no POST probe: without a liveness response there is no advertised
// type to mirror.
func TestUrlliveStagePostSkipsDeadCorpus(t *testing.T) {
	deadTr := &failLiveTransport{}
	st := NewUrlliveStage(deadTr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs: []asset.URL{
			mustURLUrllive(t, "http://example.com/a?x=1"),
			mustURLUrllive(t, "http://example.com/b?x=1"),
		},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := deadTr.count(); got != 2 {
		t.Fatalf("requests = %d, want 2 (liveness only, zero reflection on a dead corpus)", got)
	}
	if len(res.Results.Evidence) != 0 {
		t.Fatalf("evidence = %d, want 0", len(res.Results.Evidence))
	}
}

// TestUrlliveStagePostScopeOnEveryEvidence pins scope honesty end to
// end: across form, JSON, and HTML endpoints every reflection evidence
// record carries a queryable scope, and POST verdicts never parse as
// query verdicts (triage gating reads GET exactly as before).
func TestUrlliveStagePostScopeOnEveryEvidence(t *testing.T) {
	tr := &mixedCTTransport{}
	st := NewUrlliveStage(tr)
	in := pipeline.StageInput{
		Target: mustDomainUrllive(t, "example.com"),
		URLs: []asset.URL{
			mustURLUrllive(t, "http://example.com/form?q=1"),
			mustURLUrllive(t, "http://example.com/api?q=1"),
			mustURLUrllive(t, "http://example.com/page?q=1"),
		},
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := st.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, ev := range res.Results.Evidence {
		scope, ok := httpprobe.ReflectEvidenceScope(ev)
		if !ok {
			t.Fatalf("evidence without scope: %+v", ev)
		}
		src := ev.Source.String()
		switch {
		case strings.Contains(src, "/form?"):
			if scope != httpprobe.ReflectScopeQueryGET && scope != httpprobe.ReflectScopePostForm {
				t.Errorf("form endpoint evidence scope = %q", scope)
			}
		case strings.Contains(src, "/api?"):
			if scope != httpprobe.ReflectScopeQueryGET && scope != httpprobe.ReflectScopePostJSON {
				t.Errorf("api endpoint evidence scope = %q", scope)
			}
		case strings.Contains(src, "/page?"):
			if scope != httpprobe.ReflectScopeQueryGET {
				t.Errorf("html endpoint evidence scope = %q, want query-get-only", scope)
			}
		}
		if scope != httpprobe.ReflectScopeQueryGET {
			if _, _, ok := httpprobe.ParseReflectEvidence(ev); ok {
				t.Errorf("POST evidence parses as a query verdict (triage isolation broken): %+v", ev)
			}
		}
	}
	idx := postEvidenceByScope(t, res.Results.Evidence)
	if idx["url:http://example.com/form?q=1"]["post-form:q"] == "" {
		t.Errorf("form endpoint lacks post-form evidence: %v", idx)
	}
	if idx["url:http://example.com/api?q=1"]["post-json:q"] == "" {
		t.Errorf("api endpoint lacks post-json evidence: %v", idx)
	}
	for src, m := range idx {
		if strings.Contains(src, "/page?") {
			for k := range m {
				if strings.HasPrefix(k, "post-") {
					t.Errorf("html endpoint carries POST evidence %q", k)
				}
			}
		}
	}
}

// mixedCTTransport serves per-path liveness content types (form/api/html)
// and echoes every reflection probe — GET by query, POST by body.
type mixedCTTransport struct {
	mu    sync.Mutex
	posts int
}

func (t *mixedCTTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		t.mu.Lock()
		t.posts++
		t.mu.Unlock()
		data, _ := io.ReadAll(req.Body)
		return postHTMLResponse("", "<html>"+strings.Join(postBodyValues(req.Header.Get("Content-Type"), string(data)), "|")+"</html>"), nil
	}
	if strings.Contains(req.URL.RawQuery, "%3A") {
		q, _ := url.ParseQuery(req.URL.RawQuery)
		var vals []string
		for _, vs := range q {
			vals = append(vals, vs...)
		}
		return postHTMLResponse("", "<html>"+strings.Join(vals, "|")+"</html>"), nil
	}
	ct := "text/html"
	switch {
	case strings.HasPrefix(req.URL.Path, "/form"):
		ct = "application/x-www-form-urlencoded"
	case strings.HasPrefix(req.URL.Path, "/api"):
		ct = "application/json"
	}
	return postHTMLResponse(ct, "<html>liveness</html>"), nil
}
