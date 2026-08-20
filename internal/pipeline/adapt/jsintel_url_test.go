package adapt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/jsintel"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// helper to create an endpoint with GET method.
func jsURLEndpoint(t *testing.T, raw string) asset.Endpoint {
	t.Helper()
	ep, err := asset.NewEndpoint("GET", raw, asset.Provenance{Source: "jsintel"})
	if err != nil {
		t.Fatalf("NewEndpoint(%q): %v", raw, err)
	}
	return ep
}

// TestJSIntelURLFiltering pins the in-domain filtering: analyzer output with
// 3 URLs (/api/v1/users resolved as http://www.example.com/api/v1/users,
// https://other.example.com/x, https://evil.com/y) with target example.com
// admits only the first 2, evil dropped.
func TestJSIntelURLFiltering(t *testing.T) {
	target := mustDomain(t, "example.com")
	ep1 := jsURLEndpoint(t, "http://www.example.com/api/v1/users")
	ep2 := jsURLEndpoint(t, "https://other.example.com/x")
	ep3 := jsURLEndpoint(t, "https://evil.com/y")
	report := jsintel.Report{
		Entries: []jsintel.JSEntry{
			{URL: jsMustURL(t, "http://www.example.com/app.js"), Status: jsintel.StatusCompleted, Endpoints: []asset.Endpoint{ep1, ep2, ep3}},
		},
	}
	adds, overflow := jsCollectURLs(report, target, nil, jsURLCapDefault)
	if overflow {
		t.Fatalf("overflow = true, want false")
	}
	if len(adds) != 2 {
		t.Fatalf("adds = %v, want 2", jsURLTestStrings(adds))
	}
	got := jsURLTestStrings(adds)
	sort.Strings(got)
	want := []string{"http://www.example.com/api/v1/users", "https://other.example.com/x"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("adds = %v, want %v", got, want)
	}
	// Ensure evil dropped.
	for _, u := range adds {
		if u.String() == "https://evil.com/y" {
			t.Fatalf("evil URL not dropped: %v", adds)
		}
	}
}

// TestJSIntelURLDedup verifies dedup against incoming corpus and within new set.
func TestJSIntelURLDedup(t *testing.T) {
	target := mustDomain(t, "example.com")
	epA := jsURLEndpoint(t, "http://www.example.com/api/v1/users")
	epB := jsURLEndpoint(t, "http://www.example.com/api/v1/orders")
	// Duplicate within analyzer output: two entries both contain epA.
	report := jsintel.Report{
		Entries: []jsintel.JSEntry{
			{URL: jsMustURL(t, "http://www.example.com/a.js"), Status: jsintel.StatusCompleted, Endpoints: []asset.Endpoint{epA, epB}},
			{URL: jsMustURL(t, "http://www.example.com/b.js"), Status: jsintel.StatusCompleted, Endpoints: []asset.Endpoint{epA}},
		},
	}
	incoming := []asset.URL{jsMustURL(t, "http://www.example.com/api/v1/users")}
	adds, overflow := jsCollectURLs(report, target, incoming, jsURLCapDefault)
	if overflow {
		t.Fatalf("overflow = true, want false")
	}
	// epA already in incoming, should be deduped, leaving only epB.
	if len(adds) != 1 || adds[0].String() != "http://www.example.com/api/v1/orders" {
		t.Fatalf("adds = %v, want [http://www.example.com/api/v1/orders]", jsURLTestStrings(adds))
	}
	// Also test duplicate within new set without incoming: should dedup to 2 unique.
	report2 := jsintel.Report{
		Entries: []jsintel.JSEntry{
			{URL: jsMustURL(t, "http://www.example.com/a.js"), Status: jsintel.StatusCompleted, Endpoints: []asset.Endpoint{epA, epA, epB}},
		},
	}
	adds2, _ := jsCollectURLs(report2, target, nil, jsURLCapDefault)
	if len(adds2) != 2 {
		t.Fatalf("adds2 = %v, want 2 unique", jsURLTestStrings(adds2))
	}
}

// TestJSIntelURLCapOverflow verifies the bounded per-run cap and overflow
// signaling: cap=2 with 3 in-domain URLs → 2 retained + overflow flag + Truncated.
func TestJSIntelURLCapOverflow(t *testing.T) {
	// Use the adapter's Run path with StageParams cap.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		// Body contains 3 endpoint literals that will be extracted.
		body := `const a = "/api/v1/a"; const b = "/api/v1/b"; const c = "/api/v1/c";`
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	tr := &rewriteTransport{base: srv.URL}

	// Three in-domain endpoints will be extracted from the single JS file:
	// /api/v1/a, /api/v1/b, /api/v1/c resolved against http://www.example.com/app.js
	// => http://www.example.com/api/v1/a etc.
	in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, map[string]string{"jsintel_url_cap": "2"}, nil)
	// Need to inject the transport seam via NewJSIntelStage.
	stage := NewJSIntelStage(tr)
	res, err := jsRunBounded(t, stage, context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (overflow is flagged, not failed)", res.Outcome)
	}
	if !res.Truncated {
		t.Fatalf("Truncated = false, want true when cap overflow")
	}
	if !res.StickyFlags[jsURLOverflowFlag] {
		t.Fatalf("StickyFlags = %v, want %q", res.StickyFlags, jsURLOverflowFlag)
	}
	if len(res.Additions.URLs) != 2 {
		t.Fatalf("Additions.URLs = %v, want 2 (capped)", jsURLTestStrings(res.Additions.URLs))
	}
	// Sorted order deterministic.
	if !sort.StringsAreSorted(jsURLTestStrings(res.Additions.URLs)) {
		t.Fatalf("Additions.URLs not sorted: %v", jsURLTestStrings(res.Additions.URLs))
	}
	// Also directly test the helper cap logic with synthetic report (unit).
	target := mustDomain(t, "example.com")
	eps := []asset.Endpoint{
		jsURLEndpoint(t, "http://www.example.com/api/v1/a"),
		jsURLEndpoint(t, "http://www.example.com/api/v1/b"),
		jsURLEndpoint(t, "http://www.example.com/api/v1/c"),
	}
	report := jsintel.Report{
		Entries: []jsintel.JSEntry{
			{URL: jsMustURL(t, "http://www.example.com/app.js"), Status: jsintel.StatusCompleted, Endpoints: eps},
		},
	}
	adds, overflow := jsCollectURLs(report, target, nil, 2)
	if !overflow || len(adds) != 2 {
		t.Fatalf("helper adds=%v overflow=%v, want 2/true", jsURLTestStrings(adds), overflow)
	}
	// Default cap via missing param and via zero value.
	if got := jsURLCap(nil); got != jsURLCapDefault {
		t.Fatalf("jsURLCap(nil) = %d, want %d", got, jsURLCapDefault)
	}
	if got := jsURLCap(map[string]string{"jsintel_url_cap": "0"}); got != jsURLCapDefault {
		t.Fatalf("jsURLCap(0) = %d, want default", got)
	}
	if got := jsURLCap(map[string]string{"jsintel_url_cap": "bogus"}); got != jsURLCapDefault {
		t.Fatalf("jsURLCap(bogus) = %d, want default", got)
	}
	if got := jsURLCap(map[string]string{"jsintel_url_cap": "-5"}); got != jsURLCapDefault {
		t.Fatalf("jsURLCap(-5) = %d, want default", got)
	}
	if got := jsURLCap(map[string]string{"jsintel_url_cap": "10"}); got != 10 {
		t.Fatalf("jsURLCap(10) = %d, want 10", got)
	}
}

// TestJSIntelURLDeterminism verifies sorted deterministic output.
func TestJSIntelURLDeterminism(t *testing.T) {
	target := mustDomain(t, "example.com")
	eps := []asset.Endpoint{
		jsURLEndpoint(t, "http://www.example.com/b"),
		jsURLEndpoint(t, "http://www.example.com/a"),
		jsURLEndpoint(t, "http://www.example.com/c"),
	}
	report := jsintel.Report{
		Entries: []jsintel.JSEntry{
			{URL: jsMustURL(t, "http://www.example.com/app.js"), Status: jsintel.StatusCompleted, Endpoints: eps},
		},
	}
	adds1, _ := jsCollectURLs(report, target, nil, 500)
	adds2, _ := jsCollectURLs(report, target, nil, 500)
	if !reflect.DeepEqual(adds1, adds2) {
		t.Fatalf("determinism: first %v second %v", jsURLTestStrings(adds1), jsURLTestStrings(adds2))
	}
	// Also via adapter Run twice.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`const x = "/api/a"; const y = "/api/b";`))
	}))
	defer srv.Close()
	tr := &rewriteTransport{base: srv.URL}
	run := func() pipeline.StageResult {
		in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil)
		res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}
	r1 := run()
	r2 := run()
	if !reflect.DeepEqual(r1.Additions.URLs, r2.Additions.URLs) {
		t.Fatalf("adapter determinism: %v != %v", jsURLTestStrings(r1.Additions.URLs), jsURLTestStrings(r2.Additions.URLs))
	}
	if !sort.StringsAreSorted(jsURLTestStrings(r1.Additions.URLs)) {
		t.Fatalf("not sorted: %v", jsURLTestStrings(r1.Additions.URLs))
	}
}

// TestJSIntelURLPipelineE2E runs the full pipeline with jsintel producing URLs
// and verifies RunReport.URLs contains the filtered additions and flags.
func TestJSIntelURLPipelineE2E(t *testing.T) {
	// Loopback serving JS that yields 3 in-domain endpoints, one evil.
	// The JS body strings are endpoint literals extracted as endpoints.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		body := `const a = "/api/v1/users"; const b = "https://other.example.com/x"; const c = "https://evil.com/y";`
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	tr := &rewriteTransport{base: srv.URL}

	// Pipeline with seed + jsintel (deterministic via fixed clock).
	clk := jsFixedClock{}
	cfg := pipeline.ScanConfig{
		Target: mustDomain(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDiscover, pipeline.StageJSIntel},
		StageParams: map[pipeline.StageName]map[string]string{
			pipeline.StageJSIntel: {"jsintel_url_cap": "500"},
		},
	}
	// Provide initial corpus containing the JS file to fetch.
	initialURLs := []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}
	seedStageImpl := &pipelineSeedStage{target: mustDomain(t, "example.com"), urls: initialURLs}

	stages := []pipeline.Stage{seedStageImpl, NewJSIntelStage(tr)}
	report, err := pipeline.Run(context.Background(), cfg, nil, clk, stages)
	if err != nil {
		t.Fatalf("pipeline Run: %v", err)
	}
	// RunReport.URLs should be seed URLs plus jsintel-derived additions (in-domain only)
	// Seed contributed 1 URL, jsintel should add 2 (the in-domain endpoints, evil dropped)
	// Merge is first-seen dedup, so total 3.
	if len(report.URLs) != 3 {
		t.Fatalf("RunReport.URLs = %v, want 3 (seed 1 + 2 in-domain)", jsURLTestStrings(report.URLs))
	}
	// Check that evil not present.
	for _, u := range report.URLs {
		if u.String() == "https://evil.com/y" {
			t.Fatalf("evil URL leaked into corpus: %v", jsURLTestStrings(report.URLs))
		}
	}
	// The jsintel stage record should have no overflow flag (cap 500 not hit)
	if len(report.Stages) != 2 {
		t.Fatalf("stages = %d, want 2", len(report.Stages))
	}
	jsRec := report.Stages[1]
	if jsRec.Truncated || len(jsRec.StickyFlags) != 0 {
		t.Fatalf("jsintel stage truncated/flags = %v/%v, want none (no overflow)", jsRec.Truncated, jsRec.StickyFlags)
	}
	// Now test overflow via pipeline with cap=2.
	cfg2 := pipeline.ScanConfig{
		Target: mustDomain(t, "example.com"),
		Stages: []pipeline.StageName{pipeline.StageDiscover, pipeline.StageJSIntel},
		StageParams: map[pipeline.StageName]map[string]string{
			pipeline.StageJSIntel: {"jsintel_url_cap": "2"},
		},
	}
	// The JS body yields 3 in-domain endpoints, but cap 2 should overflow.
	// Need a JS that yields 3 distinct in-domain URLs.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`const a="/api/a"; const b="/api/b"; const c="/api/c";`))
	}))
	defer srv2.Close()
	tr2 := &rewriteTransport{base: srv2.URL}
	stages2 := []pipeline.Stage{seedStageImpl, NewJSIntelStage(tr2)}
	report2, err := pipeline.Run(context.Background(), cfg2, nil, clk, stages2)
	if err != nil {
		t.Fatalf("pipeline Run2: %v", err)
	}
	// Seed 1 + capped 2 = 3 total
	if len(report2.URLs) != 3 {
		t.Fatalf("overflow RunReport.URLs = %v, want 3 (seed 1 + capped 2)", jsURLTestStrings(report2.URLs))
	}
	jsRec2 := report2.Stages[1]
	if !jsRec2.Truncated || !jsRec2.StickyFlags[jsURLOverflowFlag] {
		t.Fatalf("overflow flag missing: truncated=%v flags=%v", jsRec2.Truncated, jsRec2.StickyFlags)
	}
	if !report2.Truncated {
		t.Fatalf("RunReport.Truncated = false, want true when stage overflow")
	}
}

// pipelineSeedStage is a minimal stage that seeds corpus URLs (for E2E test).
type pipelineSeedStage struct {
	target asset.Domain
	urls   []asset.URL
}

func (s *pipelineSeedStage) Name() pipeline.StageName { return pipeline.StageDiscover }

func (s *pipelineSeedStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	// Emit seed URLs as corpus additions (first stage, so no dedup needed).
	return pipeline.StageResult{
		Outcome:   pipeline.OutcomeCompleted,
		Additions: pipeline.StageAdditions{URLs: s.urls},
	}, nil
}

func jsURLTestStrings(urls []asset.URL) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		out = append(out, u.String())
	}
	return out
}
