package adapt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/jsintel"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// jsFixedTime is the deterministic provenance timestamp for the jsintel
// adapter tests. It is UTC, so the engine's Now().UTC() normalization is
// identity.
var jsFixedTime = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

// jsFixedClock is a deterministic runtime.Clock: Now always returns
// jsFixedTime and After returns a channel that never fires. Adapter tests
// run with rate limiting disabled (DefaultStageConfig Rate 0), so the engine
// creates no limiter and After is never consulted; the fixed Now drives the
// engine's provenance timestamps and cache record timestamps deterministically.
type jsFixedClock struct{}

func (jsFixedClock) Now() time.Time { return jsFixedTime }
func (jsFixedClock) After(time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

var _ runtime.Clock = jsFixedClock{}

// jsMustURL normalizes a URL or fails the test.
func jsMustURL(t testing.TB, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u
}

// jsStageInput assembles a StageInput with the deterministic bounds, clock,
// params, and cache of one test.
func jsStageInput(t testing.TB, target string, urls []asset.URL, params map[string]string, c cache.Cache) pipeline.StageInput {
	t.Helper()
	return pipeline.StageInput{
		Target: mustDomain(t, target),
		URLs:   urls,
		Bounds: pipeline.DefaultStageConfig(),
		Config: params,
		Clock:  jsFixedClock{},
		Cache:  c,
	}
}

// jsRunBounded runs the stage with a hard test-level bound, so a regression
// that hangs Run fails fast instead of wedging the suite.
func jsRunBounded(t *testing.T, s pipeline.Stage, ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	t.Helper()
	type outcome struct {
		res pipeline.StageResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := s.Run(ctx, in)
		ch <- outcome{res, err}
	}()
	select {
	case o := <-ch:
		return o.res, o.err
	case <-time.After(15 * time.Second):
		t.Fatal("stage Run did not finish within 15s")
		return pipeline.StageResult{}, errors.New("run timed out")
	}
}

// jsWaitForRequests patience-polls until the transport has served at least n
// requests (bounded patience, small sleeps — it only fails on a genuine
// stall).
func jsWaitForRequests(t *testing.T, tr *cannedTransport, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if tr.requestCount() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("transport served %d requests, want at least %d", tr.requestCount(), n)
}

// rewriteTransport is a hermetic http.RoundTripper seam that forwards every
// request to a loopback httptest server while keeping the request's original
// URL (host, path, query) intact on the wire-facing side: it records the
// original canonical URL and rewrites only scheme+host to the loopback base.
// It proves the injected transport is the one the engine fetches through,
// while the loopback server exercises the REAL HTTP stack (chunked bodies,
// real streaming) without any public internet access.
type rewriteTransport struct {
	base     string // loopback server URL, e.g. http://127.0.0.1:PORT
	mu       sync.Mutex
	requests []string
}

// RoundTrip implements http.RoundTripper.
func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requests = append(t.requests, req.URL.String())
	t.mu.Unlock()
	bu, err := url.Parse(t.base)
	if err != nil {
		return nil, err
	}
	u := *req.URL
	u.Scheme = bu.Scheme
	u.Host = bu.Host
	req2 := req.Clone(req.Context())
	req2.URL = &u
	req2.RequestURI = ""
	return http.DefaultTransport.RoundTrip(req2)
}

// requestCount reports how many requests the transport has forwarded.
func (t *rewriteTransport) requestCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.requests)
}

// TestJSIntelStageName pins the stage identity and the nil-transport
// construction (nil = the engine's bounded production transport, never
// exercised here — the seam is injected in every other test).
func TestJSIntelStageName(t *testing.T) {
	if got := NewJSIntelStage(nil).Name(); got != pipeline.StageJSIntel {
		t.Fatalf("Name() = %q, want %q", got, pipeline.StageJSIntel)
	}
	if got := NewJSIntelStage(&cannedTransport{}).Name(); got != pipeline.StageJSIntel {
		t.Fatalf("Name() = %q, want %q", got, pipeline.StageJSIntel)
	}
}

// TestJSIntelStageItemLineMapping pins the input construction: every in-domain
// corpus URL becomes ONE ItemLine candidate whose Line is the URL's exact
// canonical string (the engine's parseLine resolves an absolute http(s) line
// back to that exact candidate), while out-of-domain and IP-literal URLs are
// filtered at the input boundary and never reach the engine. ItemHTML is not
// constructible from the corpus: it requires a page URL plus response headers
// and a body (jsintel.Item.URL/Headers/Body), which []asset.URL does not
// carry — the mapping choice is documented on the adapter type.
func TestJSIntelStageItemLineMapping(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "console.log(1)"})
	cannedHost(tr, "api.example.com", cannedResponse{status: 200, body: "console.log(2)"})

	in := jsStageInput(t, "example.com", []asset.URL{
		jsMustURL(t, "http://www.example.com/a.js"),
		jsMustURL(t, "http://api.example.com/b.js"),
		jsMustURL(t, "http://evil.example.net/c.js"), // out-of-domain: filtered
		jsMustURL(t, "http://93.184.216.34/d.js"),    // IP literal: never in scope
	}, nil, nil)
	res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 2 || res.ItemsFailed != 0 {
		t.Fatalf("counters = %d/%d, want 2/0 (only the two in-domain URLs are processed)", res.ItemsProcessed, res.ItemsFailed)
	}
	// The canned transport records scheme://host keys, and the engine's pool
	// (4 workers) serves the two fetches in nondeterministic order — compare
	// sorted.
	tr.mu.Lock()
	served := append([]string(nil), tr.requests...)
	tr.mu.Unlock()
	sort.Strings(served)
	requireEqualStrings(t, "served hosts", served,
		[]string{"http://api.example.com", "http://www.example.com"})
}

// TestJSIntelStageHappyPathCompleted pins the happy path: every in-domain
// candidate is fetched through the injected transport and processed into a
// completed entry, the outcome is completed, the counters are honest, and the
// stage produces NO corpus additions (scripts/endpoints/secrets are results,
// propagated by a separate milestone).
func TestJSIntelStageHappyPathCompleted(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{
		status:  200,
		body:    "console.log('hello')",
		headers: map[string]string{"Content-Type": "application/javascript"},
	})
	cannedHost(tr, "api.example.com", cannedResponse{
		status:  200,
		body:    "console.log('api')",
		headers: map[string]string{"Content-Type": "application/javascript"},
	})

	in := jsStageInput(t, "example.com", []asset.URL{
		jsMustURL(t, "http://www.example.com/app.js"),
		jsMustURL(t, "http://api.example.com/app.js"),
	}, map[string]string{"unknown_param": "ignored"}, nil)
	res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("Truncated/flags = %v/%v, want false/empty", res.Truncated, res.StickyFlags)
	}
	if res.ItemsProcessed != 2 || res.ItemsFailed != 0 {
		t.Fatalf("counters = %d/%d, want 2/0", res.ItemsProcessed, res.ItemsFailed)
	}
	if len(res.Additions.Domains) != 0 || len(res.Additions.Hosts) != 0 || len(res.Additions.URLs) != 0 {
		t.Fatalf("additions = %v/%v/%v, want all empty (results are a separate milestone)",
			res.Additions.Domains, res.Additions.Hosts, res.Additions.URLs)
	}
	if got := tr.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

// TestJSIntelStageAllFailed pins the all-failed fold: every fetch fails (a
// deterministic DNS-style error from the transport), every entry is
// StatusFailed, and the stage folds to failed with the honest failed count.
func TestJSIntelStageAllFailed(t *testing.T) {
	tr := &cannedTransport{} // no canned host: every fetch fails with a DNS error
	in := jsStageInput(t, "example.com", []asset.URL{
		jsMustURL(t, "http://www.example.com/app.js"),
	}, nil, nil)
	res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want failed", res.Outcome)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 1 {
		t.Fatalf("counters = %d/%d, want 1/1", res.ItemsProcessed, res.ItemsFailed)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("Truncated/flags = %v/%v, want false/empty", res.Truncated, res.StickyFlags)
	}
	if len(res.Additions.Hosts) != 0 || len(res.Additions.URLs) != 0 {
		t.Fatalf("additions = %v/%v, want empty", res.Additions.Hosts, res.Additions.URLs)
	}
}

// TestJSIntelStageMixedPartial pins the mixed fold: one completed entry
// together with one failed entry folds to partial (never completed, never
// failed).
func TestJSIntelStageMixedPartial(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	// api.example.com has no canned response: its fetch fails.

	in := jsStageInput(t, "example.com", []asset.URL{
		jsMustURL(t, "http://www.example.com/app.js"),
		jsMustURL(t, "http://api.example.com/app.js"),
	}, nil, nil)
	res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("Outcome = %q, want partial", res.Outcome)
	}
	if res.ItemsProcessed != 2 || res.ItemsFailed != 1 {
		t.Fatalf("counters = %d/%d, want 2/1", res.ItemsProcessed, res.ItemsFailed)
	}
}

// TestJSIntelStageCancellation verifies both cancellation paths: a context
// cancelled before the engine is invoked reports cancelled with the context
// error (the engine rejects a pre-cancelled context), and an in-flight
// cancellation reports cancelled while retaining the honest per-URL
// observation.
func TestJSIntelStageCancellation(t *testing.T) {
	t.Run("pre-cancelled context", func(t *testing.T) {
		tr := &cannedTransport{}
		cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil)
		res, err := jsRunBounded(t, NewJSIntelStage(tr), ctx, in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCancelled {
			t.Fatalf("Outcome = %q, want cancelled", res.Outcome)
		}
		if !errors.Is(res.Err, context.Canceled) {
			t.Fatalf("Err = %v, want a wrapped context.Canceled", res.Err)
		}
		if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
			t.Fatalf("counters = %d/%d, want 0/0 (no report)", res.ItemsProcessed, res.ItemsFailed)
		}
		if got := tr.requestCount(); got != 0 {
			t.Fatalf("requests = %d, want 0 (engine never fetched)", got)
		}
	})

	t.Run("in-flight cancellation", func(t *testing.T) {
		tr := &cannedTransport{}
		cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
		tr.blockUntil = make(chan struct{}) // never closed: block every request

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		type outcome struct {
			res pipeline.StageResult
			err error
		}
		ch := make(chan outcome, 1)
		go func() {
			res, err := NewJSIntelStage(tr).Run(ctx, jsStageInput(t, "example.com",
				[]asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil))
			ch <- outcome{res, err}
		}()

		jsWaitForRequests(t, tr, 1) // the fetch is in flight, parked on blockUntil
		cancel()

		var o outcome
		select {
		case o = <-ch:
		case <-time.After(15 * time.Second):
			t.Fatal("stage Run did not finish within 15s after cancellation")
		}
		if o.err != nil {
			t.Fatalf("Run: %v", o.err)
		}
		if o.res.Outcome != pipeline.OutcomeCancelled {
			t.Fatalf("Outcome = %q, want cancelled", o.res.Outcome)
		}
		if !errors.Is(o.res.Err, context.Canceled) {
			t.Fatalf("Err = %v, want a wrapped context.Canceled", o.res.Err)
		}
		// The candidate was consumed and pre-registered, then its work was
		// cancelled: one honest cancelled entry.
		if o.res.ItemsProcessed != 1 {
			t.Fatalf("ItemsProcessed = %d, want 1", o.res.ItemsProcessed)
		}
	})
}

// TestJSIntelStageCachePassedThrough pins the Cache pass-through (and, with
// it, the clock bridge's determinism): with a real filesystem cache and the
// fixed clock, the first run populates the js.fetch and js.analyze records
// and the second run performs ZERO transport requests — a cache hit serves
// the completed record and the analysis from cache — proving in.Cache reaches
// the engine's cache-before-execute and in.Clock makes the round-trip
// deterministic.
func TestJSIntelStageCachePassedThrough(t *testing.T) {
	c, err := cache.Open(t.TempDir(), cache.WithClock(jsFixedClock{}.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{
		status:  200,
		body:    "console.log('cached')",
		headers: map[string]string{"Content-Type": "application/javascript"},
	})

	run := func() pipeline.StageResult {
		t.Helper()
		in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, c)
		res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}

	res1 := run()
	if res1.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("first run Outcome = %q, want completed", res1.Outcome)
	}
	if got := tr.requestCount(); got != 1 {
		t.Fatalf("first run requests = %d, want 1 (one cache-miss fetch)", got)
	}

	res2 := run()
	if res2.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("second run Outcome = %q, want completed (served from cache)", res2.Outcome)
	}
	if got := tr.requestCount(); got != 1 {
		t.Fatalf("second run requests = %d, want 1 (unchanged: a cache hit performs zero fetches)", got)
	}
	if res2.ItemsProcessed != 1 || res2.ItemsFailed != 0 {
		t.Fatalf("second run counters = %d/%d, want 1/0", res2.ItemsProcessed, res2.ItemsFailed)
	}
	if len(res2.Additions.Hosts) != 0 || len(res2.Additions.URLs) != 0 {
		t.Fatalf("second run additions = %v/%v, want empty", res2.Additions.Hosts, res2.Additions.URLs)
	}
}

// TestJSIntelStageClockBridge pins the clock bridge: the StageResult surface
// itself carries no timestamps, so the bridge is observed through the
// engine's report under the exact config surface the adapter constructs —
// Source = pipeline.StageJSIntel and Clock = the injected clock — and the
// entry's observation window must be the fake clock's Now, never the wall
// clock (mirroring the dns adapter's fixed-clock determinism).
func TestJSIntelStageClockBridge(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{
		status:  200,
		body:    "console.log('x')",
		headers: map[string]string{"Content-Type": "application/javascript"},
	})

	// Through the adapter: deterministic completed run under the fixed clock.
	in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil)
	res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}

	// The engine's report with the adapter's exact construction surface: the
	// observation window is the injected clock's Now.
	dflt := pipeline.DefaultStageConfig()
	report, err := jsintel.Run(context.Background(), jsintel.Config{
		Concurrency: dflt.MaxConcurrency,
		QueueSize:   dflt.QueueSize,
		Source:      string(pipeline.StageJSIntel),
		Clock:       jsFixedClock{},
		Transport:   tr,
	}, jsintel.SliceSource([]jsintel.Item{{Kind: jsintel.ItemLine, Line: "http://www.example.com/app.js"}}))
	if err != nil {
		t.Fatalf("engine Run: %v", err)
	}
	if len(report.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(report.Entries))
	}
	e := report.Entries[0]
	if !e.FirstSeen.Equal(jsFixedTime) || !e.LastSeen.Equal(jsFixedTime) {
		t.Fatalf("entry FirstSeen/LastSeen = %v/%v, want %v (clock bridge: the injected clock, never the wall clock)",
			e.FirstSeen, e.LastSeen, jsFixedTime)
	}
}

// TestJSIntelStageTruncationFlag verifies that the engine's bounded-fetch
// truncation marker is never swallowed: a fetch whose content exceeds the
// engine's MaxJSBytes cap (2 MiB — the adapter never configures the cap)
// truncates, the entry is StatusIncomplete, and the stage folds to partial
// with Truncated=true and the js_fetch_truncated sticky flag (AGENTS §0.6).
// Both cap-detection paths are exercised hermetically: the declared
// Content-Length bound (a canned transport with a >2 MiB body) and the
// streamed bound against a real loopback HTTP stack.
func TestJSIntelStageTruncationFlag(t *testing.T) {
	const over = (2 << 20) + 1 // engine default MaxJSBytes is 2 MiB; +1 exceeds it

	t.Run("declared content-length bound (canned transport)", func(t *testing.T) {
		tr := &cannedTransport{}
		// ContentLength = len(body) > 2 MiB: readTerminal closes the body
		// without reading a byte (the declared bound) and truncates.
		cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: strings.Repeat("x", over)})

		in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil)
		res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomePartial {
			t.Fatalf("Outcome = %q, want partial (truncated entry is engine-incomplete, which folds to partial)", res.Outcome)
		}
		if !res.Truncated {
			t.Fatal("Truncated = false, want true (the bounded-fetch cap was hit)")
		}
		if !res.StickyFlags[jsFetchTruncated] {
			t.Fatalf("StickyFlags = %v, want %q set", res.StickyFlags, jsFetchTruncated)
		}
		if res.ItemsProcessed != 1 || res.ItemsFailed != 0 {
			t.Fatalf("counters = %d/%d, want 1/0 (incomplete is partial, not failed)", res.ItemsProcessed, res.ItemsFailed)
		}
		if got := tr.requestCount(); got != 1 {
			t.Fatalf("requests = %d, want 1 (a truncated fetch is never retried)", got)
		}
	})

	t.Run("streamed bound (loopback httptest server)", func(t *testing.T) {
		// The handler writes the body in two chunks, so the response is
		// chunked (Content-Length -1): the streamed read hits the cap after
		// 2 MiB+1 bytes and truncates against the real HTTP stack.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			if _, err := w.Write([]byte(strings.Repeat("y", 2<<20))); err != nil {
				return
			}
			_, _ = w.Write([]byte("y"))
		}))
		defer srv.Close()

		tr := &rewriteTransport{base: srv.URL}
		in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil)
		res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomePartial {
			t.Fatalf("Outcome = %q, want partial (truncated entry is engine-incomplete, which folds to partial)", res.Outcome)
		}
		if !res.Truncated {
			t.Fatal("Truncated = false, want true (the streamed read hit the bounded-fetch cap)")
		}
		if !res.StickyFlags[jsFetchTruncated] {
			t.Fatalf("StickyFlags = %v, want %q set", res.StickyFlags, jsFetchTruncated)
		}
		if res.ItemsProcessed != 1 || res.ItemsFailed != 0 {
			t.Fatalf("counters = %d/%d, want 1/0", res.ItemsProcessed, res.ItemsFailed)
		}
		if got := tr.requestCount(); got != 1 {
			t.Fatalf("requests = %d, want 1 (fetches go through the injected transport, exactly once)", got)
		}
	})

	t.Run("small body through the loopback completes", func(t *testing.T) {
		// Control: the same loopback seam with a small body completes — the
		// truncation above is the cap, not the transport.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("console.log('small')"))
		}))
		defer srv.Close()

		tr := &rewriteTransport{base: srv.URL}
		in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil)
		res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = %q, want completed", res.Outcome)
		}
		if res.Truncated || len(res.StickyFlags) != 0 {
			t.Fatalf("Truncated/flags = %v/%v, want false/empty", res.Truncated, res.StickyFlags)
		}
	})
}

// TestJSIntelStageEmptyFilteredShortCircuit verifies the empty-filtered
// short-circuit: when the corpus is empty or every URL is out-of-domain the
// stage completes with zero work and zero counters WITHOUT invoking the
// engine (the transport serves nothing). A cancelled context on that path
// reports cancelled, and a non-canonical target falls through to the engine
// instead of taking the short-circuit — proven by handing the fall-through an
// engine-rejecting zero config, which surfaces the engine's own error (the
// short-circuit never validates engine config).
func TestJSIntelStageEmptyFilteredShortCircuit(t *testing.T) {
	t.Run("empty corpus", func(t *testing.T) {
		tr := &cannedTransport{}
		in := jsStageInput(t, "example.com", nil, nil, nil)
		res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = %q, want completed", res.Outcome)
		}
		if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
			t.Fatalf("counters = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
		}
		if got := tr.requestCount(); got != 0 {
			t.Fatalf("requests = %d, want 0 (engine never called)", got)
		}
	})

	t.Run("only out-of-domain URLs", func(t *testing.T) {
		tr := &cannedTransport{}
		in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://evil.example.net/x.js")}, nil, nil)
		res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = %q, want completed", res.Outcome)
		}
		if got := tr.requestCount(); got != 0 {
			t.Fatalf("requests = %d, want 0 (engine never called)", got)
		}
	})

	t.Run("cancelled short-circuit", func(t *testing.T) {
		tr := &cannedTransport{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		in := jsStageInput(t, "example.com", nil, nil, nil)
		res, err := jsRunBounded(t, NewJSIntelStage(tr), ctx, in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCancelled {
			t.Fatalf("Outcome = %q, want cancelled", res.Outcome)
		}
		if !errors.Is(res.Err, context.Canceled) {
			t.Fatalf("Err = %v, want a wrapped context.Canceled", res.Err)
		}
		if got := tr.requestCount(); got != 0 {
			t.Fatalf("requests = %d, want 0 (engine never called)", got)
		}
	})

	t.Run("canonical short-circuit never validates engine config", func(t *testing.T) {
		tr := &cannedTransport{}
		in := jsStageInput(t, "example.com", nil, nil, nil)
		in.Bounds = pipeline.StageConfig{} // zero Concurrency: the engine would reject it
		res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = %q, want completed (the short-circuit returns before any engine config validation)", res.Outcome)
		}
	})

	t.Run("non-canonical target falls through to the engine", func(t *testing.T) {
		// The jsintel engine has no scope validation of its own, so nothing
		// is masked by the fall-through: with the default bounds the engine
		// processes the (empty) filtered remainder and completes with zero
		// work; with an engine-rejecting zero config the engine's own error
		// surfaces as failed — proving the engine was actually invoked
		// rather than short-circuited.
		t.Run("default bounds: engine's honest empty-source completion", func(t *testing.T) {
			tr := &cannedTransport{}
			in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil)
			in.Target = asset.Domain{Name: "Example.com"} // non-canonical: the filter drops everything
			res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.Outcome != pipeline.OutcomeCompleted {
				t.Fatalf("Outcome = %q, want completed (the engine's honest empty-source run)", res.Outcome)
			}
			if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
				t.Fatalf("counters = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
			}
			if got := tr.requestCount(); got != 0 {
				t.Fatalf("requests = %d, want 0", got)
			}
		})

		t.Run("zero bounds: the engine's config error surfaces", func(t *testing.T) {
			tr := &cannedTransport{}
			in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil)
			in.Target = asset.Domain{Name: "Example.com"} // non-canonical: no short-circuit
			in.Bounds = pipeline.StageConfig{}            // zero Concurrency: the engine rejects it
			res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
			if res.Outcome != pipeline.OutcomeFailed {
				t.Fatalf("Outcome = %q, want failed (the fall-through invoked the engine, which rejected the zero config)", res.Outcome)
			}
			if err == nil || !strings.Contains(err.Error(), "stage jsintel:") {
				t.Fatalf("err = %v, want a wrapped stage error", err)
			}
			if !strings.Contains(err.Error(), "concurrency") {
				t.Fatalf("err = %v, want the engine's concurrency cause preserved", err)
			}
		})
	})
}

// TestJSIntelStageEngineErrorWrappedNoPanic pins the error contract: an
// engine error (here the engine's own rejection of a zero Concurrency, which
// a direct caller could pass) is wrapped with "stage jsintel: ...", forces
// Outcome failed, and never panics.
func TestJSIntelStageEngineErrorWrappedNoPanic(t *testing.T) {
	tr := &cannedTransport{}
	in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil)
	in.Bounds = pipeline.StageConfig{} // zero Concurrency: the engine rejects it

	res, err := jsRunBounded(t, NewJSIntelStage(tr), context.Background(), in)
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, pipeline.OutcomeFailed)
	}
	if err == nil || !strings.Contains(err.Error(), "stage jsintel:") {
		t.Fatalf("err = %v, want a wrapped error containing %q", err, "stage jsintel:")
	}
	if !strings.Contains(err.Error(), "concurrency") {
		t.Fatalf("err = %v, want the engine's concurrency cause preserved", err)
	}
	if got := tr.requestCount(); got != 0 {
		t.Fatalf("requests = %d, want 0 (the engine rejected the config before any fetch)", got)
	}
}

// TestJSIntelStageRequestTimeoutParam verifies end-to-end that the
// request_timeout StageParam reaches the engine: with a transport that blocks
// every request and a 50 ms per-attempt deadline, the fetch fails on the
// deadline and the run folds to failed. The stage context is bounded to 3 s,
// so a broken parse (deadline silently defaulted to the engine's 10 s) would
// surface as cancelled instead of failed — failing fast.
func TestJSIntelStageRequestTimeoutParam(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	tr.blockUntil = make(chan struct{}) // never closed: every request parks until its deadline

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	in := jsStageInput(t, "example.com", []asset.URL{jsMustURL(t, "http://www.example.com/app.js")},
		map[string]string{"request_timeout": "50ms"}, nil)
	res, err := jsRunBounded(t, NewJSIntelStage(tr), ctx, in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want failed (the fetch hit the 50 ms per-attempt deadline)", res.Outcome)
	}
	if res.ItemsProcessed != 1 || res.ItemsFailed != 1 {
		t.Fatalf("counters = %d/%d, want 1/1", res.ItemsProcessed, res.ItemsFailed)
	}
}

// TestJSIntelStageFoldPins the outcome-mapping table directly: the per-entry
// status fold is exactly the unified adapter shape — cancelled >
// failed&&!completed > completed > partial — with StatusIncomplete folding
// into partial and never completed.
func TestJSIntelStageFoldPins(t *testing.T) {
	entry := func(status jsintel.Status) jsintel.JSEntry {
		return jsintel.JSEntry{URL: jsMustURL(t, "http://www.example.com/app.js"), Status: status}
	}
	cases := []struct {
		name    string
		entries []jsintel.JSEntry
		want    pipeline.Outcome
	}{
		{"empty report is vacuous completed", nil, pipeline.OutcomeCompleted},
		{"all completed", []jsintel.JSEntry{entry(jsintel.StatusCompleted), entry(jsintel.StatusCompleted)}, pipeline.OutcomeCompleted},
		{"all incomplete folds to partial", []jsintel.JSEntry{entry(jsintel.StatusIncomplete)}, pipeline.OutcomePartial},
		{"all failed", []jsintel.JSEntry{entry(jsintel.StatusFailed)}, pipeline.OutcomeFailed},
		{"all cancelled", []jsintel.JSEntry{entry(jsintel.StatusCancelled)}, pipeline.OutcomeCancelled},
		{"completed mixed with failed is partial", []jsintel.JSEntry{entry(jsintel.StatusCompleted), entry(jsintel.StatusFailed)}, pipeline.OutcomePartial},
		{"completed mixed with incomplete is partial", []jsintel.JSEntry{entry(jsintel.StatusCompleted), entry(jsintel.StatusIncomplete)}, pipeline.OutcomePartial},
		{"failed with incomplete and no completed is failed", []jsintel.JSEntry{entry(jsintel.StatusFailed), entry(jsintel.StatusIncomplete)}, pipeline.OutcomeFailed},
		{"cancelled wins over completed", []jsintel.JSEntry{entry(jsintel.StatusCompleted), entry(jsintel.StatusCancelled)}, pipeline.OutcomeCancelled},
		{"cancelled wins over failed", []jsintel.JSEntry{entry(jsintel.StatusFailed), entry(jsintel.StatusCancelled)}, pipeline.OutcomeCancelled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := foldJSEntries(jsintel.Report{Entries: tc.entries})
			if got != tc.want {
				t.Fatalf("foldJSEntries = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestJSIntelStageBuildResultPins the StageResult mapping directly: honest
// counters (failed entries plus the report's malformed count), the truncation
// marker with its named sticky flag (never swallowed), and always-empty
// additions (results are a separate milestone). The report-level truncation
// counter (Metrics().Snapshot().Truncated) is unexported to this package and
// is exercised end-to-end by TestJSIntelStageTruncationFlag; the per-entry
// StatusIncomplete branch is pinned here.
func TestJSIntelStageBuildResultPins(t *testing.T) {
	u := jsMustURL(t, "http://www.example.com/app.js")
	entry := func(status jsintel.Status) jsintel.JSEntry {
		return jsintel.JSEntry{URL: u, Status: status}
	}

	t.Run("completed report: honest counters, no flags, empty additions", func(t *testing.T) {
		rep := jsintel.Report{Entries: []jsintel.JSEntry{entry(jsintel.StatusCompleted), entry(jsintel.StatusCompleted)}}
		res := buildJSResult(rep, foldJSEntries(rep), nil)
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("Outcome = %q, want completed", res.Outcome)
		}
		if res.ItemsProcessed != 2 || res.ItemsFailed != 0 {
			t.Fatalf("counters = %d/%d, want 2/0", res.ItemsProcessed, res.ItemsFailed)
		}
		if res.Truncated || len(res.StickyFlags) != 0 {
			t.Fatalf("Truncated/flags = %v/%v, want false/empty", res.Truncated, res.StickyFlags)
		}
		assertJSAdditionsEmpty(t, res)
	})

	t.Run("failed entries plus malformed lines are the failed count", func(t *testing.T) {
		rep := jsintel.Report{
			Entries: []jsintel.JSEntry{entry(jsintel.StatusFailed), entry(jsintel.StatusCompleted)},
			// A malformed line is an input the engine rejected at ingest (for
			// this adapter: a corpus URL with a non-http(s) scheme).
			Malformed: 2,
		}
		res := buildJSResult(rep, foldJSEntries(rep), nil)
		if res.ItemsProcessed != 2 || res.ItemsFailed != 3 {
			t.Fatalf("counters = %d/%d, want 2/3 (1 failed entry + 2 malformed lines)", res.ItemsProcessed, res.ItemsFailed)
		}
		assertJSAdditionsEmpty(t, res)
	})

	t.Run("truncation marker never swallowed", func(t *testing.T) {
		rep := jsintel.Report{Entries: []jsintel.JSEntry{entry(jsintel.StatusIncomplete)}}
		res := buildJSResult(rep, foldJSEntries(rep), nil)
		if res.Outcome != pipeline.OutcomePartial {
			t.Fatalf("Outcome = %q, want partial", res.Outcome)
		}
		if !res.Truncated {
			t.Fatal("Truncated = false, want true (StatusIncomplete entries are truncation-derived)")
		}
		if !res.StickyFlags[jsFetchTruncated] {
			t.Fatalf("StickyFlags = %v, want %q set", res.StickyFlags, jsFetchTruncated)
		}
	})

	t.Run("jsTruncated: completed entries are not truncation", func(t *testing.T) {
		rep := jsintel.Report{Entries: []jsintel.JSEntry{entry(jsintel.StatusCompleted)}, Malformed: 1}
		if jsTruncated(rep) {
			t.Fatal("jsTruncated = true for a completed-only report, want false")
		}
	})
}

// assertJSAdditionsEmpty fails when the stage result carries any corpus
// additions (the jsintel stage produces none by contract).
func assertJSAdditionsEmpty(t *testing.T, res pipeline.StageResult) {
	t.Helper()
	if len(res.Additions.Domains) != 0 || len(res.Additions.Hosts) != 0 || len(res.Additions.URLs) != 0 {
		t.Fatalf("additions = %v/%v/%v, want all empty (scripts/endpoints/secrets are results)",
			res.Additions.Domains, res.Additions.Hosts, res.Additions.URLs)
	}
}

// TestJSIntelStageRequestTimeoutParsingReusesSharedHelper pins that the
// jsintel stage reads the same "request_timeout" StageParam through the
// shared httpprobe helper (absent, unparseable, zero, and negative values
// resolve to 0 = the engine's 10 s default; unknown params are ignored). The
// parsing table itself is pinned by TestRequestTimeoutParamParsing.
func TestJSIntelStageRequestTimeoutParsingReusesSharedHelper(t *testing.T) {
	for _, tc := range []struct {
		params map[string]string
		want   time.Duration
	}{
		{nil, 0},
		{map[string]string{"request_timeout": "5s"}, 5 * time.Second},
		{map[string]string{"request_timeout": "bogus"}, 0},
		{map[string]string{"request_timeout": "-5s"}, 0},
		{map[string]string{"other_key": "5s"}, 0},
	} {
		if got := requestTimeoutFromParams(tc.params); got != tc.want {
			t.Fatalf("requestTimeoutFromParams(%v) = %v, want %v", tc.params, got, tc.want)
		}
	}
}

// TestJSIntelStageProvenanceSource pins that the stage identity enters the
// engine config as the provenance source: a directly-run engine with the
// adapter's Source value records that exact source on the observed entry.
func TestJSIntelStageProvenanceSource(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{
		status:  200,
		body:    "console.log('x')",
		headers: map[string]string{"Content-Type": "application/javascript"},
	})
	dflt := pipeline.DefaultStageConfig()
	report, err := jsintel.Run(context.Background(), jsintel.Config{
		Concurrency: dflt.MaxConcurrency,
		QueueSize:   dflt.QueueSize,
		Source:      string(pipeline.StageJSIntel),
		Clock:       jsFixedClock{},
		Transport:   tr,
	}, jsintel.SliceSource([]jsintel.Item{{Kind: jsintel.ItemLine, Line: "http://www.example.com/app.js"}}))
	if err != nil {
		t.Fatalf("engine Run: %v", err)
	}
	if len(report.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(report.Entries))
	}
	if len(report.Entries[0].Sources) != 1 || report.Entries[0].Sources[0] != string(pipeline.StageJSIntel) {
		t.Fatalf("entry sources = %v, want [%q]", report.Entries[0].Sources, pipeline.StageJSIntel)
	}
	if report.Entries[0].JS == nil || report.Entries[0].JS.Prov.Source != string(pipeline.StageJSIntel) {
		t.Fatalf("JS provenance source = %v, want %q", report.Entries[0].JS.Prov.Source, pipeline.StageJSIntel)
	}
}

// TestJSIntelStageEngineErrorCancelled verifies the engine-error cancellation
// contract: when the engine surfaces an error while the stage context fired,
// the outcome is cancelled with the context error AND the engine's shutdown
// detail joined in (nothing is lost; the runner's isContextError traverses
// the join), and the Go error return is nil so the runner keeps the cancelled
// classification.
func TestJSIntelStageEngineErrorCancelled(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})
	tr.blockUntil = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		res pipeline.StageResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := NewJSIntelStage(tr).Run(ctx, jsStageInput(t, "example.com",
			[]asset.URL{jsMustURL(t, "http://www.example.com/app.js")}, nil, nil))
		ch <- outcome{res, err}
	}()

	jsWaitForRequests(t, tr, 1)
	cancel()

	var o outcome
	select {
	case o = <-ch:
	case <-time.After(15 * time.Second):
		t.Fatal("stage Run did not finish within 15s after cancellation")
	}
	if o.err != nil {
		t.Fatalf("Run returned a Go error %v; the outcome, not the error field, carries cancellation", o.err)
	}
	if o.res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("Outcome = %q, want cancelled", o.res.Outcome)
	}
	if !errors.Is(o.res.Err, context.Canceled) {
		t.Fatalf("Err = %v, want a wrapped context.Canceled", o.res.Err)
	}
	if o.res.Err == nil || !strings.Contains(fmt.Sprintf("%v", o.res.Err), "jsintel") {
		t.Fatalf("Err = %v, want the engine's shutdown detail joined in", o.res.Err)
	}
}
