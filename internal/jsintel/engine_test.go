package jsintel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// testEngineConfig returns a deterministic Config for engine tests: bounded
// pool, no fetch pacing (deterministic without clock advancement), a fixed
// clock, and a hermetic transport to srv (nil srv leaves the production
// transport, used by tests that must dial loopback addresses directly).
func testEngineConfig(t *testing.T, srv *httptest.Server) Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Concurrency = 4
	cfg.QueueSize = 16
	cfg.Timeout = 15 * time.Second
	cfg.Rate = 0 // no pacing: token waits would require clock advancement
	cfg.Source = "test-source"
	cfg.Clock = newFakeClock(fixedTime)
	if srv != nil {
		cfg.Transport = transportFor(t, srv)
	}
	return cfg
}

// runEngine runs one Run over items and fails the test on a run error.
func runEngine(t *testing.T, cfg Config, items []Item) Report {
	t.Helper()
	rep, err := Run(context.Background(), cfg, SliceSource(items))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// entryByURL returns the entry for rawURL, failing the test when absent.
func entryByURL(t *testing.T, rep Report, rawURL string) JSEntry {
	t.Helper()
	want := mustURL(t, rawURL)
	for _, e := range rep.Entries {
		if e.URL == want {
			return e
		}
	}
	t.Fatalf("no entry for %s (entries: %v)", rawURL, entryURLs(rep))
	return JSEntry{}
}

// entryURLs lists the report's entry URLs for diagnostics.
func entryURLs(rep Report) []string {
	var out []string
	for _, e := range rep.Entries {
		out = append(out, e.URL.String())
	}
	return out
}

func TestEngineLineJSObservation(t *testing.T) {
	body := []byte("var app = {x: 1};\nconsole.log(\"hi\");\n")
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC).Format(http.TimeFormat))
		w.Write(body)
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}})

	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(rep.Entries))
	}
	e := rep.Entries[0]
	if e.Status != StatusCompleted {
		t.Errorf("status = %s, want completed", e.Status)
	}
	if e.Cached {
		t.Error("fresh fetch must not be a cache hit")
	}
	if !reflect.DeepEqual(e.Sources, []string{"test-source"}) {
		t.Errorf("sources = %v, want [test-source]", e.Sources)
	}
	if !e.FirstSeen.Equal(fixedTime) || !e.LastSeen.Equal(fixedTime) {
		t.Errorf("FirstSeen/LastSeen = %v/%v, want %v", e.FirstSeen, e.LastSeen, fixedTime)
	}
	if e.JS == nil {
		t.Fatal("no JS asset for a JS-classified fetch")
	}
	js := e.JS
	if js.URL.String() != "http://js.test/app.js" {
		t.Errorf("js URL = %q", js.URL)
	}
	wantHash := hex.EncodeToString(sha256Sum(body))
	if js.ContentHash != wantHash {
		t.Errorf("content hash = %q, want %q", js.ContentHash, wantHash)
	}
	if js.Size != int64(len(body)) {
		t.Errorf("size = %d, want %d", js.Size, len(body))
	}
	if js.ContentType != "application/javascript" {
		t.Errorf("content type = %q", js.ContentType)
	}
	if js.ETag != `"v1"` {
		t.Errorf("etag = %q", js.ETag)
	}
	if js.StatusCode != 200 {
		t.Errorf("status code = %d, want 200", js.StatusCode)
	}
	if js.DiscoverySource != "test-source" {
		t.Errorf("discovery source = %q, want test-source", js.DiscoverySource)
	}
	if js.Prov.Source != "test-source" || !js.Prov.DiscoveredAt.Equal(fixedTime) {
		t.Errorf("provenance = %+v, want source test-source at %v", js.Prov, fixedTime)
	}
	if js.Host.Name != "js.test" {
		t.Errorf("host = %q, want js.test", js.Host.Name)
	}
	if js.FinalURL.String() != "http://js.test/app.js" {
		t.Errorf("final url = %q, want the requested URL (no redirect)", js.FinalURL)
	}
	if rep.Metrics().Fetches != 1 || rep.Metrics().Parses != 1 {
		t.Errorf("metrics = %+v, want 1 fetch and 1 parse", rep.Metrics())
	}
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func TestEngineHTMLCandidates(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, "console.log(%q);\n", r.URL.Path)
	})
	cfg := testEngineConfig(t, srv.srv)
	page := mustURL(t, "http://js.test/page")
	item := Item{
		Kind: ItemHTML,
		URL:  page,
		Headers: []HeaderEntry{{
			Name:  "Link",
			Value: `<//js.test/header.js>; rel=modulepreload, <https://js.test/style.css>; rel=stylesheet`,
		}},
		Body: `<html><head>
<script src="/a.js"></script>
<script src='/b.js'></script>
<script src=c.js></script>
<link rel="modulepreload" href="/m.js">
<link rel="preload" as="script" href="/p.js">
<link rel="prefetch" as="script" href="/pf.js">
<link rel="prefetch" href="/not-script.png">
<link rel="stylesheet" href="/style.css">
<script>import "./inline.js"; import("/dyn.js"); import("react");</script>
</head></html>`,
	}
	rep := runEngine(t, cfg, []Item{item})

	want := []string{
		"http://js.test/a.js",
		"http://js.test/b.js",
		"http://js.test/c.js",
		"http://js.test/m.js",
		"http://js.test/p.js",
		"http://js.test/pf.js",
		"http://js.test/inline.js",
		"http://js.test/dyn.js",
		"http://js.test/header.js",
	}
	if len(rep.Entries) != len(want) {
		t.Fatalf("entries = %v, want %d", entryURLs(rep), len(want))
	}
	for _, w := range want {
		e := entryByURL(t, rep, w)
		if e.Status != StatusCompleted || e.JS == nil {
			t.Errorf("%s: status = %s, JS nil = %v", w, e.Status, e.JS == nil)
		}
	}
	if got := srv.count(); got != len(want) {
		t.Errorf("server requests = %d, want %d", got, len(want))
	}
	if rep.Malformed != 0 {
		t.Errorf("malformed = %d, want 0", rep.Malformed)
	}
	if got := rep.Metrics().Skipped; got != 0 {
		t.Errorf("skipped = %d, want 0 (non-qualifying links are uncounted)", got)
	}
}

func TestEngineVisitedDedup(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	items := []Item{
		{Kind: ItemLine, Line: "http://js.test/app.js"},
		{Kind: ItemLine, Line: "http://js.test/app.js?x=1"},
		{Kind: ItemLine, Line: "http://js.test/app.js"},
	}
	rep := runEngine(t, cfg, items)

	if len(rep.Entries) != 2 {
		t.Fatalf("entries = %v, want 2 (app.js and app.js?x=1 are distinct identities)", entryURLs(rep))
	}
	e := entryByURL(t, rep, "http://js.test/app.js")
	if rep.Metrics().Fetches != 2 || srv.count() != 2 {
		t.Errorf("fetches = %d, server requests = %d, want 2 (duplicate URL fetched once)", rep.Metrics().Fetches, srv.count())
	}
	if !reflect.DeepEqual(e.Sources, []string{"test-source"}) {
		t.Errorf("sources = %v, want a single deduplicated source", e.Sources)
	}
}

func TestEngineNonJSObservation(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>hello</body></html>"))
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/page"}})

	e := rep.Entries[0]
	if e.Status != StatusCompleted {
		t.Errorf("status = %s, want completed (non-JS content is a completed observation)", e.Status)
	}
	if e.JS != nil {
		t.Error("non-JS content must not produce a JS asset")
	}
	if rep.Metrics().Parses != 0 {
		t.Errorf("parses = %d, want 0 (no JS asset, no parse)", rep.Metrics().Parses)
	}
}

func TestEngine404(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		http.Error(w, "not found", http.StatusNotFound)
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}})

	e := rep.Entries[0]
	if e.Status != StatusCompleted {
		t.Errorf("status = %s, want completed (any HTTP status is a completed observation)", e.Status)
	}
	if e.JS == nil {
		t.Fatal("a JS-content 404 must still classify as a JS asset")
	}
	if e.JS.StatusCode != 404 {
		t.Errorf("status code = %d, want 404", e.JS.StatusCode)
	}
}

func TestEngine404JSPathStillClassified(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Explicitly non-JS content type: the URL path rule must still win.
		w.Header().Set("Content-Type", "text/plain")
		http.Error(w, "not found", http.StatusNotFound)
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}})

	e := rep.Entries[0]
	if e.Status != StatusCompleted {
		t.Errorf("status = %s, want completed", e.Status)
	}
	if e.JS == nil {
		t.Error("a .js path must classify as a JS asset even with a non-JS content type")
	}
	if e.JS != nil && e.JS.StatusCode != 404 {
		t.Errorf("status code = %d, want 404", e.JS.StatusCode)
	}
}

func TestEngineConnRefused(t *testing.T) {
	addr := refusedLoopbackAddr(t)
	cfg := testEngineConfig(t, nil) // production transport: dials the address directly
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://" + addr + "/x.js"}})

	e := rep.Entries[0]
	if e.Status != StatusCompleted {
		t.Errorf("status = %s, want completed (conn_refused is a legitimate negative)", e.Status)
	}
	if e.JS != nil {
		t.Error("a completed negative must not produce a JS asset")
	}
	if e.Err != nil {
		t.Errorf("err = %v, want nil for a completed negative", e.Err)
	}
	if rep.Metrics().Fetches != 1 {
		t.Errorf("fetches = %d, want 1", rep.Metrics().Fetches)
	}
}

func TestEngineTimeoutFails(t *testing.T) {
	cfg := testEngineConfig(t, nil)
	cfg.Transport = blockingRT{}
	cfg.RequestTimeout = 300 * time.Millisecond
	cfg.Timeout = 5 * time.Second
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/slow.js"}})

	e := rep.Entries[0]
	if e.Status != StatusFailed {
		t.Errorf("status = %s, want failed", e.Status)
	}
	if e.Err == nil {
		t.Error("a failed fetch must carry its cause")
	}
	if rep.Metrics().Fetches != 1 {
		t.Errorf("fetches = %d, want 1 (retries are attempts, not fetches)", rep.Metrics().Fetches)
	}
}

func TestEngineTruncatedFetch(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(100<<10))
		w.Write(bytes.Repeat([]byte("x"), 100<<10))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.MaxJSBytes = 64 << 10 // clamped minimum: the 100 KiB body truncates
	cfg.Cache = openTestCache(t)
	items := []Item{{Kind: ItemLine, Line: "http://js.test/big.js"}}

	rep := runEngine(t, cfg, items)
	e := rep.Entries[0]
	if e.Status != StatusIncomplete {
		t.Errorf("status = %s, want incomplete (truncated fetch)", e.Status)
	}
	if e.JS != nil {
		t.Error("a truncated fetch must not produce a JS asset (no content was retained)")
	}
	if e.Cached {
		t.Error("a truncated fetch must never be served from cache")
	}
	if got := rep.Metrics().Truncated; got != 1 {
		t.Errorf("truncated = %d, want 1", got)
	}
	if got := rep.Metrics().Stores; got != 1 {
		t.Errorf("stores = %d, want 1 (truncated stored as incomplete)", got)
	}

	// The truncated record is stored incomplete: a second run re-fetches.
	rep2 := runEngine(t, cfg, items)
	e2 := rep2.Entries[0]
	if e2.Cached {
		t.Error("run 2 must not be a cache hit for a truncated record")
	}
	if rep2.Metrics().Fetches != 1 || rep2.Metrics().Reads != 1 {
		t.Errorf("run 2 metrics = %+v, want 1 fetch and 1 read", rep2.Metrics())
	}
}

func TestEngineCacheHit(t *testing.T) {
	body := []byte("var app = {x: 1};\n")
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("ETag", `"v1"`)
		w.Write(body)
	})
	cfg := testEngineConfig(t, srv.srv)
	counting := countingRT{inner: transportFor(t, srv.srv)}
	cfg.Transport = &counting
	cfg.Cache = openTestCache(t)
	items := []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}}

	rep1 := runEngine(t, cfg, items)
	if rep1.Entries[0].Cached {
		t.Error("run 1 must be a fresh fetch, not a cache hit")
	}
	if rep1.Metrics().Fetches != 1 {
		t.Errorf("run 1 fetches = %d, want 1", rep1.Metrics().Fetches)
	}

	rep2 := runEngine(t, cfg, items)
	e2 := rep2.Entries[0]
	if !e2.Cached {
		t.Error("run 2 must be served from the completed cache record")
	}
	if rep2.Metrics().Fetches != 0 {
		t.Errorf("run 2 fetches = %d, want 0 (a hit performs zero network)", rep2.Metrics().Fetches)
	}
	if rep2.Metrics().Reads != 2 {
		t.Errorf("run 2 reads = %d, want 2 (one js.fetch lookup and one js.analyze lookup)", rep2.Metrics().Reads)
	}
	if rep2.Metrics().Parses != 0 {
		t.Errorf("run 2 parses = %d, want 0 (the analysis is served from the completed js.analyze record)", rep2.Metrics().Parses)
	}
	if counting.calls() != 1 {
		t.Errorf("round trips = %d, want 1 (zero across run 2)", counting.calls())
	}
	if rep1.Entries[0].JS == nil || e2.JS == nil {
		t.Fatal("both runs must carry the JS asset")
	}
	if !reflect.DeepEqual(rep1.Entries[0].JS, e2.JS) {
		t.Errorf("cached JS asset differs from the fresh one:\n%+v\nvs\n%+v", *rep1.Entries[0].JS, *e2.JS)
	}
}

func TestEngineImportExpansion(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		switch r.URL.Path {
		case "/app.js":
			w.Write([]byte("import \"./lib.js\";\nconsole.log(\"app\");\n"))
		default:
			w.Write([]byte("export const x = 1;\n"))
		}
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}})

	if len(rep.Entries) != 2 {
		t.Fatalf("entries = %v, want app.js and lib.js", entryURLs(rep))
	}
	if srv.count() != 2 {
		t.Errorf("server requests = %d, want 2 (the import is fetched as a new job)", srv.count())
	}
	app := entryByURL(t, rep, "http://js.test/app.js")
	lib := entryByURL(t, rep, "http://js.test/lib.js")
	if len(app.Imports) != 1 {
		t.Fatalf("app imports = %d, want 1 edge", len(app.Imports))
	}
	wantEdge, err := asset.NewRelationship(
		asset.Identity{Kind: asset.KindJavaScript, Value: "http://js.test/app.js"},
		asset.RelationshipJavaScriptToJavaScript,
		asset.Identity{Kind: asset.KindJavaScript, Value: "http://js.test/lib.js"},
	)
	if err != nil {
		t.Fatalf("build expected edge: %v", err)
	}
	if app.Imports[0].ID() != wantEdge.ID() {
		t.Errorf("import edge = %q, want %q", app.Imports[0].ID(), wantEdge.ID())
	}
	if len(app.BareImports) != 0 {
		t.Errorf("bare imports = %v, want none", app.BareImports)
	}
	if lib.JS == nil || len(lib.Imports) != 0 {
		t.Errorf("lib entry: JS nil = %v, imports = %d", lib.JS == nil, len(lib.Imports))
	}
}

func TestEngineCircularImports(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		switch r.URL.Path {
		case "/a.js":
			w.Write([]byte("import \"./b.js\";\n"))
		case "/b.js":
			w.Write([]byte("import \"./a.js\";\n"))
		}
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/a.js"}})

	if len(rep.Entries) != 2 {
		t.Fatalf("entries = %v, want a.js and b.js", entryURLs(rep))
	}
	if srv.count() != 2 {
		t.Errorf("server requests = %d, want 2 (the cycle must terminate: each URL is fetched once)", srv.count())
	}
	a := entryByURL(t, rep, "http://js.test/a.js")
	b := entryByURL(t, rep, "http://js.test/b.js")
	if len(a.Imports) != 1 || len(b.Imports) != 1 {
		t.Errorf("import edges = a:%d b:%d, want 1 each", len(a.Imports), len(b.Imports))
	}
}

func TestEngineDepthCap(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		switch r.URL.Path {
		case "/a.js":
			w.Write([]byte("import \"./b.js\";\n"))
		case "/b.js":
			w.Write([]byte("import \"./c.js\";\n"))
		default:
			w.Write([]byte("export const c = 3;\n"))
		}
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.MaxImportDepth = 1
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/a.js"}})

	if len(rep.Entries) != 2 {
		t.Fatalf("entries = %v, want a.js and b.js only (c.js is depth-capped)", entryURLs(rep))
	}
	if srv.count() != 2 {
		t.Errorf("server requests = %d, want 2 (c.js is recorded as an edge, never fetched)", srv.count())
	}
	b := entryByURL(t, rep, "http://js.test/b.js")
	if len(b.Imports) != 1 {
		t.Fatalf("b imports = %d, want the edge to c.js even though c was never fetched", len(b.Imports))
	}
	if got := rep.Metrics().Skipped; got != 1 {
		t.Errorf("skipped = %d, want 1 (the depth-capped import)", got)
	}
}

func TestEngineTotalCap(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.MaxScripts = 1
	rep := runEngine(t, cfg, []Item{
		{Kind: ItemLine, Line: "http://js.test/one.js"},
		{Kind: ItemLine, Line: "http://js.test/two.js"},
	})

	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %v, want one.js only", entryURLs(rep))
	}
	if got := entryByURL(t, rep, "http://js.test/one.js"); got.JS == nil {
		t.Error("the first candidate must be processed normally")
	}
	if srv.count() != 1 {
		t.Errorf("server requests = %d, want 1", srv.count())
	}
	if got := rep.Metrics().Skipped; got != 1 {
		t.Errorf("skipped = %d, want 1 (the capped candidate)", got)
	}
}

func TestEngineRelativeLineWithBase(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.Base = mustURL(t, "http://js.test/page/index.html")
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "./x.js"}})

	e := entryByURL(t, rep, "http://js.test/page/x.js")
	if e.JS == nil {
		t.Error("the relative line must resolve against cfg.Base and be fetched")
	}
	if rep.Malformed != 0 {
		t.Errorf("malformed = %d, want 0", rep.Malformed)
	}

	// Without a base, a relative line is malformed: never a candidate.
	cfg2 := testEngineConfig(t, nil)
	rep2 := runEngine(t, cfg2, []Item{{Kind: ItemLine, Line: "./x.js"}})
	if len(rep2.Entries) != 0 {
		t.Errorf("entries = %v, want none without a base", entryURLs(rep2))
	}
	if rep2.Malformed != 1 {
		t.Errorf("malformed = %d, want 1", rep2.Malformed)
	}
}

// TestEngineSecretLines pins the D2 line-seam contract: a secretfinder
// "name\t->\tvalue" line is recognized (counted SecretLines), never a URL
// candidate, and a line that follows a "[ + ] URL:" progress form is
// ingested as a typed secret candidate against that URL's entry — the
// candidate's source is the URL's JavaScript identity, its provenance the
// run's source and clock, matching content-derived candidates exactly.
func TestEngineSecretLines(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{
		{Kind: ItemLine, Line: "[ + ] URL: <http://js.test/app.js>"},
		{Kind: ItemLine, Line: "google_api_key\t->\tAIzaSyA-test-key-123456789012345678901234"},
		{Kind: ItemLine, Line: "aws_access_key_id\t->\tAKIAIOSFODNN7EXAMPLE"},
	})

	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %v, want app.js only (secret lines produce no candidates)", entryURLs(rep))
	}
	if got := rep.Metrics().SecretLines; got != 2 {
		t.Errorf("secret lines = %d, want 2", got)
	}
	if rep.Malformed != 0 {
		t.Errorf("malformed = %d, want 0 (a recognized secret line is not malformed)", rep.Malformed)
	}
	if got := rep.Metrics().Skipped; got != 0 {
		t.Errorf("skipped = %d, want 0 (every secret under the caps is ingested)", got)
	}

	e := entryByURL(t, rep, "http://js.test/app.js")
	wantSrc := asset.Identity{Kind: asset.KindJavaScript, Value: "http://js.test/app.js"}
	wantProv := asset.Provenance{Source: "test-source", DiscoveredAt: fixedTime}
	want := map[string]asset.SecretType{
		"AIzaSyA-test-key-123456789012345678901234": asset.SecretTypeGoogle,
		"AKIAIOSFODNN7EXAMPLE":                      asset.SecretTypeAWS,
	}
	if len(e.Secrets) != len(want) {
		t.Fatalf("secrets = %v, want %d typed candidates", secretValues(e.Secrets), len(want))
	}
	for _, s := range e.Secrets {
		if s.Source != wantSrc {
			t.Errorf("secret %q source = %v, want %v", s.Value, s.Source, wantSrc)
		}
		if s.Prov != wantProv {
			t.Errorf("secret %q provenance = %+v, want %+v", s.Value, s.Prov, wantProv)
		}
		if want[s.Value] != s.Type {
			t.Errorf("secret %q type = %q, want %q", s.Value, s.Type, want[s.Value])
		}
	}
}

// TestEngineSecretLineContentDedup pins the cross-stream dedup: a
// line-secret whose type/value/source match a content-derived candidate is
// ONE candidate in the merged entry (the line-secret shares the URL's
// JavaScript identity, so the merge sees the same candidate identity).
func TestEngineSecretLineContentDedup(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`var k = "AKIAIOSFODNN7EXAMPLE";` + "\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{
		{Kind: ItemLine, Line: "http://js.test/app.js"},
		{Kind: ItemLine, Line: "[ + ] URL: <http://js.test/app.js>"},
		{Kind: ItemLine, Line: "aws_access_key_id\t->\tAKIAIOSFODNN7EXAMPLE"},
	})
	e := entryByURL(t, rep, "http://js.test/app.js")
	if len(e.Secrets) != 1 {
		t.Fatalf("secrets = %v, want the single deduplicated aws candidate", secretValues(e.Secrets))
	}
	if e.Secrets[0].Type != asset.SecretTypeAWS || e.Secrets[0].Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("secret = type %q value %q, want aws AKIAIOSFODNN7EXAMPLE", e.Secrets[0].Type, e.Secrets[0].Value)
	}
}

// TestEngineSecretLineDropAccounting pins the counted-drop paths: a secret
// line before any "[ + ] URL:" context and one with an empty value are both
// recognized (SecretLines) but counted Skipped and never ingested — the raw
// count stays exact and nothing is silently lost.
func TestEngineSecretLineDropAccounting(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{
		{Kind: ItemLine, Line: "api_key\t->\tno-context-value"},
		{Kind: ItemLine, Line: "google_api_key\t->\t"}, // empty value: dropped
		{Kind: ItemLine, Line: "[ + ] URL: <http://js.test/app.js>"},
		{Kind: ItemLine, Line: "aws_access_key_id\t->\tAKIAIOSFODNN7EXAMPLE"},
	})
	if got := rep.Metrics().SecretLines; got != 3 {
		t.Errorf("secret lines = %d, want 3 (recognized even when dropped)", got)
	}
	if got := rep.Metrics().Skipped; got != 2 {
		t.Errorf("skipped = %d, want 2 (no context + empty value)", got)
	}
	e := entryByURL(t, rep, "http://js.test/app.js")
	if len(e.Secrets) != 1 || e.Secrets[0].Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("secrets = %v, want only the ingested aws candidate", secretValues(e.Secrets))
	}
}

// TestEngineSecretLinePerURLCap pins the per-URL retention bound: the 65th
// secret line for ONE URL context is counted Skipped and dropped. The
// entry's MaxSecretsPerFile is raised so the merged retention cap does not
// confound the line-seam bound under test (pending 64 > default retain 32).
func TestEngineSecretLinePerURLCap(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.MaxSecretsPerFile = maxLineSecretsPerURL + 1
	items := []Item{
		{Kind: ItemLine, Line: "[ + ] URL: <http://js.test/app.js>"},
	}
	for i := 0; i < maxLineSecretsPerURL+1; i++ {
		items = append(items, Item{Kind: ItemLine, Line: fmt.Sprintf("aws_access_key_id\t->\tAKIA%016d", i)})
	}
	rep := runEngine(t, cfg, items)

	e := entryByURL(t, rep, "http://js.test/app.js")
	if len(e.Secrets) != maxLineSecretsPerURL {
		t.Errorf("secrets = %d, want %d (the 65th is dropped)", len(e.Secrets), maxLineSecretsPerURL)
	}
	if got := rep.Metrics().SecretLines; got != maxLineSecretsPerURL+1 {
		t.Errorf("secret lines = %d, want %d", got, maxLineSecretsPerURL+1)
	}
	if got := rep.Metrics().Skipped; got != 1 {
		t.Errorf("skipped = %d, want 1 (the 65th secret)", got)
	}
}

// TestEngineSecretLineURLContextCap pins the URL-context bound: secret lines
// under a 33rd distinct "[ + ] URL:" context are counted Skipped and
// dropped. The 32 admitted contexts ingest their secrets normally.
func TestEngineSecretLineURLContextCap(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	var items []Item
	for i := 0; i < maxLineSecretURLs+1; i++ {
		items = append(items, Item{Kind: ItemLine, Line: fmt.Sprintf("[ + ] URL: <http://js.test/s%d.js>", i)})
		items = append(items, Item{Kind: ItemLine, Line: fmt.Sprintf("api_key\t->\tvalue-%d", i)})
	}
	rep := runEngine(t, cfg, items)

	if len(rep.Entries) != maxLineSecretURLs+1 {
		t.Fatalf("entries = %d, want %d (every progress URL is a candidate)", len(rep.Entries), maxLineSecretURLs+1)
	}
	for i := 0; i < maxLineSecretURLs; i++ {
		e := entryByURL(t, rep, fmt.Sprintf("http://js.test/s%d.js", i))
		if len(e.Secrets) != 1 {
			t.Errorf("s%d: secrets = %v, want its single secret ingested", i, secretValues(e.Secrets))
		}
	}
	last := entryByURL(t, rep, fmt.Sprintf("http://js.test/s%d.js", maxLineSecretURLs))
	if len(last.Secrets) != 0 {
		t.Errorf("s%d: secrets = %v, want none (33rd context is dropped)", maxLineSecretURLs, secretValues(last.Secrets))
	}
	if got := rep.Metrics().SecretLines; got != maxLineSecretURLs+1 {
		t.Errorf("secret lines = %d, want %d", got, maxLineSecretURLs+1)
	}
	if got := rep.Metrics().Skipped; got != 1 {
		t.Errorf("skipped = %d, want 1 (the 33rd context's secret)", got)
	}
}

// TestEngineSecretLineUnprocessedURL pins the admission guard: a secret
// line under a progress URL that the MaxScripts cap refused admission is
// counted Skipped and dropped — the URL can never be processed, so its
// secrets can never be ingested.
func TestEngineSecretLineUnprocessedURL(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.MaxScripts = 1
	rep := runEngine(t, cfg, []Item{
		{Kind: ItemLine, Line: "[ + ] URL: <http://js.test/a.js>"},
		{Kind: ItemLine, Line: "api_key\t->\tvalue-a"},
		{Kind: ItemLine, Line: "[ + ] URL: <http://js.test/b.js>"},
		{Kind: ItemLine, Line: "api_key\t->\tvalue-b"},
	})
	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %v, want a.js only", entryURLs(rep))
	}
	e := entryByURL(t, rep, "http://js.test/a.js")
	if len(e.Secrets) != 1 || e.Secrets[0].Value != "value-a" {
		t.Errorf("a.js secrets = %v, want [value-a]", secretValues(e.Secrets))
	}
	if got := rep.Metrics().Skipped; got != 2 {
		t.Errorf("skipped = %d, want 2 (b.js cap-dropped + its secret dropped)", got)
	}
}

// TestEngineReofferSourceUnion pins the sources-union contract across runs:
// two runs over the same accumulator observing the same URL report the
// unioned sources in first-seen order.
func TestEngineReofferSourceUnion(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	acc := NewAccumulator(DefaultConfig())
	items := []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}}

	cfg1 := testEngineConfig(t, srv.srv)
	cfg1.Source = "s1"
	if err := RunInto(context.Background(), cfg1, SliceSource(items), acc); err != nil {
		t.Fatalf("RunInto (s1): %v", err)
	}
	cfg2 := testEngineConfig(t, srv.srv)
	cfg2.Source = "s2"
	if err := RunInto(context.Background(), cfg2, SliceSource(items), acc); err != nil {
		t.Fatalf("RunInto (s2): %v", err)
	}

	e := entryByURL(t, acc.Report(), "http://js.test/app.js")
	if !reflect.DeepEqual(e.Sources, []string{"s1", "s2"}) {
		t.Errorf("sources = %v, want [s1 s2] (first-seen order)", e.Sources)
	}
}

// TestEngineReofferCapDroppedNeverEntry pins the admission guard on
// re-observation: a cap-dropped URL that is observed again within the run
// must never gain an entry — only ADMITTED URLs union their source on
// re-offer, so a dropped URL stays dropped (idempotent).
func TestEngineReofferCapDroppedNeverEntry(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.MaxScripts = 1
	rep := runEngine(t, cfg, []Item{
		{Kind: ItemLine, Line: "http://js.test/a.js"},
		{Kind: ItemLine, Line: "http://js.test/b.js"}, // cap-dropped
		{Kind: ItemLine, Line: "http://js.test/b.js"}, // re-observed: still dropped
		{Kind: ItemLine, Line: "http://js.test/a.js"}, // re-observed: admitted, source union (no-op)
	})
	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %v, want a.js only (a cap-dropped URL never gains an entry)", entryURLs(rep))
	}
	if got := rep.Metrics().Skipped; got != 1 {
		t.Errorf("skipped = %d, want 1 (only the first b.js offer is counted)", got)
	}
}

// secretValues renders a secret list's values for diagnostics.
func secretValues(secs []asset.SecretCandidate) []string {
	var out []string
	for _, s := range secs {
		out = append(out, s.Value)
	}
	return out
}

func TestEngineMalformedLine(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{
		{Kind: ItemLine, Line: "react"},
		{Kind: ItemLine, Line: "data:text/plain,hello"},
		{Kind: ItemLine, Line: "http://js.test/app.js"},
	})

	if len(rep.Entries) != 1 {
		t.Fatalf("entries = %v, want app.js only", entryURLs(rep))
	}
	if rep.Malformed != 2 {
		t.Errorf("malformed = %d, want 2", rep.Malformed)
	}
}

func TestEngineForcedShutdown(t *testing.T) {
	cfg := testEngineConfig(t, nil)
	cfg.Concurrency = 2
	cfg.QueueSize = 64 // >= item count: the reader never blocks on Submit
	cfg.Transport = blockingRT{}
	var items []Item
	for i := 0; i < 32; i++ {
		items = append(items, Item{Kind: ItemLine, Line: fmt.Sprintf("http://js.test/s%d.js", i)})
	}
	m := &Metrics{}
	cfg.Metrics = m
	acc := NewAccumulator(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunInto(ctx, cfg, SliceSource(items), acc) }()

	// Every candidate was claimed (pre-registered) once Candidates hits the
	// item count; every job is then parked in the blocking transport.
	deadline := time.Now().Add(testTimeout)
	for m.Snapshot().Candidates != 32 {
		if time.Now().After(deadline) {
			t.Fatalf("candidates = %d, never reached 32", m.Snapshot().Candidates)
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("RunInto did not return within testTimeout")
	}

	rep := acc.Report()
	if len(rep.Entries) != 32 {
		t.Fatalf("entries = %d, want 32 (every candidate keeps its pre-registered entry)", len(rep.Entries))
	}
	for _, e := range rep.Entries {
		if e.Status != StatusCancelled {
			t.Errorf("%s: status = %s, want cancelled", e.URL, e.Status)
		}
		if e.Err == nil {
			t.Errorf("%s: no cancellation cause", e.URL)
		}
	}
}

func TestEngineConcurrencyLeak(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.Concurrency = 8
	var items []Item
	for i := 0; i < 200; i++ {
		items = append(items, Item{Kind: ItemLine, Line: fmt.Sprintf("http://js.test/f%d.js", i)})
	}

	baseline := runtime.NumGoroutine() // after the server is up, before the run
	runEngine(t, cfg, items)

	// Shutdown is the join point: after Run returns, every pool-owned
	// goroutine must be gone and the count must settle back to baseline.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+2 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines did not settle: %d, baseline %d", runtime.NumGoroutine(), baseline)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := srv.count(); got != 200 {
		t.Errorf("server requests = %d, want 200", got)
	}
}

func TestEngineDeterminism(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, "console.log(%q);\n", r.URL.Path)
	})
	cfg := testEngineConfig(t, srv.srv)
	items := []Item{
		{Kind: ItemLine, Line: "http://js.test/a.js"},
		{Kind: ItemLine, Line: "http://js.test/b.js?x=1"},
		{Kind: ItemLine, Line: "http://js.test/a.js"}, // duplicate candidate
	}
	rep1 := runEngine(t, cfg, items)
	rep2 := runEngine(t, cfg, items)
	if !reflect.DeepEqual(rep1, rep2) {
		t.Errorf("two identical runs produced different reports:\n%+v\nvs\n%+v", rep1, rep2)
	}
}

func TestEngineEmitHook(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	var mu sync.Mutex
	var emitted []JSEntry
	cfg.Emit = func(_ context.Context, e JSEntry) error {
		mu.Lock()
		emitted = append(emitted, e)
		mu.Unlock()
		return nil
	}
	items := []Item{
		{Kind: ItemLine, Line: "http://js.test/a.js"},
		{Kind: ItemLine, Line: "http://js.test/b.js"},
		{Kind: ItemLine, Line: "http://js.test/c.js"},
	}
	rep := runEngine(t, cfg, items)

	mu.Lock()
	defer mu.Unlock()
	if len(emitted) != 3 {
		t.Fatalf("emitted = %d, want one emit per entry (3)", len(emitted))
	}
	seen := make(map[string]bool)
	for _, e := range rep.Entries {
		seen[e.URL.String()] = true
	}
	for _, e := range emitted {
		if !seen[e.URL.String()] {
			t.Errorf("emitted %s which is not a report entry", e.URL)
		}
	}
}

func TestEngineEmitHookPanicContained(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.Emit = func(context.Context, JSEntry) error { panic("boom") }
	items := []Item{
		{Kind: ItemLine, Line: "http://js.test/a.js"},
		{Kind: ItemLine, Line: "http://js.test/b.js"},
	}

	rep, err := Run(context.Background(), cfg, SliceSource(items))
	if err == nil || !strings.Contains(err.Error(), "emit hook panicked") {
		t.Fatalf("Run error = %v, want a contained emit-hook panic diagnostic", err)
	}
	if len(rep.Entries) != 2 {
		t.Errorf("entries = %d, want 2 (a panicking hook must not lose observations)", len(rep.Entries))
	}
}

func TestEngineD2Extraction(t *testing.T) {
	// A script with an import, endpoint references, a secret candidate,
	// and a technology marker: the entry carries the classified assets and
	// every derived edge.
	body := []byte(`
import "./lib.js";
const api = "/api/v1/users";
const ws = "wss://example.com/socket";
const key = "AKIAIOSFODNN7EXAMPLE";
window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = true;
`)
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(body)
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}})
	e := entryByURL(t, rep, "http://js.test/app.js")

	// Endpoint candidates with their classes. The import specifier
	// "./lib.js" is a string literal too, so it is also an endpoint
	// candidate (the parser contract: consumers filter the literal
	// stream; endpoint extraction does not special-case imports).
	if len(e.Endpoints) != 3 {
		t.Fatalf("endpoints = %d, want 3", len(e.Endpoints))
	}
	classes := map[string]string{}
	for _, ep := range e.Endpoints {
		classes[ep.URL.String()] = ep.Method
	}
	wantClasses := map[string]string{
		"http://js.test/api/v1/users": "GET",
		"wss://example.com/socket":    "WS",
		"http://js.test/lib.js":       "GET",
	}
	if len(classes) != len(wantClasses) {
		t.Fatalf("classes = %v, want %v", classes, wantClasses)
	}
	for raw, method := range wantClasses {
		if classes[raw] != method {
			t.Errorf("class of %s = %q, want %q", raw, classes[raw], method)
		}
	}
	// The wss:// endpoint is a different host:port observation, so it is
	// ALSO a URL asset.
	if len(e.URLs) != 1 || e.URLs[0].String() != "wss://example.com/socket" {
		t.Errorf("urls = %v, want the different-host socket URL", e.URLs)
	}

	// Secret candidate (detection only).
	if len(e.Secrets) != 1 || e.Secrets[0].Type != asset.SecretTypeAWS || e.Secrets[0].Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("secrets = %+v, want the AWS candidate", e.Secrets)
	}

	// Technology + per-marker evidence.
	if len(e.Technologies) != 1 || e.Technologies[0].Name != "react" {
		t.Errorf("technologies = %+v, want react", e.Technologies)
	}
	if len(e.Evidence) != 1 || e.Evidence[0].Method != asset.MethodJS {
		t.Errorf("evidence = %+v, want one js marker", e.Evidence)
	}

	// Relationships carry the D1 and D2 edges.
	wantKinds := map[asset.RelationshipKind]bool{
		asset.RelationshipJavaScriptToJavaScript:      false,
		asset.RelationshipJavaScriptToEndpoint:        false,
		asset.RelationshipJavaScriptToSecretCandidate: false,
		asset.RelationshipJavaScriptToTechnology:      false,
		asset.RelationshipTechnologyToEvidence:        false,
	}
	for _, r := range e.Relationships {
		if _, ok := wantKinds[r.Kind]; ok {
			wantKinds[r.Kind] = true
		}
	}
	for kind, seen := range wantKinds {
		if !seen {
			t.Errorf("relationships lack an edge of kind %s", kind)
		}
	}
	if len(e.Imports) != 1 {
		t.Errorf("imports = %d, want 1 (the lib.js edge)", len(e.Imports))
	}
	// The lib.js expansion still happened (the D1 path is unchanged).
	if len(rep.Entries) != 2 {
		t.Errorf("entries = %v, want app.js and lib.js", entryURLs(rep))
	}
}

func TestEngineAnalyzeCacheHitServesStoredAnalysis(t *testing.T) {
	body := []byte(`
import "./lib.js";
const api = "/api/v1/users";
const key = "AKIAIOSFODNN7EXAMPLE";
window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = true;
`)
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(body)
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.Cache = openTestCache(t)
	items := []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}}

	rep1 := runEngine(t, cfg, items)
	if rep1.Metrics().Parses != 2 {
		t.Fatalf("run 1 parses = %d, want 2 (app.js and its expanded import lib.js)", rep1.Metrics().Parses)
	}
	rep2 := runEngine(t, cfg, items)
	e2 := entryByURL(t, rep2, "http://js.test/app.js")
	if !e2.Cached {
		t.Fatal("run 2 must be a cache hit")
	}
	if rep2.Metrics().Parses != 0 {
		t.Errorf("run 2 parses = %d, want 0 (the analysis is served from the js.analyze record)", rep2.Metrics().Parses)
	}
	if srv.count() != 2 {
		t.Errorf("server requests = %d, want 2 (app.js + its import lib.js on run 1 only; run 2 performs zero network)", srv.count())
	}
	// The cache-served entry is byte-identical in payload to the fresh one.
	e1 := entryByURL(t, rep1, "http://js.test/app.js")
	if !reflect.DeepEqual(e1.JS, e2.JS) {
		t.Errorf("cached JS asset differs:\n%+v\nvs\n%+v", *e1.JS, *e2.JS)
	}
	if !reflect.DeepEqual(e1.Endpoints, e2.Endpoints) ||
		!reflect.DeepEqual(e1.URLs, e2.URLs) ||
		!reflect.DeepEqual(e1.Secrets, e2.Secrets) ||
		!reflect.DeepEqual(e1.Technologies, e2.Technologies) ||
		!reflect.DeepEqual(e1.Evidence, e2.Evidence) ||
		!reflect.DeepEqual(e1.Relationships, e2.Relationships) {
		t.Errorf("cache-served D2 payload differs from the fresh one")
	}

	// Self-healing fall-through: deleting the analyze record makes the
	// next run re-analyze (parse) while the fetch is still served from
	// cache — zero network, one parse.
	key, err := analyzeKey(mustURL(t, "http://js.test/app.js"))
	if err != nil {
		t.Fatalf("analyzeKey: %v", err)
	}
	if err := cfg.Cache.Delete(context.Background(), key); err != nil {
		t.Fatalf("delete analyze record: %v", err)
	}
	rep3 := runEngine(t, cfg, items)
	e3 := entryByURL(t, rep3, "http://js.test/app.js")
	if !e3.Cached {
		t.Fatal("run 3 fetch must still be a cache hit")
	}
	if rep3.Metrics().Parses != 1 {
		t.Errorf("run 3 parses = %d, want 1 (the analysis record was deleted, so it re-parses)", rep3.Metrics().Parses)
	}
	if srv.count() != 2 {
		t.Errorf("server requests = %d, want 2 (run 3 still performs zero network)", srv.count())
	}
	if !reflect.DeepEqual(e2.Endpoints, e3.Endpoints) || !reflect.DeepEqual(e2.Secrets, e3.Secrets) {
		t.Errorf("re-analyzed D2 payload differs from the cache-served one")
	}
}

// TestEngineOverlongSpecifierNoChurn pins the >maxParserStringBytes
// specifier path end to end. The parser's addImport is the SINGLE capture
// point for every import form: a 5000-byte line-continuation specifier is
// dropped there (counted malformed at the parser) and never enters
// Parsed.Imports, so run 1 leaves a completed entry with NO import edge to
// a bogus overlong target and exactly ONE stored js.analyze record;
// run 2 serves that record from cache with ZERO parses and byte-identical
// payloads. Without the cap the overlong specifier would be stored,
// rejected by decodeStoredAnalyze, deleted, and re-parsed on every run —
// permanent delete/recompute churn.
func TestEngineOverlongSpecifierNoChurn(t *testing.T) {
	// A legal line-continuation string: the escaped newline is consumed,
	// yielding one 5001-byte printable specifier — over the 4096 cap.
	overlong := "import x from \"a" + "\\\n" + strings.Repeat("b", 5000) + "\";\n"

	// The capture point: the overlong specifier drops with malformed=1
	// and nothing enters Parsed.Imports; the boundary is exact (4096
	// round-trips, 4097 drops).
	pr := parse(t, overlong)
	if pr.Malformed != 1 || len(pr.Imports) != 0 || pr.Truncated {
		t.Errorf("parse of the served script: malformed=%d imports=%d truncated=%v, want malformed 1, no imports, not truncated", pr.Malformed, len(pr.Imports), pr.Truncated)
	}
	boundary := func(n int) string { return "import y from \"a" + "\\\n" + strings.Repeat("b", n-1) + "\";" }
	for _, tc := range []struct {
		name        string
		n           int
		wantMal     int
		wantImports int
	}{
		{name: "at the cap round-trips", n: maxParserStringBytes, wantMal: 0, wantImports: 1},
		{name: "one over the cap drops", n: maxParserStringBytes + 1, wantMal: 1, wantImports: 0},
	} {
		r := parse(t, boundary(tc.n))
		if r.Malformed != tc.wantMal || len(r.Imports) != tc.wantImports {
			t.Errorf("%s (%d bytes): malformed=%d imports=%d, want malformed %d imports %d",
				tc.name, tc.n, r.Malformed, len(r.Imports), tc.wantMal, tc.wantImports)
		}
	}

	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(overlong))
	})
	cfg := testEngineConfig(t, srv.srv)
	counting := countingRT{inner: transportFor(t, srv.srv)}
	cfg.Transport = &counting
	cfg.Cache = openTestCache(t)
	items := []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}}

	rep1 := runEngine(t, cfg, items)
	if len(rep1.Entries) != 1 {
		t.Fatalf("entries = %v, want app.js only (a dropped specifier must not expand)", entryURLs(rep1))
	}
	e1 := entryByURL(t, rep1, "http://js.test/app.js")
	if e1.Status != StatusCompleted {
		t.Errorf("status = %s, want completed (the drop is a counted recovery, not a truncation)", e1.Status)
	}
	if e1.Cached || e1.JS == nil {
		t.Errorf("run 1: cached = %v, JS nil = %v, want a fresh fetch with a JS asset", e1.Cached, e1.JS == nil)
	}
	if len(e1.Imports) != 0 || len(e1.BareImports) != 0 {
		t.Errorf("imports = %d, bare = %d, want no edge or bare entry for the overlong specifier", len(e1.Imports), len(e1.BareImports))
	}
	m1 := rep1.Metrics()
	if m1.Parses != 1 || m1.Fetches != 1 || m1.Reads != 2 || m1.Stores != 2 {
		t.Errorf("run 1 metrics = %+v, want 1 parse, 1 fetch, 2 reads, 2 stores (js.fetch + js.analyze)", m1)
	}
	if m1.Malformed != 0 {
		t.Errorf("run 1 malformed = %d, want 0 (the overlong drop is counted at the parser capture point above; the engine metric counts extraction-layer rejects only)", m1.Malformed)
	}
	// The analyze record is stored COMPLETED (served as a hit on run 2):
	// a single store, nothing deleted or recomputed.
	key, err := analyzeKey(mustURL(t, "http://js.test/app.js"))
	if err != nil {
		t.Fatalf("analyzeKey: %v", err)
	}
	out := cfg.Cache.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatal("run 1 must leave a cache record for js.analyze")
	}
	if out.Record.Operation != AnalyzeOperation || out.Record.Status != cache.StatusCompleted {
		t.Errorf("stored record = operation %q status %q, want %q/%q", out.Record.Operation, out.Record.Status, AnalyzeOperation, cache.StatusCompleted)
	}

	rep2 := runEngine(t, cfg, items)
	e2 := entryByURL(t, rep2, "http://js.test/app.js")
	if !e2.Cached {
		t.Fatal("run 2 must be served from the completed js.fetch + js.analyze records")
	}
	m2 := rep2.Metrics()
	if m2.Parses != 0 {
		t.Errorf("run 2 parses = %d, want 0 (the analyze record serves the analysis: no recompute)", m2.Parses)
	}
	if m2.Fetches != 0 || m2.Stores != 0 {
		t.Errorf("run 2 fetches/stores = %d/%d, want 0/0 (no network, no record churn)", m2.Fetches, m2.Stores)
	}
	if m2.Reads != 2 {
		t.Errorf("run 2 reads = %d, want 2 (one js.fetch lookup and one js.analyze lookup)", m2.Reads)
	}
	if counting.calls() != 1 {
		t.Errorf("round trips = %d, want 1 (run 1's single fetch; run 2 performs zero network)", counting.calls())
	}
	if srv.count() != 1 {
		t.Errorf("server requests = %d, want 1 (run 2 cache-served)", srv.count())
	}
	// The cache-served entry is byte-identical to the fresh one.
	if !reflect.DeepEqual(e1.JS, e2.JS) {
		t.Errorf("cached JS asset differs:\n%+v\nvs\n%+v", *e1.JS, *e2.JS)
	}
	if !reflect.DeepEqual(e1.Imports, e2.Imports) ||
		!reflect.DeepEqual(e1.BareImports, e2.BareImports) ||
		!reflect.DeepEqual(e1.Exports, e2.Exports) ||
		!reflect.DeepEqual(e1.Endpoints, e2.Endpoints) ||
		!reflect.DeepEqual(e1.URLs, e2.URLs) ||
		!reflect.DeepEqual(e1.Secrets, e2.Secrets) ||
		!reflect.DeepEqual(e1.Technologies, e2.Technologies) ||
		!reflect.DeepEqual(e1.Evidence, e2.Evidence) ||
		!reflect.DeepEqual(e1.Relationships, e2.Relationships) {
		t.Errorf("cache-served entry data differs from the fresh one")
	}
}

// TestEngineAnalyzeRebindsOnContentChange pins the M-5 content binding end
// to end: a js.analyze record is bound to the content hash it was derived
// from, so a refreshed fetch with NEW content can never pair with an OLD
// analysis (fetch and analyze records have independent lifecycles). Content
// A is analyzed on run 1; the js.fetch record is then deleted and the
// server switches to content B, so run 2 re-fetches B: the stale analyze
// record (bound to A) must be refused and deleted, B must be re-analyzed,
// and the record rebound to B's hash under the SAME key. Run 3 is fully
// cache-served (zero parses); run 4 refreshes the fetch again with
// IDENTICAL content B — the stored analysis must still serve.
func TestEngineAnalyzeRebindsOnContentChange(t *testing.T) {
	contentA := []byte(`const api = "/api/alpha";`)
	contentB := []byte(`const api = "/api/beta";`)
	var served atomic.Value // holds []byte
	served.Store(contentA)
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(served.Load().([]byte))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.Cache = openTestCache(t)
	items := []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}}
	u := mustURL(t, "http://js.test/app.js")

	endpointURLs := func(rep Report) []string {
		e := entryByURL(t, rep, "http://js.test/app.js")
		out := make([]string, 0, len(e.Endpoints))
		for _, ep := range e.Endpoints {
			out = append(out, ep.URL.String())
		}
		return out
	}
	has := func(xs []string, x string) bool {
		for _, y := range xs {
			if y == x {
				return true
			}
		}
		return false
	}

	// Run 1: content A analyzed fresh; the record is bound to A's hash.
	rep1 := runEngine(t, cfg, items)
	if m := rep1.Metrics(); m.Parses != 1 || m.Fetches != 1 {
		t.Fatalf("run 1 metrics = %+v, want 1 parse, 1 fetch", m)
	}
	if eps := endpointURLs(rep1); !has(eps, "http://js.test/api/alpha") {
		t.Errorf("run 1 endpoints = %v, want /api/alpha", eps)
	}

	// Refresh the fetch with NEW content: delete the js.fetch record (the
	// js.analyze record stays) and switch the server to content B.
	fkey, err := fetchKey(u)
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}
	if err := cfg.Cache.Delete(context.Background(), fkey); err != nil {
		t.Fatalf("delete fetch record: %v", err)
	}
	served.Store(contentB)

	// Run 2: the refreshed fetch serves B, and the stale analyze record
	// (bound to A) must NOT serve — it is deleted and B is re-analyzed.
	// The discard is a routine lifecycle event (content change between
	// runs), so it must NOT surface a run-error diagnostic: runEngine
	// fails the test on any run error, so passing run 2 asserts the
	// silent-miss behavior end to end.
	rep2 := runEngine(t, cfg, items)
	if m := rep2.Metrics(); m.Fetches != 1 || m.Parses != 1 || m.Stores != 2 {
		t.Fatalf("run 2 metrics = %+v, want 1 fetch, 1 parse (stale analysis refused), 2 stores (js.fetch + rebound js.analyze)", m)
	}
	if e2 := entryByURL(t, rep2, "http://js.test/app.js"); e2.Cached {
		t.Error("run 2 must be a fresh fetch (the fetch record was deleted)")
	}
	eps2 := endpointURLs(rep2)
	if !has(eps2, "http://js.test/api/beta") {
		t.Errorf("run 2 endpoints = %v, want /api/beta (a fresh analysis of content B)", eps2)
	}
	if has(eps2, "http://js.test/api/alpha") {
		t.Errorf("run 2 endpoints = %v, contain the OLD analysis's /api/alpha", eps2)
	}

	// The rebound record carries B's hash under the SAME key.
	akey, err := analyzeKey(u)
	if err != nil {
		t.Fatalf("analyzeKey: %v", err)
	}
	out := cfg.Cache.Get(context.Background(), akey)
	if !out.IsHit() {
		t.Fatal("run 2 must leave a completed js.analyze record")
	}
	var st storedAnalyze
	if err := json.Unmarshal(out.Record.Data, &st); err != nil {
		t.Fatalf("decode stored analyze: %v", err)
	}
	if want := hex.EncodeToString(sha256Sum(contentB)); st.AnalyzedHash != want {
		t.Errorf("stored analyzed_hash = %q, want %q (the hash of content B)", st.AnalyzedHash, want)
	}

	// Run 3: both records cache-served — zero network, zero parses.
	rep3 := runEngine(t, cfg, items)
	if m := rep3.Metrics(); m.Parses != 0 || m.Fetches != 0 || m.Stores != 0 {
		t.Errorf("run 3 metrics = %+v, want 0 parses/fetches/stores (full cache)", m)
	}
	if !entryByURL(t, rep3, "http://js.test/app.js").Cached {
		t.Error("run 3 must be fully cache-served")
	}
	if eps := endpointURLs(rep3); !has(eps, "http://js.test/api/beta") {
		t.Errorf("run 3 endpoints = %v, want /api/beta", eps)
	}

	// Run 4: refresh the fetch again with IDENTICAL content B — the
	// stored analysis, still bound to B's hash, must serve (zero parses).
	if err := cfg.Cache.Delete(context.Background(), fkey); err != nil {
		t.Fatalf("delete fetch record (run 4): %v", err)
	}
	rep4 := runEngine(t, cfg, items)
	if m := rep4.Metrics(); m.Fetches != 1 || m.Parses != 0 {
		t.Errorf("run 4 metrics = %+v, want 1 fetch, 0 parses (identical content still serves the hit)", m)
	}
	if eps := endpointURLs(rep4); !has(eps, "http://js.test/api/beta") {
		t.Errorf("run 4 endpoints = %v, want /api/beta", eps)
	}
}

func TestEngineRetentionDisabledByDefault(t *testing.T) {
	// The default memory profile is unchanged: without Config.RetainContent
	// entries carry no content and RetainedContent() is empty, even though
	// the fetch itself retained the body for analysis.
	body := []byte("var app = {x: 1};\n")
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(body)
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}})

	e := rep.Entries[0]
	if e.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", e.Status)
	}
	if e.Content != nil {
		t.Errorf("entry content = %q, want nil (retention disabled by default)", e.Content)
	}
	if got := rep.RetainedContent(); len(got) != 0 {
		t.Errorf("RetainedContent() = %+v, want empty", got)
	}
}

func TestEngineRetentionEnabled(t *testing.T) {
	body := []byte("var app = {x: 1};\nconsole.log(\"hi\");\n")
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(body)
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.RetainContent = true
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}})

	e := rep.Entries[0]
	if e.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", e.Status)
	}
	if !bytes.Equal(e.Content, body) {
		t.Errorf("entry content = %q, want the exact body %q", e.Content, body)
	}
	got := rep.RetainedContent()
	if len(got) != 1 {
		t.Fatalf("RetainedContent() = %+v, want one retained body", got)
	}
	if got[0].URL.String() != "http://js.test/app.js" {
		t.Errorf("retained URL = %q, want http://js.test/app.js", got[0].URL.String())
	}
	if !bytes.Equal(got[0].Content, body) {
		t.Errorf("retained content = %q, want the exact body", got[0].Content)
	}
}

func TestEngineRetentionNonJSCompletedPositive(t *testing.T) {
	// A completed positive that is not a JS asset (an HTML body) is still
	// retained when the flag is on: documents legitimately include observed
	// content, and the content is fully retained by construction.
	html := []byte("<html><body>hello</body></html>")
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(html)
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.RetainContent = true
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/page"}})

	e := rep.Entries[0]
	if e.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", e.Status)
	}
	if e.JS != nil {
		t.Fatal("a non-JS body must not produce a JS asset")
	}
	if !bytes.Equal(e.Content, html) {
		t.Errorf("entry content = %q, want the HTML body", e.Content)
	}
	if got := rep.RetainedContent(); len(got) != 1 {
		t.Fatalf("RetainedContent() = %+v, want one retained body", got)
	}
}

func TestEngineRetentionTruncatedNeverRetainsPrefix(t *testing.T) {
	// Retention never weakens the truncation honesty contract: a truncated
	// fetch's partial prefix is NEVER retained, flag or no flag.
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(100<<10))
		w.Write(bytes.Repeat([]byte("x"), 100<<10))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.MaxJSBytes = 64 << 10 // the 100 KiB body truncates
	cfg.RetainContent = true
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/big.js"}})

	e := rep.Entries[0]
	if e.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete (truncated fetch)", e.Status)
	}
	if e.Content != nil {
		t.Errorf("entry content = %q, want nil (a partial prefix is never retained)", e.Content)
	}
	if got := rep.RetainedContent(); len(got) != 0 {
		t.Errorf("RetainedContent() = %+v, want empty (no complete body)", got)
	}
}

func TestEngineRetentionCacheHitRestoresContent(t *testing.T) {
	// The js.fetch cache record stores the content byte-identically, so a
	// completed cache hit restores the SAME retained body as the fresh
	// fetch — retention works on both paths.
	body := []byte("var app = {x: 1};\n")
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(body)
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.RetainContent = true
	cfg.Cache = openTestCache(t)
	items := []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}}

	rep1 := runEngine(t, cfg, items)
	if rep1.Entries[0].Cached {
		t.Fatal("run 1 must be a fresh fetch")
	}
	rep2 := runEngine(t, cfg, items)
	if !rep2.Entries[0].Cached {
		t.Fatal("run 2 must be served from the completed cache record")
	}
	if !bytes.Equal(rep1.Entries[0].Content, body) {
		t.Errorf("run 1 content = %q, want the body", rep1.Entries[0].Content)
	}
	if !bytes.Equal(rep2.Entries[0].Content, body) {
		t.Errorf("run 2 (cached) content = %q, want the byte-identical body", rep2.Entries[0].Content)
	}
	if got := rep2.RetainedContent(); len(got) != 1 || !bytes.Equal(got[0].Content, body) {
		t.Errorf("run 2 RetainedContent() = %+v, want the body", got)
	}
}

func TestMergeEntriesRetentionFirstSeenWins(t *testing.T) {
	// The retained body merges first-seen-wins: the earliest observation's
	// body is the entry's, and an entry without content adopts the first
	// observed one (mirrors the JS asset's earliest-observation-wins rule).
	cfg := DefaultConfig()
	u := mustURL(t, "http://js.test/app.js")
	first := JSEntry{URL: u, Status: StatusCompleted, Content: []byte("first body")}
	second := JSEntry{URL: u, Status: StatusCompleted, Content: []byte("second body")}

	dst := first
	mergeEntries(&dst, second, cfg)
	if !bytes.Equal(dst.Content, []byte("first body")) {
		t.Errorf("merged content = %q, want the first-seen body", dst.Content)
	}

	dst2 := JSEntry{URL: u, Status: StatusCompleted}
	mergeEntries(&dst2, second, cfg)
	if !bytes.Equal(dst2.Content, []byte("second body")) {
		t.Errorf("adopted content = %q, want the first observed body", dst2.Content)
	}
}

func TestReportRetainedContentSortedDedupedNilSkipped(t *testing.T) {
	// RetainedContent mirrors the report's other merged accessors: sorted
	// by canonical URL string, deduplicated by URL identity (earliest wins),
	// and including only entries with non-nil Content — even for a
	// hand-built report whose entries are unsorted and carry duplicate
	// URLs (real reports hold one sorted entry per URL, so the
	// normalization is a no-op there).
	ua := mustURL(t, "http://js.test/a.js")
	ub := mustURL(t, "http://js.test/b.js")
	uc := mustURL(t, "http://js.test/c.js")
	rep := Report{Entries: []JSEntry{
		// Out of canonical order, and a.js appears twice with two bodies.
		{URL: uc, Status: StatusCompleted, Content: []byte("c body")},
		{URL: ua, Status: StatusCompleted, Content: []byte("a body")},
		{URL: ub, Status: StatusCompleted},                                  // nil content: skipped
		{URL: ua, Status: StatusCompleted, Content: []byte("a body later")}, // duplicate URL: dropped
	}}
	got := rep.RetainedContent()
	want := []RetainedContent{
		{URL: ua, Content: []byte("a body")},
		{URL: uc, Content: []byte("c body")},
	}
	if len(got) != len(want) {
		t.Fatalf("RetainedContent() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].URL.String() != want[i].URL.String() {
			t.Errorf("retained[%d] URL = %q, want %q", i, got[i].URL.String(), want[i].URL.String())
		}
		if !bytes.Equal(got[i].Content, want[i].Content) {
			t.Errorf("retained[%d] content = %q, want %q", i, got[i].Content, want[i].Content)
		}
	}
}
