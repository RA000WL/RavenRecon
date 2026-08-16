package jsintel

import (
	"net/http"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// testSourceMapConfig returns a Config for extractSourceMaps unit tests.
func testSourceMapConfig() Config {
	return Config{Source: "test-src", Clock: newFakeClock(fixedTime)}
}

func TestExtractSourceMapsComment(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u, Prov: asset.Provenance{Source: "test-src"}}
	parsed := Parsed{HasSourceMapRef: true, SourceMapRef: "/app.js.map"}
	out := extractSourceMaps(js, FetchResult{}, parsed, testSourceMapConfig())

	if len(out.maps) != 1 {
		t.Fatalf("maps = %d, want 1", len(out.maps))
	}
	m := out.maps[0]
	if m.URL.String() != "https://example.com/app.js.map" {
		t.Errorf("map URL = %q", m.URL)
	}
	if m.Prov.Source != "test-src" || !m.Prov.DiscoveredAt.Equal(fixedTime) {
		t.Errorf("map provenance = %+v", m.Prov)
	}
	if len(out.edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(out.edges))
	}
	wantEdge, err := asset.NewRelationship(
		js.Identity(),
		asset.RelationshipJavaScriptToSourceMap,
		m.Identity(),
	)
	if err != nil {
		t.Fatalf("build expected edge: %v", err)
	}
	if out.edges[0].ID() != wantEdge.ID() {
		t.Errorf("edge = %q, want %q", out.edges[0].ID(), wantEdge.ID())
	}
	if out.skipped != 0 || out.dropped != 0 {
		t.Errorf("skipped = %d, dropped = %d, want 0/0", out.skipped, out.dropped)
	}
}

func TestExtractSourceMapsHeader(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	res := FetchResult{XSourceMap: "../maps/app.js.map"}
	out := extractSourceMaps(js, res, Parsed{}, testSourceMapConfig())

	if len(out.maps) != 1 {
		t.Fatalf("maps = %d, want 1", len(out.maps))
	}
	if out.maps[0].URL.String() != "https://example.com/maps/app.js.map" {
		t.Errorf("map URL = %q, want the reference resolved against the file URL", out.maps[0].URL)
	}
}

func TestExtractSourceMapsDedup(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	parsed := Parsed{HasSourceMapRef: true, SourceMapRef: "/app.js.map"}
	res := FetchResult{XSourceMap: "/app.js.map"}
	out := extractSourceMaps(js, res, parsed, testSourceMapConfig())

	if len(out.maps) != 1 {
		t.Fatalf("maps = %d, want 1 (the same map URL from both sources is one asset)", len(out.maps))
	}
	if len(out.edges) != 1 {
		t.Errorf("edges = %d, want 1", len(out.edges))
	}
}

func TestExtractSourceMapsDataSkipped(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	parsed := Parsed{HasSourceMapRef: true, SourceMapRef: "data:application/json;base64,xx"}
	res := FetchResult{XSourceMap: "bare-map-name"}
	out := extractSourceMaps(js, res, parsed, testSourceMapConfig())

	if len(out.maps) != 0 {
		t.Fatalf("maps = %d, want 0 (data: and bare references never resolve)", len(out.maps))
	}
	if out.skipped != 2 {
		t.Errorf("skipped = %d, want 2", out.skipped)
	}
	if out.dropped != 0 {
		t.Errorf("dropped = %d, want 0", out.dropped)
	}
}

func TestExtractSourceMapsCap(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	parsed := Parsed{HasSourceMapRef: true, SourceMapRef: "/a.map"}
	res := FetchResult{XSourceMap: "/b.map"}
	cfg := testSourceMapConfig()
	cfg.MaxSourceMapsPerFile = 1
	out := extractSourceMaps(js, res, parsed, cfg)

	if len(out.maps) != 1 {
		t.Fatalf("maps = %d, want 1 (the cap)", len(out.maps))
	}
	if out.maps[0].URL.String() != "https://example.com/a.map" {
		t.Errorf("map URL = %q, want the comment reference first", out.maps[0].URL)
	}
	if out.dropped != 1 {
		t.Errorf("dropped = %d, want 1", out.dropped)
	}
}

func TestEngineSourceMapDetectionNoFetch(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("X-SourceMap", "/app.js.map")
		w.Write([]byte("var x = 1;\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	rep := runEngine(t, cfg, []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}})

	e := rep.Entries[0]
	if len(e.SourceMaps) != 1 {
		t.Fatalf("source maps = %d, want 1", len(e.SourceMaps))
	}
	m := e.SourceMaps[0]
	if m.URL.String() != "http://js.test/app.js.map" {
		t.Errorf("map URL = %q", m.URL)
	}
	if m.Prov.Source != "test-source" {
		t.Errorf("map provenance source = %q, want test-source", m.Prov.Source)
	}
	if srv.count() != 1 {
		t.Errorf("server requests = %d, want 1 (source maps are detection-only: never fetched)", srv.count())
	}
	// The map edge is part of the entry's relationships.
	wantEdge, err := asset.NewRelationship(
		asset.Identity{Kind: asset.KindJavaScript, Value: "http://js.test/app.js"},
		asset.RelationshipJavaScriptToSourceMap,
		m.Identity(),
	)
	if err != nil {
		t.Fatalf("build expected edge: %v", err)
	}
	found := false
	for _, r := range e.Relationships {
		if r.ID() == wantEdge.ID() {
			found = true
		}
	}
	if !found {
		t.Errorf("relationships %v do not contain the source map edge", e.Relationships)
	}
}

func TestEngineSourceMapCacheHitReExtraction(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("X-SourceMap", "/app.js.map")
		w.Write([]byte("var x = 1;\n//# sourceMappingURL=/app.js.map\n"))
	})
	cfg := testEngineConfig(t, srv.srv)
	cfg.Cache = openTestCache(t)
	items := []Item{{Kind: ItemLine, Line: "http://js.test/app.js"}}

	rep1 := runEngine(t, cfg, items)
	if len(rep1.Entries[0].SourceMaps) != 1 {
		t.Fatalf("run 1 source maps = %d, want 1 (comment and header deduplicate)", len(rep1.Entries[0].SourceMaps))
	}
	rep2 := runEngine(t, cfg, items)
	if !rep2.Entries[0].Cached {
		t.Fatal("run 2 must be a cache hit")
	}
	if len(rep2.Entries[0].SourceMaps) != 1 {
		t.Errorf("run 2 source maps = %d, want 1 (re-extracted from the restored content and header)", len(rep2.Entries[0].SourceMaps))
	}
	if srv.count() != 1 {
		t.Errorf("server requests = %d, want 1 (run 2 performs zero network)", srv.count())
	}
}
