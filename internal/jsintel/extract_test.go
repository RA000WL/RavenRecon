// Endpoint extraction tests: classification classes, different-host URL
// observations, skip accounting, and the per-file cap.
package jsintel

import (
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// testExtractConfig returns a Config for endpoint extraction unit tests.
func testExtractConfig() Config {
	return Config{Source: "test-src", Clock: newFakeClock(fixedTime)}
}

func TestExtractEndpointsClasses(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u, Prov: asset.Provenance{Source: "test-src"}}
	parsed := Parsed{Strings: []StringLit{
		{Value: "/api/v1/users"},
		{Value: "https://example.com/graphql"},
		{Value: "wss://example.com/socket"},
		{Value: "/events/stream"},
		{Value: "./lib/x.js"},
	}}
	out := extractEndpoints(js, parsed, testExtractConfig())

	if len(out.endpoints) != 5 {
		t.Fatalf("endpoints = %d, want 5", len(out.endpoints))
	}
	classes := map[string]string{}
	for _, ep := range out.endpoints {
		classes[ep.URL.String()] = ep.Method
		if ep.Prov.Source != "test-src" || !ep.Prov.DiscoveredAt.Equal(fixedTime) {
			t.Errorf("endpoint provenance = %+v, want test-src at %v", ep.Prov, fixedTime)
		}
	}
	want := map[string]string{
		"https://example.com/api/v1/users":  "GET",
		"https://example.com/graphql":       "GQL",
		"wss://example.com/socket":          "WS",
		"https://example.com/events/stream": "SSE",
		"https://example.com/lib/x.js":      "GET",
	}
	if len(classes) != len(want) {
		t.Fatalf("classes = %v, want %v", classes, want)
	}
	for raw, method := range want {
		if classes[raw] != method {
			t.Errorf("class of %s = %q, want %q", raw, classes[raw], method)
		}
	}
	if len(out.edges) != 5 {
		t.Fatalf("edges = %d, want 5 (1:1 with endpoints)", len(out.edges))
	}
	if len(out.urls) != 0 {
		t.Errorf("urls = %v, want none (all candidates share the file's host)", out.urls)
	}
	if out.skipped != 0 || out.dropped != 0 {
		t.Errorf("skipped/dropped = %d/%d, want 0/0", out.skipped, out.dropped)
	}
}

func TestExtractEndpointsExternalURLs(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	parsed := Parsed{Strings: []StringLit{
		{Value: "https://cdn.example.net/lib.js"},
		{Value: "https://example.com/self.js"}, // same host: endpoint only
	}}
	out := extractEndpoints(js, parsed, testExtractConfig())

	if len(out.endpoints) != 2 {
		t.Fatalf("endpoints = %d, want 2", len(out.endpoints))
	}
	if len(out.urls) != 1 || out.urls[0].String() != "https://cdn.example.net/lib.js" {
		t.Fatalf("urls = %v, want only the different-host observation", out.urls)
	}
	// Every URL observation accompanies an endpoint (the URL list can
	// never exceed the endpoint list).
	if len(out.urls) > len(out.endpoints) {
		t.Errorf("urls (%d) exceed endpoints (%d)", len(out.urls), len(out.endpoints))
	}
}

func TestExtractEndpointsSkipped(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	parsed := Parsed{Strings: []StringLit{
		{Value: "/ok.js"},
		{Value: "/dyn-${x}.js", Template: true}, // dynamic template: skipped
		{Value: "a b"},                          // whitespace: skipped
		{Value: "ab"},                           // too short: skipped
		{Value: "data:text/plain,x"},            // unsupported scheme: skipped
		{Value: "mailto:admin@example.com"},     // unsupported scheme: skipped
		{Value: "javascript:alert(1)"},          // unsupported scheme: skipped
	}}
	out := extractEndpoints(js, parsed, testExtractConfig())

	if len(out.endpoints) != 1 || out.endpoints[0].URL.String() != "https://example.com/ok.js" {
		t.Fatalf("endpoints = %v, want only /ok.js", out.endpoints)
	}
	if out.skipped != 6 {
		t.Errorf("skipped = %d, want 6", out.skipped)
	}
	if out.dropped != 0 {
		t.Errorf("dropped = %d, want 0", out.dropped)
	}
}

func TestExtractEndpointsCap(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	cfg := testExtractConfig()
	cfg.MaxEndpointsPerFile = 2
	parsed := Parsed{Strings: []StringLit{
		{Value: "https://other.example/x.js"}, // external: URL + endpoint retained
		{Value: "/aaa"},
		{Value: "/bbb"},
		{Value: "/ccc"},
	}}
	out := extractEndpoints(js, parsed, cfg)

	if len(out.endpoints) != 2 {
		t.Fatalf("endpoints = %d, want 2 (cap)", len(out.endpoints))
	}
	if len(out.urls) != 1 {
		t.Errorf("urls = %d, want 1 (the external candidate was retained)", len(out.urls))
	}
	if out.dropped != 2 {
		t.Errorf("dropped = %d, want 2", out.dropped)
	}
}
