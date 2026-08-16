package jsintel

import (
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func TestResolveRef(t *testing.T) {
	base := mustURL(t, "https://example.com/app/dir/main.js")

	tests := []struct {
		name     string
		ref      string
		want     string // canonical URL; empty when not resolved
		resolved bool
		bare     bool
	}{
		{name: "absolute http", ref: "http://other.com/x.js", want: "http://other.com/x.js", resolved: true},
		{name: "absolute https", ref: "https://other.com/x.js", want: "https://other.com/x.js", resolved: true},
		{name: "absolute canonicalized", ref: "HTTPS://OTHER.COM:443/X.JS", want: "https://other.com/X.JS", resolved: true},
		{name: "absolute query kept", ref: "http://other.com/x.js?q=1", want: "http://other.com/x.js?q=1", resolved: true},
		{name: "absolute fragment stripped", ref: "http://other.com/x.js#frag", want: "http://other.com/x.js", resolved: true},
		{name: "protocol-relative", ref: "//cdn.example.com/lib.js", want: "https://cdn.example.com/lib.js", resolved: true},
		{name: "root-relative", ref: "/lib.js", want: "https://example.com/lib.js", resolved: true},
		{name: "relative dot", ref: "./lib.js", want: "https://example.com/app/dir/lib.js", resolved: true},
		{name: "relative dotdot", ref: "../lib.js", want: "https://example.com/app/lib.js", resolved: true},
		{name: "relative query preserved", ref: "./lib.js?v=2", want: "https://example.com/app/dir/lib.js?v=2", resolved: true},
		{name: "relative fragment stripped", ref: "./lib.js#frag", want: "https://example.com/app/dir/lib.js", resolved: true},
		{name: "double slash preserved", ref: "/a//b.js", want: "https://example.com/a//b.js", resolved: true},
		{name: "dotdot clamped at root", ref: "/../../x.js", want: "https://example.com/x.js", resolved: true},
		{name: "bare package", ref: "react", bare: true},
		{name: "bare scoped", ref: "@scope/pkg", bare: true},
		{name: "bare path", ref: "lodash/fp", bare: true},
		{name: "data scheme", ref: "data:text/plain,a"},
		{name: "file scheme", ref: "file:///x"},
		{name: "javascript scheme", ref: "javascript:void(0)"},
		{name: "empty", ref: ""},
		{name: "whitespace", ref: "  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, resolved, bare := resolveRef(base, tt.ref)
			if resolved != tt.resolved || bare != tt.bare {
				t.Fatalf("resolved = %v, bare = %v, want %v/%v", resolved, bare, tt.resolved, tt.bare)
			}
			if !resolved {
				return
			}
			if u.String() != tt.want {
				t.Errorf("resolved = %q, want %q", u, tt.want)
			}
		})
	}

	// Without a base there is nothing to resolve relative forms against.
	zero := asset.URL{}
	if _, resolved, bare := resolveRef(zero, "/x.js"); resolved || bare {
		t.Errorf("root-relative without base: resolved = %v, bare = %v, want false/false", resolved, bare)
	}
	if _, resolved, bare := resolveRef(zero, "./x.js"); resolved || bare {
		t.Errorf("relative without base: resolved = %v, bare = %v, want false/false", resolved, bare)
	}
	if u, resolved, bare := resolveRef(zero, "https://example.com/x.js"); !resolved || bare || u.String() != "https://example.com/x.js" {
		t.Errorf("absolute without base: resolved = %v, bare = %v, u = %v", resolved, bare, u)
	}
}

func TestResolveHTMLRef(t *testing.T) {
	page := mustURL(t, "https://example.com/app/page.html")

	tests := []struct {
		name     string
		ref      string
		want     string
		resolved bool
	}{
		{name: "plain name is relative", ref: "x.js", want: "https://example.com/app/x.js", resolved: true},
		{name: "absolute", ref: "http://other.com/x.js", want: "http://other.com/x.js", resolved: true},
		{name: "protocol-relative", ref: "//cdn.example.com/x.js", want: "https://cdn.example.com/x.js", resolved: true},
		{name: "root-relative", ref: "/x.js", want: "https://example.com/x.js", resolved: true},
		{name: "dot", ref: "./x.js", want: "https://example.com/app/x.js", resolved: true},
		{name: "dotdot", ref: "../x.js", want: "https://example.com/x.js", resolved: true},
		{name: "data scheme", ref: "data:text/plain,a"},
		{name: "empty", ref: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, resolved := resolveHTMLRef(page, tt.ref)
			if resolved != tt.resolved {
				t.Fatalf("resolved = %v, want %v", resolved, tt.resolved)
			}
			if resolved && u.String() != tt.want {
				t.Errorf("resolved = %q, want %q", u, tt.want)
			}
		})
	}

	// A zero page URL resolves nothing, not even absolute references: the
	// observation is unusable.
	if _, resolved := resolveHTMLRef(asset.URL{}, "https://example.com/x.js"); resolved {
		t.Error("zero page must not resolve any reference")
	}
}

func TestCleanPathSegments(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "/"},
		{in: "/", want: "/"},
		{in: "/a", want: "/a"},
		{in: "/a/../b", want: "/b"},
		{in: "/../x", want: "/x"},
		{in: "/a/../../x", want: "/x"},
		{in: "/a/./b", want: "/a/b"},
		{in: "/a//b", want: "/a//b"},
		{in: "/a/../", want: "/"},
	}
	for _, tt := range tests {
		if got := cleanPathSegments(tt.in); got != tt.want {
			t.Errorf("cleanPathSegments(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExtractImports(t *testing.T) {
	u := mustURL(t, "https://example.com/app/main.js")
	js := asset.JavaScript{URL: u, Prov: asset.Provenance{Source: "test"}}
	parsed := Parsed{Imports: []Import{
		{Specifier: "./a.js"},
		{Specifier: "./a.js"}, // duplicate: one edge
		{Specifier: "react"},  // bare: external
		{Specifier: "@scope/pkg"},
		{Specifier: ""},                  // unresolvable dynamic: skipped silently
		{Specifier: "data:text/plain,a"}, // unsupported scheme: skipped
	}}
	out := extractImports(js, parsed, normalizeCaps(Config{}))

	if len(out.edges) != 1 {
		t.Fatalf("edges = %d, want 1 (duplicates deduplicated)", len(out.edges))
	}
	wantEdge, err := asset.NewRelationship(
		asset.Identity{Kind: asset.KindJavaScript, Value: "https://example.com/app/main.js"},
		asset.RelationshipJavaScriptToJavaScript,
		asset.Identity{Kind: asset.KindJavaScript, Value: "https://example.com/app/a.js"},
	)
	if err != nil {
		t.Fatalf("build expected edge: %v", err)
	}
	if out.edges[0].ID() != wantEdge.ID() {
		t.Errorf("edge = %q, want %q", out.edges[0].ID(), wantEdge.ID())
	}
	if len(out.resolved) != 1 || out.resolved[0].String() != "https://example.com/app/a.js" {
		t.Errorf("resolved = %v, want a.js", out.resolved)
	}
	if len(out.external) != 2 || out.external[0] != "@scope/pkg" || out.external[1] != "react" {
		t.Errorf("external = %v, want sorted [@scope/pkg react]", out.external)
	}
	if out.skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the data: specifier)", out.skipped)
	}
	if out.dropped != 0 {
		t.Errorf("dropped = %d, want 0", out.dropped)
	}
}

func TestExtractImportsBareSpecifierValidation(t *testing.T) {
	u := mustURL(t, "https://example.com/app/main.js")
	js := asset.JavaScript{URL: u}
	// The parser's addImport already bounds live specifiers; these are the
	// direct/stored-input defense path the stored js.analyze record decode
	// re-validates. A bare specifier with a control byte, or one longer
	// than maxParserStringBytes, must be skipped and counted malformed —
	// never retained in external (the record's own decode would reject it).
	parsed := Parsed{Imports: []Import{
		{Specifier: "react"},                                     // valid bare specifier
		{Specifier: "react\x01control"},                          // control byte: skipped
		{Specifier: strings.Repeat("a", maxParserStringBytes+1)}, // overlong: skipped
	}}
	out := extractImports(js, parsed, normalizeCaps(Config{}))

	if len(out.external) != 1 || out.external[0] != "react" {
		t.Errorf("external = %v, want just [react]", out.external)
	}
	if out.skipped != 2 {
		t.Errorf("skipped = %d, want 2 (control-byte and overlong bare specifiers)", out.skipped)
	}
	if out.dropped != 0 {
		t.Errorf("dropped = %d, want 0", out.dropped)
	}
}

func TestExtractImportsRetentionCap(t *testing.T) {
	u := mustURL(t, "https://example.com/app/main.js")
	js := asset.JavaScript{URL: u}
	cfg := normalizeCaps(Config{MaxImportsPerFile: 2})
	parsed := Parsed{Imports: []Import{
		{Specifier: "./a.js"},
		{Specifier: "./b.js"},
		{Specifier: "./c.js"},
		{Specifier: "pkg-a"},
		{Specifier: "pkg-b"},
		{Specifier: "pkg-c"},
	}}
	out := extractImports(js, parsed, cfg)

	if len(out.edges) != 2 || len(out.resolved) != 2 {
		t.Errorf("edges/resolved = %d/%d, want 2/2", len(out.edges), len(out.resolved))
	}
	if len(out.external) != 2 {
		t.Errorf("external = %v, want 2 entries", out.external)
	}
	if out.dropped != 2 {
		t.Errorf("dropped = %d, want 2 (one resolved and one bare beyond the cap)", out.dropped)
	}
	if out.skipped != 0 {
		t.Errorf("skipped = %d, want 0", out.skipped)
	}
}
