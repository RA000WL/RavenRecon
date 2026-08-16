// Endpoint and URL extraction from parsed string literals: candidates become
// Endpoint assets carrying the extraction CLASS in the Method field (GET/WS/
// SSE/GQL — never an observed HTTP method; see doc.go "Endpoint
// classification") plus javascript_to_endpoint edges; different-host absolute
// URLs are ALSO recorded as URL assets (CDN/external observations). Bounded
// by MaxEndpointsPerFile, deterministic, and never panics.
package jsintel

import (
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// maxEndpointCandidateBytes bounds ONE string literal considered as an
// endpoint candidate. Longer literals are skipped and counted; the parser's
// own per-literal retention cap (maxParserStringBytes, 4096) bounds the
// input, and 1024 is the classification window.
const maxEndpointCandidateBytes = 1024

// sseSuffixes are the canonical last-path-segment suffixes classified as SSE
// endpoints (lowercased). A path whose LAST segment is one of these (and
// whose path is at least 3 bytes) classifies as "SSE".
var sseSuffixes = map[string]struct{}{
	"sse":    {},
	"events": {},
	"stream": {},
}

// endpointExtract is the bounded endpoint + URL extraction of ONE parsed
// file.
type endpointExtract struct {
	// endpoints are the classified endpoint candidates, deduplicated by
	// endpoint identity in source order and bounded by
	// MaxEndpointsPerFile.
	endpoints []asset.Endpoint
	// edges are the javascript_to_endpoint edges (1:1 with endpoints).
	edges []asset.Relationship
	// urls are the URL assets observed in the file whose canonical
	// host:port differs from the file's own (CDN/external observations),
	// deduplicated and bounded by MaxEndpointsPerFile (each such
	// observation also produces an endpoint). No edge kind links them in
	// this phase — the URL asset IS the observation.
	urls []asset.URL
	// skipped counts candidates that could not be classified (dynamic
	// ${...} templates, junk characters, unsupported schemes, bare words,
	// unparseable references, over/under-length) — reported through the
	// Malformed metric.
	skipped int
	// dropped counts candidates beyond the MaxEndpointsPerFile cap —
	// reported through the Skipped metric.
	dropped int
}

// extractEndpoints walks a parsed file's string literals and produces the
// bounded endpoint candidate set plus the different-host URL observations.
//
// Classification contract (see doc.go "Endpoint classification" for the
// full write-up):
//
//   - Template literals whose value contains "${" are DYNAMIC — the value
//     is a partial expression, never a resolvable reference — and are
//     skipped and counted;
//   - a candidate shorter than 3 or longer than maxEndpointCandidateBytes
//     bytes, containing whitespace or any of <>&"' (raw), or that resolves
//     to nothing (bare words, data:/file:/javascript: schemes, emails) is
//     skipped and counted;
//   - ws:// and wss:// absolutes classify as "WS" (and, like every other
//     absolute, are ALSO retained as URL assets when their canonical
//     host:port differs from the file's own);
//   - http(s) absolutes and references resolved against the file's own URL
//     classify by PATH: a segment equal to "graphql" or a .graphql/.gql
//     extension is "GQL"; a last segment in the SSE suffix set with a path
//     of at least 3 bytes is "SSE"; everything else is "GET" (REST
//     candidate);
//   - an absolute whose canonical host:port differs from the file's own is
//     ALSO retained as a URL asset.
//
// Deduplication is per file by endpoint identity (Method + canonical URL);
// candidates beyond MaxEndpointsPerFile are dropped and counted. The cap
// bounds the URL list too: every URL asset accompanies an endpoint, so the
// URL list can never exceed the endpoint list.
func extractEndpoints(js asset.JavaScript, parsed Parsed, cfg Config) endpointExtract {
	// Caps are normalized here so a directly constructed Config (unit
	// tests, embedding callers) applies the documented defaults.
	cfg = normalizeCaps(cfg)
	var out endpointExtract
	seen := make(map[asset.Identity]struct{})
	urlSeen := make(map[asset.Identity]struct{})
	prov := asset.Provenance{Source: cfg.Source, DiscoveredAt: cfg.Clock.Now().UTC()}

	// add classifies one resolved candidate: build the endpoint, dedup,
	// cap, and record the edge; asURL additionally retains the URL asset.
	add := func(method string, u asset.URL, asURL bool) {
		ep, err := asset.NewEndpoint(method, u.String(), prov)
		if err != nil {
			out.skipped++
			return
		}
		if _, ok := seen[ep.Identity()]; ok {
			return
		}
		if len(out.endpoints) >= cfg.MaxEndpointsPerFile {
			out.dropped++
			return
		}
		seen[ep.Identity()] = struct{}{}
		out.endpoints = append(out.endpoints, ep)
		if r, err := asset.NewRelationship(js.Identity(), asset.RelationshipJavaScriptToEndpoint, ep.Identity()); err == nil {
			out.edges = append(out.edges, r)
		}
		if asURL {
			if _, ok := urlSeen[u.Identity()]; ok {
				return
			}
			urlSeen[u.Identity()] = struct{}{}
			out.urls = append(out.urls, u)
		}
	}

	for _, lit := range parsed.Strings {
		if lit.Template && strings.Contains(lit.Value, "${") {
			// Dynamic template: the value is a partial expression —
			// never a resolvable reference.
			out.skipped++
			continue
		}
		v := strings.TrimSpace(lit.Value)
		if len(v) < 3 || len(v) > maxEndpointCandidateBytes {
			out.skipped++
			continue
		}
		if !endpointCandidateOK(v) {
			out.skipped++
			continue
		}
		if strings.HasPrefix(v, "ws://") || strings.HasPrefix(v, "wss://") {
			// WebSocket endpoint class. NewEndpoint parses and
			// canonicalizes the ws:// URL. Like any other absolute, a
			// ws/wss URL whose canonical host:port differs from the
			// file's own is ALSO retained as a URL asset.
			u, err := asset.ParseURL(v, prov)
			if err != nil {
				out.skipped++
				continue
			}
			add("WS", u, u.HostPort != js.URL.HostPort)
			continue
		}
		u, resolved, _ := resolveRef(js.URL, v)
		if !resolved {
			// Bare words, data:/file:/javascript: schemes, emails,
			// and unparseable references have no URL meaning here.
			out.skipped++
			continue
		}
		// A resolved candidate shares the file's host UNLESS it is an
		// absolute URL pointing elsewhere (relative references resolve
		// against the file's own URL). Different host:port absolutes
		// are ALSO retained as URL assets.
		add(classifyEndpointURL(u), u, u.HostPort != js.URL.HostPort)
	}
	return out
}

// endpointCandidateOK rejects candidates containing raw whitespace or any
// of the HTML-dangerous / ambiguous bytes <>&"' — a candidate with such a
// byte is not a clean reference.
func endpointCandidateOK(v string) bool {
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c <= ' ', c == '<', c == '>', c == '&', c == '"', c == '\'':
			return false
		}
	}
	return true
}

// classifyEndpointURL maps a resolved canonical URL path to its extraction
// class: "GQL" for a graphql segment or a .graphql/.gql extension, "SSE"
// for a last segment in the SSE suffix set (path of at least 3 bytes), and
// "GET" (REST candidate) otherwise. The class is carried in the endpoint's
// Method field; it is NEVER an observed HTTP method.
func classifyEndpointURL(u asset.URL) string {
	p := strings.ToLower(u.Path)
	for _, seg := range strings.Split(p, "/") {
		if seg == "graphql" {
			return "GQL"
		}
	}
	last := p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		last = p[i+1:]
	}
	if strings.HasSuffix(last, ".graphql") || strings.HasSuffix(last, ".gql") {
		return "GQL"
	}
	if len(p) >= 3 {
		if _, ok := sseSuffixes[last]; ok {
			return "SSE"
		}
	}
	return "GET"
}
