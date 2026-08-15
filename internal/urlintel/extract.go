package urlintel

import (
	"net/url"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// maxParametersPerURL bounds how many DISTINCT parameters are retained per
// canonical URL. It is the "huge parameter list" security bound on the
// parameter side: a URL with more distinct query parameters than the cap has
// the extras dropped and the entry/record flagged Overflow (the record is
// still completed, but the observed parameter set is incomplete). The Phase 2
// per-parameter value cap (1024, enforced by asset.WithValue) bounds values
// within each parameter.
//
// The cap is a fixed constant, deliberately NOT configuration, and must
// never enter cache keys: a completed entry written under the current cap
// stays valid under any future cap that only retains more parameters
// (mirroring the DNS answer cap and the HTTP probing caps).
const maxParametersPerURL = 256

// extractURL builds the full observation for one canonical URL: the GET
// endpoint asset, the host asset derived from the URL's host, the query
// parameters (when ParseParameters is enabled), and the typed graph edges.
//
// It is the "extraction work" a cache hit avoids entirely: on a hit the
// stored observation is served and extractURL is never called (asserted in
// the benchmark harness).
func extractURL(u asset.URL, adapter string, parseParams bool, now time.Time) URLEntry {
	prov := asset.Provenance{Source: adapter, DiscoveredAt: now.UTC()}
	e := URLEntry{
		URL:        u,
		Host:       hostOrZero(u, prov),
		Status:     StatusCompleted,
		Sources:    []string{adapter},
		FirstSeen:  now.UTC(),
		LastSeen:   now.UTC(),
		Parameters: nil,
	}
	ep, err := asset.NewEndpoint("GET", u.String(), prov)
	if err == nil {
		e.Endpoints = []asset.Endpoint{ep}
	}
	if parseParams && u.Query != "" {
		e.Parameters, e.Overflow = extractParams(u.Query, adapter, now)
	}
	e.Relationships = graphOf(u, e.Host, e.Endpoints, e.Parameters)
	return e
}

// hostOrZero derives the canonical host asset from a canonical URL's host.
// IP literals are not hosts in the Phase 2 model (asset.NewHost rejects
// them), so an IP-literal URL yields the zero host: no host asset and no
// host_to_url edge, exactly like the phase 5B scope rules.
//
// A zero Host is detected by its Name, NOT by Identity().IsZero(): the
// asset model's zero Host still carries the constant "host" kind, so its
// identity is never "zero" in the IsZero sense. Detecting an absent host
// asset must therefore compare the Name field.
func hostOrZero(u asset.URL, prov asset.Provenance) asset.Host {
	parsed, err := url.Parse(u.String())
	if err != nil {
		return asset.Host{}
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return asset.Host{}
	}
	h, err := asset.NewHost(hostname, prov)
	if err != nil {
		return asset.Host{}
	}
	return h
}

// hostIsZero reports whether h is the zero host asset (no host was derived).
// See hostOrZero for why Name — not Identity().IsZero() — is the correct
// absence check.
func hostIsZero(h asset.Host) bool { return h.Name == "" }

// extractParams extracts distinct parameters from a canonical URL's query
// string, following the pinned Phase 6A rules:
//
//   - names and values are taken AS-OBSERVED from the canonical query — the
//     escaped/raw forms — and are NEVER unescaped before identity use, so
//     "x=a%20b", "x=a+b", and raw non-ASCII values stay distinct identities;
//   - within one URL, repeated names merge via asset.WithValue with values
//     deduplicated in first-seen order;
//   - distinct parameters beyond maxParametersPerURL are dropped and
//     Overflow is set (the record stays completed but flagged);
//   - values that the Phase 2 model cannot represent (empty values from
//     "?flag" or "?flag=" — the model requires a non-empty observed value)
//     are skipped.
//
// The query passed in is asset.URL.Query, the canonical raw query string:
// keys sorted, values in their as-observed raw/escaped form with the four
// query-corrupting raw bytes (' ', '#', '&', '=') percent-escaped, so
// splitting on "&" and cutting on the first "=" round-trips each original
// pair exactly.
func extractParams(query, adapter string, now time.Time) ([]asset.Parameter, bool) {
	prov := asset.Provenance{Source: adapter, DiscoveredAt: now.UTC()}
	var params []asset.Parameter
	byName := make(map[string]int)
	overflow := false
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		if value == "" {
			// "?flag" / "?flag=": the Phase 2 model requires a non-empty
			// observed value, so a value-less query key cannot become a
			// Parameter asset. Skipped by design (see doc.go).
			continue
		}
		if idx, ok := byName[name]; ok {
			p, err := asset.WithValue(params[idx], value, adapter, now.UTC())
			if err == nil {
				params[idx] = p
			}
			continue
		}
		if len(params) >= maxParametersPerURL {
			overflow = true
			continue
		}
		p, err := asset.NewParameter(name, "query", value, adapter, now.UTC(), prov)
		if err != nil {
			// Inexpressible in the model (name/value over their bounds):
			// skipped, never fatal, never crashes the run.
			continue
		}
		byName[name] = len(params)
		params = append(params, p)
	}
	return params, overflow
}

// graphOf assembles a URL entry's typed graph edges:
//
//   - host -> url (RelationshipHostToURL) when the URL has a host asset;
//   - url -> endpoint (RelationshipURLToEndpoint) for each endpoint;
//   - url -> parameter (RelationshipURLToParameter) for each parameter;
//   - endpoint -> parameter (RelationshipEndpointToParameter) for each
//     parameter per endpoint.
//
// Edges are deduplicated by edge identity and emitted sorted. The same
// builder serves fresh extractions and cached observations, so a cache hit
// reproduces the graph exactly as the original run would have.
func graphOf(u asset.URL, host asset.Host, endpoints []asset.Endpoint, params []asset.Parameter) []asset.Relationship {
	var rels []asset.Relationship
	relSet := make(map[asset.Relationship]bool)
	add := func(from asset.Identity, kind asset.RelationshipKind, to asset.Identity) {
		r, err := asset.NewRelationship(from, kind, to)
		if err != nil {
			return // cannot happen with validated identities; skip defensively
		}
		if relSet[r] {
			return
		}
		relSet[r] = true
		rels = append(rels, r)
	}
	if !hostIsZero(host) {
		add(host.Identity(), asset.RelationshipHostToURL, u.Identity())
	}
	for _, ep := range endpoints {
		add(u.Identity(), asset.RelationshipURLToEndpoint, ep.Identity())
	}
	for _, p := range params {
		add(u.Identity(), asset.RelationshipURLToParameter, p.Identity())
		for _, ep := range endpoints {
			add(ep.Identity(), asset.RelationshipEndpointToParameter, p.Identity())
		}
	}
	return sortRelationships(rels)
}
