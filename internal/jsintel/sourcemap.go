// Source map normalization: detection and asset/edge construction only. No
// map content is ever fetched and no map is ever parsed in this phase (the
// asset model normalizes observations; roadmap passes beyond Phase 7 may
// fetch and analyze map content).
package jsintel

import (
	"github.com/RA000WL/RavenRecon/internal/asset"
)

// sourceMapExtract is the bounded source map detection of ONE JS file.
type sourceMapExtract struct {
	// maps are the detected source map assets, deduplicated by canonical
	// URL and bounded by MaxSourceMapsPerFile.
	maps []asset.SourceMap
	// edges are the javascript_to_source_map edges (1:1 with maps).
	edges []asset.Relationship
	// skipped counts references that could not resolve (empty, bare,
	// unsupported scheme like data:/file:, unparseable) — reported through
	// the Malformed metric.
	skipped int
	// dropped counts references beyond the MaxSourceMapsPerFile cap —
	// reported through the Skipped metric.
	dropped int
}

// extractSourceMaps detects the source map references of one observed JS
// file from both sources:
//
//  1. Parsed.SourceMapRef — the LAST sourceMappingURL comment reference in
//     the body (per the source map spec, last-wins within the file);
//  2. FetchResult.XSourceMap — the response header.
//
// Each reference is resolved against the JS file's own URL via the shared
// resolver (query preserved, fragment stripped); a resolved reference
// becomes a SourceMap asset (with the run's provenance) plus a
// javascript_to_source_map edge. The same map URL observed from both
// sources is one asset (comment first). Resolution failures (data:, file:,
// bare, unparseable) are counted and dropped; references beyond the cap are
// counted and dropped.
func extractSourceMaps(js asset.JavaScript, res FetchResult, parsed Parsed, cfg Config) sourceMapExtract {
	// Caps are normalized here so a directly constructed Config (unit
	// tests, embedding callers) applies the documented defaults: a zero
	// MaxSourceMapsPerFile must not silently drop every map.
	cfg = normalizeCaps(cfg)
	var out sourceMapExtract
	seen := make(map[asset.Identity]struct{})
	add := func(ref string) {
		u, resolved, bare := resolveRef(js.URL, ref)
		if bare || !resolved {
			out.skipped++
			return
		}
		if _, ok := seen[u.Identity()]; ok {
			return
		}
		if len(out.maps) >= cfg.MaxSourceMapsPerFile {
			out.dropped++
			return
		}
		seen[u.Identity()] = struct{}{}
		sm := asset.SourceMap{
			URL: u,
			Prov: asset.Provenance{
				Source:       cfg.Source,
				DiscoveredAt: cfg.Clock.Now().UTC(),
			},
		}
		out.maps = append(out.maps, sm)
		if e, err := asset.NewRelationship(js.Identity(), asset.RelationshipJavaScriptToSourceMap, sm.Identity()); err == nil {
			out.edges = append(out.edges, e)
		}
	}
	if parsed.HasSourceMapRef && parsed.SourceMapRef != "" {
		add(parsed.SourceMapRef)
	}
	if res.XSourceMap != "" {
		add(res.XSourceMap)
	}
	return out
}
