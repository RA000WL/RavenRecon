// Technology detection from raw JavaScript content: a fixed marker table
// (data, not configuration), a deterministic single-pass needle scan, and
// techintel's confidence math (score = 1 − ∏(1 − wᵢ) over matched markers;
// High ≥ 0.8, Medium ≥ 0.5, else Low) with jsintel's own constants.
//
// Markers are treated as STRUCTURAL (like techintel's html indicators): a
// marker's presence is evidence regardless of how easy it is to spoof, so
// there is no spoofable-only cap. Identical content always yields an
// identical result: the table is fixed, the scan order is fixed, and the
// retention order is deterministic (score desc, then name asc).
package jsintel

import (
	"bytes"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Confidence thresholds. Fixed constants, deliberately NOT configuration:
// the confidence model is a documented contract (see doc.go "Technology
// detection"), mirroring techintel's thresholds with jsintel's own
// constants.
const (
	// highConfidenceThreshold: scores at or above 0.8 are High.
	highConfidenceThreshold = 0.8
	// mediumConfidenceThreshold: scores at or above 0.5 (and below 0.8)
	// are Medium; everything else is Low.
	mediumConfidenceThreshold = 0.5
)

// ConfidenceLevel is the typed confidence classification of one technology
// detection.
type ConfidenceLevel string

const (
	// LevelHigh: score >= 0.8.
	LevelHigh ConfidenceLevel = "high"
	// LevelMedium: score >= 0.5.
	LevelMedium ConfidenceLevel = "medium"
	// LevelLow: score < 0.5.
	LevelLow ConfidenceLevel = "low"
)

// String returns the canonical lowercase level label.
func (l ConfidenceLevel) String() string { return string(l) }

// levelForScore maps a raw score to its threshold level.
func levelForScore(score float64) ConfidenceLevel {
	switch {
	case score >= highConfidenceThreshold:
		return LevelHigh
	case score >= mediumConfidenceThreshold:
		return LevelMedium
	default:
		return LevelLow
	}
}

// techMarker is ONE marker needle with its contribution weight.
type techMarker struct {
	needle string
	weight float64
}

// techSpec is ONE detectable technology: its canonical name, its asset
// category, and its markers. The table is data; identical content always
// produces the identical technology set.
type techSpec struct {
	name     string
	category asset.TechnologyCategory
	markers  []techMarker
}

// techTable is the fixed detection table. Weights are tuned so that two
// mid-weight markers clear High (0.6+0.5 = 0.8) while one strong marker
// alone reaches Medium. Categories reuse the asset enum; conventions mirror
// techintel's fingerprint DB (react/next.js/vue/angular/nuxt/svelte ->
// framework, webpack/vite/parcel/rollup/requirejs -> build_tool,
// cloudflare/akamai -> cdn, auth0/firebase -> authentication, apollo/relay
// -> graphql). tailwind and bootstrap have no techintel precedent and are
// classified framework (front-end frameworks).
var techTable = []techSpec{
	{name: "react", category: asset.CategoryFramework, markers: []techMarker{
		{needle: "React.createElement", weight: 0.6},
		{needle: "__REACT_DEVTOOLS_GLOBAL_HOOK__", weight: 0.5},
		{needle: "react-dom", weight: 0.5},
	}},
	{name: "next.js", category: asset.CategoryFramework, markers: []techMarker{
		{needle: "__NEXT_DATA__", weight: 0.6},
		{needle: "next/dist", weight: 0.6},
		{needle: "next/router", weight: 0.5},
	}},
	{name: "angular", category: asset.CategoryFramework, markers: []techMarker{
		{needle: "@angular/core", weight: 0.6},
		{needle: "ng-version", weight: 0.5},
		{needle: "platformBrowserDynamic", weight: 0.5},
	}},
	{name: "vue", category: asset.CategoryFramework, markers: []techMarker{
		{needle: "__VUE__", weight: 0.6},
		{needle: "@vue/", weight: 0.5},
		{needle: "vue.runtime", weight: 0.5},
	}},
	{name: "nuxt", category: asset.CategoryFramework, markers: []techMarker{
		{needle: "__NUXT__", weight: 0.7},
		{needle: "nuxt/dist", weight: 0.6},
	}},
	{name: "svelte", category: asset.CategoryFramework, markers: []techMarker{
		{needle: "svelte/internal", weight: 0.6},
		{needle: "svelte/store", weight: 0.5},
	}},
	{name: "webpack", category: asset.CategoryBuildTool, markers: []techMarker{
		{needle: "__webpack_require__", weight: 0.7},
		{needle: "webpackChunk", weight: 0.5},
		{needle: "__webpack_modules__", weight: 0.4},
	}},
	{name: "vite", category: asset.CategoryBuildTool, markers: []techMarker{
		{needle: "@vite/client", weight: 0.6},
		{needle: "__vite__", weight: 0.5},
		{needle: "vite/modulepreload", weight: 0.5},
	}},
	{name: "parcel", category: asset.CategoryBuildTool, markers: []techMarker{
		{needle: "parcelRequire", weight: 0.6},
		{needle: "parcel/runtime", weight: 0.5},
	}},
	{name: "rollup", category: asset.CategoryBuildTool, markers: []techMarker{
		{needle: "System.register", weight: 0.3},
	}},
	{name: "requirejs", category: asset.CategoryBuildTool, markers: []techMarker{
		{needle: "define.amd", weight: 0.5},
		{needle: "requirejs", weight: 0.3},
	}},
	{name: "cloudflare", category: asset.CategoryCDN, markers: []techMarker{
		{needle: "cloudflare", weight: 0.2},
	}},
	{name: "akamai", category: asset.CategoryCDN, markers: []techMarker{
		{needle: "bm-verify", weight: 0.5},
		{needle: "_abck", weight: 0.5},
		{needle: "akamai", weight: 0.2},
	}},
	{name: "auth0", category: asset.CategoryAuthentication, markers: []techMarker{
		{needle: "@auth0/", weight: 0.6},
		{needle: "Auth0Lock", weight: 0.5},
		{needle: "auth0-js", weight: 0.5},
	}},
	{name: "firebase", category: asset.CategoryAuthentication, markers: []techMarker{
		{needle: "@firebase/", weight: 0.6},
		{needle: "firebaseio", weight: 0.6},
		{needle: "FirebaseApp", weight: 0.5},
	}},
	{name: "apollo", category: asset.CategoryGraphQL, markers: []techMarker{
		{needle: "@apollo/client", weight: 0.6},
		{needle: "ApolloClient", weight: 0.4},
		{needle: "apollo-boost", weight: 0.5},
	}},
	{name: "relay", category: asset.CategoryGraphQL, markers: []techMarker{
		{needle: "relay-runtime", weight: 0.6},
		{needle: "RelayModern", weight: 0.4},
	}},
	{name: "tailwind", category: asset.CategoryFramework, markers: []techMarker{
		{needle: "tailwindcss", weight: 0.6},
		{needle: "tailwind.config", weight: 0.5},
		{needle: "@tailwindcss", weight: 0.5},
	}},
	{name: "bootstrap", category: asset.CategoryFramework, markers: []techMarker{
		{needle: "bootstrap.bundle", weight: 0.6},
		{needle: "@popperjs/core", weight: 0.4},
		{needle: "data-bs-", weight: 0.4},
		{needle: "bootstrap", weight: 0.2},
	}},
}

// markersFor returns the needles of one technology by canonical name, in
// table order. The table is the single source of truth for both detection
// and technology->evidence edge reconstruction (see technologyEvidenceEdges).
func markersFor(name string) []string {
	for _, spec := range techTable {
		if spec.name == name {
			out := make([]string, 0, len(spec.markers))
			for _, m := range spec.markers {
				out = append(out, m.needle)
			}
			return out
		}
	}
	return nil
}

// techExtract is the bounded technology detection result of ONE JS file.
type techExtract struct {
	// techs are the detected technologies, deduplicated by asset identity
	// in deterministic retention order (score desc, then name asc) and
	// bounded by MaxTechPerFile. Prov.Confidence carries the detection
	// score.
	techs []asset.Technology
	// evidence are the per-marker evidence records (MethodJS,
	// "js_content:<needle>"), deduplicated by asset identity in the same
	// order and bounded by MaxEvidencePerFile. Evidence whose technology
	// was dropped past the tech cap is still retained (it is a real
	// observation) but has no technology edge.
	evidence []asset.Evidence
	// dropped counts technologies beyond MaxTechPerFile and evidence
	// beyond MaxEvidencePerFile — reported through the Skipped metric.
	dropped int
}

// fired is one technology that matched content.
type fired struct {
	spec    techSpec
	score   float64
	needles []string // matched needles in table order
}

// detectTechnologies scans the RAW content bytes (markers live in
// identifiers and comments alike) with a deterministic single-pass needle
// scan and builds the bounded technology + evidence set.
//
// Score = 1 − ∏(1 − wᵢ) over the technology's MATCHED markers; the level
// derives from the fixed thresholds. Markers are structural: there is no
// spoofable-only cap. Retention order is deterministic: score desc, then
// canonical name asc. One Evidence record is built per matched marker
// (NewEvidence(MethodJS, "js_content:"+needle, needle, source, prov));
// technologies beyond MaxTechPerFile and evidence beyond
// MaxEvidencePerFile are dropped and counted.
func detectTechnologies(js asset.JavaScript, content []byte, cfg Config) techExtract {
	cfg = normalizeCaps(cfg)
	var out techExtract

	var firedList []fired
	for _, spec := range techTable {
		score := 1.0
		var needles []string
		for _, m := range spec.markers {
			if bytes.Contains(content, []byte(m.needle)) {
				needles = append(needles, m.needle)
				score *= 1 - m.weight
			}
		}
		if len(needles) > 0 {
			firedList = append(firedList, fired{spec: spec, score: 1 - score, needles: needles})
		}
	}

	// Deterministic retention order: score desc, then name asc.
	sort.SliceStable(firedList, func(i, j int) bool {
		if firedList[i].score != firedList[j].score {
			return firedList[i].score > firedList[j].score
		}
		return firedList[i].spec.name < firedList[j].spec.name
	})

	prov := asset.Provenance{Source: cfg.Source, DiscoveredAt: cfg.Clock.Now().UTC()}
	evSeen := make(map[asset.Identity]struct{})

	for _, f := range firedList {
		tech, err := asset.NewTechnology(f.spec.name, f.spec.category, prov)
		if err != nil {
			continue
		}
		tech.Prov.Confidence = f.score
		if len(out.techs) >= cfg.MaxTechPerFile {
			out.dropped++
		} else {
			out.techs = append(out.techs, tech)
		}
		// Evidence for every matched marker, even when the technology
		// itself was capped (the marker is a real observation): it is
		// retained but has no technology edge (technologyEvidenceEdges
		// only links retained technologies).
		for _, needle := range f.needles {
			ev, err := asset.NewEvidence(asset.MethodJS, "js_content:"+needle, needle, js.Identity(), prov)
			if err != nil {
				continue
			}
			if _, ok := evSeen[ev.Identity()]; ok {
				continue
			}
			if len(out.evidence) >= cfg.MaxEvidencePerFile {
				out.dropped++
				continue
			}
			evSeen[ev.Identity()] = struct{}{}
			out.evidence = append(out.evidence, ev)
		}
	}
	return out
}

// technologyEvidenceEdges derives the technology_to_evidence edges from the
// retained technologies and evidence, using the marker table as the single
// source of truth for the association: for each retained technology, every
// evidence record whose indicator is "js_content:<needle>" for one of the
// technology's table needles is linked. One function serves BOTH the fresh
// analysis path and the analyze-cache hit path, so a cache-served entry
// derives byte-identical edges.
func technologyEvidenceEdges(techs []asset.Technology, evidence []asset.Evidence) []asset.Relationship {
	byIndicator := make(map[string][]asset.Evidence)
	for _, ev := range evidence {
		byIndicator[ev.Indicator] = append(byIndicator[ev.Indicator], ev)
	}
	var edges []asset.Relationship
	for _, tech := range techs {
		for _, needle := range markersFor(tech.Name) {
			for _, ev := range byIndicator["js_content:"+needle] {
				if r, err := asset.NewRelationship(tech.Identity(), asset.RelationshipTechnologyToEvidence, ev.Identity()); err == nil {
					edges = append(edges, r)
				}
			}
		}
	}
	return edges
}
