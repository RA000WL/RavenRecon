// The js.analyze cache operation: key derivation, the stored record shape,
// decode re-validation, and the cache-before-execute lookup/store sides.
// Mirrors record_fetch.go in structure and guarantees.
package jsintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// AnalyzeOperation is the stable cache operation name for the JS analysis
// pipeline. It is part of the key payload; changing it invalidates every
// previously stored analysis record by construction.
const AnalyzeOperation = "js.analyze"

// JSParserSchemaVersion versions the analysis payload semantics (the
// analysisData shape and the D1/D2 extraction contract). It enters the
// cache key, so a record written by a different parser-schema build is
// unreachable and recomputed, never misinterpreted.
const JSParserSchemaVersion = 1

// analyzeMask selects the enabled analysis families: endpoints, imports,
// maps (source maps), secrets, technologies. Today the mask is a constant
// with every family enabled; it is entered in the key for future-proofing
// so a future build that disables a family derives different keys than this
// build. The letters are stable per family: e=endpoints, i=imports,
// m=maps, s=secrets, t=technologies.
const analyzeMask = "eimst"

// Fixed stored-analysis bounds, re-checked at decode time so a tampered or
// corrupt record can never smuggle values past the model. These are
// deliberately NOT the configurable per-file caps (MaxEndpointsPerFile and
// friends): entries must never invalidate when a cap changes, so decode
// validates against the fixed bounds a record written by ANY cap
// configuration stays within.
const (
	// maxStoredAnalysisItems bounds every per-family list in a stored
	// record. The largest default cap (256) is far below it; a future
	// configuration may raise caps, and records stay valid up to this
	// fixed ceiling.
	maxStoredAnalysisItems = 1024
	// maxStoredSpecifierBytes bounds one import specifier or bare import
	// in a stored record. The parser enforces the same 4096 at its single
	// import capture point (addImport in parse.go): overlong specifiers are
	// dropped and counted malformed there, so a record this layer writes
	// can never violate this bound. Decode re-checks the length (and
	// printable ASCII) of every stored import specifier below; bare
	// imports are length-checked too. Export names are identifier-derived
	// and bounded by the smaller maxParserIdentBytes.
	maxStoredSpecifierBytes = 4096
)

// analysisImport is ONE resolved-import observation of a parsed file: the
// specifier as written, the canonical resolved URL, and the static/dynamic
// kind. It is the engine-side form of the stored record's import entry.
type analysisImport struct {
	Specifier string
	URL       asset.URL
	Kind      ImportKind
}

// analysisData is the entry-relevant analysis payload of ONE JS file: the
// D1 extraction results (imports, bare imports, exports, source maps) and
// the D2 extraction results (endpoints, URL observations, secret
// candidates, technologies, evidence). It is the unit the analyze cache
// record stores and the analyze-hit path reconstructs; the fresh path and
// the hit path both build entries through applyAnalysis, so a cache-served
// entry is byte-identical in payload to a freshly analyzed one.
type analysisData struct {
	// Imports are the resolved-import observations in source order (the
	// expansion candidates and the javascript_to_javascript edges derive
	// from their URLs).
	Imports []analysisImport
	// BareImports are the specifiers with no relative meaning.
	BareImports []string
	// Exports are the module's exported names.
	Exports []string
	// SourceMaps are the detected source map assets.
	SourceMaps []asset.SourceMap
	// Endpoints are the classified endpoint candidates.
	Endpoints []asset.Endpoint
	// URLs are the different-host URL observations (CDN/external).
	URLs []asset.URL
	// Secrets are the detected secret candidates.
	Secrets []asset.SecretCandidate
	// Technologies are the detected technologies (Prov.Confidence carries
	// the detection score).
	Technologies []asset.Technology
	// Evidence are the per-marker MethodJS evidence records.
	Evidence []asset.Evidence
}

// analyzeKey derives the cache key for one (canonical URL) analysis
// observation.
//
// The key contains every input that materially changes the result: the
// operation ("js.analyze"), the canonical URL identity, and the parser
// schema version + family mask ("1:eimst"). The parser version and mask
// enter the key so a record produced by a different analysis contract is
// unreachable by construction, and a future build that changes either
// derives different keys without ever misreading old records. Per-file
// caps, timings, and concurrency NEVER enter the key: a completed record
// stays a complete record under any cap configuration.
func analyzeKey(u asset.URL) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: AnalyzeOperation,
		Target:    u.Identity().String(),
		Config:    map[string]string{"parser": fmt.Sprintf("%d:%s", JSParserSchemaVersion, analyzeMask)},
	})
}

// storedImport is the stored form of one resolved-import observation.
type storedImport struct {
	// Specifier is the import specifier as written (escapes decoded).
	Specifier string `json:"specifier"`
	// URL is the canonical resolved URL.
	URL asset.URL `json:"url"`
	// Kind is the static/dynamic kind ("static" | "dynamic").
	Kind string `json:"kind"`
}

// storedAnalyze is the structured Data payload of one js.analyze cache
// record: the analysisData payload plus the record's identity and
// observation window. The record's cache Status is "completed" for a full
// analysis and "incomplete" for a truncated one (a parser cap hit) — a
// truncated record is stored incomplete and NEVER served as a hit.
type storedAnalyze struct {
	// Target is the canonical URL identity the record belongs to.
	Target string `json:"target"`
	// ParserVersion is the parser-schema version that produced the
	// payload; must equal JSParserSchemaVersion.
	ParserVersion int `json:"parser_version"`
	// Mask is the analysis-family mask; must equal analyzeMask.
	Mask string `json:"mask"`
	// Imports are the resolved-import observations.
	Imports []storedImport `json:"imports,omitempty"`
	// BareImports are the bare specifiers.
	BareImports []string `json:"bare_imports,omitempty"`
	// Exports are the exported names.
	Exports []string `json:"exports,omitempty"`
	// Endpoints are the classified endpoint candidates.
	Endpoints []asset.Endpoint `json:"endpoints,omitempty"`
	// URLs are the different-host URL observations.
	URLs []asset.URL `json:"urls,omitempty"`
	// Secrets are the detected secret candidates.
	Secrets []asset.SecretCandidate `json:"secrets,omitempty"`
	// Technologies are the detected technologies.
	Technologies []asset.Technology `json:"technologies,omitempty"`
	// Evidence are the per-marker MethodJS evidence records.
	Evidence []asset.Evidence `json:"evidence,omitempty"`
	// SourceMaps are the detected source map assets.
	SourceMaps []asset.SourceMap `json:"source_maps,omitempty"`
	// Truncated marks an analysis whose parse hit a parser cap: the
	// payload is a partial prefix. Such records are stored under
	// StatusIncomplete and never served as a hit; a completed record
	// never carries Truncated.
	Truncated bool `json:"truncated,omitempty"`
	// FirstSeen is the earliest and LastSeen the latest observation time.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// analysisToStored converts an engine analysis payload into its stored
// record form. The reverse is storedToAnalysis.
func analysisToStored(data analysisData) storedAnalyze {
	st := storedAnalyze{
		ParserVersion: JSParserSchemaVersion,
		Mask:          analyzeMask,
		BareImports:   data.BareImports,
		Exports:       data.Exports,
		Endpoints:     data.Endpoints,
		URLs:          data.URLs,
		Secrets:       data.Secrets,
		Technologies:  data.Technologies,
		Evidence:      data.Evidence,
		SourceMaps:    data.SourceMaps,
	}
	for _, imp := range data.Imports {
		st.Imports = append(st.Imports, storedImport{Specifier: imp.Specifier, URL: imp.URL, Kind: imp.Kind.String()})
	}
	return st
}

// storedToAnalysis converts a validated stored record into the engine
// analysis payload. The caller must have run decodeStoredAnalyze first: the
// conversion itself performs no validation.
func storedToAnalysis(st storedAnalyze) analysisData {
	data := analysisData{
		BareImports:  st.BareImports,
		Exports:      st.Exports,
		Endpoints:    st.Endpoints,
		URLs:         st.URLs,
		Secrets:      st.Secrets,
		Technologies: st.Technologies,
		Evidence:     st.Evidence,
		SourceMaps:   st.SourceMaps,
	}
	for _, imp := range st.Imports {
		kind := ImportStatic
		if imp.Kind == "dynamic" {
			kind = ImportDynamic
		}
		data.Imports = append(data.Imports, analysisImport{Specifier: imp.Specifier, URL: imp.URL, Kind: kind})
	}
	return data
}

// applyAnalysis builds the entry payload of ONE JS observation from a
// validated analysis payload: the D1 results (imports, bare imports,
// exports, source maps) and the D2 results (endpoints, URL observations,
// secret candidates, technologies, evidence), plus every derived edge. It
// serves BOTH paths — the fresh analysis path and the analyze-cache hit
// path — so a cache-served entry is byte-identical in payload to a freshly
// analyzed one: edges are derived from the payload's assets, never from
// per-path extraction state.
//
// The payload lists are bounded to the CURRENT per-file caps at the entry
// boundary (a stored record may legitimately carry more — caps never enter
// cache keys — so the entry truncates, and edges are derived only for
// retained assets). Import edges and relationships are deduplicated by edge
// identity; entry.Imports is the subset of relationships of kind
// javascript_to_javascript (the expansion view), mirroring the pre-D2
// entry shape.
func applyAnalysis(entry JSEntry, js asset.JavaScript, data analysisData, cfg Config) JSEntry {
	entry.BareImports = capStrings(data.BareImports, cfg.MaxImportsPerFile)
	entry.Exports = append([]string(nil), data.Exports...)
	entry.SourceMaps = capSourceMaps(data.SourceMaps, cfg.MaxSourceMapsPerFile)
	entry.Endpoints = capEndpoints(data.Endpoints, cfg.MaxEndpointsPerFile)
	entry.URLs = capURLs(data.URLs, cfg.MaxEndpointsPerFile)
	entry.Secrets = capSecrets(data.Secrets, cfg.MaxSecretsPerFile)
	entry.Technologies = capTechnologies(data.Technologies, cfg.MaxTechPerFile)
	entry.Evidence = capEvidence(data.Evidence, cfg.MaxEvidencePerFile)

	// D1 edges: imports and source maps, derived from the payload so both
	// paths agree.
	var rels []asset.Relationship
	for _, imp := range data.Imports {
		if len(rels) >= cfg.MaxImportsPerFile {
			break
		}
		to := asset.Identity{Kind: asset.KindJavaScript, Value: imp.URL.String()}
		if r, err := asset.NewRelationship(js.Identity(), asset.RelationshipJavaScriptToJavaScript, to); err == nil {
			rels = append(rels, r)
		}
	}
	for _, m := range entry.SourceMaps {
		if r, err := asset.NewRelationship(js.Identity(), asset.RelationshipJavaScriptToSourceMap, m.Identity()); err == nil {
			rels = append(rels, r)
		}
	}
	// D2 edges: endpoints, secrets, technologies, and the marker evidence
	// of the retained technologies (the marker table is the single source
	// of truth for the association).
	for _, ep := range entry.Endpoints {
		if r, err := asset.NewRelationship(js.Identity(), asset.RelationshipJavaScriptToEndpoint, ep.Identity()); err == nil {
			rels = append(rels, r)
		}
	}
	for _, s := range entry.Secrets {
		if r, err := asset.NewRelationship(js.Identity(), asset.RelationshipJavaScriptToSecretCandidate, s.Identity()); err == nil {
			rels = append(rels, r)
		}
	}
	for _, t := range entry.Technologies {
		if r, err := asset.NewRelationship(js.Identity(), asset.RelationshipJavaScriptToTechnology, t.Identity()); err == nil {
			rels = append(rels, r)
		}
	}
	rels = append(rels, technologyEvidenceEdges(entry.Technologies, entry.Evidence)...)

	// Deduplicate by edge identity, preserving first-derivation order. The
	// extraction layers already dedup within each family, but a marker that
	// is shared by two retained technologies can produce the same
	// technology_to_evidence edge twice.
	seen := make(map[string]struct{}, len(rels))
	unique := make([]asset.Relationship, 0, len(rels))
	for _, r := range rels {
		if _, ok := seen[r.ID()]; ok {
			continue
		}
		seen[r.ID()] = struct{}{}
		unique = append(unique, r)
	}
	entry.Relationships = unique
	entry.Imports = make([]asset.Relationship, 0, len(data.Imports))
	for _, r := range unique {
		if r.Kind == asset.RelationshipJavaScriptToJavaScript {
			entry.Imports = append(entry.Imports, r)
		}
	}
	return entry
}

// analysisResolved returns the resolved import URLs of a validated analysis
// payload — the expansion candidates of a cache-served entry. The stored
// decode already guarantees per-URL deduplication, so the list needs no
// further dedup here.
func analysisResolved(data analysisData) []asset.URL {
	out := make([]asset.URL, 0, len(data.Imports))
	for _, imp := range data.Imports {
		out = append(out, imp.URL)
	}
	return out
}

// capStrings bounds a string list to cap entries.
func capStrings(xs []string, cap int) []string {
	if len(xs) > cap {
		return append([]string(nil), xs[:cap]...)
	}
	return append([]string(nil), xs...)
}

// capSourceMaps bounds a source map list to cap entries.
func capSourceMaps(xs []asset.SourceMap, cap int) []asset.SourceMap {
	if len(xs) > cap {
		return append([]asset.SourceMap(nil), xs[:cap]...)
	}
	return append([]asset.SourceMap(nil), xs...)
}

// capEndpoints bounds an endpoint list to cap entries.
func capEndpoints(xs []asset.Endpoint, cap int) []asset.Endpoint {
	if len(xs) > cap {
		return append([]asset.Endpoint(nil), xs[:cap]...)
	}
	return append([]asset.Endpoint(nil), xs...)
}

// capURLs bounds a URL observation list to cap entries.
func capURLs(xs []asset.URL, cap int) []asset.URL {
	if len(xs) > cap {
		return append([]asset.URL(nil), xs[:cap]...)
	}
	return append([]asset.URL(nil), xs...)
}

// capSecrets bounds a secret candidate list to cap entries.
func capSecrets(xs []asset.SecretCandidate, cap int) []asset.SecretCandidate {
	if len(xs) > cap {
		return append([]asset.SecretCandidate(nil), xs[:cap]...)
	}
	return append([]asset.SecretCandidate(nil), xs...)
}

// capTechnologies bounds a technology list to cap entries.
func capTechnologies(xs []asset.Technology, cap int) []asset.Technology {
	if len(xs) > cap {
		return append([]asset.Technology(nil), xs[:cap]...)
	}
	return append([]asset.Technology(nil), xs...)
}

// capEvidence bounds an evidence list to cap entries.
func capEvidence(xs []asset.Evidence, cap int) []asset.Evidence {
	if len(xs) > cap {
		return append([]asset.Evidence(nil), xs[:cap]...)
	}
	return append([]asset.Evidence(nil), xs...)
}

// decodeStoredAnalyze validates and decodes a stored js.analyze payload
// before it may be served as a hit. It refuses payloads whose identity
// fields contradict the queried URL, whose parser version or family mask
// differ from this build's contract, whose URL-bearing entries do not
// re-parse canonically to their own identities, whose secrets/technologies/
// evidence do not re-derive their own identities through the asset
// constructors (unknown types, empty values, non-canonical names, wrong
// methods, foreign sources), whose lists exceed the fixed stored-analysis
// bounds or carry duplicate identities, or whose timestamps are inverted —
// so a corrupt, tampered, or legacy record can never produce bogus
// observations. On any error the caller deletes the record and falls
// through to a fresh analysis (self-healing), never serving it as a hit.
func decodeStoredAnalyze(raw json.RawMessage, u asset.URL) (storedAnalyze, error) {
	var s storedAnalyze
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("jsintel: parse stored analyze: %w", err)
	}
	if s.Target != u.Identity().String() {
		return s, fmt.Errorf("jsintel: stored analyze target %q does not match %q", truncateStored(s.Target), u.Identity().String())
	}
	if s.ParserVersion != JSParserSchemaVersion {
		return s, fmt.Errorf("jsintel: stored analyze parser version %d does not match %d", s.ParserVersion, JSParserSchemaVersion)
	}
	if s.Mask != analyzeMask {
		return s, fmt.Errorf("jsintel: stored analyze mask %q does not match %q", truncateStored(s.Mask), analyzeMask)
	}
	// Every URL-bearing entry must re-parse canonically to its own
	// identity: a non-canonical or non-reparseable URL could only be
	// tampered with or mis-stored.
	checkURL := func(field string, i int, u asset.URL) error {
		got, err := asset.ParseURL(u.String(), u.Prov)
		if err != nil {
			return fmt.Errorf("jsintel: stored analyze %s[%d] url %q does not parse: %w", field, i, truncateStored(u.String()), err)
		}
		if got.String() != u.String() {
			return fmt.Errorf("jsintel: stored analyze %s[%d] url %q is not in canonical form (normalized %q)", field, i, truncateStored(u.String()), got.String())
		}
		return nil
	}
	for i, u := range s.URLs {
		if err := checkURL("urls", i, u); err != nil {
			return s, err
		}
	}
	for i, imp := range s.Imports {
		if err := checkURL("imports", i, imp.URL); err != nil {
			return s, err
		}
		if imp.Kind != "static" && imp.Kind != "dynamic" {
			return s, fmt.Errorf("jsintel: stored analyze import[%d] kind %q is unknown", i, truncateStored(imp.Kind))
		}
		if err := checkStoredString("import specifier", imp.Specifier, maxStoredSpecifierBytes); err != nil {
			return s, fmt.Errorf("jsintel: stored analyze import[%d]: %w", i, err)
		}
	}
	// Bare imports are length-bounded AND printability-checked before they
	// ever reach a stored record: the parser's single capture point
	// (addImport) caps every specifier at 4096, and the extraction layer's
	// bare path (graph.go extractImports) already rejects non-printable
	// ASCII, so a record this build writes can never carry a longer or
	// non-printable specifier, and a tampered record must not smuggle one
	// into the payload. Re-validating them here stays as defense-in-depth
	// against tampered or foreign records; it no longer guards against
	// delete/recompute churn, since nothing this build writes can violate
	// it.
	for i, b := range s.BareImports {
		if len(b) > maxStoredSpecifierBytes {
			return s, fmt.Errorf("jsintel: stored analyze bare import[%d] is %d bytes, longer than the %d maximum", i, len(b), maxStoredSpecifierBytes)
		}
	}
	for i, m := range s.SourceMaps {
		if err := checkURL("source_maps", i, m.URL); err != nil {
			return s, err
		}
	}
	// Endpoints must re-derive their own identity through NewEndpoint:
	// the stored method and canonical URL must be exactly what the
	// constructor produces (a tampered method or URL changes the
	// identity).
	for i, ep := range s.Endpoints {
		got, err := asset.NewEndpoint(ep.Method, ep.URL.String(), ep.URL.Prov)
		if err != nil {
			return s, fmt.Errorf("jsintel: stored analyze endpoint[%d] %q does not re-parse: %w", i, truncateStored(ep.String()), err)
		}
		if !got.Identity().Equal(ep.Identity()) {
			return s, fmt.Errorf("jsintel: stored analyze endpoint[%d] %q is not in canonical form (re-derived %q)", i, truncateStored(ep.String()), got.Identity().String())
		}
	}
	// Secrets must carry a known type, a non-empty value, the file's own
	// identity as source, and must re-derive their identity.
	jsID := asset.Identity{Kind: asset.KindJavaScript, Value: u.String()}
	for i, sec := range s.Secrets {
		if !sec.Type.Valid() {
			return s, fmt.Errorf("jsintel: stored analyze secret[%d] type %q is unknown", i, truncateStored(string(sec.Type)))
		}
		if sec.Value == "" {
			return s, fmt.Errorf("jsintel: stored analyze secret[%d] value is empty", i)
		}
		if !sec.Source.Equal(jsID) {
			return s, fmt.Errorf("jsintel: stored analyze secret[%d] source %q does not match %q", i, truncateStored(sec.Source.String()), jsID.String())
		}
		got, err := asset.NewSecretCandidate(sec.Type, sec.Value, sec.Source, sec.Prov)
		if err != nil {
			return s, fmt.Errorf("jsintel: stored analyze secret[%d]: %w", i, err)
		}
		if !got.Identity().Equal(sec.Identity()) {
			return s, fmt.Errorf("jsintel: stored analyze secret[%d] is not in canonical form (re-derived %q)", i, got.Identity().String())
		}
	}
	// Technologies must re-derive their identity (canonical name within a
	// known category).
	for i, tech := range s.Technologies {
		got, err := asset.NewTechnology(tech.Name, tech.Category, tech.Prov)
		if err != nil {
			return s, fmt.Errorf("jsintel: stored analyze technology[%d]: %w", i, err)
		}
		if !got.Identity().Equal(tech.Identity()) {
			return s, fmt.Errorf("jsintel: stored analyze technology[%d] %q is not in canonical form (re-derived %q)", i, truncateStored(tech.String()), got.Identity().String())
		}
	}
	// Evidence must be MethodJS records with a js_content: indicator whose
	// value equals the needle part, sourced from the file itself, and
	// re-deriving their identity (the constructors also enforce the
	// indicator and value bounds).
	for i, ev := range s.Evidence {
		if ev.Method != asset.MethodJS {
			return s, fmt.Errorf("jsintel: stored analyze evidence[%d] method %q is not js", i, truncateStored(ev.Method.String()))
		}
		if !ev.Source.Equal(jsID) {
			return s, fmt.Errorf("jsintel: stored analyze evidence[%d] source %q does not match %q", i, truncateStored(ev.Source.String()), jsID.String())
		}
		needle, ok := strings.CutPrefix(ev.Indicator, "js_content:")
		if !ok || needle == "" {
			return s, fmt.Errorf("jsintel: stored analyze evidence[%d] indicator %q is not a js_content marker", i, truncateStored(ev.Indicator))
		}
		if ev.Value != needle {
			return s, fmt.Errorf("jsintel: stored analyze evidence[%d] value %q does not match marker %q", i, truncateStored(ev.Value), truncateStored(needle))
		}
		got, err := asset.NewEvidence(ev.Method, ev.Indicator, ev.Value, ev.Source, ev.Prov)
		if err != nil {
			return s, fmt.Errorf("jsintel: stored analyze evidence[%d]: %w", i, err)
		}
		if !got.Identity().Equal(ev.Identity()) {
			return s, fmt.Errorf("jsintel: stored analyze evidence[%d] is not in canonical form (re-derived %q)", i, got.Identity().String())
		}
	}
	// Fixed per-family bounds: counts are validated against the FIXED
	// stored-analysis constants, never the configurable caps, so a record
	// stays valid under any cap configuration.
	if n := len(s.Imports); n > maxStoredAnalysisItems {
		return s, fmt.Errorf("jsintel: stored analyze has %d imports (cap %d)", n, maxStoredAnalysisItems)
	}
	if n := len(s.BareImports); n > maxStoredAnalysisItems {
		return s, fmt.Errorf("jsintel: stored analyze has %d bare imports (cap %d)", n, maxStoredAnalysisItems)
	}
	if n := len(s.Exports); n > maxStoredAnalysisItems {
		return s, fmt.Errorf("jsintel: stored analyze has %d exports (cap %d)", n, maxStoredAnalysisItems)
	}
	if n := len(s.Endpoints); n > maxStoredAnalysisItems {
		return s, fmt.Errorf("jsintel: stored analyze has %d endpoints (cap %d)", n, maxStoredAnalysisItems)
	}
	if n := len(s.URLs); n > maxStoredAnalysisItems {
		return s, fmt.Errorf("jsintel: stored analyze has %d urls (cap %d)", n, maxStoredAnalysisItems)
	}
	if n := len(s.Secrets); n > maxStoredAnalysisItems {
		return s, fmt.Errorf("jsintel: stored analyze has %d secrets (cap %d)", n, maxStoredAnalysisItems)
	}
	if n := len(s.Technologies); n > maxStoredAnalysisItems {
		return s, fmt.Errorf("jsintel: stored analyze has %d technologies (cap %d)", n, maxStoredAnalysisItems)
	}
	if n := len(s.Evidence); n > maxStoredAnalysisItems {
		return s, fmt.Errorf("jsintel: stored analyze has %d evidence records (cap %d)", n, maxStoredAnalysisItems)
	}
	if n := len(s.SourceMaps); n > maxStoredAnalysisItems {
		return s, fmt.Errorf("jsintel: stored analyze has %d source maps (cap %d)", n, maxStoredAnalysisItems)
	}
	// Every list must be deduplicated by identity: duplicate identities
	// indicate a corrupt or tampered record, never a legitimate one (the
	// extraction layers dedup before retention).
	if err := checkStringDedup("bare imports", s.BareImports); err != nil {
		return s, err
	}
	if err := checkStringDedup("exports", s.Exports); err != nil {
		return s, err
	}
	checkListDedup := func(field string, ids []string) error {
		seen := make(map[string]struct{}, len(ids))
		for i, id := range ids {
			if _, ok := seen[id]; ok {
				return fmt.Errorf("jsintel: stored analyze %s[%d] duplicates identity %q", field, i, truncateStored(id))
			}
			seen[id] = struct{}{}
		}
		return nil
	}
	if err := checkListDedup("imports", importIDs(s.Imports)); err != nil {
		return s, err
	}
	if err := checkListDedup("urls", urlIDs(s.URLs)); err != nil {
		return s, err
	}
	if err := checkListDedup("source_maps", urlIDs(sourceMapURLs(s.SourceMaps))); err != nil {
		return s, err
	}
	if err := checkListDedup("endpoints", endpointIDs(s.Endpoints)); err != nil {
		return s, err
	}
	if err := checkListDedup("secrets", secretIDs(s.Secrets)); err != nil {
		return s, err
	}
	if err := checkListDedup("technologies", technologyIDs(s.Technologies)); err != nil {
		return s, err
	}
	if err := checkListDedup("evidence", evidenceIDs(s.Evidence)); err != nil {
		return s, err
	}
	if s.FirstSeen.IsZero() || s.LastSeen.IsZero() {
		return s, fmt.Errorf("jsintel: stored analyze timestamps are incomplete")
	}
	if s.LastSeen.Before(s.FirstSeen) {
		return s, fmt.Errorf("jsintel: stored analyze last_seen %v is before first_seen %v", s.LastSeen, s.FirstSeen)
	}
	return s, nil
}

// checkStoredString bounds one stored string field: non-empty, at most max
// bytes of printable ASCII.
func checkStoredString(field, s string, max int) error {
	if s == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if len(s) > max {
		return fmt.Errorf("%s is %d bytes, longer than the %d maximum", field, len(s), max)
	}
	if !printableASCII(s) {
		return fmt.Errorf("%s is not printable ASCII", field)
	}
	return nil
}

// checkStringDedup rejects a string list with duplicates.
func checkStringDedup(field string, xs []string) error {
	seen := make(map[string]struct{}, len(xs))
	for i, x := range xs {
		if _, ok := seen[x]; ok {
			return fmt.Errorf("jsintel: stored analyze %s[%d] duplicates value %q", field, i, truncateStored(x))
		}
		seen[x] = struct{}{}
	}
	return nil
}

func importIDs(imps []storedImport) []string {
	ids := make([]string, 0, len(imps))
	for _, imp := range imps {
		ids = append(ids, imp.URL.Identity().String())
	}
	return ids
}

func urlIDs(urls []asset.URL) []string {
	ids := make([]string, 0, len(urls))
	for _, u := range urls {
		ids = append(ids, u.Identity().String())
	}
	return ids
}

func sourceMapURLs(maps []asset.SourceMap) []asset.URL {
	urls := make([]asset.URL, 0, len(maps))
	for _, m := range maps {
		urls = append(urls, m.URL)
	}
	return urls
}

func endpointIDs(eps []asset.Endpoint) []string {
	ids := make([]string, 0, len(eps))
	for _, ep := range eps {
		ids = append(ids, ep.Identity().String())
	}
	return ids
}

func secretIDs(secs []asset.SecretCandidate) []string {
	ids := make([]string, 0, len(secs))
	for _, s := range secs {
		ids = append(ids, s.Identity().String())
	}
	return ids
}

func technologyIDs(techs []asset.Technology) []string {
	ids := make([]string, 0, len(techs))
	for _, t := range techs {
		ids = append(ids, t.Identity().String())
	}
	return ids
}

func evidenceIDs(evs []asset.Evidence) []string {
	ids := make([]string, 0, len(evs))
	for _, e := range evs {
		ids = append(ids, e.Identity().String())
	}
	return ids
}

// analyzeLookup is the outcome of one cache lookup: a validated hit with
// the reconstructed analysis payload and its provenance window, or a
// fall-through to execution (miss, incomplete, or a discarded unusable
// record). Err is a diagnostic — never fatal; the caller falls through to a
// fresh analysis and reports the diagnostic.
type analyzeLookup struct {
	// Result is the reconstructed analysis payload on a hit. Zero
	// otherwise.
	Result analysisData
	// FirstSeen and LastSeen are the record's observation window on a hit.
	FirstSeen time.Time
	LastSeen  time.Time
	// Hit reports a usable completed record was served.
	Hit bool
	// Err carries the diagnostic of a lookup that could not serve a hit
	// for a non-miss reason (key build failure, cache error, discarded
	// mismatched or unusable record). Nil on a hit and on a clean miss.
	Err error
}

// lookupAnalyze is the cache-before-execute read side for one analysis
// observation. It returns a usable hit (completed, validated record for the
// exact key — zero parse, and when the fetch was also cache-served, zero
// HTTP), or a fall-through to execution with an optional diagnostic. The
// engine performs the lookup BEFORE parsing, so an analyze hit never parses
// content.
//
// A hit serves the stored record regardless of the current per-file caps:
// cap changes never invalidate entries (see analyzeKey and the fixed
// stored-analysis bounds). Records failing the identity or decode
// validation are deleted and recomputed in this same run (self-healing), so
// they are never served as hits and never wedge the observation into
// repeated failures. cfg and clock are accepted for the engine's calling
// convention and future use; the lookup itself does not consult them — its
// inputs are the URL, the cache, and the context only.
func lookupAnalyze(ctx context.Context, u asset.URL, cfg Config, c cache.Cache, clock runtime.Clock) analyzeLookup {
	key, err := analyzeKey(u)
	if err != nil {
		return analyzeLookup{Err: fmt.Errorf("jsintel: %s: build cache key: %w", u.String(), err)}
	}
	out := c.Get(ctx, key)
	if !out.IsHit() {
		// Miss, expired, incomplete (a truncated analysis is stored
		// incomplete and never served), corrupt, and schema-incompatible
		// are all "execute" outcomes. Only a filesystem-level failure
		// carries a diagnosis; it is surfaced as a warning, never as a
		// failure — the run falls through to a fresh analysis. Cache
		// failures that wrap context cancellation are suppressed: they are
		// not diagnostics, the caller's context is simply done.
		if out.State == cache.StateError && out.Err != nil &&
			!errors.Is(out.Err, context.Canceled) && !errors.Is(out.Err, context.DeadlineExceeded) {
			return analyzeLookup{Err: fmt.Errorf("jsintel: %s: cache get: %w", u.String(), out.Err)}
		}
		return analyzeLookup{}
	}

	// Only a completed, unexpired record for the exact key is a hit (the
	// cache enforces that). The record's own identity fields must also
	// match the observation — a record found under this key with different
	// operation or target fields could only be tampered with — and the
	// payload is cross-checked by decodeStoredAnalyze.
	if out.Record.Operation != AnalyzeOperation || out.Record.Target != u.Identity().String() {
		if delerr := c.Delete(ctx, key); delerr != nil {
			return analyzeLookup{Err: fmt.Errorf("jsintel: %s: delete mismatched cached record: %w", u.String(), delerr)}
		}
		return analyzeLookup{Err: fmt.Errorf("jsintel: %s: discarded cached record with mismatched identity %q/%q",
			u.String(), out.Record.Operation, out.Record.Target)}
	}
	st, derr := decodeStoredAnalyze(out.Record.Data, u)
	if derr != nil {
		if delerr := c.Delete(ctx, key); delerr != nil {
			return analyzeLookup{Err: fmt.Errorf("jsintel: %s: delete unusable cached record: %w", u.String(), delerr)}
		}
		return analyzeLookup{Err: fmt.Errorf("jsintel: %s: discarded unusable cached analyze: %w", u.String(), derr)}
	}
	return analyzeLookup{
		Result:    storedToAnalysis(st),
		FirstSeen: st.FirstSeen,
		LastSeen:  st.LastSeen,
		Hit:       true,
	}
}

// storeAnalyze is the cache write side for one analysis observation. Only
// completed analyses — including truncated ones, which are persisted as
// INCOMPLETE records (never served as a hit; a later run re-analyzes) — are
// stored. The caller only invokes it for completed-positive JS observations
// (a failed or cancelled fetch never reaches analysis, and the caller never
// stores those). A record this layer writes always satisfies the decode
// invariants: identity fields are derived from the canonical URL, lists
// come from the extraction layers (deduplicated and bounded), and
// timestamps default to the clock. Zero provenance timestamps default to
// the clock; a cancelled run still persists its terminal records using a
// detached, bounded context so the write cannot wedge shutdown (Phase 4
// convention). Put failures are returned as diagnostics, never fatal.
func storeAnalyze(ctx context.Context, cfg Config, c cache.Cache, clock runtime.Clock, u asset.URL, data analysisData, truncated bool, sources []string, firstSeen, lastSeen time.Time) error {
	if clock == nil {
		clock = wallClock{}
	}
	if firstSeen.IsZero() {
		firstSeen = clock.Now().UTC()
	}
	if lastSeen.IsZero() {
		lastSeen = firstSeen
	}
	if lastSeen.Before(firstSeen) {
		lastSeen = firstSeen
	}
	// A record this layer writes must never be rejected by its own decode:
	// sources must be present and bounded.
	if len(sources) == 0 {
		return fmt.Errorf("jsintel: store analyze %s: no sources", u.String())
	}
	for _, src := range sources {
		if src == "" {
			return fmt.Errorf("jsintel: store analyze %s: empty source", u.String())
		}
		if len(src) > maxStoredSourceBytes {
			return fmt.Errorf("jsintel: store analyze %s: source longer than %d bytes", u.String(), maxStoredSourceBytes)
		}
	}

	st := analysisToStored(data)
	st.Target = u.Identity().String()
	st.Truncated = truncated
	st.FirstSeen = firstSeen
	st.LastSeen = lastSeen

	key, err := analyzeKey(u)
	if err != nil {
		return fmt.Errorf("jsintel: store analyze %s: build cache key: %w", u.String(), err)
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("jsintel: store analyze %s: encode result: %w", u.String(), err)
	}
	status := cache.StatusCompleted
	if truncated {
		status = cache.StatusIncomplete
	}
	rec := cache.Record{
		Operation: AnalyzeOperation,
		Target:    u.Identity().String(),
		Status:    status,
		Meta:      map[string]string{"source": sources[0]},
		Data:      raw,
	}
	storeCtx := ctx
	if ctx.Err() != nil {
		var scancel context.CancelFunc
		storeCtx, scancel = context.WithTimeout(context.Background(), storeTimeout)
		defer scancel()
	}
	if perr := c.Put(storeCtx, key, rec); perr != nil {
		return fmt.Errorf("jsintel: store analyze %s: cache put: %w", u.String(), perr)
	}
	return nil
}
