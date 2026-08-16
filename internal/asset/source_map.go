package asset

import "fmt"

// SourceMap is a source map resource observed at a URL. Phase 7 normalizes
// source map ASSETS (detection and observation only); the model never parses
// source map content.
//
// The identity is the canonical URL — KindSourceMap + URL.String() — and
// Hash and Size are observations, never part of the identity.
type SourceMap struct {
	// URL is the canonical URL of the source map resource.
	URL URL `json:"url"`

	// Hash is the lowercase hex SHA-256 of the source map body — exactly
	// 64 characters when observed. Empty means "not observed".
	Hash string `json:"hash,omitempty"`

	// Size is the observed source map body size in bytes; zero means "not
	// observed".
	Size int64 `json:"size,omitempty"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewSourceMap parses rawURL into a SourceMap asset.
func NewSourceMap(rawURL string, p Provenance) (SourceMap, error) {
	u, err := ParseURL(rawURL, p)
	if err != nil {
		return SourceMap{}, fmt.Errorf("invalid source map URL: %w", err)
	}
	return SourceMap{URL: u, Prov: p}, nil
}

// Identity returns the deterministic identity used for deduplication.
//
// The identity is exactly the canonical URL of the source map resource
// (KindSourceMap + URL.String()). Observations never enter the identity.
func (m SourceMap) Identity() Identity {
	return Identity{Kind: KindSourceMap, Value: m.URL.String()}
}

// ID returns the canonical identity string.
func (m SourceMap) ID() string { return m.Identity().String() }

// WithHash returns a copy of m carrying the observed content hash of the
// source map body. It never mutates m.
//
// A set value must be in canonical form — exactly 64 lowercase hex characters
// (the SHA-256 digest of the body), validated exactly like the JavaScript
// content hash; uppercase or otherwise non-canonical input is rejected, never
// coerced. Empty means "not observed" and is always accepted.
func WithHash(m SourceMap, hash string) (SourceMap, error) {
	if err := validateJavaScriptContentHash(hash); err != nil {
		return SourceMap{}, fmt.Errorf("set source map hash: %w", err)
	}
	out := m
	out.Hash = hash
	return out, nil
}

// WithSourceMapSize returns a copy of m carrying the observed source map body
// size in bytes. It never mutates m. Size must be non-negative; zero means
// "not observed". (Named WithSourceMapSize because package asset already has
// JavaScript's WithSize; Go has no function overloading.)
func WithSourceMapSize(m SourceMap, size int64) (SourceMap, error) {
	if size < 0 {
		return SourceMap{}, fmt.Errorf("set source map size: size %d must not be negative", size)
	}
	out := m
	out.Size = size
	return out, nil
}

// MergeSourceMaps combines two observations of the same source map.
//
// Rules, mirroring MergeJavaScripts:
//   - identities (canonical URLs) must match exactly, otherwise an error is
//     returned
//   - the URL fields themselves merge via MergeURLs
//   - provenance is the earliest observation's
//   - conflicting observation fields (Hash, Size): the unset value loses to
//     the set one; when both are set and DIFFER, the value from the
//     observation with the EARLIER DiscoveredAt wins, and an exact tie (or an
//     unresolvable comparison, e.g. a zero timestamp) resolves
//     deterministically to a's value
//
// The result is deterministic and order-independent: merge(a, b) equals
// merge(b, a) field-for-field whenever the two observations' DiscoveredAt
// times differ (exact ties resolve to the first argument, like the other
// merge primitives).
func MergeSourceMaps(a, b SourceMap) (SourceMap, error) {
	if !a.Identity().Equal(b.Identity()) {
		return SourceMap{}, mergeMismatch(KindSourceMap, a.Identity(), b.Identity())
	}
	mergedURL, err := MergeURLs(a.URL, b.URL)
	if err != nil {
		return SourceMap{}, err
	}
	m := a
	m.URL = mergedURL
	m.Hash = preferSourceMapString(a, b, a.Hash, b.Hash)
	m.Size = preferSourceMapInt64(a, b, a.Size, b.Size)
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}

// smObservedEarlier reports whether b's observation predates a's. A
// zero-time observation on either side is unresolvable and reports false
// (ties resolve to a, the first argument).
func smObservedEarlier(a, b SourceMap) bool {
	return !a.Prov.DiscoveredAt.IsZero() && !b.Prov.DiscoveredAt.IsZero() && b.Prov.DiscoveredAt.Before(a.Prov.DiscoveredAt)
}

// preferSourceMapString picks the deterministic merged value for a
// conflicting observation field: the non-empty value wins; when both are
// non-empty and DIFFER, the earlier observation's value wins (see
// MergeSourceMaps); an exact tie or an unresolvable comparison resolves to
// a's value.
func preferSourceMapString(a, b SourceMap, av, bv string) string {
	if av == "" {
		return bv
	}
	if bv == "" {
		return av
	}
	if av == bv {
		return av
	}
	if smObservedEarlier(a, b) {
		return bv
	}
	return av
}

// preferSourceMapInt64 is preferSourceMapString for int64 (body size); zero
// is the unset value.
func preferSourceMapInt64(a, b SourceMap, av, bv int64) int64 {
	if av == 0 {
		return bv
	}
	if bv == 0 {
		return av
	}
	if av == bv {
		return av
	}
	if smObservedEarlier(a, b) {
		return bv
	}
	return av
}
