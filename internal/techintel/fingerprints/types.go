package fingerprints

import (
	"fmt"
	"regexp"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// IndicatorKind identifies the observation channel an indicator matches
// against. String values are the canonical lowercase forms; unknown values
// are rejected at load time.
type IndicatorKind string

// The 16 indicator kinds. Their mapping onto asset.DetectionMethod is
// documented on asset.DetectionMethod.
const (
	// IndicatorHeader matches the "Name: value" line of an HTTP response
	// header (case-insensitive substring).
	IndicatorHeader IndicatorKind = "header"
	// IndicatorCookie matches a response cookie's name (case-insensitive
	// substring, so prefix and suffix forms both work).
	IndicatorCookie IndicatorKind = "cookie"
	// IndicatorHTMLRegex matches the response HTML/body with a regular
	// expression; Match is compiled as a regex.
	IndicatorHTMLRegex IndicatorKind = "html_regex"
	// IndicatorHTMLSubstring matches the response HTML/body with a
	// case-insensitive substring.
	IndicatorHTMLSubstring IndicatorKind = "html_substring"
	// IndicatorMetaName matches a meta tag's name attribute
	// (case-insensitive substring).
	IndicatorMetaName IndicatorKind = "meta_name"
	// IndicatorGenerator matches the generator meta content with a regular
	// expression; Match is compiled as a regex.
	IndicatorGenerator IndicatorKind = "generator"
	// IndicatorScriptName matches a script resource's basename.
	IndicatorScriptName IndicatorKind = "script_name"
	// IndicatorScriptPath matches a script resource's URL path.
	IndicatorScriptPath IndicatorKind = "script_path"
	// IndicatorCSSPath matches a stylesheet resource's URL path.
	IndicatorCSSPath IndicatorKind = "css_path"
	// IndicatorAttribute matches an HTML attribute name.
	IndicatorAttribute IndicatorKind = "attribute"
	// IndicatorEndpointPath matches a request path (case-insensitive
	// substring, so suffix and prefix forms both work).
	IndicatorEndpointPath IndicatorKind = "endpoint_path"
	// IndicatorTLSIssuer matches the certificate issuer string.
	IndicatorTLSIssuer IndicatorKind = "tls_issuer"
	// IndicatorTLSCN matches the certificate subject CN string.
	IndicatorTLSCN IndicatorKind = "tls_cn"
	// IndicatorTLSALPN matches an ALPN protocol offered during the TLS
	// handshake (e.g. "h3").
	IndicatorTLSALPN IndicatorKind = "tls_alpn"
	// IndicatorDNSCNAME matches the CNAME target of a DNS record.
	IndicatorDNSCNAME IndicatorKind = "dns_cname"
	// IndicatorSourceMapPath matches a source map resource's URL path.
	IndicatorSourceMapPath IndicatorKind = "sourcemap_path"
)

// String returns the canonical lowercase kind value.
func (k IndicatorKind) String() string { return string(k) }

// Valid reports whether k is one of the 16 known kinds.
func (k IndicatorKind) Valid() bool {
	switch k {
	case IndicatorHeader, IndicatorCookie, IndicatorHTMLRegex,
		IndicatorHTMLSubstring, IndicatorMetaName, IndicatorGenerator,
		IndicatorScriptName, IndicatorScriptPath, IndicatorCSSPath,
		IndicatorAttribute, IndicatorEndpointPath, IndicatorTLSIssuer,
		IndicatorTLSCN, IndicatorTLSALPN, IndicatorDNSCNAME, IndicatorSourceMapPath:
		return true
	}
	return false
}

// ParseIndicatorKind validates s and returns the canonical kind. An unknown
// value is an error: kinds are never silently coerced.
func ParseIndicatorKind(s string) (IndicatorKind, error) {
	k := IndicatorKind(s)
	if !k.Valid() {
		return "", fmt.Errorf("unknown indicator kind %q", s)
	}
	return k, nil
}

// Tier classifies indicators by how trivially a server operator can fake
// them. Confidence scoring (a later pass) weights tiers; spoofable evidence
// never outweighs structural evidence alone.
type Tier string

const (
	// TierSpoofable marks indicators any server operator can emit without
	// running the technology: HTTP headers, cookies, DNS CNAMEs.
	TierSpoofable Tier = "spoofable"
	// TierStructural marks indicators that are hard to fake without
	// actually running the technology: HTML markers, script/CSS paths,
	// endpoints, TLS certificate fields.
	TierStructural Tier = "structural"
)

// Tier returns the tier for a kind: spoofable for header, cookie, and
// dns_cname indicators; structural for everything else.
func (k IndicatorKind) Tier() Tier {
	switch k {
	case IndicatorHeader, IndicatorCookie, IndicatorDNSCNAME:
		return TierSpoofable
	default:
		return TierStructural
	}
}

// VersionSpec extracts a version string from the matched observation.
type VersionSpec struct {
	// Pattern is a regular expression applied to the matched value as
	// observed (no case folding; use (?i) where the marker case varies).
	Pattern string `json:"pattern"`
	// Group is the capture group whose text becomes the version.
	Group int `json:"group"`
}

// Indicator is one observable marker for a technology.
//
// Match is a case-insensitive substring for literal kinds and a regular
// expression for html_regex and generator kinds (see the package doc's
// matching contract). Weight must satisfy 0 < weight <= 1 and is validated
// at load time.
type Indicator struct {
	Kind    IndicatorKind `json:"kind"`
	Match   string        `json:"match"`
	Weight  float64       `json:"weight"`
	Version *VersionSpec  `json:"version,omitempty"`

	// matchRe is Match compiled as a regex, but only for the regex kinds
	// (html_regex, generator); nil otherwise. versionRe is
	// Version.Pattern compiled. Both are filled exactly once by the
	// compiler and are never serialized. MatchRe and VersionRe are the
	// exported accessors; the engine must never compile its own regexes
	// and consumes both through these compile-once accessors.
	matchRe   *regexp.Regexp
	versionRe *regexp.Regexp
}

// VersionRe returns the compiled Version.Pattern, or nil when the indicator
// carries no version spec. The returned instance is shared: every call
// returns the same *regexp.Regexp (compile-once proof). The engine must
// never compile its own regexes.
//
// VersionRe is nil for indicators that never went through the compiler (for
// example hand-built test fixtures); production indicators always come from
// a compiled DB.
func (i Indicator) VersionRe() *regexp.Regexp { return i.versionRe }

// MatchRe returns the compiled Match expression, but only for the regex
// kinds (html_regex, generator); nil for every other kind. The returned
// instance is shared: every call returns the same *regexp.Regexp
// (compile-once proof). The engine must never compile its own regexes; it
// consumes MatchRe exactly like VersionRe.
//
// MatchRe is nil for indicators that never went through the compiler (for
// example hand-built test fixtures); production indicators always come from
// a compiled DB.
func (i Indicator) MatchRe() *regexp.Regexp { return i.matchRe }

// Fingerprint is one technology's full detection rule set: a canonical name
// within one technology category, plus the indicators that fire for it.
type Fingerprint struct {
	// Name is the canonical lowercase technology name, e.g. "cloudflare"
	// or "next.js". Names are unique across the whole database.
	Name string `json:"name"`

	// Category classifies the technology (see asset.TechnologyCategory).
	Category asset.TechnologyCategory `json:"category"`

	// Indicators are the observable markers for this technology.
	Indicators []Indicator `json:"indicators"`
}

// SchemaVersion versions the fingerprint database schema.
//
// Cache keys for technology detection results must include it: bumping
// SchemaVersion invalidates every cached result by construction, mirroring
// internal/cache's schema versioning. Never reuse a bumped version number.
const SchemaVersion = 1

// DB is an immutable, validated, compile-once fingerprint database.
//
// A DB is produced only by Load (production tables) or the test-only
// newRawDB constructor. It never mutates after construction: Fingerprints
// returns deep copies, and the compiled regexes are shared, never rewritten.
type DB struct {
	schemaVersion int
	fingerprints  []Fingerprint // sorted by Name, then Category
}

// Version returns the schema version of this database.
func (d *DB) Version() int { return d.schemaVersion }

// Len returns the number of fingerprints in the database.
func (d *DB) Len() int { return len(d.fingerprints) }

// Fingerprints returns every fingerprint sorted deterministically by name,
// then category. The returned slice is a fresh deep copy: callers may
// mutate it freely without affecting the DB.
func (d *DB) Fingerprints() []Fingerprint {
	out := make([]Fingerprint, len(d.fingerprints))
	for i, fp := range d.fingerprints {
		out[i] = fp
		out[i].Indicators = make([]Indicator, len(fp.Indicators))
		copy(out[i].Indicators, fp.Indicators)
	}
	return out
}
