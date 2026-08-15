package asset

import (
	"fmt"
	"unicode/utf8"
)

// DetectionMethod identifies the observation channel an Evidence record came
// from. It maps onto the fingerprint database's finer-grained indicator kinds:
//
//	header    <- header indicators (name and name=value forms)
//	cookie    <- cookie indicators (name and name* prefix forms)
//	html      <- html_regex and html_substring indicators
//	generator <- generator indicators
//	meta      <- meta_name indicators
//	script    <- script_name and script_path indicators
//	css       <- css_path indicators
//	attribute <- attribute indicators
//	endpoint  <- endpoint_path indicators
//	tls       <- tls_issuer, tls_cn, tls_alpn indicators
//	dns       <- dns_cname indicators
//	sourcemap <- sourcemap_path indicators
//
// The method is part of the evidence identity.
type DetectionMethod string

const (
	MethodHeader    DetectionMethod = "header"
	MethodCookie    DetectionMethod = "cookie"
	MethodHTML      DetectionMethod = "html"
	MethodGenerator DetectionMethod = "generator"
	MethodMeta      DetectionMethod = "meta"
	MethodScript    DetectionMethod = "script"
	MethodCSS       DetectionMethod = "css"
	MethodAttribute DetectionMethod = "attribute"
	MethodEndpoint  DetectionMethod = "endpoint"
	MethodTLS       DetectionMethod = "tls"
	MethodDNS       DetectionMethod = "dns"
	MethodSourceMap DetectionMethod = "sourcemap"
)

// String returns the canonical lowercase method value.
func (m DetectionMethod) String() string { return string(m) }

// Valid reports whether m is one of the known detection methods.
func (m DetectionMethod) Valid() bool {
	switch m {
	case MethodHeader, MethodCookie, MethodHTML, MethodGenerator, MethodMeta,
		MethodScript, MethodCSS, MethodAttribute, MethodEndpoint, MethodTLS,
		MethodDNS, MethodSourceMap:
		return true
	}
	return false
}

// ParseDetectionMethod validates s and returns the canonical method.
func ParseDetectionMethod(s string) (DetectionMethod, error) {
	m := DetectionMethod(s)
	if !m.Valid() {
		return "", fmt.Errorf("unknown detection method %q", s)
	}
	return m, nil
}

// KnownMethods returns every detection method in canonical sorted order. The
// returned slice is a fresh copy; callers may mutate it freely.
func KnownMethods() []DetectionMethod {
	return []DetectionMethod{
		MethodAttribute, MethodCookie, MethodCSS, MethodDNS, MethodEndpoint,
		MethodGenerator, MethodHeader, MethodHTML, MethodMeta, MethodScript,
		MethodSourceMap, MethodTLS,
	}
}

// Bounds applied by NewEvidence.
const (
	// maxEvidenceIndicatorBytes bounds the canonical indicator key, e.g.
	// "header:server" or "html:generator_meta". Indicators are embedded in
	// the identity value, so this also bounds identity sizes.
	maxEvidenceIndicatorBytes = 128
	// maxEvidenceValueBytes bounds the STORED observed value. Raw values
	// longer than this are truncated at ingestion (see NewEvidence); the
	// identity always covers exactly the stored bytes.
	maxEvidenceValueBytes = 256
	// evidenceTruncationMarker marks a value that was truncated at
	// ingestion. It is U+2026 ("…", 3 bytes in UTF-8), chosen because it is
	// visually unambiguous and cannot be confused with an emitted byte.
	evidenceTruncationMarker = "…"
)

// Evidence is one per-observation indicator record: the matched fingerprint
// indicator, the observed value, and the source asset the observation came
// from.
//
// The identity is "method/indicator/value/source" where value is the STORED
// (already truncated) value and source is the percent-encoded identity of the
// source asset. Because truncation happens before identity derivation, two
// observations whose raw values differ only after the 256-byte bound are the
// SAME evidence asset — the identity covers exactly what is stored, and
// re-ingesting the stored value reproduces the same identity. The source
// asset participates in the identity: the same indicator matched on two
// different hosts is two distinct evidence records, never one merged record
// that silently drops one host's attribution.
type Evidence struct {
	// Method is the detection channel (see DetectionMethod).
	Method DetectionMethod `json:"method"`

	// Indicator is the canonical key of the matched fingerprint indicator,
	// e.g. "header:server" or "html:generator_meta". It is a bounded,
	// opaque canonical key; the fingerprint database owns the universe of
	// indicator keys.
	Indicator string `json:"indicator"`

	// Value is the observed evidence string, truncated to at most
	// maxEvidenceValueBytes bytes with the evidenceTruncationMarker suffix
	// when the raw observation was longer. Values are never rejected.
	Value string `json:"value"`

	// Source is the identity of the source asset — the URL, endpoint, host,
	// or other asset the observation came from.
	Source Identity `json:"source"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewEvidence builds a validated Evidence record.
//
// The observed value is NEVER rejected: if it exceeds maxEvidenceValueBytes
// it is truncated to a rune-safe prefix of at most 253 bytes plus the
// evidenceTruncationMarker ("…"), for a stored size of at most 256 bytes.
// The identity is derived from the STORED value (see Evidence.Identity).
func NewEvidence(method DetectionMethod, indicator, value string, source Identity, p Provenance) (Evidence, error) {
	if !method.Valid() {
		return Evidence{}, fmt.Errorf("invalid detection method %q", method)
	}
	if err := validateEvidenceIndicator(indicator); err != nil {
		return Evidence{}, err
	}
	if source.IsZero() {
		return Evidence{}, fmt.Errorf("evidence source identity must not be zero")
	}
	return Evidence{
		Method:    method,
		Indicator: indicator,
		Value:     truncateEvidence(value),
		Source:    source,
		Prov:      p,
	}, nil
}

// Identity returns the deterministic identity used for deduplication.
//
// The identity value is "method/indicator/value/source", each component
// percent-encoded (service.go's percentEncode), so separators inside an
// indicator, value, or source identity can never blur the boundaries. The
// encoded value is the STORED value — the one truncateEvidence produced — so
// the identity covers exactly what is stored, never the original raw
// observation. The source component is the canonical identity string of the
// source asset (e.g. "host:www.example.com"), encoded like any other
// component: two observations from different source assets are two distinct
// evidence records.
func (e Evidence) Identity() Identity {
	return Identity{
		Kind: KindEvidence,
		Value: string(e.Method) + "/" + percentEncode(e.Indicator) + "/" +
			percentEncode(e.Value) + "/" + percentEncode(e.Source.String()),
	}
}

// ID returns the canonical identity string.
func (e Evidence) ID() string { return e.Identity().String() }

// String returns the canonical identity value, e.g.
// "header/header%3Aserver/cloudflare/host%3Awww.example.com".
func (e Evidence) String() string { return e.Identity().Value }

// validateEvidenceIndicator enforces the indicator bounds: non-empty, at
// most maxEvidenceIndicatorBytes bytes, printable ASCII (including space:
// match strings like "server: nginx" are part of the canonical key). The
// indicator is an opaque canonical key; the fingerprint database defines its
// universe.
func validateEvidenceIndicator(indicator string) error {
	if indicator == "" {
		return fmt.Errorf("evidence indicator must not be empty")
	}
	if len(indicator) > maxEvidenceIndicatorBytes {
		return fmt.Errorf("evidence indicator is longer than %d bytes", maxEvidenceIndicatorBytes)
	}
	for i := 0; i < len(indicator); i++ {
		if indicator[i] < 0x20 || indicator[i] > 0x7e {
			return fmt.Errorf("evidence indicator %q contains a non-printable character", indicator)
		}
	}
	return nil
}

// truncateEvidence bounds a raw observed value to maxEvidenceValueBytes
// bytes. Values within the bound are returned unchanged. Longer values are
// truncated to a rune-safe prefix of at most 253 bytes plus the "…" marker
// (3 bytes) for a total of at most 256 bytes. The result carries no
// information about whether truncation happened beyond the marker itself;
// callers that need the flag should compare lengths before calling.
func truncateEvidence(raw string) string {
	if len(raw) <= maxEvidenceValueBytes {
		return raw
	}
	prefix := raw[:maxEvidenceValueBytes-len(evidenceTruncationMarker)]
	// Trim an incomplete trailing UTF-8 sequence so the marker never follows
	// a torn rune. For valid UTF-8 this loop does not run.
	for len(prefix) > 0 {
		r, size := utf8.DecodeLastRuneInString(prefix)
		if r != utf8.RuneError || size > 1 {
			break
		}
		prefix = prefix[:len(prefix)-1]
	}
	return prefix + evidenceTruncationMarker
}

// MergeEvidence combines two observations of the same evidence record.
//
// All identifying fields (method, indicator, value, source) are part of the
// identity, so the only mergeable state is provenance: the earliest
// observation wins, mirroring the other Merge primitives.
func MergeEvidence(a, b Evidence) (Evidence, error) {
	if !a.Identity().Equal(b.Identity()) {
		return Evidence{}, mergeMismatch(KindEvidence, a.Identity(), b.Identity())
	}
	m := a
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}
