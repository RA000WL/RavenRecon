package asset

import (
	"fmt"
	"strings"
	"time"
)

// Bounds applied by the JavaScript observation setters.
const (
	// maxJavaScriptContentHashChars is the exact length of a canonical
	// content hash: the lowercase hex SHA-256 of the script body. Empty
	// means "not observed".
	maxJavaScriptContentHashChars = 64
	// maxJavaScriptContentTypeBytes bounds an observed Content-Type value.
	maxJavaScriptContentTypeBytes = 128
	// maxJavaScriptETagBytes bounds an observed ETag value.
	maxJavaScriptETagBytes = 256
	// maxJavaScriptDiscoverySourceBytes bounds an observed discovery-source
	// label (the capability that surfaced the script observation).
	maxJavaScriptDiscoverySourceBytes = 128
	// minJavaScriptStatusCode and maxJavaScriptStatusCode bound an observed
	// HTTP status code (the 1xx..5xx range); zero means "not observed".
	minJavaScriptStatusCode = 100
	maxJavaScriptStatusCode = 599
)

// JavaScript is a script resource observed at a URL.
//
// The identity is the canonical URL — KindJavaScript + URL.String() — and
// every other field is an OBSERVATION of that resource, never part of the
// identity: a changed or dropped observation never changes the asset. The
// URL asset's own Original field carries the raw form as first observed.
type JavaScript struct {
	// URL is the canonical URL of the script resource.
	URL URL `json:"url"`

	// Hash is an optional content hash, kept for later content-level
	// deduplication. It is not part of the identity.
	Hash string `json:"hash,omitempty"`

	// Host is the host the script resource was observed on, as a canonical
	// Host asset. The zero Host (no name) means "not observed".
	Host Host `json:"host"`

	// ContentHash is the lowercase hex SHA-256 of the script body — exactly
	// maxJavaScriptContentHashChars characters when observed. Empty means
	// "not observed". Not part of the identity.
	ContentHash string `json:"content_hash,omitempty"`

	// Size is the observed script body size in bytes; zero means "not
	// observed".
	Size int64 `json:"size,omitempty"`

	// ContentType is the observed Content-Type header value of the script
	// response, bounded printable ASCII. Empty means "not observed".
	ContentType string `json:"content_type,omitempty"`

	// ETag is the observed ETag header value of the script response, bounded
	// printable ASCII. Empty means "not observed".
	ETag string `json:"etag,omitempty"`

	// LastModified is the observed Last-Modified header time of the script
	// response. The zero time means "not observed".
	LastModified time.Time `json:"last_modified,omitempty"`

	// DiscoverySource is a generic label for the capability that surfaced
	// this script observation (e.g. "html-scan"), bounded printable ASCII.
	// Empty means "not observed".
	DiscoverySource string `json:"discovery_source,omitempty"`

	// StatusCode is the observed HTTP status code of the script response,
	// 100..599 when observed; zero means "not observed".
	StatusCode int `json:"status_code,omitempty"`

	// FinalURL is the canonical URL the script response was actually served
	// from after redirects. The zero URL means "no redirect observed" — the
	// resource was served from URL itself.
	FinalURL URL `json:"final_url"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewJavaScript parses rawURL into a JavaScript asset.
func NewJavaScript(rawURL string, p Provenance) (JavaScript, error) {
	u, err := ParseURL(rawURL, p)
	if err != nil {
		return JavaScript{}, fmt.Errorf("invalid javascript URL: %w", err)
	}
	return JavaScript{URL: u, Prov: p}, nil
}

// Identity returns the deterministic identity used for deduplication.
//
// The identity is exactly the canonical URL of the script resource
// (KindJavaScript + URL.String()); the URL asset's own Original field carries
// the raw form. Observations never enter the identity.
func (j JavaScript) Identity() Identity {
	return Identity{Kind: KindJavaScript, Value: j.URL.String()}
}

// ID returns the canonical identity string.
func (j JavaScript) ID() string { return j.Identity().String() }

// WithHost returns a copy of j carrying the host the script was observed on.
// It never mutates j. The name is normalized through NewHost, so the stored
// Host is always canonical. An empty (or blank) name clears the observation
// to the zero Host ("not observed").
func WithHost(j JavaScript, name string) (JavaScript, error) {
	if strings.TrimSpace(name) == "" {
		out := j
		out.Host = Host{}
		return out, nil
	}
	h, err := NewHost(name, Provenance{})
	if err != nil {
		return JavaScript{}, fmt.Errorf("set javascript host: %w", err)
	}
	out := j
	out.Host = h
	return out, nil
}

// WithContentHash returns a copy of j carrying the observed content hash of
// the script body. It never mutates j.
//
// A set value must be in canonical form — exactly
// maxJavaScriptContentHashChars lowercase hex characters (the SHA-256 digest
// of the body); uppercase or otherwise non-canonical input is rejected, never
// coerced, so identity-adjacent inputs are never silently rewritten. Empty
// means "not observed" and is always accepted.
func WithContentHash(j JavaScript, hash string) (JavaScript, error) {
	if err := validateJavaScriptContentHash(hash); err != nil {
		return JavaScript{}, fmt.Errorf("set javascript content hash: %w", err)
	}
	out := j
	out.ContentHash = hash
	return out, nil
}

// validateJavaScriptContentHash enforces the canonical content-hash form:
// empty (unobserved) or exactly maxJavaScriptContentHashChars lowercase hex
// characters. Uppercase hex is rejected (the canonical form boundary), never
// lowercased.
func validateJavaScriptContentHash(hash string) error {
	if hash == "" {
		return nil
	}
	if len(hash) != maxJavaScriptContentHashChars {
		return fmt.Errorf("content hash must be exactly %d lowercase hex characters, got %d", maxJavaScriptContentHashChars, len(hash))
	}
	for i := 0; i < len(hash); i++ {
		c := hash[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("content hash must contain only lowercase hex characters [0-9a-f], got %q at index %d", c, i)
		}
	}
	return nil
}

// WithSize returns a copy of j carrying the observed script body size in
// bytes. It never mutates j. Size must be non-negative; zero means "not
// observed".
func WithSize(j JavaScript, size int64) (JavaScript, error) {
	if size < 0 {
		return JavaScript{}, fmt.Errorf("set javascript size: size %d must not be negative", size)
	}
	out := j
	out.Size = size
	return out, nil
}

// WithContentType returns a copy of j carrying the observed Content-Type
// header value of the script response. It never mutates j. The value must be
// at most maxJavaScriptContentTypeBytes bytes of printable ASCII; empty means
// "not observed".
func WithContentType(j JavaScript, contentType string) (JavaScript, error) {
	if err := validateJavaScriptString("content type", contentType, maxJavaScriptContentTypeBytes); err != nil {
		return JavaScript{}, fmt.Errorf("set javascript content type: %w", err)
	}
	out := j
	out.ContentType = contentType
	return out, nil
}

// WithETag returns a copy of j carrying the observed ETag header value of the
// script response. It never mutates j. The value must be at most
// maxJavaScriptETagBytes bytes of printable ASCII; empty means "not
// observed".
func WithETag(j JavaScript, etag string) (JavaScript, error) {
	if err := validateJavaScriptString("etag", etag, maxJavaScriptETagBytes); err != nil {
		return JavaScript{}, fmt.Errorf("set javascript etag: %w", err)
	}
	out := j
	out.ETag = etag
	return out, nil
}

// WithLastModified returns a copy of j carrying the observed Last-Modified
// header time of the script response. It never mutates j. Any time is
// accepted; the zero time means "not observed".
func WithLastModified(j JavaScript, lastModified time.Time) (JavaScript, error) {
	out := j
	out.LastModified = lastModified
	return out, nil
}

// WithDiscoverySource returns a copy of j carrying the generic label of the
// capability that surfaced this script observation. It never mutates j. The
// label must be at most maxJavaScriptDiscoverySourceBytes bytes of printable
// ASCII; empty means "not observed".
func WithDiscoverySource(j JavaScript, source string) (JavaScript, error) {
	if err := validateJavaScriptString("discovery source", source, maxJavaScriptDiscoverySourceBytes); err != nil {
		return JavaScript{}, fmt.Errorf("set javascript discovery source: %w", err)
	}
	out := j
	out.DiscoverySource = source
	return out, nil
}

// WithStatusCode returns a copy of j carrying the observed HTTP status code
// of the script response. It never mutates j. A set value must lie in
// minJavaScriptStatusCode..maxJavaScriptStatusCode (the 1xx..5xx range); zero
// means "not observed".
func WithStatusCode(j JavaScript, status int) (JavaScript, error) {
	if status != 0 && (status < minJavaScriptStatusCode || status > maxJavaScriptStatusCode) {
		return JavaScript{}, fmt.Errorf("set javascript status code: %d is outside %d..%d", status, minJavaScriptStatusCode, maxJavaScriptStatusCode)
	}
	out := j
	out.StatusCode = status
	return out, nil
}

// WithFinalURL returns a copy of j carrying the canonical URL the script
// response was served from after redirects. It never mutates j.
//
// The value is canonicalized through ParseURL and must re-parse canonically
// to its own identity — the stored FinalURL is always a canonical URL asset,
// never a raw redirect string. An empty (or blank) value clears the
// observation to the zero URL ("no redirect observed").
func WithFinalURL(j JavaScript, rawURL string) (JavaScript, error) {
	if strings.TrimSpace(rawURL) == "" {
		out := j
		out.FinalURL = URL{}
		return out, nil
	}
	u, err := ParseURL(rawURL, Provenance{})
	if err != nil {
		return JavaScript{}, fmt.Errorf("set javascript final url: %w", err)
	}
	re, err := ParseURL(u.String(), Provenance{})
	if err != nil {
		return JavaScript{}, fmt.Errorf("set javascript final url: %w", err)
	}
	if !re.Identity().Equal(u.Identity()) {
		return JavaScript{}, fmt.Errorf("set javascript final url: %q does not re-parse canonically to its own identity", u.String())
	}
	out := j
	out.FinalURL = u
	return out, nil
}

// validateJavaScriptString enforces the shared bounds for bounded observed
// string fields: at most max bytes of printable ASCII. Empty values are
// allowed: they mean "not observed", and the merge treats them as unset.
func validateJavaScriptString(field, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("javascript %s is %d bytes, longer than the %d maximum", field, len(s), max)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return fmt.Errorf("javascript %s %q contains a non-printable character", field, s)
		}
	}
	return nil
}
