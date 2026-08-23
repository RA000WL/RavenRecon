package asset

import (
	"fmt"
	"strings"
)

// Endpoint is an HTTP request shape: a method applied to a URL.
type Endpoint struct {
	// Method is the canonical uppercase HTTP method; empty input becomes "GET".
	Method string `json:"method"`

	// URL is the canonical URL the method applies to.
	URL URL `json:"url"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewEndpoint builds a validated Endpoint from a method and a raw URL.
func NewEndpoint(method, rawURL string, p Provenance) (Endpoint, error) {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	if err := validateMethod(m); err != nil {
		return Endpoint{}, err
	}
	u, err := ParseURL(rawURL, p)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid endpoint URL: %w", err)
	}
	return Endpoint{Method: m, URL: u, Prov: p}, nil
}

// maxMethodBytes bounds the canonical HTTP method. Standard methods are at
// most 7 bytes ("CONNECT"); the endpoint classes jsintel/urlintel emit
// ("GET", "WS", "SSE", "GQL") are shorter still. 16 bytes leaves generous
// headroom for WebDAV-style verbs while keeping method strings out of
// identities unbounded.
const maxMethodBytes = 16

func validateMethod(m string) error {
	if len(m) > maxMethodBytes {
		return fmt.Errorf("method %q is longer than %d bytes", m, maxMethodBytes)
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return fmt.Errorf("method %q contains invalid character %q", m, c)
		}
	}
	return nil
}

// Identity returns the deterministic identity used for deduplication.
func (e Endpoint) Identity() Identity {
	return Identity{Kind: KindEndpoint, Value: e.Method + " " + e.URL.String()}
}

// ID returns the canonical identity string.
func (e Endpoint) ID() string { return e.Identity().String() }

// String returns the canonical identity value, e.g. "GET https://example.com/api".
func (e Endpoint) String() string { return e.Identity().Value }
