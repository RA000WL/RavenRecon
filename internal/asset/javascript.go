package asset

import "fmt"

// JavaScript is a script resource observed at a URL.
type JavaScript struct {
	// URL is the canonical URL of the script resource.
	URL URL `json:"url"`

	// Hash is an optional content hash, kept for later content-level
	// deduplication. It is not part of the identity.
	Hash string `json:"hash,omitempty"`

	// Prov records where and where this observation came from.
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
func (j JavaScript) Identity() Identity {
	return Identity{Kind: KindJavaScript, Value: j.URL.String()}
}

// ID returns the canonical identity string.
func (j JavaScript) ID() string { return j.Identity().String() }
