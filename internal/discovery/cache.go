package discovery

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// cacheKey derives the Phase 3 cache key for one source and target.
//
// The key contains every input that materially changes the result: the
// operation ("passive-discovery"), the canonical Phase 2 target identity
// ("domain:example.com" — raw user input never reaches a key), the
// result-relevant configuration, and the tool identity (name plus detected
// version), because a tool version change can change results.
//
// The only result-relevant configuration today is the passive mode. Adding
// other invocation modes (or any option that changes the results' meaning)
// MUST extend this map; timings, rate limits, and other non-semantic settings
// must never enter the key.
//
// Callers must invoke cacheKey only for known-version tools: by policy (see
// runSource) an unknown version (det.Version == "") makes the tool
// NON-CACHEABLE, and it must never be keyed, read, or written under a
// ""-version identity, which could not be distinguished from any other
// unknown version.
func cacheKey(target asset.Domain, src Source, det Detection) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    target.Identity().String(),
		Config:    map[string]string{"mode": "passive"},
		Tool:      cache.ToolInfo{Name: src.Name(), Version: det.Version},
	})
}

// storedResult is the structured Data payload stored in cache records. It is
// never terminal output; it is the normalized, deduplicated result model.
type storedResult struct {
	Source  string       `json:"source"`
	Version string       `json:"version,omitempty"`
	Target  string       `json:"target"`
	Hosts   []asset.Host `json:"hosts"`
	// Malformed counts lines skipped by the parser (diagnostics).
	Malformed int `json:"malformed,omitempty"`
	// Truncated reports that stdout hit the capture cap at execution time.
	Truncated bool `json:"truncated,omitempty"`
	// QualityIssues records the data-quality gate findings for this source
	// at the time the producing run stored the record (flag-and-continue by
	// default). Missing in old records decodes as nil — no issues.
	QualityIssues []QualityIssue `json:"quality_issues,omitempty"`
}

// decodeStored validates and decodes a stored payload before it may be served
// as a hit. It re-validates every host through the Phase 2 asset model,
// refuses payloads whose target does not match the query, whose Source field
// names a different tool than the queried source, whose hosts fall outside
// the queried domain, or whose hosts are not in canonical form, so a corrupt,
// tampered, or legacy completed record can never produce bogus assets.
func decodeStored(raw json.RawMessage, target asset.Domain, srcName string) (storedResult, error) {
	var s storedResult
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("parse stored result: %w", err)
	}
	if s.Target != target.Identity().String() {
		return s, fmt.Errorf("stored result target %q does not match %q", s.Target, target.Identity().String())
	}
	if s.Source == "" {
		return s, fmt.Errorf("stored result has no source")
	}
	if s.Source != srcName {
		return s, fmt.Errorf("stored result source %q does not match queried source %q", s.Source, srcName)
	}
	for _, h := range s.Hosts {
		nh, err := asset.NewHost(h.Name, h.Prov)
		if err != nil {
			return s, fmt.Errorf("stored result contains invalid host %q: %w", h.Name, err)
		}
		// Stored hosts must be in canonical form, mirroring validateTarget's
		// requirement for the target: asset.NewHost trims surrounding
		// whitespace and lowercases, so a raw name that differs from its
		// normalization (e.g. " api.example.com" or "api.example.com.")
		// could pass a raw-string containment check while breaking dedup
		// and formatting. Such a record is refused — never served with its
		// raw name — and runSource deletes it and falls through to a fresh
		// execution whose canonical result replaces it in the same run
		// (self-healing), so a rejected record can never wedge the source
		// into repeated failures until TTL expiry.
		if nh.Name != h.Name {
			return s, fmt.Errorf("stored result host %q is not in canonical form (normalized %q)", h.Name, nh.Name)
		}
		if nh.Name != target.Name && !strings.HasSuffix(nh.Name, "."+target.Name) {
			return s, fmt.Errorf("stored result host %q is outside target domain %q", nh.Name, target.Name)
		}
	}
	return s, nil
}
