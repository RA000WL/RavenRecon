package secrentel

import (
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// The correlation engine assembles multi-evidence signals for one document:
//
//   - provider ENDPOINTS observed in the content (s3.amazonaws.com next to
//     an AWS key),
//   - provider TECHNOLOGIES (caller-provided techintel detections),
//   - sibling PAIRS: two candidates of the same provider with different
//     types (AWS access key + AWS secret key → both boosted),
//
// and cross-document REPEATED OBSERVATION at report build (the same
// (type, value) in two documents). Evidence accumulates; a lone random
// base64 blob never gains any of these factors.

// providerSignals are the correlation signals of one provider inside one
// document.
type providerSignals struct {
	endpoint string // first matched endpoint indicator
	tech     string // first matched technology name
}

// signalScan is the bounded provider-endpoint scan of one document.
type signalScan struct {
	byProvider map[string]providerSignals
	scanned    int // endpoint indicators examined (bounded by the table)
}

// scanSignals finds, for every provider in the correlation table, the first
// endpoint indicator present in the content and the first matching
// technology hint. One pass per indicator (the table is small and fixed;
// strings.Contains is bounded by the 2 MiB document cap).
func scanSignals(content []byte, correlations []patterns.ProviderCorrelation, technologies []string) signalScan {
	out := signalScan{byProvider: make(map[string]providerSignals)}
	s := string(content)
	for _, c := range correlations {
		out.scanned += len(c.Endpoints) + len(c.Tech)
		sig := out.byProvider[c.Provider]
		for _, e := range c.Endpoints {
			if strings.Contains(s, e) {
				sig.endpoint = e
				break
			}
		}
		for _, t := range technologies {
			matched := false
			for _, ct := range c.Tech {
				if strings.Contains(t, ct) {
					matched = true
					break
				}
			}
			if matched {
				sig.tech = t
				break
			}
		}
		if sig.endpoint != "" || sig.tech != "" {
			out.byProvider[c.Provider] = sig
		}
	}
	return out
}

// pairMap identifies sibling pairs: for every provider with candidates of
// two or more DISTINCT types (structured or contextual families only — a
// generic blob sharing a provider tag is not a pair), every candidate of
// that provider is pair-boosted and linked to its siblings.
type pairMap map[string][]string // candidate ID -> sibling candidate IDs

// buildPairs computes the sibling links over the scanned candidates.
func buildPairs(cands []scannedCandidate) pairMap {
	byProvider := make(map[string]map[string][]string) // provider -> type -> ids
	for _, c := range cands {
		if c.provider == "" {
			continue
		}
		if c.family != patterns.FamilyStructured && c.family != patterns.FamilyContextual {
			continue
		}
		if byProvider[c.provider] == nil {
			byProvider[c.provider] = make(map[string][]string)
		}
		byProvider[c.provider][string(c.typ)] = append(byProvider[c.provider][string(c.typ)], c.id)
	}
	pairs := make(pairMap)
	for _, types := range byProvider {
		if len(types) < 2 {
			continue
		}
		var all []string
		for _, ids := range types {
			all = append(all, ids...)
		}
		sort.Strings(all)
		for _, id := range all {
			siblings := make([]string, 0, len(all)-1)
			for _, other := range all {
				if other != id {
					siblings = append(siblings, other)
				}
			}
			pairs[id] = siblings
		}
	}
	return pairs
}
