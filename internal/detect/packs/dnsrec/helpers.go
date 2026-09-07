package dnsrec

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// DNS evidence indicators carried from the pipeline DNS adapter (NEW-126 T2).
// The adapter synthesizes these from the engine's retained string/port
// payloads with MethodDNS and the queried host as Evidence.Source; values
// longer than the asset package's 256-byte evidence bound arrive clipped
// with the "…" suffix marker (see asset.NewEvidence). These constants must
// stay byte-identical to the adapter's dnsTXTIndicator/dnsSRVIndicator —
// they are repeated here (not imported) because a detect→pipeline import
// would cycle.
const (
	dnsTXTIndicator = "dns:txt"
	dnsSRVIndicator = "dns:srv"
)

// clippedMarker is the asset package's evidence-truncation suffix (U+2026).
// A value carrying this suffix is a clipped prefix of a longer observation,
// never a complete record.
const clippedMarker = "…"

// isClipped reports whether a stored evidence value is a clipped prefix.
func isClipped(v string) bool {
	return strings.HasSuffix(v, clippedMarker)
}

// dnsrecFinding builds one canonical dnsrec-pack finding. Subject must be
// observed; evidence is a MethodDetection record on the subject with
// provenance Source "dnsrec". Category is information, priority info,
// confidence 0.6 (heuristic observation, not a vulnerability claim), status
// open, timestamps from injected Clock for determinism.
func dnsrecFinding(dctx *detect.Context, ruleID, ruleName string, subject asset.Identity, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "dnsrec pack signal: "+ruleID, subject, asset.Provenance{Source: "dnsrec"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleName,
		Category:   detect.CategoryInformation.String(),
		Subject:    subject,
		Confidence: 0.6,
		Evidence:   []asset.Evidence{ev},
		Metadata:   meta,
		Priority:   detect.PriorityInfo.String(),
		Status:     detect.StatusOpen.String(),
		Created:    dctx.Clock.Now().UTC(),
	})
}

// sortedKeys returns map keys in deterministic sorted order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// formatConfigKeys logs sorted config keys via Logger for deterministic handling.
func formatConfigKeys(dctx *detect.Context, ruleID string) {
	if len(dctx.Config) == 0 {
		return
	}
	keys := sortedKeys(dctx.Config)
	msg := fmt.Sprintf("config keys: %s", strings.Join(keys, ","))
	dctx.Logger.Log(detect.LevelInfo, ruleID, msg)
}

// hostsWithIP returns the set of host identities that have a host->IP relationship.
func hostsWithIP(dctx *detect.Context) map[asset.Identity]struct{} {
	m := make(map[asset.Identity]struct{})
	for _, rel := range dctx.Relationships {
		if rel.Kind == asset.RelationshipHostToIP {
			m[rel.From] = struct{}{}
		}
	}
	return m
}

// hostAssets returns the sorted set of host identities present in the asset
// census. Evidence rules iterate this (not raw evidence sources) so every
// subject is an observed census member and findings always pass the
// observed-corpus check.
func hostAssets(dctx *detect.Context) []asset.Identity {
	var out []asset.Identity
	for _, id := range dctx.Assets {
		if id.Kind == asset.KindHost {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// hostAssetSet returns the census set behind hostAssets for O(1) membership.
func hostAssetSet(dctx *detect.Context) map[asset.Identity]struct{} {
	m := make(map[asset.Identity]struct{})
	for _, id := range dctx.Assets {
		if id.Kind == asset.KindHost {
			m[id] = struct{}{}
		}
	}
	return m
}
