package takeover

import (
	"context"
	"fmt"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// providerConfirmedDetector is the NEW-143 enrichment over
// takeover.cname.unclaimed: it emits a SECOND finding per host whose
// sibling unclaimed finding completed at an earlier dependency level
// (Context.PriorFindings) AND whose observed host→CNAME graph edge maps
// to the curated provider suffix table (Context.GraphView.Neighbors +
// providerForHost — the existing helper table, no new provider list).
//
// Identity discipline: the enrichment finding's identity is
// "takeover.cname.provider-confirmed@<subject>" — distinct from the
// sibling unclaimed finding by rule ID — so the unclaimed finding stays
// byte-identical whether or not this rule is loaded (pinned by
// TestTakeoverEnrichmentLeavesUnclaimedUntouched).
//
// Target-equality note: the corroboration is per host, not per target —
// cname_target below comes from the live host→CNAME graph edge, and the
// sibling's cname_target metadata is never cross-checked, so the two can
// differ on multi-CNAME hosts without blocking the finding (pinned by
// TestTakeoverEnrichmentPerHostNotTargetEquality).
//
// Fail-open quiets (nil, nil — never an error, never a guess):
//
//   - nil GraphView (hand-constructed Context outside the engine; the
//     engine always installs it),
//   - empty PriorFindings (level 0 produced nothing),
//   - no sibling unclaimed priors, or no CNAME→provider graph edge for a
//     prior subject (dangling-only hosts and non-provider CNAMEs fall
//     out naturally).
//
// This is RECON CORROBORATION, not a vulnerability claim: Category
// Information, PriorityInfo, confidence 0.6 (heuristic), StatusOpen —
// the finding names the observed correlation and never claims
// exploitability, reachability, or validity (AGENTS §0.1).
//
// Cache honesty note: the engine's prior digest (graph_digest) is a v4
// judgment-set digest over PriorFindings (see record.go
// fingerprintPriorFindings) — identity plus full sorted metadata plus
// confidence — so an unclaimed finding whose METADATA changed
// (confirmation keys edited) or whose confidence changed invalidates this
// rule's cached record and recomputes. The pre-v4 identity-only staleness
// (metadata-only edits served warm) is fixed as of SchemaVersion 4
// (NEW-145 Slices 1-2). Identity changes (new/removed unclaimed findings)
// always recompute, as before.
func providerConfirmedDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleCNAMEProviderConfirmed+".disabled"] == "true" {
		return nil, nil
	}
	if dctx.GraphView == nil {
		return nil, nil
	}
	if len(dctx.PriorFindings) == 0 {
		return nil, nil
	}
	// Index sibling unclaimed findings by subject identity, keeping the
	// deterministically smallest prior per subject for confirmation
	// carry-over (priors arrive sorted, but the detector never assumes
	// it — the walk below re-sorts regardless).
	siblings := make(map[asset.Identity]asset.Finding)
	for _, f := range dctx.PriorFindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.RuleID != ruleCNAMEUnclaimed {
			continue
		}
		if prev, ok := siblings[f.Subject]; !ok || f.Identity().String() < prev.Identity().String() {
			siblings[f.Subject] = f
		}
	}
	if len(siblings) == 0 {
		return nil, nil
	}
	// Deterministic subject walk: identity-sorted. Neighbors arrive
	// sorted by Relationship.ID (the engine contract), so the first
	// provider match per subject is deterministic.
	subjects := make([]asset.Identity, 0, len(siblings))
	for s := range siblings {
		subjects = append(subjects, s)
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].String() < subjects[j].String() })
	metaFor := make(map[asset.Identity]map[string]string, len(subjects))
	var confirmed []asset.Identity
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var target, provider string
		for _, rel := range dctx.GraphView.Neighbors(s) {
			if rel.Kind != asset.RelationshipHostToCNAME {
				continue
			}
			if p := providerForHost(rel.To.Value); p != "" {
				target, provider = rel.To.Value, p
				break
			}
		}
		if provider == "" {
			continue
		}
		confirmed = append(confirmed, s)
		meta := map[string]string{
			"signal":         "takeover_cname_provider_confirmed",
			"cname_target":   target,
			"provider":       provider,
			"category":       "provider_confirmed",
			"unclaimed_rule": ruleCNAMEUnclaimed,
		}
		// Carry the sibling's HTTP-confirmation citation when present —
		// the corroboration inherits the observation, never invents one.
		if sib := siblings[s]; sib.Metadata["confirmed"] == "true" {
			meta["confirmed"] = "true"
			if cp := sib.Metadata["confirmed_provider"]; cp != "" {
				meta["confirmed_provider"] = cp
			}
		}
		metaFor[s] = meta
	}
	if len(confirmed) == 0 {
		return nil, nil
	}
	confirmed, dropped := capSubjects(confirmed, nil)
	var out []asset.Finding
	for _, s := range confirmed {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m := make(map[string]string, len(metaFor[s])+2)
		for k, v := range metaFor[s] {
			m[k] = v
		}
		if dropped > 0 {
			m["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			m["truncated"] = "true"
		}
		f, err := takeoverFinding(dctx, ruleCNAMEProviderConfirmed, "Takeover CNAME Provider Confirmed", s, m)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleCNAMEProviderConfirmed, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleCNAMEProviderConfirmed)
	return out, nil
}
