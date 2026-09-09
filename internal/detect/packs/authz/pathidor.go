package authz

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/apis"
)

// Segment semantics are the apis pack's single implementation
// (internal/detect/packs/apis/restidor.go — HasIDORSegment over
// IsNumericSegment with the R2-M4 year-shape 1900-2100 and short-pagination
// ≤2-digit exclusions, plus IsUUIDSegment over the 8-4-4-4-12 hyphenated
// hex form), called directly: the boolean gate is apis.HasIDORSegment and
// the per-endpoint token derivation is apis.IDORSegments (qualifying tokens,
// lowercased for deterministic cross-endpoint comparison — UUID hex is
// case-insensitive; numerics are unaffected). No fork, no copy: when
// restidor.go changes, this rule changes with it. Agreement is pinned by
// TestAuthzPathSegmentUnits through the SAME exported symbols.
func pathHasIDORSegment(path string) bool {
	return apis.HasIDORSegment(path)
}

func pathIDORSegments(path string) []string {
	return apis.IDORSegments(path)
}

// pathParticipant is one endpoint carrying an api.rest.idor-indicator prior
// with qualifying IDOR segments confirmed present in its own canonical path.
type pathParticipant struct {
	endpoint asset.Endpoint
	id       asset.Identity
	urlID    asset.Identity
	host     string
	hostID   asset.Identity
	segments map[string]struct{}
}

// idorPathObjectDetector correlates api.rest.idor-indicator priors across
// hosts: it emits one candidate-surface finding per UNAUTHENTICATED endpoint
// that shares a qualifying path IDOR segment value with an AUTHENTICATED
// peer on a different host of the same domain. It mirrors Rule 1's R-EMIT
// with the path-segment token replacing the query-param token.
//
// N4-equivalent containment: participation requires a prior finding for the
// endpoint subject (the apis signal gates — an endpoint the apis pack never
// flagged never participates, however segment-shaped its path), AND the
// token set is re-derived from the endpoint's own canonical path
// (ep.URL.Path, the asset layer's normalization — AGENTS §0.5, no second
// normalizer). The apis priors carry no segment list (metadata is signal
// only), so the own-path confirmation IS the token derivation; the gate is
// what keeps it from being mining: no prior, no tokens, no pair.
//
// Confidence decision (NEW-146): fixed info/0.5, never medium. Rule 1's
// 0.7/medium split keys on the triage reflection_backed marker; the apis
// restidor detector never emits that marker (its metadata is signal-only),
// so there is no reflection_backed-equivalent signal to split on. A fixed
// 0.5 is the honest ceiling — never medium, never a severity or
// exploitability claim (AGENTS §0.1).
//
// Fail-open quiets (nil, nil — never an error, never a guess): nil
// GraphView, empty PriorFindings, no api.rest.idor-indicator priors, no
// participating endpoints (prior without own-path confirmation, e.g. a
// hand-built prior on a segment-less path), or no divergent pair (twins,
// same-host pairs, auth-symmetric pairs, and pairs sharing no segment
// value all fall out of the pairing predicate naturally). Year-shaped and
// short-pagination segments stay quiet through the pinned exclusions.
//
// Cache honesty note: same v4 judgment-set contract as Rule 1 — the
// engine's prior digest covers identity plus full sorted metadata plus
// confidence (see record.go fingerprintPriorFindings), so an apis finding
// whose metadata or confidence changed invalidates this rule's cached
// record and recomputes. The pre-v4 identity-only staleness is fixed as
// of SchemaVersion 4 (NEW-145 Slices 1-2). Identity changes always
// recompute, as before.
func idorPathObjectDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleIDORPathObject+".disabled"] == "true" {
		return nil, nil
	}
	if dctx.GraphView == nil {
		return nil, nil
	}
	if len(dctx.PriorFindings) == 0 {
		return nil, nil
	}
	flagged := restIDORSubjects(dctx.PriorFindings)
	if len(flagged) == 0 {
		return nil, nil
	}
	// Index participating endpoints deterministically: identity-sorted
	// walk, deduped by endpoint identity (twins collapse here).
	seen := make(map[asset.Identity]struct{})
	var parts []pathParticipant
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := ep.Identity()
		if _, dup := seen[id]; dup {
			continue
		}
		if _, ok := flagged[id]; !ok {
			continue
		}
		tokens := pathIDORSegments(ep.URL.Path)
		if len(tokens) == 0 {
			continue
		}
		host := endpointHost(ep.URL.HostPort)
		if host == "" {
			continue
		}
		set := make(map[string]struct{}, len(tokens))
		for _, tok := range tokens {
			set[tok] = struct{}{}
		}
		seen[id] = struct{}{}
		parts = append(parts, pathParticipant{
			endpoint: ep,
			id:       id,
			urlID:    ep.URL.Identity(),
			host:     host,
			hostID:   hostIdentityOf(host),
			segments: set,
		})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].id.String() < parts[j].id.String() })
	if len(parts) == 0 {
		return nil, nil
	}
	// Auth sides, one lookup per host (Neighbors + evidence scan) — the
	// same hostAuthenticated surface Rule 1 uses, reused directly.
	authSide := make(map[string]bool, len(parts))
	for _, p := range parts {
		if _, ok := authSide[p.host]; !ok {
			authSide[p.host] = hostAuthenticated(dctx, p.hostID, p.id, p.urlID)
		}
	}
	// Pairing: for each unauthenticated subject, the deterministically
	// smallest qualifying authenticated peer — cross-host, same base
	// domain, non-empty shared segment values. Same-host pairs, twins,
	// auth-symmetric pairs, and pairs sharing no segment value never
	// qualify (R-QUIET).
	type candidate struct {
		subject pathParticipant
		peer    pathParticipant
		shared  []string
	}
	var candidates []candidate
	for _, s := range parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if authSide[s.host] {
			continue
		}
		var best *pathParticipant
		var bestShared []string
		for i := range parts {
			p := &parts[i]
			if p.id == s.id {
				continue
			}
			if p.host == s.host {
				continue
			}
			if !sameBaseDomain(s.host, p.host) {
				continue
			}
			if !authSide[p.host] {
				continue
			}
			var shared []string
			for tok := range s.segments {
				if _, ok := p.segments[tok]; ok {
					shared = append(shared, tok)
				}
			}
			if len(shared) == 0 {
				continue
			}
			sort.Strings(shared)
			if best == nil || p.id.String() < best.id.String() {
				cp := *p
				best = &cp
				bestShared = shared
			}
		}
		if best == nil {
			continue
		}
		if len(best.id.String()) > maxPeerEndpointMetaBytes {
			continue
		}
		candidates = append(candidates, candidate{subject: s, peer: *best, shared: bestShared})
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	// Fixed confidence (see decision above): the cap runs on pure identity
	// order (nil scorer — byte-identical to the pre-NEW-135 prefix cut).
	subjects := make([]asset.Identity, 0, len(candidates))
	bySubject := make(map[asset.Identity]candidate, len(candidates))
	for _, c := range candidates {
		subjects = append(subjects, c.subject.id)
		bySubject[c.subject.id] = c
	}
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, sid := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c := bySubject[sid]
		meta := map[string]string{
			"signal":          "authz_idor_path_object_candidate_surface",
			"shared_segments": strings.Join(c.shared, ","),
			"peer_endpoint":   c.peer.id.String(),
			"peer_host":       c.peer.host,
			"auth_side":       "unauthenticated",
			"prior_rule":      depApisRestIDOR,
			"verdict":         "candidate-surface",
		}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := authzFinding(dctx, ruleIDORPathObject, "IDOR Path Object", sid, detect.PriorityInfo, 0.5, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleIDORPathObject, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleIDORPathObject)
	return out, nil
}

// restIDORSubjects returns the endpoint-subject identity set carrying an
// api.rest.idor-indicator prior finding. The filter is the exact registered
// rule ID only: the apis pack has no overlap-precedence shadowing (a single
// rule owns the IDOR-segment signal), so Rule 1's all_classes recovery has
// no equivalent here — and the finding metadata carries no token list, so
// there is nothing further to index (tokens come from own-path
// confirmation, gated on this set).
func restIDORSubjects(priors []asset.Finding) map[asset.Identity]struct{} {
	out := make(map[asset.Identity]struct{})
	for _, f := range priors {
		if f.RuleID == depApisRestIDOR {
			out[f.Subject] = struct{}{}
		}
	}
	return out
}
