package authz

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// maxPeerEndpointMetaBytes bounds the peer_endpoint metadata value: finding
// metadata values must fit 256 bytes (asset finding bounds), and an endpoint
// identity embeds a full URL that may exceed it. Pairs whose peer citation
// would overflow are skipped deterministically (documented, never truncated
// silently) — the subject emits nothing this run.
const maxPeerEndpointMetaBytes = 256

// participant is one endpoint carrying a triage-IDOR signal with
// triage-flagged params confirmed present in its own query string.
type participant struct {
	endpoint asset.Endpoint
	id       asset.Identity
	urlID    asset.Identity
	host     string
	hostID   asset.Identity
	params   map[string]struct{}
	backed   bool
}

// idorInsecureDirectObjectDetector correlates triage.idor priors across
// hosts: it emits one candidate-surface finding per UNAUTHENTICATED endpoint
// that shares a triage-flagged IDOR param with an AUTHENTICATED peer on a
// different host of the same domain.
//
// Fail-open quiets (nil, nil — never an error, never a guess):
//
//   - nil GraphView (hand-constructed Context outside the engine; the engine
//     always installs it),
//   - empty PriorFindings (level-0 produced nothing — there is no IDOR
//     signal to correlate),
//   - no triage.idor-relevant priors, no participating endpoints, or no
//     divergent pair (twins, same-host pairs, and auth-symmetric pairs all
//     fall out of the pairing predicate naturally).
//
// Cache honesty note: the engine's prior digest (graph_digest) is a v4
// judgment-set digest over PriorFindings (see record.go
// fingerprintPriorFindings) — identity plus full sorted metadata plus
// confidence — so a triage finding whose METADATA changed (params edited,
// reflection verdict flipped) or whose confidence changed invalidates this
// rule's cached record and recomputes. The pre-v4 identity-only staleness
// (such edits served warm) is fixed as of SchemaVersion 4 (NEW-145 Slices
// 1-2). Identity changes (new/removed triage findings) always recompute,
// as before.
func idorInsecureDirectObjectDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleIDORInsecureDirectObject+".disabled"] == "true" {
		return nil, nil
	}
	if dctx.GraphView == nil {
		return nil, nil
	}
	if len(dctx.PriorFindings) == 0 {
		return nil, nil
	}
	signals := triageIDORSignals(dctx.PriorFindings)
	if len(signals) == 0 {
		return nil, nil
	}
	// Index participating endpoints deterministically: identity-sorted
	// walk, deduped by endpoint identity (twins collapse here).
	seen := make(map[asset.Identity]struct{})
	var parts []participant
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := ep.Identity()
		if _, dup := seen[id]; dup {
			continue
		}
		sig, ok := signals[id]
		if !ok || len(sig.params) == 0 {
			continue
		}
		// N4 containment: the URL query is parsed only to CONFIRM the
		// triage-flagged params are present — the intersection can only
		// shrink the triage set, never grow it with mined names.
		queryParams := extractQueryParamNames(ep.URL.Query)
		flagged := make(map[string]struct{})
		for p := range sig.params {
			if _, ok := queryParams[p]; ok {
				flagged[p] = struct{}{}
			}
		}
		if len(flagged) == 0 {
			continue
		}
		host := endpointHost(ep.URL.HostPort)
		if host == "" {
			continue
		}
		seen[id] = struct{}{}
		parts = append(parts, participant{
			endpoint: ep,
			id:       id,
			urlID:    ep.URL.Identity(),
			host:     host,
			hostID:   hostIdentityOf(host),
			params:   flagged,
			backed:   sig.backed,
		})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].id.String() < parts[j].id.String() })
	if len(parts) == 0 {
		return nil, nil
	}
	// Auth sides, one lookup per host (Neighbors + evidence scan).
	authSide := make(map[string]bool, len(parts))
	for _, p := range parts {
		if _, ok := authSide[p.host]; !ok {
			authSide[p.host] = hostAuthenticated(dctx, p.hostID, p.id, p.urlID)
		}
	}
	// Pairing: for each unauthenticated subject, the deterministically
	// smallest qualifying authenticated peer — cross-host, same base
	// domain, non-empty shared flagged params. Same-host pairs, twins,
	// and auth-symmetric pairs never qualify (R-QUIET).
	type candidate struct {
		subject participant
		peer    participant
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
		var best *participant
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
			for param := range s.params {
				if _, ok := p.params[param]; ok {
					shared = append(shared, param)
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
	// Score BEFORE the cap (NEW-135): reflection-backed candidates (0.7)
	// outrank name-only ones (0.5) — the same confidence emission assigns
	// below, so the cap keeps the highest-score findings.
	subjects := make([]asset.Identity, 0, len(candidates))
	bySubject := make(map[asset.Identity]candidate, len(candidates))
	for _, c := range candidates {
		subjects = append(subjects, c.subject.id)
		bySubject[c.subject.id] = c
	}
	subjects, dropped := capSubjects(subjects, func(id asset.Identity) float64 {
		if bySubject[id].subject.backed {
			return 0.7
		}
		return 0.5
	})
	var out []asset.Finding
	for _, sid := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c := bySubject[sid]
		priority, confidence := detect.PriorityInfo, 0.5
		if c.subject.backed {
			priority, confidence = detect.PriorityMedium, 0.7
		}
		meta := map[string]string{
			"signal":        "authz_idor_candidate_surface",
			"shared_params": joinParams(c.shared),
			"peer_endpoint": c.peer.id.String(),
			"peer_host":     c.peer.host,
			"auth_side":     "unauthenticated",
			"triage_rule":   depTriageIDOR,
			"verdict":       "candidate-surface",
		}
		if c.subject.backed {
			meta["reflection_backed"] = "true"
		}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := authzFinding(dctx, ruleIDORInsecureDirectObject, "IDOR Insecure Direct Object", sid, priority, confidence, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleIDORInsecureDirectObject, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleIDORInsecureDirectObject)
	return out, nil
}

// joinParams renders a sorted shared-param list deterministically. The input
// is already sorted by the pairing loop; the join inherits triage's 256-byte
// metadata discipline for free — every name rode a validated params value,
// and the intersection only shrinks it.
func joinParams(shared []string) string {
	return strings.Join(shared, ",")
}
