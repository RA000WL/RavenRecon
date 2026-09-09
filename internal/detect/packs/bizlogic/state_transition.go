package bizlogic

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// maxSubjectMetaBytes bounds the flow_steps and authz_member metadata
// values: finding metadata values must fit 256 bytes (asset finding
// bounds), and an endpoint identity embeds a full URL that may exceed it.
// Flows whose step citation would overflow are skipped deterministically
// (documented, never truncated silently) — the steps emit nothing this run.
const maxSubjectMetaBytes = 256

// maxFlowSteps bounds one candidate flow's step count. A candidate-flow
// finding must stay a reviewable correlation: longer step sets are skipped
// with a LevelInfo count (documented, never truncated into a shorter
// flow — truncation would misrepresent the observed set).
const maxFlowSteps = 8

// participant is one endpoint carrying a T1 triage-IDOR token confirmed
// present in its own query string.
type participant struct {
	endpoint asset.Endpoint
	id       asset.Identity
	host     string
	token    string
	gql      bool
}

// candidateFlow is one emitting (host, token) step set: the sorted steps,
// the auth-divergent member, and the emission confidence.
type candidateFlow struct {
	steps      []asset.Endpoint
	subject    asset.Identity
	authMember asset.Identity
	token      string
	host       string
	confidence float64
}

// workflowStateTransitionDetector correlates T1 IDOR tokens across the
// same host: it emits one candidate-flow finding per (host, shared token)
// step set whose steps are co-reachable through the observed graph and of
// which at least one step carries an authz IDOR candidate.
//
// Fail-open quiets (nil, nil — never an error, never a guess):
//
//   - nil GraphView (hand-constructed Context outside the engine; the engine
//     always installs it),
//   - empty PriorFindings (level-0/level-1 produced nothing — there is no
//     token or member signal to correlate),
//   - no T1 priors, no participating endpoints, no auth-divergent member, or
//     no co-reachable dissimilar step set (singletons, pagination twins,
//     cross-host sets, and mixed-grade sets all fall out of the flow
//     predicate naturally).
//
// Cross-host sets never emit (exact-host T2): steps must share one bare
// hostname. Co-reachability is Path-only: every step carries a directed
// host⇝step path through the observed graph. A shared JavaScript hub is NOT
// a co-reachability basis — the SDK GraphView exposes Neighbors as
// outgoing-only edges, so no reverse lookup from a step to its referencing
// scripts exists (adding one is an explicit SDK follow-up needing sign-off,
// never improvised here) — and a hub must never bridge hosts anyway.
//
// Cache honesty note: the engine's prior digest (graph_digest) is a v4
// judgment-set digest over PriorFindings (see record.go
// fingerprintPriorFindings) — identity plus full sorted metadata plus
// confidence — so a triage/authz finding whose METADATA changed or whose
// confidence changed invalidates this rule's cached record and recomputes.
// The pre-v4 identity-only staleness (such edits served warm) is fixed as
// of SchemaVersion 4 (NEW-145 Slices 1-2). Identity changes (new/removed
// priors) always recompute, as before.
func workflowStateTransitionDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleWorkflowStateTransition+".disabled"] == "true" {
		return nil, nil
	}
	if dctx.GraphView == nil {
		return nil, nil
	}
	if len(dctx.PriorFindings) == 0 {
		return nil, nil
	}
	signals := triageTokenSignals(dctx.PriorFindings)
	if len(signals) == 0 {
		return nil, nil
	}
	members := authzMembers(dctx.PriorFindings)
	if len(members) == 0 {
		return nil, nil
	}
	graphql := graphqlSubjects(dctx.PriorFindings)
	robots := robotsSubjects(dctx.PriorFindings)
	// Index participating endpoints deterministically: identity-sorted
	// walk, deduped by endpoint identity. Robots-graded utility surfaces
	// never participate.
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
		if _, excluded := robots[id]; excluded {
			continue
		}
		sig, ok := signals[id]
		if !ok || len(sig.params) == 0 {
			continue
		}
		// N4 containment: the URL query is parsed only to CONFIRM the
		// triage-flagged params are present — the confirmed set can only
		// shrink the triage set, never grow it with mined names.
		queryParams := extractQueryParamNames(ep.URL.Query)
		var tokens []string
		for p := range sig.params {
			if _, ok := queryParams[p]; ok {
				tokens = append(tokens, p)
			}
		}
		if len(tokens) == 0 {
			continue
		}
		sort.Strings(tokens)
		host := endpointHost(ep.URL.HostPort)
		if host == "" {
			continue
		}
		seen[id] = struct{}{}
		for _, tok := range tokens {
			parts = append(parts, participant{
				endpoint: ep,
				id:       id,
				host:     host,
				token:    tok,
				gql:      isGraphQLClass(ep, graphql),
			})
		}
	}
	sort.Slice(parts, func(i, j int) bool {
		if parts[i].host != parts[j].host {
			return parts[i].host < parts[j].host
		}
		if parts[i].token != parts[j].token {
			return parts[i].token < parts[j].token
		}
		return parts[i].id.String() < parts[j].id.String()
	})
	if len(parts) == 0 {
		return nil, nil
	}
	// Group into (host, token) step sets in sorted order.
	var flows []candidateFlow
	var skippedLong, skippedWide int
	for len(parts) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		j := 1
		for j < len(parts) && parts[j].host == parts[0].host && parts[j].token == parts[0].token {
			j++
		}
		group := parts[:j]
		parts = parts[j:]
		flow, why := buildFlow(dctx, group, members)
		switch why {
		case flowOK:
			flows = append(flows, flow)
		case flowSkipLong:
			skippedLong++
		case flowSkipWide:
			skippedWide++
		}
	}
	if len(flows) == 0 {
		if skippedLong+skippedWide > 0 {
			dctx.Logger.Log(detect.LevelInfo, ruleWorkflowStateTransition,
				fmt.Sprintf("skipped %d long/over-wide flows (never truncated)", skippedLong+skippedWide))
		}
		formatConfigKeys(dctx, ruleWorkflowStateTransition)
		return nil, nil
	}
	// Score BEFORE the cap (NEW-135): 3+ step flows (0.6) outrank 2-step
	// ones (0.5) — the same confidence emission assigns below, so the cap
	// keeps the highest-score findings.
	subjects := make([]asset.Identity, 0, len(flows))
	bySubject := make(map[asset.Identity]candidateFlow, len(flows))
	for _, f := range flows {
		subjects = append(subjects, f.subject)
		bySubject[f.subject] = f
	}
	subjects, dropped := capSubjects(subjects, func(id asset.Identity) float64 {
		return bySubject[id].confidence
	})
	var out []asset.Finding
	for _, sid := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f := bySubject[sid]
		steps := make([]string, 0, len(f.steps))
		for _, s := range f.steps {
			steps = append(steps, s.Identity().String())
		}
		meta := map[string]string{
			"signal":       "bizlogic_workflow_candidate_flow",
			"flow_steps":   strings.Join(steps, ","),
			"flow_len":     strconv.Itoa(len(f.steps)),
			"shared_token": f.token,
			"host":         f.host,
			"edge_basis":   "correlated-not-traversed",
			"authz_member": f.authMember.String(),
			"triage_rule":  depTriageIDOR,
			"verdict":      "candidate-flow",
		}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		got, err := bizlogicFinding(dctx, ruleWorkflowStateTransition, "Workflow State Transition", sid, f.confidence, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, got)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleWorkflowStateTransition, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	if skippedLong+skippedWide > 0 {
		dctx.Logger.Log(detect.LevelInfo, ruleWorkflowStateTransition,
			fmt.Sprintf("skipped %d long/over-wide flows (never truncated)", skippedLong+skippedWide))
	}
	formatConfigKeys(dctx, ruleWorkflowStateTransition)
	return out, nil
}

// flowVerdict is the buildFlow outcome: emit, skip for length, skip for
// citation width, or quiet (the set never formed a flow).
type flowVerdict int

const (
	flowOK flowVerdict = iota
	flowSkipLong
	flowSkipWide
	flowQuiet
)

// buildFlow reduces one sorted (host, token) participant group to an
// emitting candidate flow. Quiet (flowQuiet, zero flow) covers every
// non-flow shape: singletons, pagination-twin collapses, mixed-grade
// sets, memberless sets, and unreachable sets. Skips (flowSkipLong,
// flowSkipWide) cover sets that ARE flows but cannot fit the finding
// bounds — skipped, never truncated.
func buildFlow(dctx *detect.Context, group []participant, members map[asset.Identity]struct{}) (candidateFlow, flowVerdict) {
	// Step dissimilarity: one step per (method, URL path) pair, keeping
	// the identity-smallest representative — pagination twins (same
	// method and path, differing only in query) collapse here, and a
	// pure-twin group reduces to a singleton and stays quiet below.
	// The method is part of the key so a canonical view/update pair
	// (GET + POST on one path) still counts as two dissimilar steps.
	var steps []asset.Endpoint
	seenStep := make(map[string]struct{})
	for _, p := range group {
		key := p.endpoint.Method + " " + p.endpoint.URL.Path
		if _, dup := seenStep[key]; dup {
			continue
		}
		seenStep[key] = struct{}{}
		steps = append(steps, p.endpoint)
	}
	if len(steps) < 2 {
		return candidateFlow{}, flowQuiet
	}
	if len(steps) > maxFlowSteps {
		return candidateFlow{}, flowSkipLong
	}
	// Mixed-grade sets never form one flow: GraphQL-grade and REST-grade
	// steps are different API styles. The class rode each participant
	// (opportunistic apis signal or the /graphql path heuristic), so the
	// check reads the group participants for the kept steps.
	classes := make(map[bool]struct{})
	for _, p := range group {
		for _, s := range steps {
			if s.Identity() == p.id {
				classes[p.gql] = struct{}{}
			}
		}
	}
	if len(classes) > 1 {
		return candidateFlow{}, flowQuiet
	}
	// Auth divergence: at least one step must carry an authz IDOR
	// candidate. The cited member is the identity-smallest such step.
	var authMember asset.Identity
	first := true
	for _, s := range steps {
		id := s.Identity()
		if _, ok := members[id]; !ok {
			continue
		}
		if first || id.String() < authMember.String() {
			authMember = id
			first = false
		}
	}
	if first {
		return candidateFlow{}, flowQuiet
	}
	if len(authMember.String()) > maxSubjectMetaBytes {
		return candidateFlow{}, flowSkipWide
	}
	// Co-reachability through the observed graph (Path only): every step
	// carries a directed host⇝step path. Graph edges are used for
	// correlation, never traversed as behavior — hence
	// edge_basis=correlated-not-traversed. JavaScript-hub correlation is
	// deliberately absent: without an SDK reverse lookup (step → its
	// referencing scripts) it cannot be observed through the read-only
	// view, so hub-linked steps without host⇝step paths stay quiet.
	hostID := hostIdentityOf(group[0].host)
	for _, s := range steps {
		if len(dctx.GraphView.Path(hostID, s.Identity())) == 0 {
			return candidateFlow{}, flowQuiet
		}
	}
	// Citation bound: the sorted step list must fit one metadata value.
	cited := make([]string, 0, len(steps))
	for _, s := range steps {
		cited = append(cited, s.Identity().String())
	}
	if len(strings.Join(cited, ",")) > maxSubjectMetaBytes {
		return candidateFlow{}, flowSkipWide
	}
	confidence := 0.5
	if len(steps) >= 3 {
		confidence = 0.6
	}
	return candidateFlow{
		steps:      steps,
		subject:    steps[0].Identity(),
		authMember: authMember,
		token:      group[0].token,
		host:       group[0].host,
		confidence: confidence,
	}, flowOK
}
