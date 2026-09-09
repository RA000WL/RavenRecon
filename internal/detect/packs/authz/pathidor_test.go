package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/apis"
)

// mustPriorRestidor builds a canonical synthetic apis-pack prior finding:
// subject is an endpoint identity flagged as carrying an IDOR-like path
// segment. The metadata is signal-only (the apis detector never emits
// reflection_backed or a token list) — the token set always comes from
// own-path confirmation, gated on this prior.
func mustPriorRestidor(t testing.TB, subject asset.Identity) asset.Finding {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodDetection, depApisRestIDOR, "apis pack signal: "+depApisRestIDOR, subject, asset.Provenance{Source: "apis"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	f, err := asset.NewFinding(asset.Finding{
		RuleID:     depApisRestIDOR,
		RuleName:   "REST IDOR Indicator",
		Category:   detect.CategoryInformation.String(),
		Subject:    subject,
		Confidence: 0.5,
		Evidence:   []asset.Evidence{ev},
		Metadata:   map[string]string{"signal": "rest_idor_indicator"},
		Priority:   detect.PriorityInfo.String(),
		Status:     detect.StatusOpen.String(),
		Created:    testClock.at.UTC(),
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

// buildPathDivergenceSnapshot returns the canonical Rule 2 emit fixture:
// two endpoints on different hosts of example.com sharing the path object
// /users/12345 (no query string, so triage.idor stays quiet and Rule 1
// cannot fire), with an authentication technology linked to the api host
// only. The www endpoint is the expected unauthenticated subject.
func buildPathDivergenceSnapshot(t testing.TB) (detect.Snapshot, asset.Endpoint, asset.Endpoint) {
	t.Helper()
	apiEP := mustEndpoint(t, "GET", "https://api.example.com/users/12345")
	webEP := mustEndpoint(t, "GET", "https://www.example.com/users/12345")
	apiHost := mustHost(t, "api.example.com")
	webHost := mustHost(t, "www.example.com")
	tech := mustTechnology(t, "keycloak", asset.CategoryAuthentication)
	rel := mustRelationship(t, apiHost.Identity(), asset.RelationshipHostToTechnology, tech.Identity())
	return detect.Snapshot{
		Assets:        []asset.Identity{apiHost.Identity(), webHost.Identity()},
		Relationships: []asset.Relationship{rel},
		Technologies:  []asset.Technology{tech},
		Endpoints:     []asset.Endpoint{apiEP, webEP},
	}, apiEP, webEP
}

func authzPathFindings(rep detect.Report) []asset.Finding {
	var out []asset.Finding
	for _, f := range rep.Findings {
		if f.RuleID == ruleIDORPathObject {
			out = append(out, f)
		}
	}
	return out
}

func TestAuthzPathPackShape(t *testing.T) {
	if err := detect.CheckAPIVersion(2, 0); err != nil {
		t.Fatalf("CheckAPIVersion(2,0): %v", err)
	}
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("pack carries %d rules, want 2 (Rule 1 query-param + Rule 2 path-object)", len(rules))
	}
	// The dependency must name the exact registered apis rule ID.
	apisRules, err := apis.Rules()
	if err != nil {
		t.Fatalf("apis.Rules: %v", err)
	}
	registered := false
	for _, r := range apisRules {
		if r.ID == depApisRestIDOR {
			registered = true
		}
	}
	if !registered {
		t.Fatalf("dep %q is not a registered apis rule ID", depApisRestIDOR)
	}
	r := rules[1]
	if r.ID != ruleIDORPathObject {
		t.Fatalf("rule ID %q, want %q", r.ID, ruleIDORPathObject)
	}
	if r.Version != "1.0.0" {
		t.Fatalf("rule version %q, want 1.0.0", r.Version)
	}
	if r.Category != detect.CategoryAuthorization {
		t.Fatalf("rule category %q, want authorization", r.Category)
	}
	if len(r.Dependencies) != 1 || r.Dependencies[0] != depApisRestIDOR {
		t.Fatalf("rule deps %v, want [api.rest.idor-indicator]", r.Dependencies)
	}
	if len(r.RequiredAssetTypes) != 1 || r.RequiredAssetTypes[0] != asset.KindEndpoint {
		t.Fatalf("RequiredAssetTypes %v, want [endpoint]", r.RequiredAssetTypes)
	}
	if err := detect.ValidateRule(r); err != nil {
		t.Fatalf("ValidateRule: %v", err)
	}
}

func TestAuthzPathSegmentUnits(t *testing.T) {
	// Agreement pin through the REAL shared symbols: the predicates below
	// are the apis pack's exported implementation (single implementation —
	// this test fails if the shared semantics drift), exercised here over
	// the numeric/UUID/year/pagination table.
	const uuidLower = "123e4567-e89b-12d3-a456-426614174000"
	const uuidUpper = "123E4567-E89B-12D3-A456-426614174000"
	cases := []struct {
		segment string
		want    bool
	}{
		{"123", true},     // numeric over the pagination bound
		{"007", true},     // leading zeros still numeric
		{"12345", true},   // canonical object id
		{"2101", true},    // 4-digit above the year window
		{"1899", true},    // 4-digit below the year window
		{"12", false},     // short pagination excluded
		{"1", false},      // single-digit pagination excluded
		{"2021", false},   // year-shaped excluded
		{"1999", false},   // year-shaped excluded
		{"2100", false},   // year window is inclusive
		{"1900", false},   // year window is inclusive
		{"abc", false},    // non-numeric
		{"12a", false},    // mixed alnum is not numeric
		{"", false},       // empty never qualifies
		{uuidLower, true}, // canonical UUID
		{uuidUpper, true}, // UUID hex is case-insensitive
		{"123e4567-e89b-12d3-a456-42661417400", false},  // one hex short
		{"123e4567e89b12d3a4564266141740000", false},    // missing hyphens
		{"123e4567-e89b-12d3-a456-42661417400g", false}, // non-hex tail
	}
	for _, tc := range cases {
		t.Run("segment/"+tc.segment, func(t *testing.T) {
			num, uuid := apis.IsNumericSegment(tc.segment), apis.IsUUIDSegment(tc.segment)
			if got := num || uuid; got != tc.want {
				t.Fatalf("segment %q qualifying=%v, want %v", tc.segment, got, tc.want)
			}
			if got := pathHasIDORSegment("/users/" + tc.segment); tc.segment != "" && got != tc.want {
				t.Fatalf("path gate /users/%q =%v, want %v", tc.segment, got, tc.want)
			}
		})
	}
	// Multi-segment derivation: qualifying tokens only, lowercased,
	// year/pagination segments dropped.
	got := pathIDORSegments("/api/2021/users/" + uuidUpper + "/page/12/profile/12345")
	want := map[string]struct{}{uuidLower: {}, "12345": {}}
	if len(got) != len(want) {
		t.Fatalf("tokens %v, want %v", got, want)
	}
	for _, tok := range got {
		if _, ok := want[tok]; !ok {
			t.Fatalf("tokens %v, want %v", got, want)
		}
	}
	if len(pathIDORSegments("/archive/2021/page/12")) != 0 {
		t.Fatalf("year/pagination-only path must yield no tokens")
	}
	if len(pathIDORSegments("/profile")) != 0 {
		t.Fatalf("segment-less path must yield no tokens")
	}
}

func TestAuthzPathEmitsOnCrossHostDivergence(t *testing.T) {
	reg := registerTriageAuthz(t)
	snap, apiEP, webEP := buildPathDivergenceSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Levels != 2 {
		t.Fatalf("levels %d, want 2 (triage+apis level 0, authz level 1)", rep.Levels)
	}
	got := authzPathFindings(rep)
	if len(got) != 1 {
		t.Fatalf("path findings %d, want 1", len(got))
	}
	f := got[0]
	if f.Subject != webEP.Identity() {
		t.Fatalf("subject %s, want unauthenticated endpoint %s", f.Subject, webEP.Identity())
	}
	if f.Category != detect.CategoryAuthorization.String() {
		t.Fatalf("category %q, want authorization", f.Category)
	}
	if f.Priority != detect.PriorityInfo.String() {
		t.Fatalf("priority %q, want info (fixed — no reflection split)", f.Priority)
	}
	if f.Confidence != 0.5 {
		t.Fatalf("confidence %v, want 0.5 (fixed)", f.Confidence)
	}
	if len(f.Evidence) == 0 || f.Evidence[0].Method != asset.MethodDetection {
		t.Fatalf("evidence method wrong")
	}
	if f.Evidence[0].Source != webEP.Identity() {
		t.Fatalf("evidence source %s, want subject %s", f.Evidence[0].Source, webEP.Identity())
	}
	if len(f.RelatedAssets) != 0 {
		t.Fatalf("related assets %v, want none (peer rides metadata strings only)", f.RelatedAssets)
	}
	for _, k := range []string{"signal", "shared_segments", "peer_endpoint", "peer_host", "auth_side", "prior_rule", "verdict"} {
		if f.Metadata[k] == "" {
			t.Fatalf("metadata key %q missing: %+v", k, f.Metadata)
		}
	}
	if f.Metadata["signal"] != "authz_idor_path_object_candidate_surface" {
		t.Fatalf("signal %q", f.Metadata["signal"])
	}
	if f.Metadata["shared_segments"] != "12345" {
		t.Fatalf("shared_segments %q, want 12345", f.Metadata["shared_segments"])
	}
	if f.Metadata["peer_endpoint"] != apiEP.Identity().String() {
		t.Fatalf("peer_endpoint %q, want %q", f.Metadata["peer_endpoint"], apiEP.Identity())
	}
	if f.Metadata["peer_host"] != "api.example.com" {
		t.Fatalf("peer_host %q", f.Metadata["peer_host"])
	}
	if f.Metadata["auth_side"] != "unauthenticated" {
		t.Fatalf("auth_side %q", f.Metadata["auth_side"])
	}
	if f.Metadata["prior_rule"] != "api.rest.idor-indicator" {
		t.Fatalf("prior_rule %q", f.Metadata["prior_rule"])
	}
	if f.Metadata["verdict"] != "candidate-surface" {
		t.Fatalf("verdict %q", f.Metadata["verdict"])
	}
	// No medium ceiling breach, ever.
	if f.Priority == detect.PriorityMedium.String() || f.Priority == detect.PriorityHigh.String() {
		t.Fatalf("priority %q exceeds the info ceiling", f.Priority)
	}
	// Rule 1 must stay quiet on the path-only corpus (no query params, so
	// triage.idor has no signal to correlate).
	if q := authzFindings(rep); len(q) != 0 {
		t.Fatalf("Rule 1 findings %d on path-only corpus, want 0", len(q))
	}
	// Signal-not-proof wording: no finding may claim exploitability.
	buf, _ := json.Marshal(rep)
	for _, bad := range []string{"exploit", "vulnerab", "unauthorized access", "proof of"} {
		if strings.Contains(strings.ToLower(string(buf)), bad) {
			t.Fatalf("report claims beyond signal: contains %q", bad)
		}
	}
}

func TestAuthzPathQuietDirectTable(t *testing.T) {
	apiEP := mustEndpoint(t, "GET", "https://api.example.com/users/12345")
	webEP := mustEndpoint(t, "GET", "https://www.example.com/users/12345")
	apiHost := mustHost(t, "api.example.com")
	tech := mustTechnology(t, "keycloak", asset.CategoryAuthentication)
	hostTech := func() map[asset.Identity][]asset.Relationship {
		rel, err := asset.NewRelationship(apiHost.Identity(), asset.RelationshipHostToTechnology, tech.Identity())
		if err != nil {
			t.Fatalf("NewRelationship: %v", err)
		}
		return map[asset.Identity][]asset.Relationship{apiHost.Identity(): {rel}}
	}
	directCtx := func(endpoints []asset.Endpoint, priors []asset.Finding, gv detect.GraphQuerier) *detect.Context {
		return &detect.Context{
			Endpoints:     endpoints,
			PriorFindings: priors,
			GraphView:     gv,
			Logger:        &recLogger{},
			Clock:         testClock,
		}
	}
	priors := []asset.Finding{mustPriorRestidor(t, apiEP.Identity()), mustPriorRestidor(t, webEP.Identity())}
	plainEP := mustEndpoint(t, "GET", "https://api.example.com/profile")
	plainWeb := mustEndpoint(t, "GET", "https://www.example.com/profile")
	yearEP := mustEndpoint(t, "GET", "https://api.example.com/archive/2021")
	yearWeb := mustEndpoint(t, "GET", "https://www.example.com/archive/2021")
	pageEP := mustEndpoint(t, "GET", "https://api.example.com/users/page/12")
	pageWeb := mustEndpoint(t, "GET", "https://www.example.com/users/page/12")
	otherSeg := mustEndpoint(t, "GET", "https://www.example.com/orders/99999")
	cases := []struct {
		name      string
		endpoints []asset.Endpoint
		priors    []asset.Finding
		graph     detect.GraphQuerier
	}{
		{"nil-graph", []asset.Endpoint{apiEP, webEP}, priors, nil},
		{"empty-priors", []asset.Endpoint{apiEP, webEP}, nil, stubGraph{hostTech()}},
		{"no-relevant-priors", []asset.Endpoint{apiEP, webEP},
			[]asset.Finding{mustPriorIDOR(t, apiEP.Identity(), []string{"id"}, false)},
			stubGraph{hostTech()}},
		{"twins", []asset.Endpoint{apiEP, apiEP}, priors, stubGraph{hostTech()}},
		{"same-host", []asset.Endpoint{webEP, otherSeg},
			[]asset.Finding{
				mustPriorRestidor(t, webEP.Identity()),
				mustPriorRestidor(t, otherSeg.Identity()),
			},
			stubGraph{hostTech()}},
		{"single-endpoint", []asset.Endpoint{webEP},
			[]asset.Finding{mustPriorRestidor(t, webEP.Identity())},
			stubGraph{hostTech()}},
		{"segments-without-prior", []asset.Endpoint{apiEP, webEP}, nil, stubGraph{hostTech()}},
		// N4 asymmetric prior: the only prior sits on the authenticated
		// host (shared /users/12345 segments on both sides) — the
		// unauthenticated endpoint never participated, so no pair forms.
		{"asymmetric-prior-auth-side-only", []asset.Endpoint{apiEP, webEP},
			[]asset.Finding{mustPriorRestidor(t, apiEP.Identity())},
			stubGraph{hostTech()}},
		{"prior-without-own-segments", []asset.Endpoint{plainEP, plainWeb},
			[]asset.Finding{
				mustPriorRestidor(t, plainEP.Identity()),
				mustPriorRestidor(t, plainWeb.Identity()),
			},
			stubGraph{hostTech()}},
		{"year-segments-quiet", []asset.Endpoint{yearEP, yearWeb},
			[]asset.Finding{
				mustPriorRestidor(t, yearEP.Identity()),
				mustPriorRestidor(t, yearWeb.Identity()),
			},
			stubGraph{hostTech()}},
		{"pagination-segments-quiet", []asset.Endpoint{pageEP, pageWeb},
			[]asset.Finding{
				mustPriorRestidor(t, pageEP.Identity()),
				mustPriorRestidor(t, pageWeb.Identity()),
			},
			stubGraph{hostTech()}},
		{"unshared-segments-quiet", []asset.Endpoint{apiEP, otherSeg},
			[]asset.Finding{
				mustPriorRestidor(t, apiEP.Identity()),
				mustPriorRestidor(t, otherSeg.Identity()),
			},
			stubGraph{hostTech()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := idorPathObjectDetector(context.Background(), directCtx(tc.endpoints, tc.priors, tc.graph))
			if err != nil {
				t.Fatalf("detector error: %v", err)
			}
			if got != nil {
				t.Fatalf("fail-open quiet violated: got %d findings, want nil", len(got))
			}
		})
	}
}

func TestAuthzPathQuietDifferentDomainEngine(t *testing.T) {
	reg := registerTriageAuthz(t)
	a := mustEndpoint(t, "GET", "https://api.example.com/users/12345")
	b := mustEndpoint(t, "GET", "https://api.other.com/users/12345")
	apiHost := mustHost(t, "api.example.com")
	otherHost := mustHost(t, "api.other.com")
	tech := mustTechnology(t, "keycloak", asset.CategoryAuthentication)
	snap := detect.Snapshot{
		Assets:        []asset.Identity{apiHost.Identity(), otherHost.Identity()},
		Relationships: []asset.Relationship{mustRelationship(t, apiHost.Identity(), asset.RelationshipHostToTechnology, tech.Identity())},
		Technologies:  []asset.Technology{tech},
		Endpoints:     []asset.Endpoint{a, b},
	}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := authzPathFindings(rep); len(got) != 0 {
		t.Fatalf("cross-domain path findings %d, want 0", len(got))
	}
}

func TestAuthzPathOrderingDepSkip(t *testing.T) {
	// A failing level-0 api.rest.idor-indicator (stub with the same rule
	// ID — the dependency contract keys on the ID string) must dep-skip
	// Rule 2 with the honest dependency reason and zero findings.
	stubApisIDOR := detect.Rule{
		ID:            "api.rest.idor-indicator",
		Name:          "REST IDOR Stub",
		Description:   "Synthetic failing api.rest.idor-indicator for the path-object dep-skip test",
		Category:      detect.CategoryInformation,
		Version:       "9.9.9",
		Inputs:        []detect.RuleInput{detect.InputEndpoints},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "authz-test",
		Enabled:       true,
		Detector: func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
			return nil, fmt.Errorf("synthetic api.rest.idor-indicator failure")
		},
	}
	authzRules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	var rule2 detect.Rule
	for _, r := range authzRules {
		if r.ID == ruleIDORPathObject {
			rule2 = r
		}
	}
	if rule2.ID == "" {
		t.Fatalf("Rule 2 %q missing from pack", ruleIDORPathObject)
	}
	reg := detect.NewRegistry()
	if err := reg.Register(stubApisIDOR); err != nil {
		t.Fatalf("Register stub: %v", err)
	}
	if err := reg.Register(rule2); err != nil {
		t.Fatalf("Register(%q): %v", rule2.ID, err)
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	reg.Seal()
	snap, _, _ := buildPathDivergenceSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	statuses := map[string]detect.RuleResult{}
	for _, r := range rep.Rules {
		statuses[r.RuleID] = r
	}
	if statuses["api.rest.idor-indicator"].Status != detect.RuleStatusFailed {
		t.Fatalf("apis status %s, want failed (stub)", statuses["api.rest.idor-indicator"].Status)
	}
	pathRes := statuses[ruleIDORPathObject]
	if pathRes.Status != detect.RuleStatusSkipped {
		t.Fatalf("path status %s, want skipped (dep did not complete)", pathRes.Status)
	}
	if !strings.Contains(pathRes.SkipReason, `dependency "api.rest.idor-indicator" did not complete`) {
		t.Fatalf("path skip reason %q, want dependency reason", pathRes.SkipReason)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("dep-skip run findings %d, want 0", len(rep.Findings))
	}
}

func TestAuthzPathCap256Truncation(t *testing.T) {
	// 300 unauthenticated endpoints + 1 authenticated peer, all sharing
	// /users/12345 with apis priors: the rule keeps 256 with
	// subjects_dropped=44, truncated=true, and a LevelWarn log — never
	// silent.
	authEP := mustEndpoint(t, "GET", "https://auth.example.com/users/12345")
	authHost := mustHost(t, "auth.example.com")
	tech := mustTechnology(t, "keycloak", asset.CategoryAuthentication)
	authRel := mustRelationship(t, authHost.Identity(), asset.RelationshipHostToTechnology, tech.Identity())
	var endpoints []asset.Endpoint
	var priors []asset.Finding
	endpoints = append(endpoints, authEP)
	priors = append(priors, mustPriorRestidor(t, authEP.Identity()))
	for i := 0; i < 300; i++ {
		ep := mustEndpoint(t, "GET", fmt.Sprintf("https://h-%03d.example.com/users/12345", i))
		endpoints = append(endpoints, ep)
		priors = append(priors, mustPriorRestidor(t, ep.Identity()))
	}
	logger := &recLogger{}
	dctx := &detect.Context{
		Endpoints:     endpoints,
		PriorFindings: priors,
		GraphView:     stubGraph{map[asset.Identity][]asset.Relationship{authHost.Identity(): {authRel}}},
		Logger:        logger,
		Clock:         testClock,
	}
	got, err := idorPathObjectDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if len(got) != 256 {
		t.Fatalf("capped findings %d, want 256", len(got))
	}
	for _, f := range got {
		if f.Metadata["subjects_dropped"] != "44" {
			t.Fatalf("subjects_dropped %q, want 44", f.Metadata["subjects_dropped"])
		}
		if f.Metadata["truncated"] != "true" {
			t.Fatalf("truncated marker missing: %+v", f.Metadata)
		}
		if f.Priority != detect.PriorityInfo.String() {
			t.Fatalf("priority %q, want info (fixed ceiling)", f.Priority)
		}
		if f.Confidence != 0.5 {
			t.Fatalf("confidence %v, want 0.5 (fixed)", f.Confidence)
		}
		if f.Subject == authEP.Identity() {
			t.Fatalf("authenticated peer must never be a subject")
		}
	}
	if !logger.has(ruleIDORPathObject, detect.LevelWarn, "truncated 44 subjects over bound 256") {
		t.Fatalf("missing LevelWarn truncation log")
	}
}

func TestAuthzPathCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerTriageAuthz(t)
	snap, _, _ := buildPathDivergenceSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Cache = fs
	cfg.Clock = testClock
	cold, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("cold Run: %v", err)
	}
	if cold.CacheHits != 0 {
		t.Fatalf("cold hits %d, want 0", cold.CacheHits)
	}
	coldPaths := authzPathFindings(cold)
	if len(coldPaths) != 1 {
		t.Fatalf("cold path findings %d, want 1", len(coldPaths))
	}
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Cache = fs
	cfg2.Clock = testClock
	warm, err := detect.Run(context.Background(), cfg2, snap)
	if err != nil {
		t.Fatalf("warm Run: %v", err)
	}
	if warm.CacheHits != len(cold.Rules)-cold.Skipped {
		t.Fatalf("warm hits %d, want %d (all attempted rules)", warm.CacheHits, len(cold.Rules)-cold.Skipped)
	}
	warmPaths := authzPathFindings(warm)
	if len(warmPaths) != len(coldPaths) {
		t.Fatalf("warm path findings %d vs cold %d", len(warmPaths), len(coldPaths))
	}
	for i := range warmPaths {
		if warmPaths[i].ID() != coldPaths[i].ID() {
			t.Fatalf("finding %d ID drift: warm %s cold %s", i, warmPaths[i].ID(), coldPaths[i].ID())
		}
		if warmPaths[i].Truncated != coldPaths[i].Truncated {
			t.Fatalf("Truncated marker drift at %d", i)
		}
	}
}

func TestAuthzPathDeterminism(t *testing.T) {
	reg := registerTriageAuthz(t)
	snap, _, _ := buildPathDivergenceSnapshot(t)
	snap.Endpoints = append(snap.Endpoints,
		mustEndpoint(t, "GET", "https://www.example.com/archive/2021"),
		mustEndpoint(t, "GET", "https://api.other.com/users/12345"),
		mustEndpoint(t, "GET", "https://www.example.com/health"),
	)
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		rep, err := detect.Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}
	rep1, rep2 := run(), run()
	b1, _ := json.Marshal(rep1)
	b2, _ := json.Marshal(rep2)
	if string(b1) != string(b2) {
		t.Fatalf("determinism: two identical runs diverged")
	}
	if got := authzPathFindings(rep1); len(got) != 1 {
		t.Fatalf("path findings %d, want 1 (year/cross-domain/plain endpoints stay quiet)", len(got))
	}
}

func TestAuthzPathDisabledConfig(t *testing.T) {
	reg := registerTriageAuthz(t)
	snap, _, _ := buildPathDivergenceSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	cfg.Config = map[string]string{ruleIDORPathObject + ".disabled": "true"}
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Pack convention: ".disabled" is detector-quiet (completed, no
	// findings), not an engine skip.
	for _, r := range rep.Rules {
		if r.RuleID == ruleIDORPathObject && r.Status != detect.RuleStatusCompleted {
			t.Fatalf("disabled path status %s, want completed (quiet)", r.Status)
		}
	}
	if got := authzPathFindings(rep); len(got) != 0 {
		t.Fatalf("disabled path findings %d, want 0", len(got))
	}
}

func TestAuthzPathDetectorHonorsContext(t *testing.T) {
	apiEP := mustEndpoint(t, "GET", "https://api.example.com/users/12345")
	webEP := mustEndpoint(t, "GET", "https://www.example.com/users/12345")
	apiHost := mustHost(t, "api.example.com")
	rel := mustRelationship(t, apiHost.Identity(), asset.RelationshipHostToTechnology,
		mustTechnology(t, "keycloak", asset.CategoryAuthentication).Identity())
	dctx := &detect.Context{
		Endpoints: []asset.Endpoint{apiEP, webEP},
		PriorFindings: []asset.Finding{
			mustPriorRestidor(t, apiEP.Identity()),
			mustPriorRestidor(t, webEP.Identity()),
		},
		GraphView: stubGraph{map[asset.Identity][]asset.Relationship{apiHost.Identity(): {rel}}},
		Logger:    &recLogger{},
		Clock:     testClock,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := idorPathObjectDetector(ctx, dctx); err == nil {
		t.Fatalf("cancelled detector error nil, want context error")
	}
}
