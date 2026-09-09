package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/apis"
	"github.com/RA000WL/RavenRecon/internal/detect/packs/triage"
	"github.com/RA000WL/RavenRecon/internal/golden"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
)

// fixedClock pins Now to a constant for deterministic reports.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time                         { return c.at }
func (c fixedClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

var testClock = fixedClock{at: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)}

// recLogger is a concurrent-safe recording Logger for direct-detector tests.
type recLogger struct {
	mu      sync.Mutex
	entries []detect.LogEntry
}

func (l *recLogger) Log(level detect.LogLevel, ruleID, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, detect.LogEntry{Level: level, Rule: ruleID, Message: message})
}

func (l *recLogger) has(ruleID string, level detect.LogLevel, substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if e.Rule == ruleID && e.Level == level && strings.Contains(e.Message, substr) {
			return true
		}
	}
	return false
}

// stubGraph is a hand-built GraphQuerier for direct-detector tests.
type stubGraph struct {
	adj map[asset.Identity][]asset.Relationship
}

func (s stubGraph) Neighbors(id asset.Identity) []asset.Relationship {
	return s.adj[id]
}

func (s stubGraph) Path(from, to asset.Identity) []asset.Identity { return nil }

func mustEndpoint(t testing.TB, method, rawURL string) asset.Endpoint {
	t.Helper()
	ep, err := asset.NewEndpoint(method, rawURL, asset.Provenance{Source: "authz-test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return ep
}

func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "authz-test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

func mustTechnology(t testing.TB, name string, cat asset.TechnologyCategory) asset.Technology {
	t.Helper()
	tech, err := asset.NewTechnology(name, cat, asset.Provenance{Source: "authz-test"})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	return tech
}

func mustRelationship(t testing.TB, from asset.Identity, kind asset.RelationshipKind, to asset.Identity) asset.Relationship {
	t.Helper()
	rel, err := asset.NewRelationship(from, kind, to)
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	return rel
}

// mustPriorFinding builds a canonical synthetic triage-pack prior finding:
// subject is an endpoint identity, params is the flagged param list.
func mustPriorFinding(t testing.TB, ruleID, ruleName, short string, subject asset.Identity, params []string, backed bool, allClasses string) asset.Finding {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "triage pack signal: "+ruleID, subject, asset.Provenance{Source: "triage"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	meta := map[string]string{
		"signal":       "triage_" + short,
		"triage_class": short,
		"params":       strings.Join(params, ","),
	}
	if allClasses != "" {
		meta["multi_class"] = "true"
		meta["all_classes"] = allClasses
	}
	if backed {
		meta["reflection_backed"] = "true"
	}
	f, err := asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleName,
		Category:   detect.CategoryInformation.String(),
		Subject:    subject,
		Confidence: 0.6,
		Evidence:   []asset.Evidence{ev},
		Metadata:   meta,
		Priority:   detect.PriorityInfo.String(),
		Status:     detect.StatusOpen.String(),
		Created:    testClock.at.UTC(),
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

func mustPriorIDOR(t testing.TB, subject asset.Identity, params []string, backed bool) asset.Finding {
	t.Helper()
	return mustPriorFinding(t, "triage.idor", "Triage IDOR", "idor", subject, params, backed, "")
}

// registerTriageAuthz registers the triage pack plus the apis pack plus the
// authz pack (the only valid standalone topology: Rule 1 depends on
// triage.idor, Rule 2 depends on api.rest.idor-indicator).
func registerTriageAuthz(t testing.TB) *detect.Registry {
	t.Helper()
	reg := detect.NewRegistry()
	for _, load := range []func() ([]detect.Rule, error){triage.Rules, apis.Rules, Rules} {
		rules, err := load()
		if err != nil {
			t.Fatalf("Rules: %v", err)
		}
		for _, r := range rules {
			if err := reg.Register(r); err != nil {
				t.Fatalf("Register(%q): %v", r.ID, err)
			}
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	reg.Seal()
	return reg
}

// buildDivergenceSnapshot returns the canonical emit fixture: two endpoints
// on different hosts of example.com sharing ?id=, with an authentication
// technology linked to the api host only. The www endpoint is the expected
// unauthenticated subject.
func buildDivergenceSnapshot(t testing.TB) (detect.Snapshot, asset.Endpoint, asset.Endpoint) {
	t.Helper()
	apiEP := mustEndpoint(t, "GET", "https://api.example.com/profile?id=1")
	webEP := mustEndpoint(t, "GET", "https://www.example.com/profile?id=1")
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

func authzFindings(rep detect.Report) []asset.Finding {
	var out []asset.Finding
	for _, f := range rep.Findings {
		if f.RuleID == ruleIDORInsecureDirectObject {
			out = append(out, f)
		}
	}
	return out
}

func TestAuthzPackCheckAPIVersion(t *testing.T) {
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
}

func TestAuthzPackLoadsThroughSDK(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	r := rules[0]
	if r.ID != ruleIDORInsecureDirectObject {
		t.Fatalf("rule ID %q, want %q", r.ID, ruleIDORInsecureDirectObject)
	}
	if r.Version != "1.0.0" {
		t.Fatalf("rule version %q, want 1.0.0", r.Version)
	}
	if r.Category != detect.CategoryAuthorization {
		t.Fatalf("rule category %q, want authorization", r.Category)
	}
	if len(r.Dependencies) != 1 || r.Dependencies[0] != depTriageIDOR {
		t.Fatalf("rule deps %v, want [triage.idor]", r.Dependencies)
	}
	if err := detect.ValidateRule(r); err != nil {
		t.Fatalf("ValidateRule: %v", err)
	}
	reg := detect.NewRegistry()
	if err := reg.Register(r); err != nil {
		t.Fatalf("Register: %v", err)
	}
	orig := r
	orig.Inputs[0] = detect.RuleInput("bogus")
	got, ok := reg.Get(orig.ID)
	if !ok {
		t.Fatalf("Get %q missing", orig.ID)
	}
	if got.Inputs[0] == detect.RuleInput("bogus") {
		t.Fatalf("deep copy broken: registered rule mutated through caller alias")
	}
	if len(got.RequiredAssetTypes) != 1 || got.RequiredAssetTypes[0] != asset.KindEndpoint {
		t.Fatalf("deep copy broken: RequiredAssetTypes aliasing, got %v", got.RequiredAssetTypes)
	}
}

func TestAuthzPackMetadataDepsCompat(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	for _, r := range rules {
		if r.Version == "" {
			t.Fatalf("rule %q version empty", r.ID)
		}
		if _, _, _, err := detect.ParseRuleVersion(r.Version); err != nil {
			t.Fatalf("rule %q version %q invalid: %v", r.ID, r.Version, err)
		}
		if !r.Category.Valid() || r.Category != detect.CategoryAuthorization {
			t.Fatalf("rule %q category %q invalid or not authorization", r.ID, r.Category)
		}
		if len(r.Inputs) == 0 || len(r.Outputs) == 0 {
			t.Fatalf("rule %q inputs/outputs empty", r.ID)
		}
		for _, in := range r.Inputs {
			if !in.Valid() {
				t.Fatalf("rule %q input %q invalid", r.ID, in)
			}
		}
		if !r.EstimatedCost.Valid() {
			t.Fatalf("rule %q cost %q invalid", r.ID, r.EstimatedCost)
		}
		if r.Timeout <= 0 {
			t.Fatalf("rule %q timeout invalid", r.ID)
		}
		if r.Author == "" {
			t.Fatalf("rule %q author empty", r.ID)
		}
		if r.Detector == nil {
			t.Fatalf("rule %q detector nil", r.ID)
		}
		if !strings.HasPrefix(r.ID, "authz.") {
			t.Fatalf("rule %q ID policy violation", r.ID)
		}
	}
}

func TestAuthzValidateFailsWithoutTriage(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	reg := detect.NewRegistry()
	for _, r := range rules {
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register(%q): %v", r.ID, err)
		}
	}
	err = reg.Validate()
	if err == nil {
		t.Fatalf("Validate without triage.idor succeeded, want unregistered-dependency error")
	}
	// Either pack edge may surface first (registry map order): the
	// contract is that a missing pack edge fails, naming its rule.
	if !strings.Contains(err.Error(), "depends on unregistered rule") ||
		(!strings.Contains(err.Error(), "triage.idor") && !strings.Contains(err.Error(), "api.rest.idor-indicator")) {
		t.Fatalf("Validate error %q names no authz dependency edge", err)
	}
}

func TestAuthzEmitsOnCrossHostDivergence(t *testing.T) {
	reg := registerTriageAuthz(t)
	snap, apiEP, webEP := buildDivergenceSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Levels != 2 {
		t.Fatalf("levels %d, want 2 (triage level 0, authz level 1)", rep.Levels)
	}
	got := authzFindings(rep)
	if len(got) != 1 {
		t.Fatalf("authz findings %d, want 1", len(got))
	}
	f := got[0]
	if f.Subject != webEP.Identity() {
		t.Fatalf("subject %s, want unauthenticated endpoint %s", f.Subject, webEP.Identity())
	}
	if f.Category != detect.CategoryAuthorization.String() {
		t.Fatalf("category %q, want authorization", f.Category)
	}
	if f.Priority != detect.PriorityInfo.String() {
		t.Fatalf("priority %q, want info (name-only pair)", f.Priority)
	}
	if f.Confidence != 0.5 {
		t.Fatalf("confidence %v, want 0.5 (name-only pair)", f.Confidence)
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
	for _, k := range []string{"signal", "shared_params", "peer_endpoint", "peer_host", "auth_side", "triage_rule", "verdict"} {
		if f.Metadata[k] == "" {
			t.Fatalf("metadata key %q missing: %+v", k, f.Metadata)
		}
	}
	if f.Metadata["signal"] != "authz_idor_candidate_surface" {
		t.Fatalf("signal %q", f.Metadata["signal"])
	}
	if f.Metadata["shared_params"] != "id" {
		t.Fatalf("shared_params %q, want id", f.Metadata["shared_params"])
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
	if f.Metadata["triage_rule"] != "triage.idor" {
		t.Fatalf("triage_rule %q", f.Metadata["triage_rule"])
	}
	if f.Metadata["verdict"] != "candidate-surface" {
		t.Fatalf("verdict %q", f.Metadata["verdict"])
	}
	if _, ok := f.Metadata["reflection_backed"]; ok {
		t.Fatalf("reflection_backed present on name-only pair: %+v", f.Metadata)
	}
	// Signal-not-proof wording: no finding may claim exploitability.
	// ("provenance" is the asset field name — match whole claim words only.)
	buf, _ := json.Marshal(rep)
	for _, bad := range []string{"exploit", "vulnerab", "unauthorized access", "proof of"} {
		if strings.Contains(strings.ToLower(string(buf)), bad) {
			t.Fatalf("report claims beyond signal: contains %q", bad)
		}
	}
}

func TestAuthzReflectionBackedMedium(t *testing.T) {
	reg := registerTriageAuthz(t)
	snap, _, webEP := buildDivergenceSnapshot(t)
	// Live reflection evidence backing the subject's flagged param: urllive
	// saw the canary return on the www URL.
	rev, err := httpprobe.ReflectEvidence(webEP.URL.Identity(), "id", httpprobe.ReflectUnencoded)
	if err != nil {
		t.Fatalf("ReflectEvidence: %v", err)
	}
	snap.Evidence = append(snap.Evidence, rev)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := authzFindings(rep)
	if len(got) != 1 {
		t.Fatalf("authz findings %d, want 1", len(got))
	}
	f := got[0]
	if f.Priority != detect.PriorityMedium.String() {
		t.Fatalf("priority %q, want medium (reflection-backed divergent)", f.Priority)
	}
	if f.Confidence != 0.7 {
		t.Fatalf("confidence %v, want 0.7", f.Confidence)
	}
	if f.Metadata["reflection_backed"] != "true" {
		t.Fatalf("reflection_backed cite missing: %+v", f.Metadata)
	}
	// The triage prior itself must carry the backing marker (the citation
	// chain is real, not synthesized).
	backed := false
	for _, pf := range rep.Findings {
		if pf.RuleID == "triage.idor" && pf.Subject == webEP.Identity() && pf.Metadata["reflection_backed"] == "true" {
			backed = true
		}
	}
	if !backed {
		t.Fatalf("triage.idor prior for subject lacks reflection_backed marker")
	}
}

func TestAuthzQuietDirectTable(t *testing.T) {
	apiEP := mustEndpoint(t, "GET", "https://api.example.com/profile?id=1")
	webEP := mustEndpoint(t, "GET", "https://www.example.com/profile?id=1")
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
	priors := []asset.Finding{
		mustPriorIDOR(t, apiEP.Identity(), []string{"id"}, false),
		mustPriorIDOR(t, webEP.Identity(), []string{"id"}, false),
	}
	cases := []struct {
		name      string
		endpoints []asset.Endpoint
		priors    []asset.Finding
		graph     detect.GraphQuerier
	}{
		{"nil-graph", []asset.Endpoint{apiEP, webEP}, priors, nil},
		{"empty-priors", []asset.Endpoint{apiEP, webEP}, nil, stubGraph{hostTech()}},
		{"no-relevant-priors", []asset.Endpoint{apiEP, webEP},
			[]asset.Finding{mustPriorFinding(t, "triage.sqli", "Triage SQLi", "sqli", apiEP.Identity(), []string{"order"}, false, "")},
			stubGraph{hostTech()}},
		{"twins", []asset.Endpoint{apiEP, apiEP}, priors, stubGraph{hostTech()}},
		{"same-host", []asset.Endpoint{webEP, mustEndpoint(t, "GET", "https://www.example.com/other?id=1")},
			[]asset.Finding{
				mustPriorIDOR(t, webEP.Identity(), []string{"id"}, false),
				mustPriorIDOR(t, mustEndpoint(t, "GET", "https://www.example.com/other?id=1").Identity(), []string{"id"}, false),
			},
			stubGraph{hostTech()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := idorInsecureDirectObjectDetector(context.Background(), directCtx(tc.endpoints, tc.priors, tc.graph))
			if err != nil {
				t.Fatalf("detector error: %v", err)
			}
			if got != nil {
				t.Fatalf("fail-open quiet violated: got %d findings, want nil", len(got))
			}
		})
	}
}

func TestAuthzQuietSameHostEngine(t *testing.T) {
	reg := registerTriageAuthz(t)
	a := mustEndpoint(t, "GET", "https://www.example.com/a?id=1")
	b := mustEndpoint(t, "GET", "https://www.example.com/b?id=1")
	host := mustHost(t, "www.example.com")
	tech := mustTechnology(t, "keycloak", asset.CategoryAuthentication)
	snap := detect.Snapshot{
		Assets:        []asset.Identity{host.Identity()},
		Relationships: []asset.Relationship{mustRelationship(t, host.Identity(), asset.RelationshipHostToTechnology, tech.Identity())},
		Technologies:  []asset.Technology{tech},
		Endpoints:     []asset.Endpoint{a, b},
	}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := authzFindings(rep); len(got) != 0 {
		t.Fatalf("same-host authz findings %d, want 0", len(got))
	}
}

func TestAuthzQuietDifferentDomainEngine(t *testing.T) {
	reg := registerTriageAuthz(t)
	a := mustEndpoint(t, "GET", "https://api.example.com/profile?id=1")
	b := mustEndpoint(t, "GET", "https://api.other.com/profile?id=1")
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
	if got := authzFindings(rep); len(got) != 0 {
		t.Fatalf("cross-domain authz findings %d, want 0", len(got))
	}
}

func TestAuthzQuietEmptyPriorsEngine(t *testing.T) {
	reg := registerTriageAuthz(t)
	// ?zzz matches no triage wordlist: every triage rule completes empty,
	// so authz sees empty PriorFindings and stays quiet (fail-open).
	a := mustEndpoint(t, "GET", "https://api.example.com/profile?zzz=1")
	b := mustEndpoint(t, "GET", "https://www.example.com/profile?zzz=1")
	snap := detect.Snapshot{Endpoints: []asset.Endpoint{a, b}}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	statuses := map[string]detect.RuleStatus{}
	for _, r := range rep.Rules {
		statuses[r.RuleID] = r.Status
	}
	if statuses[ruleIDORInsecureDirectObject] != detect.RuleStatusCompleted {
		t.Fatalf("authz status %s, want completed (quiet, not skipped)", statuses[ruleIDORInsecureDirectObject])
	}
	if got := authzFindings(rep); len(got) != 0 {
		t.Fatalf("empty-prior authz findings %d, want 0", len(got))
	}
}

func TestAuthzPrecedenceShadowRecovery(t *testing.T) {
	// ?doc= is primary triage.ssrf under overlap precedence (SSRF > IDOR):
	// the triage.idor rule never flags it, but the ssrf finding's
	// all_classes carries the idor token — recovery must count it.
	apiEP := mustEndpoint(t, "GET", "https://api.example.com/docs?doc=1")
	webEP := mustEndpoint(t, "GET", "https://www.example.com/docs?doc=1")
	apiHost := mustHost(t, "api.example.com")
	rel := mustRelationship(t, apiHost.Identity(), asset.RelationshipHostToTechnology,
		mustTechnology(t, "keycloak", asset.CategoryAuthentication).Identity())
	gv := stubGraph{map[asset.Identity][]asset.Relationship{apiHost.Identity(): {rel}}}
	priors := []asset.Finding{
		mustPriorFinding(t, "triage.ssrf", "Triage SSRF", "ssrf", apiEP.Identity(), []string{"doc"}, false, "idor,ssrf"),
		mustPriorFinding(t, "triage.ssrf", "Triage SSRF", "ssrf", webEP.Identity(), []string{"doc"}, false, "idor,ssrf"),
	}
	dctx := &detect.Context{
		Endpoints:     []asset.Endpoint{apiEP, webEP},
		PriorFindings: priors,
		GraphView:     gv,
		Logger:        &recLogger{},
		Clock:         testClock,
	}
	got, err := idorInsecureDirectObjectDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("shadow-recovery findings %d, want 1", len(got))
	}
	if got[0].Subject != webEP.Identity() {
		t.Fatalf("subject %s, want %s", got[0].Subject, webEP.Identity())
	}
	if got[0].Metadata["shared_params"] != "doc" {
		t.Fatalf("shared_params %q, want doc", got[0].Metadata["shared_params"])
	}
	// Negative: same ssrf priors WITHOUT the idor token must not recover.
	priorsNoToken := []asset.Finding{
		mustPriorFinding(t, "triage.ssrf", "Triage SSRF", "ssrf", apiEP.Identity(), []string{"doc"}, false, ""),
		mustPriorFinding(t, "triage.ssrf", "Triage SSRF", "ssrf", webEP.Identity(), []string{"doc"}, false, ""),
	}
	dctx2 := &detect.Context{
		Endpoints:     []asset.Endpoint{apiEP, webEP},
		PriorFindings: priorsNoToken,
		GraphView:     gv,
		Logger:        &recLogger{},
		Clock:         testClock,
	}
	got2, err := idorInsecureDirectObjectDetector(context.Background(), dctx2)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if got2 != nil {
		t.Fatalf("tokenless priors emitted %d findings, want nil", len(got2))
	}
}

func TestAuthzNoDirectURLMining(t *testing.T) {
	// N4: both endpoint URLs carry ?id=, but only apiEP has a triage prior.
	// The www URL must never be mined into participation — no pair, no
	// finding.
	apiEP := mustEndpoint(t, "GET", "https://api.example.com/profile?id=1")
	webEP := mustEndpoint(t, "GET", "https://www.example.com/profile?id=1")
	apiHost := mustHost(t, "api.example.com")
	rel := mustRelationship(t, apiHost.Identity(), asset.RelationshipHostToTechnology,
		mustTechnology(t, "keycloak", asset.CategoryAuthentication).Identity())
	dctx := &detect.Context{
		Endpoints:     []asset.Endpoint{apiEP, webEP},
		PriorFindings: []asset.Finding{mustPriorIDOR(t, apiEP.Identity(), []string{"id"}, false)},
		GraphView:     stubGraph{map[asset.Identity][]asset.Relationship{apiHost.Identity(): {rel}}},
		Logger:        &recLogger{},
		Clock:         testClock,
	}
	got, err := idorInsecureDirectObjectDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if got != nil {
		t.Fatalf("URL-mined findings %d, want nil (triage-flagged params only)", len(got))
	}
}

func TestAuthzO2IndicatorUniverse(t *testing.T) {
	// O2 pin: the A2 universe must name the techintel auth forms it claims.
	for _, named := range []string{"sessionid", "x-ms-request-id", "next-auth.session-token", "keycloak_identity", "connect.sid"} {
		found := false
		for _, n := range authIndicatorNames {
			if n == named {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("pinned A2 universe missing named form %q", named)
		}
	}
	// A2 path end to end: auth side carried by cookie evidence alone (no
	// technology edges anywhere).
	apiEP := mustEndpoint(t, "GET", "https://api.example.com/profile?id=1")
	webEP := mustEndpoint(t, "GET", "https://www.example.com/profile?id=1")
	apiHost := mustHost(t, "api.example.com")
	cookieEv, err := asset.NewEvidence(asset.MethodCookie, "cookie:sessionid", "synthetic-cookie-value",
		apiHost.Identity(), asset.Provenance{Source: "techintel"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	dctx := &detect.Context{
		Endpoints: []asset.Endpoint{apiEP, webEP},
		Evidence:  []asset.Evidence{cookieEv},
		PriorFindings: []asset.Finding{
			mustPriorIDOR(t, apiEP.Identity(), []string{"id"}, false),
			mustPriorIDOR(t, webEP.Identity(), []string{"id"}, false),
		},
		GraphView: stubGraph{},
		Logger:    &recLogger{},
		Clock:     testClock,
	}
	got, err := idorInsecureDirectObjectDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if len(got) != 1 || got[0].Subject != webEP.Identity() {
		t.Fatalf("A2-cookie findings = %v, want single subject %s", got, webEP.Identity())
	}
	// Documented TLS-CN cut: TLS evidence alone never authenticates a side.
	tlsEv, err := asset.NewEvidence(asset.MethodTLS, "tls_cn:okta.com", "synthetic-cert-value",
		apiHost.Identity(), asset.Provenance{Source: "techintel"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	dctxTLS := &detect.Context{
		Endpoints: []asset.Endpoint{apiEP, webEP},
		Evidence:  []asset.Evidence{tlsEv},
		PriorFindings: []asset.Finding{
			mustPriorIDOR(t, apiEP.Identity(), []string{"id"}, false),
			mustPriorIDOR(t, webEP.Identity(), []string{"id"}, false),
		},
		GraphView: stubGraph{},
		Logger:    &recLogger{},
		Clock:     testClock,
	}
	gotTLS, err := idorInsecureDirectObjectDetector(context.Background(), dctxTLS)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if gotTLS != nil {
		t.Fatalf("TLS-only evidence emitted %d findings, want nil (documented cut)", len(gotTLS))
	}
}

func TestAuthzCap256Truncation(t *testing.T) {
	// 300 unauthenticated endpoints + 1 authenticated peer, all sharing
	// ?id= with triage priors: the rule keeps 256 with subjects_dropped=44,
	// truncated=true, and a LevelWarn log — never silent.
	authEP := mustEndpoint(t, "GET", "https://auth.example.com/login?id=1")
	authHost := mustHost(t, "auth.example.com")
	tech := mustTechnology(t, "keycloak", asset.CategoryAuthentication)
	authRel := mustRelationship(t, authHost.Identity(), asset.RelationshipHostToTechnology, tech.Identity())
	var endpoints []asset.Endpoint
	var priors []asset.Finding
	endpoints = append(endpoints, authEP)
	priors = append(priors, mustPriorIDOR(t, authEP.Identity(), []string{"id"}, false))
	for i := 0; i < 300; i++ {
		ep := mustEndpoint(t, "GET", fmt.Sprintf("https://h-%03d.example.com/profile?id=1", i))
		endpoints = append(endpoints, ep)
		priors = append(priors, mustPriorIDOR(t, ep.Identity(), []string{"id"}, false))
	}
	logger := &recLogger{}
	dctx := &detect.Context{
		Endpoints:     endpoints,
		PriorFindings: priors,
		GraphView:     stubGraph{map[asset.Identity][]asset.Relationship{authHost.Identity(): {authRel}}},
		Logger:        logger,
		Clock:         testClock,
	}
	got, err := idorInsecureDirectObjectDetector(context.Background(), dctx)
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
		if f.Subject == authEP.Identity() {
			t.Fatalf("authenticated peer must never be a subject")
		}
	}
	if !logger.has(ruleIDORInsecureDirectObject, detect.LevelWarn, "truncated 44 subjects over bound 256") {
		t.Fatalf("missing LevelWarn truncation log")
	}
}

func TestAuthzCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerTriageAuthz(t)
	snap, _, _ := buildDivergenceSnapshot(t)
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
	if len(warm.Findings) != len(cold.Findings) {
		t.Fatalf("warm findings %d vs cold %d", len(warm.Findings), len(cold.Findings))
	}
	for i := range warm.Findings {
		if warm.Findings[i].ID() != cold.Findings[i].ID() {
			t.Fatalf("finding %d ID drift: warm %s cold %s", i, warm.Findings[i].ID(), cold.Findings[i].ID())
		}
		if warm.Findings[i].Truncated != cold.Findings[i].Truncated {
			t.Fatalf("Truncated marker drift at %d", i)
		}
	}
	// Identity-change recompute: a new divergent pair changes triage
	// identities, so the authz record recomputes instead of serving stale.
	snap2 := snap
	extra1 := mustEndpoint(t, "GET", "https://extra1.example.com/profile?id=1")
	extra2 := mustEndpoint(t, "GET", "https://extra2.example.com/profile?id=1")
	snap2.Endpoints = append(append([]asset.Endpoint{}, snap.Endpoints...), extra1, extra2)
	extraTech := mustTechnology(t, "keycloak", asset.CategoryAuthentication)
	extraHost := mustHost(t, "extra1.example.com")
	snap2.Assets = append(append([]asset.Identity{}, snap.Assets...), extraHost.Identity())
	snap2.Technologies = append(append([]asset.Technology{}, snap.Technologies...), extraTech)
	snap2.Relationships = append(append([]asset.Relationship{}, snap.Relationships...),
		mustRelationship(t, extraHost.Identity(), asset.RelationshipHostToTechnology, extraTech.Identity()))
	cfg3 := detect.DefaultEngineConfig(reg)
	cfg3.Cache = fs
	cfg3.Clock = testClock
	warm2, err := detect.Run(context.Background(), cfg3, snap2)
	if err != nil {
		t.Fatalf("recompute Run: %v", err)
	}
	if got := authzFindings(warm2); len(got) != 2 {
		t.Fatalf("recompute authz findings %d, want 2 (old + new pair)", len(got))
	}
}

func TestAuthzOrderingDepSkip(t *testing.T) {
	// A failing level-0 triage.idor and a failing level-0
	// api.rest.idor-indicator (stubs with the same rule IDs — the
	// dependency contract keys on the ID string) must dep-skip both authz
	// rules with honest dependency reasons and zero findings.
	stubTriageIDOR := detect.Rule{
		ID:            "triage.idor",
		Name:          "Triage IDOR Stub",
		Description:   "Synthetic failing triage.idor for the authz dep-skip test",
		Category:      detect.CategoryInformation,
		Version:       "9.9.9",
		Inputs:        []detect.RuleInput{detect.InputEndpoints},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "authz-test",
		Enabled:       true,
		Detector: func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
			return nil, fmt.Errorf("synthetic triage.idor failure")
		},
	}
	stubApisIDOR := detect.Rule{
		ID:            "api.rest.idor-indicator",
		Name:          "REST IDOR Stub",
		Description:   "Synthetic failing api.rest.idor-indicator for the authz dep-skip test",
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
	reg := detect.NewRegistry()
	if err := reg.Register(stubTriageIDOR); err != nil {
		t.Fatalf("Register stub: %v", err)
	}
	if err := reg.Register(stubApisIDOR); err != nil {
		t.Fatalf("Register stub: %v", err)
	}
	for _, r := range authzRules {
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register(%q): %v", r.ID, err)
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	reg.Seal()
	snap, _, _ := buildDivergenceSnapshot(t)
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
	if statuses["triage.idor"].Status != detect.RuleStatusFailed {
		t.Fatalf("triage.idor status %s, want failed (stub)", statuses["triage.idor"].Status)
	}
	authzRes := statuses[ruleIDORInsecureDirectObject]
	if authzRes.Status != detect.RuleStatusSkipped {
		t.Fatalf("authz status %s, want skipped (dep did not complete)", authzRes.Status)
	}
	if !strings.Contains(authzRes.SkipReason, `dependency "triage.idor" did not complete`) {
		t.Fatalf("authz skip reason %q, want dependency reason", authzRes.SkipReason)
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
	// Empty snapshot: every rule census-skips, zero findings.
	reg2 := registerTriageAuthz(t)
	cfg2 := detect.DefaultEngineConfig(reg2)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, detect.Snapshot{})
	if err != nil {
		t.Fatalf("Run empty: %v", err)
	}
	if rep2.Skipped != 13 {
		t.Fatalf("empty corpus: skipped %d, want 13 (8 triage + 3 apis + 2 authz)", rep2.Skipped)
	}
	if len(rep2.Findings) != 0 {
		t.Fatalf("empty corpus findings %d, want 0", len(rep2.Findings))
	}
}

func TestAuthzDetectorHonorsContext(t *testing.T) {
	reg := registerTriageAuthz(t)
	snap, _, _ := buildDivergenceSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := detect.Run(ctx, cfg, snap)
	if err != nil {
		t.Fatalf("Run cancelled: %v", err)
	}
	if rep.Outcome != detect.OutcomeCancelled {
		t.Fatalf("cancelled run outcome %s, want cancelled", rep.Outcome)
	}
}

func TestAuthzDisabledConfig(t *testing.T) {
	reg := registerTriageAuthz(t)
	snap, _, _ := buildDivergenceSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	cfg.Config = map[string]string{ruleIDORInsecureDirectObject + ".disabled": "true"}
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Pack convention: ".disabled" is detector-quiet (completed, no
	// findings), not an engine skip.
	for _, r := range rep.Rules {
		if r.RuleID == ruleIDORInsecureDirectObject && r.Status != detect.RuleStatusCompleted {
			t.Fatalf("disabled authz status %s, want completed (quiet)", r.Status)
		}
	}
	if got := authzFindings(rep); len(got) != 0 {
		t.Fatalf("disabled authz findings %d, want 0", len(got))
	}
}

func TestAuthzDeterminismGolden(t *testing.T) {
	reg := registerTriageAuthz(t)
	snap, _, _ := buildDivergenceSnapshot(t)
	// Mixed corpus: the divergent pair plus same-host, cross-domain, and
	// safe endpoints that must stay quiet.
	snap.Endpoints = append(snap.Endpoints,
		mustEndpoint(t, "GET", "https://www.example.com/other?id=1"),
		mustEndpoint(t, "GET", "https://api.other.com/profile?id=1"),
		mustEndpoint(t, "GET", "https://www.example.com/health?zzz=1"),
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
	golden.Compare(t, "testdata/authz_report.golden", b1)
}

func TestAuthzRequiredAssetTypesSkipHonestly(t *testing.T) {
	reg := registerTriageAuthz(t)
	host := mustHost(t, "www.example.com")
	snap := detect.Snapshot{Assets: []asset.Identity{host.Identity()}}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run host-only: %v", err)
	}
	for _, r := range rep.Rules {
		if r.RuleID == ruleIDORInsecureDirectObject {
			if r.Status != detect.RuleStatusSkipped {
				t.Fatalf("authz status %s, want skipped (no endpoint)", r.Status)
			}
			if !strings.Contains(r.SkipReason, "required asset kind") {
				t.Fatalf("authz skip reason %q", r.SkipReason)
			}
		}
	}
}

func TestAuthzHostIdentityOfKindDispatch(t *testing.T) {
	// hostIdentityOf dispatches through the asset layer (AGENTS §0.5):
	// IP literals resolve to KindIP (so Neighbors/Path lookups keyed on
	// the host identity hit the observed IP node), DNS names resolve to
	// KindHost unchanged, and a value neither builder accepts yields a
	// zero identity that matches no graph path (fail-open quiet).
	// (End to end, IP flows stay quiet regardless: the authz pairing
	// requires sameBaseDomain, which is false for IP literals — that is
	// the documented pairing contract, not this constructor's scope.)
	ip := hostIdentityOf("192.0.2.1")
	if ip.Kind != asset.KindIP || ip.Value != "192.0.2.1" {
		t.Fatalf("IP-literal identity %+v, want {Kind:ip Value:192.0.2.1}", ip)
	}
	dns := hostIdentityOf("www.example.com")
	if dns != (asset.Identity{Kind: asset.KindHost, Value: "www.example.com"}) {
		t.Fatalf("DNS identity %+v, want {Kind:host Value:www.example.com}", dns)
	}
	if bad := hostIdentityOf("not a host!!"); bad != (asset.Identity{}) {
		t.Fatalf("unparseable identity %+v, want zero identity (quiet)", bad)
	}
}
