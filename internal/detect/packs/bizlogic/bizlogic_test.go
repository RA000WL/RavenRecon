package bizlogic

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
	"github.com/RA000WL/RavenRecon/internal/detect/packs/authz"
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

// stubGraph is a hand-built GraphQuerier for direct-detector tests, with an
// optional Path function (nil ⇒ no paths, full stop).
type stubGraph struct {
	adj  map[asset.Identity][]asset.Relationship
	path func(from, to asset.Identity) []asset.Identity
}

func (s stubGraph) Neighbors(id asset.Identity) []asset.Relationship {
	return s.adj[id]
}

func (s stubGraph) Path(from, to asset.Identity) []asset.Identity {
	if s.path == nil {
		return nil
	}
	return s.path(from, to)
}

func mustEndpoint(t testing.TB, method, rawURL string) asset.Endpoint {
	t.Helper()
	ep, err := asset.NewEndpoint(method, rawURL, asset.Provenance{Source: "bizlogic-test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return ep
}

func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "bizlogic-test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

func mustTechnology(t testing.TB, name string, cat asset.TechnologyCategory) asset.Technology {
	t.Helper()
	tech, err := asset.NewTechnology(name, cat, asset.Provenance{Source: "bizlogic-test"})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	return tech
}

func mustJavaScript(t testing.TB, rawURL string) asset.JavaScript {
	t.Helper()
	js, err := asset.NewJavaScript(rawURL, asset.Provenance{Source: "bizlogic-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	return js
}

func mustRelationship(t testing.TB, from asset.Identity, kind asset.RelationshipKind, to asset.Identity) asset.Relationship {
	t.Helper()
	rel, err := asset.NewRelationship(from, kind, to)
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	return rel
}

// mustPriorFinding builds a canonical synthetic prior finding over an
// endpoint subject.
func mustPriorFinding(t testing.TB, ruleID, ruleName, category string, subject asset.Identity, source string, meta map[string]string, confidence float64) asset.Finding {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "test pack signal: "+ruleID, subject, asset.Provenance{Source: source})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	f, err := asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleName,
		Category:   category,
		Subject:    subject,
		Confidence: confidence,
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

func mustPriorIDOR(t testing.TB, subject asset.Identity, params []string) asset.Finding {
	t.Helper()
	return mustPriorFinding(t, "triage.idor", "Triage IDOR", detect.CategoryInformation.String(), subject, "triage",
		map[string]string{"signal": "triage_idor", "triage_class": "idor", "params": strings.Join(params, ",")}, 0.6)
}

func mustPriorShadow(t testing.TB, ruleID, short string, subject asset.Identity, params []string, allClasses string) asset.Finding {
	t.Helper()
	return mustPriorFinding(t, ruleID, "Triage "+short, detect.CategoryInformation.String(), subject, "triage",
		map[string]string{"signal": "triage_" + short, "triage_class": short, "params": strings.Join(params, ","),
			"multi_class": "true", "all_classes": allClasses}, 0.6)
}

func mustPriorAuthz(t testing.TB, subject asset.Identity) asset.Finding {
	t.Helper()
	return mustPriorFinding(t, "authz.idor.insecure-direct-object", "IDOR Insecure Direct Object",
		detect.CategoryAuthorization.String(), subject, "authz",
		map[string]string{"signal": "authz_idor_candidate_surface", "verdict": "candidate-surface"}, 0.5)
}

func mustPriorGraphQL(t testing.TB, subject asset.Identity) asset.Finding {
	t.Helper()
	return mustPriorFinding(t, "api.graphql.introspection", "GraphQL Introspection",
		detect.CategoryAPI.String(), subject, "apis",
		map[string]string{"signal": "graphql_endpoint"}, 0.5)
}

func mustPriorRobots(t testing.TB, subject asset.Identity) asset.Finding {
	t.Helper()
	return mustPriorFinding(t, "web.robots.exposed", "Robots Exposed",
		detect.CategoryInformation.String(), subject, "web",
		map[string]string{"signal": "robots_exposed"}, 0.5)
}

// registerTriageAuthzBizlogic registers the triage pack plus the apis pack
// plus the authz pack plus the bizlogic pack (the only valid standalone
// topology: bizlogic depends on authz.idor, which depends on triage.idor
// and api.rest.idor-indicator).
func registerTriageAuthzBizlogic(t testing.TB) *detect.Registry {
	t.Helper()
	reg := detect.NewRegistry()
	for _, load := range []func() ([]detect.Rule, error){triage.Rules, apis.Rules, authz.Rules, Rules} {
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

// hostChain returns host→url→endpoint relationships so GraphView.Path(host,
// endpoint) resolves through the observed graph.
func hostChain(t testing.TB, host asset.Host, ep asset.Endpoint) []asset.Relationship {
	t.Helper()
	return []asset.Relationship{
		mustRelationship(t, host.Identity(), asset.RelationshipHostToURL, ep.URL.Identity()),
		mustRelationship(t, ep.URL.Identity(), asset.RelationshipURLToEndpoint, ep.Identity()),
	}
}

// buildFlowSnapshot returns the canonical emit fixture: two same-host
// workflow steps sharing ?user_id= with host⇝step paths, plus a
// cross-host authenticated peer sharing the token (so authz marks step1).
// The terminal subject is step1 (identity-smallest).
func buildFlowSnapshot(t testing.TB) (detect.Snapshot, asset.Endpoint, asset.Endpoint) {
	t.Helper()
	step1 := mustEndpoint(t, "GET", "https://www.example.com/step1?user_id=1")
	step2 := mustEndpoint(t, "GET", "https://www.example.com/step2?user_id=1")
	peer := mustEndpoint(t, "GET", "https://api.example.com/peer?user_id=1")
	wwwHost := mustHost(t, "www.example.com")
	apiHost := mustHost(t, "api.example.com")
	tech := mustTechnology(t, "keycloak", asset.CategoryAuthentication)
	rels := append(hostChain(t, wwwHost, step1), hostChain(t, wwwHost, step2)...)
	rels = append(rels, mustRelationship(t, apiHost.Identity(), asset.RelationshipHostToTechnology, tech.Identity()))
	return detect.Snapshot{
		Assets:        []asset.Identity{wwwHost.Identity(), apiHost.Identity()},
		Relationships: rels,
		Technologies:  []asset.Technology{tech},
		Endpoints:     []asset.Endpoint{step1, step2, peer},
	}, step1, step2
}

func bizlogicFindings(rep detect.Report) []asset.Finding {
	var out []asset.Finding
	for _, f := range rep.Findings {
		if f.RuleID == ruleWorkflowStateTransition {
			out = append(out, f)
		}
	}
	return out
}

func TestBizlogicPackCheckAPIVersion(t *testing.T) {
	if err := detect.CheckAPIVersion(2, 0); err != nil {
		t.Fatalf("CheckAPIVersion(2,0): %v", err)
	}
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("pack carries %d rules, want 1 (Rule 2 is deferred, never placeholder)", len(rules))
	}
}

func TestBizlogicPackLoadsThroughSDK(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	r := rules[0]
	if r.ID != ruleWorkflowStateTransition {
		t.Fatalf("rule ID %q, want %q", r.ID, ruleWorkflowStateTransition)
	}
	if r.Version != "1.0.0" {
		t.Fatalf("rule version %q, want 1.0.0", r.Version)
	}
	if r.Category != detect.CategoryBusinessLogic {
		t.Fatalf("rule category %q, want business_logic", r.Category)
	}
	if len(r.Dependencies) != 1 || r.Dependencies[0] != depAuthzIDOR {
		t.Fatalf("rule deps %v, want [authz.idor.insecure-direct-object]", r.Dependencies)
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
	if len(got.Dependencies) != 1 || got.Dependencies[0] != depAuthzIDOR {
		t.Fatalf("deep copy broken: Dependencies aliasing, got %v", got.Dependencies)
	}
}

func TestBizlogicPackMetadataDepsCompat(t *testing.T) {
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
		if !r.Category.Valid() || r.Category != detect.CategoryBusinessLogic {
			t.Fatalf("rule %q category %q invalid or not business_logic", r.ID, r.Category)
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
		if !strings.HasPrefix(r.ID, "bizlogic.") {
			t.Fatalf("rule %q ID policy violation", r.ID)
		}
	}
}

func TestBizlogicValidateFailsWithoutAuthz(t *testing.T) {
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
		t.Fatalf("Validate without authz.idor succeeded, want unregistered-dependency error")
	}
	if !strings.Contains(err.Error(), "authz.idor.insecure-direct-object") {
		t.Fatalf("Validate error %q does not name authz.idor.insecure-direct-object", err)
	}
}

func TestBizlogicEmitsOnFlow(t *testing.T) {
	reg := registerTriageAuthzBizlogic(t)
	snap, step1, step2 := buildFlowSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Levels != 3 {
		t.Fatalf("levels %d, want 3 (triage L0, authz L1, bizlogic L2)", rep.Levels)
	}
	got := bizlogicFindings(rep)
	if len(got) != 1 {
		t.Fatalf("bizlogic findings %d, want 1", len(got))
	}
	f := got[0]
	if f.Subject != step1.Identity() {
		t.Fatalf("subject %s, want terminal step %s", f.Subject, step1.Identity())
	}
	if f.Category != detect.CategoryBusinessLogic.String() {
		t.Fatalf("category %q, want business_logic", f.Category)
	}
	if f.Priority != detect.PriorityInfo.String() {
		t.Fatalf("priority %q, want info (never medium+)", f.Priority)
	}
	if f.Confidence != 0.5 {
		t.Fatalf("confidence %v, want 0.5 (2-step flow)", f.Confidence)
	}
	if len(f.Evidence) == 0 || f.Evidence[0].Method != asset.MethodDetection {
		t.Fatalf("evidence method wrong")
	}
	if f.Evidence[0].Source != step1.Identity() {
		t.Fatalf("evidence source %s, want subject %s", f.Evidence[0].Source, step1.Identity())
	}
	if prov := f.Evidence[0].Prov; prov.Source != "bizlogic" {
		t.Fatalf("evidence provenance source %q, want bizlogic", prov.Source)
	}
	if len(f.RelatedAssets) != 0 {
		t.Fatalf("related assets %v, want none (peers ride metadata strings only)", f.RelatedAssets)
	}
	wantSteps := step1.Identity().String() + "," + step2.Identity().String()
	for k, want := range map[string]string{
		"signal":       "bizlogic_workflow_candidate_flow",
		"flow_steps":   wantSteps,
		"flow_len":     "2",
		"shared_token": "user_id",
		"host":         "www.example.com",
		"edge_basis":   "correlated-not-traversed",
		"authz_member": step1.Identity().String(),
		"triage_rule":  "triage.idor",
		"verdict":      "candidate-flow",
	} {
		if f.Metadata[k] != want {
			t.Fatalf("metadata %q = %q, want %q (full meta %+v)", k, f.Metadata[k], want, f.Metadata)
		}
	}
	// Signal-not-proof wording over this pack's own output: no finding may
	// claim exploitability. (Scoped to bizlogic findings — sibling packs
	// own their wording.)
	buf, _ := json.Marshal(got)
	for _, bad := range []string{"exploit", "vulnerab", "unauthorized", "proof", "verified"} {
		if strings.Contains(strings.ToLower(string(buf)), bad) {
			t.Fatalf("bizlogic output claims beyond signal: contains %q", bad)
		}
	}
}

func TestBizlogicEmitsThreeStepConfidence(t *testing.T) {
	reg := registerTriageAuthzBizlogic(t)
	snap, _, _ := buildFlowSnapshot(t)
	step3 := mustEndpoint(t, "GET", "https://www.example.com/step3?user_id=1")
	wwwHost := mustHost(t, "www.example.com")
	snap.Endpoints = append(snap.Endpoints, step3)
	snap.Relationships = append(snap.Relationships, hostChain(t, wwwHost, step3)...)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := bizlogicFindings(rep)
	if len(got) != 1 {
		t.Fatalf("bizlogic findings %d, want 1", len(got))
	}
	if got[0].Confidence != 0.6 {
		t.Fatalf("confidence %v, want 0.6 (3+ step flow)", got[0].Confidence)
	}
	if got[0].Priority != detect.PriorityInfo.String() {
		t.Fatalf("priority %q, want info (never medium+)", got[0].Priority)
	}
	if got[0].Metadata["flow_len"] != "3" {
		t.Fatalf("flow_len %q, want 3", got[0].Metadata["flow_len"])
	}
}

func TestBizlogicHubQuietPathFiresEngine(t *testing.T) {
	// Path-only co-reachability on the REAL engine graph view (not a stub):
	// a same-host pair sharing one IDOR token and one JavaScript hub — but
	// with NO host⇝step paths — stays quiet, while a Path-chained pair on
	// another host fires. Without an SDK reverse lookup (step →
	// referencing scripts) hub linkage is unobservable through the
	// outgoing-only Neighbors view, so the hub pair must emit nothing.
	reg := registerTriageAuthzBizlogic(t)
	snap, _, _ := buildFlowSnapshot(t) // pathed www pair + authz peer
	hub1 := mustEndpoint(t, "GET", "https://hub.example.com/cart?user_id=1")
	hub2 := mustEndpoint(t, "GET", "https://hub.example.com/checkout?user_id=1")
	hubHost := mustHost(t, "hub.example.com")
	hubJS := mustJavaScript(t, "https://hub.example.com/app.js")
	snap.Assets = append(snap.Assets, hubHost.Identity(), hubJS.Identity())
	snap.JavaScript = append(snap.JavaScript, hubJS)
	snap.Endpoints = append(snap.Endpoints, hub1, hub2)
	snap.Relationships = append(snap.Relationships,
		mustRelationship(t, hubJS.Identity(), asset.RelationshipJavaScriptToEndpoint, hub1.Identity()),
		mustRelationship(t, hubJS.Identity(), asset.RelationshipJavaScriptToEndpoint, hub2.Identity()),
	)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := bizlogicFindings(rep)
	if len(got) != 1 {
		t.Fatalf("bizlogic findings %d, want 1 (hub pair quiet, pathed pair fires)", len(got))
	}
	if got[0].Metadata["host"] != "www.example.com" {
		t.Fatalf("firing host %q, want www.example.com (Path-chained pair)", got[0].Metadata["host"])
	}
}

func TestBizlogicIPLiteralHostIdentity(t *testing.T) {
	// Host identity resolves through the asset layer: an IP-literal pair
	// groups under its KindIP identity (not KindHost), so host⇝step paths
	// sourced at the observed IP node are honored and the pair fires. The
	// stub sources paths ONLY at the KindIP identity — under the old
	// KindHost hardcode every Path lookup would miss and the pair would
	// stay quiet.
	// (End to end, IP flows still stay quiet because the authz pack only
	// marks same-domain DNS pairs, so no authz member can exist for an IP
	// host; that is the authz pack's documented contract, not this pack's
	// resolution — hence this pin is direct-detector with explicit priors.)
	ip, err := asset.NewIP("192.0.2.1", asset.Provenance{Source: "bizlogic-test"})
	if err != nil {
		t.Fatalf("NewIP: %v", err)
	}
	a := mustEndpoint(t, "GET", "https://192.0.2.1/step1?user_id=1")
	b := mustEndpoint(t, "GET", "https://192.0.2.1/step2?user_id=1")
	dctx := &detect.Context{
		Endpoints: []asset.Endpoint{a, b},
		PriorFindings: []asset.Finding{
			mustPriorIDOR(t, a.Identity(), []string{"user_id"}),
			mustPriorIDOR(t, b.Identity(), []string{"user_id"}),
			mustPriorAuthz(t, a.Identity()),
		},
		GraphView: stubGraph{path: func(from, to asset.Identity) []asset.Identity {
			if from == ip.Identity() && (to == a.Identity() || to == b.Identity()) {
				return []asset.Identity{from, to}
			}
			return nil
		}},
		Logger: &recLogger{},
		Clock:  testClock,
	}
	got, err := workflowStateTransitionDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("IP-literal findings %d, want 1 (KindIP host identity resolves)", len(got))
	}
	if got[0].Metadata["host"] != "192.0.2.1" {
		t.Fatalf("host %q, want 192.0.2.1", got[0].Metadata["host"])
	}
}

func TestBizlogicMethodDissimilarity(t *testing.T) {
	// Dissimilarity is keyed on method+path: GET+POST on one path are two
	// dissimilar steps (a canonical view/update pair fires), while
	// same-method same-path twins collapse and stay quiet.
	hostPaths := func(eps ...asset.Endpoint) func(from, to asset.Identity) []asset.Identity {
		byID := make(map[asset.Identity]asset.Endpoint)
		for _, ep := range eps {
			byID[ep.Identity()] = ep
		}
		return func(from, to asset.Identity) []asset.Identity {
			ep, ok := byID[to]
			if !ok {
				return nil
			}
			if from == hostIdentityOf(endpointHost(ep.URL.HostPort)) {
				return []asset.Identity{from, to}
			}
			return nil
		}
	}
	get := mustEndpoint(t, "GET", "https://www.example.com/cart?user_id=1")
	post := mustEndpoint(t, "POST", "https://www.example.com/cart?user_id=1")
	dctx := &detect.Context{
		Endpoints: []asset.Endpoint{get, post},
		PriorFindings: []asset.Finding{
			mustPriorIDOR(t, get.Identity(), []string{"user_id"}),
			mustPriorIDOR(t, post.Identity(), []string{"user_id"}),
			mustPriorAuthz(t, get.Identity()),
		},
		GraphView: stubGraph{path: hostPaths(get, post)},
		Logger:    &recLogger{},
		Clock:     testClock,
	}
	got, err := workflowStateTransitionDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("GET/POST same-path findings %d, want 1 (method-dissimilar steps fire)", len(got))
	}
	if got[0].Metadata["flow_len"] != "2" {
		t.Fatalf("flow_len %q, want 2", got[0].Metadata["flow_len"])
	}
	// Same-method same-path twins (differing only in query) collapse.
	twin := mustEndpoint(t, "GET", "https://www.example.com/cart?user_id=1&page=2")
	dctxTwin := &detect.Context{
		Endpoints: []asset.Endpoint{get, twin},
		PriorFindings: []asset.Finding{
			mustPriorIDOR(t, get.Identity(), []string{"user_id"}),
			mustPriorIDOR(t, twin.Identity(), []string{"user_id"}),
			mustPriorAuthz(t, get.Identity()),
		},
		GraphView: stubGraph{path: hostPaths(get, twin)},
		Logger:    &recLogger{},
		Clock:     testClock,
	}
	gotTwin, err := workflowStateTransitionDetector(context.Background(), dctxTwin)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if gotTwin != nil {
		t.Fatalf("pagination twins emitted %d findings, want nil (same method+path collapses)", len(gotTwin))
	}
}

func TestBizlogicQuietDirectTable(t *testing.T) {
	a := mustEndpoint(t, "GET", "https://www.example.com/cart?user_id=1")
	b := mustEndpoint(t, "GET", "https://www.example.com/checkout?user_id=1")
	c := mustEndpoint(t, "GET", "https://api.example.com/cart?user_id=1")
	hostPaths := func(eps ...asset.Endpoint) func(from, to asset.Identity) []asset.Identity {
		byID := make(map[asset.Identity]asset.Endpoint)
		for _, ep := range eps {
			byID[ep.Identity()] = ep
		}
		return func(from, to asset.Identity) []asset.Identity {
			ep, ok := byID[to]
			if !ok {
				return nil
			}
			if from == hostIdentityOf(endpointHost(ep.URL.HostPort)) {
				return []asset.Identity{from, to}
			}
			return nil
		}
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
	fullPriors := []asset.Finding{
		mustPriorIDOR(t, a.Identity(), []string{"user_id"}),
		mustPriorIDOR(t, b.Identity(), []string{"user_id"}),
		mustPriorAuthz(t, a.Identity()),
	}
	cases := []struct {
		name      string
		endpoints []asset.Endpoint
		priors    []asset.Finding
		graph     detect.GraphQuerier
	}{
		{"nil-graph", []asset.Endpoint{a, b}, fullPriors, nil},
		{"empty-priors", []asset.Endpoint{a, b}, nil, stubGraph{path: hostPaths(a, b)}},
		{"no-T1", []asset.Endpoint{a, b},
			[]asset.Finding{mustPriorAuthz(t, a.Identity())},
			stubGraph{path: hostPaths(a, b)}},
		{"no-A1", []asset.Endpoint{a, b},
			[]asset.Finding{
				mustPriorIDOR(t, a.Identity(), []string{"user_id"}),
				mustPriorIDOR(t, b.Identity(), []string{"user_id"}),
			},
			stubGraph{path: hostPaths(a, b)}},
		{"single-endpoint", []asset.Endpoint{a},
			[]asset.Finding{
				mustPriorIDOR(t, a.Identity(), []string{"user_id"}),
				mustPriorAuthz(t, a.Identity()),
			},
			stubGraph{path: hostPaths(a)}},
		{"pagination", []asset.Endpoint{a, mustEndpoint(t, "GET", "https://www.example.com/cart?user_id=1&page=2")},
			[]asset.Finding{
				mustPriorIDOR(t, a.Identity(), []string{"user_id"}),
				mustPriorIDOR(t, mustEndpoint(t, "GET", "https://www.example.com/cart?user_id=1&page=2").Identity(), []string{"user_id"}),
				mustPriorAuthz(t, a.Identity()),
			},
			stubGraph{path: hostPaths(a, mustEndpoint(t, "GET", "https://www.example.com/cart?user_id=1&page=2"))}},
		{"cross-host", []asset.Endpoint{a, c}, fullPriors, stubGraph{path: hostPaths(a, c)}},
		{"graphql-rest-mix", []asset.Endpoint{
			mustEndpoint(t, "GET", "https://www.example.com/graphql?user_id=1"),
			mustEndpoint(t, "GET", "https://www.example.com/users?user_id=1"),
		},
			[]asset.Finding{
				mustPriorIDOR(t, mustEndpoint(t, "GET", "https://www.example.com/graphql?user_id=1").Identity(), []string{"user_id"}),
				mustPriorIDOR(t, mustEndpoint(t, "GET", "https://www.example.com/users?user_id=1").Identity(), []string{"user_id"}),
				mustPriorAuthz(t, mustEndpoint(t, "GET", "https://www.example.com/graphql?user_id=1").Identity()),
			},
			stubGraph{path: hostPaths(
				mustEndpoint(t, "GET", "https://www.example.com/graphql?user_id=1"),
				mustEndpoint(t, "GET", "https://www.example.com/users?user_id=1"))}},
		{"js-hub-no-token", []asset.Endpoint{a, b},
			[]asset.Finding{mustPriorIDOR(t, mustEndpoint(t, "GET", "https://other.example.com/x?user_id=1").Identity(), []string{"user_id"})},
			stubGraph{path: hostPaths(a, b)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := workflowStateTransitionDetector(context.Background(), directCtx(tc.endpoints, tc.priors, tc.graph))
			if err != nil {
				t.Fatalf("detector error: %v", err)
			}
			if got != nil {
				t.Fatalf("fail-open quiet violated: got %d findings, want nil", len(got))
			}
		})
	}
}

func TestBizlogicQuietEngineVariants(t *testing.T) {
	reg := registerTriageAuthzBizlogic(t)
	run := func(snap detect.Snapshot) detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		rep, err := detect.Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}
	t.Run("single-endpoint", func(t *testing.T) {
		only := mustEndpoint(t, "GET", "https://www.example.com/solo?user_id=1")
		rep := run(detect.Snapshot{Endpoints: []asset.Endpoint{only}})
		if got := bizlogicFindings(rep); len(got) != 0 {
			t.Fatalf("single-endpoint bizlogic findings %d, want 0", len(got))
		}
	})
	t.Run("pagination", func(t *testing.T) {
		p1 := mustEndpoint(t, "GET", "https://www.example.com/cart?user_id=1&page=1")
		p2 := mustEndpoint(t, "GET", "https://www.example.com/cart?user_id=1&page=2")
		wwwHost := mustHost(t, "www.example.com")
		rep := run(detect.Snapshot{
			Assets:        []asset.Identity{wwwHost.Identity()},
			Relationships: append(hostChain(t, wwwHost, p1), hostChain(t, wwwHost, p2)...),
			Endpoints:     []asset.Endpoint{p1, p2},
		})
		if got := bizlogicFindings(rep); len(got) != 0 {
			t.Fatalf("pagination bizlogic findings %d, want 0", len(got))
		}
	})
	t.Run("cross-host", func(t *testing.T) {
		x := mustEndpoint(t, "GET", "https://www.example.com/cart?user_id=1")
		y := mustEndpoint(t, "GET", "https://api.example.com/cart?user_id=1")
		rep := run(detect.Snapshot{Endpoints: []asset.Endpoint{x, y}})
		if got := bizlogicFindings(rep); len(got) != 0 {
			t.Fatalf("cross-host bizlogic findings %d, want 0", len(got))
		}
	})
	t.Run("graphql-rest-mix", func(t *testing.T) {
		g := mustEndpoint(t, "GET", "https://mix.example.com/graphql?user_id=1")
		u := mustEndpoint(t, "GET", "https://mix.example.com/users?user_id=1")
		peer := mustEndpoint(t, "GET", "https://api.example.com/peer?user_id=1")
		mixHost := mustHost(t, "mix.example.com")
		apiHost := mustHost(t, "api.example.com")
		tech := mustTechnology(t, "keycloak", asset.CategoryAuthentication)
		rels := append(hostChain(t, mixHost, g), hostChain(t, mixHost, u)...)
		rels = append(rels, mustRelationship(t, apiHost.Identity(), asset.RelationshipHostToTechnology, tech.Identity()))
		rep := run(detect.Snapshot{
			Assets:        []asset.Identity{mixHost.Identity(), apiHost.Identity()},
			Relationships: rels,
			Technologies:  []asset.Technology{tech},
			Endpoints:     []asset.Endpoint{g, u, peer},
		})
		if got := bizlogicFindings(rep); len(got) != 0 {
			t.Fatalf("graphql-rest-mix bizlogic findings %d, want 0", len(got))
		}
	})
}

func TestBizlogicNoDirectURLMining(t *testing.T) {
	// N4: both endpoint URLs carry ?user_id=, but only one side has a
	// triage prior. The unpriored URL must never be mined into
	// participation — no pair, no finding.
	a := mustEndpoint(t, "GET", "https://www.example.com/cart?user_id=1")
	b := mustEndpoint(t, "GET", "https://www.example.com/checkout?user_id=1")
	byID := map[asset.Identity]asset.Endpoint{a.Identity(): a, b.Identity(): b}
	gv := stubGraph{
		path: func(from, to asset.Identity) []asset.Identity {
			ep, ok := byID[to]
			if !ok {
				return nil
			}
			if from == hostIdentityOf(endpointHost(ep.URL.HostPort)) {
				return []asset.Identity{from, to}
			}
			return nil
		},
	}
	dctx := &detect.Context{
		Endpoints: []asset.Endpoint{a, b},
		PriorFindings: []asset.Finding{
			mustPriorIDOR(t, a.Identity(), []string{"user_id"}),
			mustPriorAuthz(t, a.Identity()),
		},
		GraphView: gv,
		Logger:    &recLogger{},
		Clock:     testClock,
	}
	got, err := workflowStateTransitionDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if got != nil {
		t.Fatalf("URL-mined findings %d, want nil (triage-flagged params only)", len(got))
	}
}

func TestBizlogicPrecedenceShadowRecovery(t *testing.T) {
	// ?doc= is primary triage.ssrf under overlap precedence (SSRF > IDOR):
	// the triage.idor rule never flags it, but the ssrf finding's
	// all_classes carries the idor token — recovery must count it.
	a := mustEndpoint(t, "GET", "https://www.example.com/docs?doc=1")
	b := mustEndpoint(t, "GET", "https://www.example.com/edit?doc=1")
	byID := map[asset.Identity]asset.Endpoint{a.Identity(): a, b.Identity(): b}
	gv := stubGraph{
		path: func(from, to asset.Identity) []asset.Identity {
			ep, ok := byID[to]
			if !ok {
				return nil
			}
			if from == hostIdentityOf(endpointHost(ep.URL.HostPort)) {
				return []asset.Identity{from, to}
			}
			return nil
		},
	}
	priors := []asset.Finding{
		mustPriorShadow(t, "triage.ssrf", "ssrf", a.Identity(), []string{"doc"}, "idor,ssrf"),
		mustPriorShadow(t, "triage.ssrf", "ssrf", b.Identity(), []string{"doc"}, "idor,ssrf"),
		mustPriorAuthz(t, a.Identity()),
	}
	dctx := &detect.Context{
		Endpoints:     []asset.Endpoint{a, b},
		PriorFindings: priors,
		GraphView:     gv,
		Logger:        &recLogger{},
		Clock:         testClock,
	}
	got, err := workflowStateTransitionDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("shadow-recovery findings %d, want 1", len(got))
	}
	if got[0].Metadata["shared_token"] != "doc" {
		t.Fatalf("shared_token %q, want doc", got[0].Metadata["shared_token"])
	}
	if got[0].Metadata["triage_rule"] != "triage.idor" {
		t.Fatalf("triage_rule %q, want triage.idor (T1 only)", got[0].Metadata["triage_rule"])
	}
	// Negative: same ssrf priors WITHOUT the idor token must not recover.
	priorsNoToken := []asset.Finding{
		mustPriorFinding(t, "triage.ssrf", "Triage ssrf", detect.CategoryInformation.String(), a.Identity(), "triage",
			map[string]string{"signal": "triage_ssrf", "triage_class": "ssrf", "params": "doc"}, 0.6),
		mustPriorFinding(t, "triage.ssrf", "Triage ssrf", detect.CategoryInformation.String(), b.Identity(), "triage",
			map[string]string{"signal": "triage_ssrf", "triage_class": "ssrf", "params": "doc"}, 0.6),
		mustPriorAuthz(t, a.Identity()),
	}
	dctx2 := &detect.Context{
		Endpoints:     []asset.Endpoint{a, b},
		PriorFindings: priorsNoToken,
		GraphView:     gv,
		Logger:        &recLogger{},
		Clock:         testClock,
	}
	got2, err := workflowStateTransitionDetector(context.Background(), dctx2)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if got2 != nil {
		t.Fatalf("tokenless priors emitted %d findings, want nil", len(got2))
	}
}

func TestBizlogicOpportunisticClassSignals(t *testing.T) {
	// Apis-graded graphql via prior (no /graphql path): mixed with a REST
	// step on the same host — the opportunistic signal alone quiets the flow.
	rest := mustEndpoint(t, "GET", "https://www.example.com/api/data?user_id=1")
	gql := mustEndpoint(t, "GET", "https://www.example.com/api/other?user_id=1")
	byID := map[asset.Identity]asset.Endpoint{rest.Identity(): rest, gql.Identity(): gql}
	gv := stubGraph{
		path: func(from, to asset.Identity) []asset.Identity {
			ep, ok := byID[to]
			if !ok {
				return nil
			}
			if from == hostIdentityOf(endpointHost(ep.URL.HostPort)) {
				return []asset.Identity{from, to}
			}
			return nil
		},
	}
	dctx := &detect.Context{
		Endpoints: []asset.Endpoint{rest, gql},
		PriorFindings: []asset.Finding{
			mustPriorIDOR(t, rest.Identity(), []string{"user_id"}),
			mustPriorIDOR(t, gql.Identity(), []string{"user_id"}),
			mustPriorGraphQL(t, gql.Identity()),
			mustPriorAuthz(t, rest.Identity()),
		},
		GraphView: gv,
		Logger:    &recLogger{},
		Clock:     testClock,
	}
	got, err := workflowStateTransitionDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if got != nil {
		t.Fatalf("apis-graded mix emitted %d findings, want nil", len(got))
	}
	// Web-graded robots surface never joins: the robots endpoint is
	// excluded, leaving a singleton that stays quiet.
	robot := mustEndpoint(t, "GET", "https://www.example.com/robots.txt?user_id=1")
	byID2 := map[asset.Identity]asset.Endpoint{rest.Identity(): rest, robot.Identity(): robot}
	gv2 := stubGraph{
		path: func(from, to asset.Identity) []asset.Identity {
			ep, ok := byID2[to]
			if !ok {
				return nil
			}
			if from == hostIdentityOf(endpointHost(ep.URL.HostPort)) {
				return []asset.Identity{from, to}
			}
			return nil
		},
	}
	dctx2 := &detect.Context{
		Endpoints: []asset.Endpoint{rest, robot},
		PriorFindings: []asset.Finding{
			mustPriorIDOR(t, rest.Identity(), []string{"user_id"}),
			mustPriorIDOR(t, robot.Identity(), []string{"user_id"}),
			mustPriorRobots(t, robot.Identity()),
			mustPriorAuthz(t, rest.Identity()),
		},
		GraphView: gv2,
		Logger:    &recLogger{},
		Clock:     testClock,
	}
	got2, err := workflowStateTransitionDetector(context.Background(), dctx2)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if got2 != nil {
		t.Fatalf("robots-surfaced pair emitted %d findings, want nil", len(got2))
	}
}

func TestBizlogicCap256Truncation(t *testing.T) {
	// 300 same-token 2-step flows on distinct hosts: the rule keeps 256
	// with subjects_dropped=44, truncated=true, and a LevelWarn log —
	// never silent.
	var endpoints []asset.Endpoint
	var priors []asset.Finding
	byID := make(map[asset.Identity]asset.Endpoint)
	for i := 0; i < 300; i++ {
		a := mustEndpoint(t, "GET", fmt.Sprintf("https://h-%03d.example.com/a?id=1", i))
		b := mustEndpoint(t, "GET", fmt.Sprintf("https://h-%03d.example.com/b?id=1", i))
		endpoints = append(endpoints, a, b)
		byID[a.Identity()] = a
		byID[b.Identity()] = b
		priors = append(priors,
			mustPriorIDOR(t, a.Identity(), []string{"id"}),
			mustPriorIDOR(t, b.Identity(), []string{"id"}),
			mustPriorAuthz(t, a.Identity()),
		)
	}
	logger := &recLogger{}
	dctx := &detect.Context{
		Endpoints:     endpoints,
		PriorFindings: priors,
		GraphView: stubGraph{
			path: func(from, to asset.Identity) []asset.Identity {
				ep, ok := byID[to]
				if !ok {
					return nil
				}
				if from == hostIdentityOf(endpointHost(ep.URL.HostPort)) {
					return []asset.Identity{from, to}
				}
				return nil
			},
		},
		Logger: logger,
		Clock:  testClock,
	}
	got, err := workflowStateTransitionDetector(context.Background(), dctx)
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
		if f.Confidence != 0.5 {
			t.Fatalf("confidence %v, want 0.5 (all 2-step)", f.Confidence)
		}
	}
	if !logger.has(ruleWorkflowStateTransition, detect.LevelWarn, "truncated 44 subjects over bound 256") {
		t.Fatalf("missing LevelWarn truncation log")
	}
}

func TestBizlogicLongFlowSkipped(t *testing.T) {
	// 9 same-host steps sharing one token: over maxFlowSteps — skipped
	// with a LevelInfo count, never truncated into a shorter flow.
	var endpoints []asset.Endpoint
	var priors []asset.Finding
	byID := make(map[asset.Identity]asset.Endpoint)
	for i := 0; i < 9; i++ {
		ep := mustEndpoint(t, "GET", fmt.Sprintf("https://www.example.com/step%d?id=1", i))
		endpoints = append(endpoints, ep)
		byID[ep.Identity()] = ep
		priors = append(priors, mustPriorIDOR(t, ep.Identity(), []string{"id"}))
	}
	priors = append(priors, mustPriorAuthz(t, endpoints[0].Identity()))
	logger := &recLogger{}
	dctx := &detect.Context{
		Endpoints:     endpoints,
		PriorFindings: priors,
		GraphView: stubGraph{
			path: func(from, to asset.Identity) []asset.Identity {
				ep, ok := byID[to]
				if !ok {
					return nil
				}
				if from == hostIdentityOf(endpointHost(ep.URL.HostPort)) {
					return []asset.Identity{from, to}
				}
				return nil
			},
		},
		Logger: logger,
		Clock:  testClock,
	}
	got, err := workflowStateTransitionDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("detector error: %v", err)
	}
	if got != nil {
		t.Fatalf("long flow emitted %d findings, want nil (skipped, never truncated)", len(got))
	}
	if !logger.has(ruleWorkflowStateTransition, detect.LevelInfo, "skipped 1 long/over-wide flows (never truncated)") {
		t.Fatalf("missing LevelInfo long-flow skip log")
	}
}

func TestBizlogicCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerTriageAuthzBizlogic(t)
	snap, step1, _ := buildFlowSnapshot(t)
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
	coldBiz := bizlogicFindings(cold)
	if len(coldBiz) != 1 {
		t.Fatalf("cold bizlogic findings %d, want 1", len(coldBiz))
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
	// Metadata-only prior change (reflection verdict on the step1 URL):
	// the triage prior gains reflection_backed without an identity change.
	// The rule key's snapshot fingerprint covers evidence, so the engine
	// honestly RECOMPUTES every rule (CacheHits 0) — and the bizlogic
	// output is byte-identical to cold: the rule reads prior identities
	// and flagged params only, never reflection verdicts. The identity-only
	// graph_digest property (a metadata-only prior change alone would not
	// alter the digest) is DOCUMENTED on the detector, not fixed here:
	// through the engine it is unreachable, because any snapshot change
	// already alters the snapshot fingerprint that enters every rule key.
	rev, err := httpprobe.ReflectEvidence(step1.URL.Identity(), "user_id", httpprobe.ReflectUnencoded)
	if err != nil {
		t.Fatalf("ReflectEvidence: %v", err)
	}
	snapMeta := snap
	snapMeta.Evidence = append(append([]asset.Evidence{}, snap.Evidence...), rev)
	cfgMeta := detect.DefaultEngineConfig(reg)
	cfgMeta.Cache = fs
	cfgMeta.Clock = testClock
	repMeta, err := detect.Run(context.Background(), cfgMeta, snapMeta)
	if err != nil {
		t.Fatalf("metadata-change Run: %v", err)
	}
	if repMeta.CacheHits != 0 {
		t.Fatalf("metadata-change hits %d, want 0 (snapshot fingerprint covers evidence: honest recompute)", repMeta.CacheHits)
	}
	metaBiz := bizlogicFindings(repMeta)
	if len(metaBiz) != len(coldBiz) {
		t.Fatalf("metadata-change bizlogic findings %d, want %d (output insensitive to the metadata change)", len(metaBiz), len(coldBiz))
	}
	coldJSON, _ := json.Marshal(coldBiz)
	metaJSON, _ := json.Marshal(metaBiz)
	if string(coldJSON) != string(metaJSON) {
		t.Fatalf("metadata-change bizlogic output drifted:\ncold %s\nmeta %s", coldJSON, metaJSON)
	}
	// Identity-change recompute: a new same-host step pair on a new host
	// (with its own auth peer) changes prior identities, so the bizlogic
	// record recomputes instead of serving stale.
	snap2 := snap
	n1 := mustEndpoint(t, "GET", "https://new.example.com/n1?id=1")
	n2 := mustEndpoint(t, "GET", "https://new.example.com/n2?id=1")
	n3 := mustEndpoint(t, "GET", "https://auth2.example.com/n3?id=1")
	newHost := mustHost(t, "new.example.com")
	auth2Host := mustHost(t, "auth2.example.com")
	auth2Tech := mustTechnology(t, "keycloak", asset.CategoryAuthentication)
	snap2.Endpoints = append(append([]asset.Endpoint{}, snap.Endpoints...), n1, n2, n3)
	snap2.Assets = append(append([]asset.Identity{}, snap.Assets...), newHost.Identity(), auth2Host.Identity())
	snap2.Relationships = append(append([]asset.Relationship{}, snap.Relationships...),
		append(hostChain(t, newHost, n1), hostChain(t, newHost, n2)...)...)
	snap2.Relationships = append(snap2.Relationships,
		mustRelationship(t, auth2Host.Identity(), asset.RelationshipHostToTechnology, auth2Tech.Identity()))
	snap2.Technologies = append(append([]asset.Technology{}, snap.Technologies...), auth2Tech)
	cfg3 := detect.DefaultEngineConfig(reg)
	cfg3.Cache = fs
	cfg3.Clock = testClock
	warm2, err := detect.Run(context.Background(), cfg3, snap2)
	if err != nil {
		t.Fatalf("recompute Run: %v", err)
	}
	if got := bizlogicFindings(warm2); len(got) != 2 {
		t.Fatalf("recompute bizlogic findings %d, want 2 (old + new flow)", len(got))
	}
}

func TestBizlogicOrderingDepSkip(t *testing.T) {
	// A failing level-1 authz rule (stub with the same rule ID — the
	// dependency contract keys on the ID string) must dep-skip bizlogic
	// with the honest dependency reason and zero findings.
	stubAuthz := detect.Rule{
		ID:            "authz.idor.insecure-direct-object",
		Name:          "Authz IDOR Stub",
		Description:   "Synthetic failing authz.idor for the bizlogic dep-skip test",
		Category:      detect.CategoryAuthorization,
		Version:       "9.9.9",
		Inputs:        []detect.RuleInput{detect.InputEndpoints},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "bizlogic-test",
		Enabled:       true,
		Detector: func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
			return nil, fmt.Errorf("synthetic authz.idor failure")
		},
	}
	bizlogicRules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	reg := detect.NewRegistry()
	if err := reg.Register(stubAuthz); err != nil {
		t.Fatalf("Register stub: %v", err)
	}
	for _, r := range bizlogicRules {
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register(%q): %v", r.ID, err)
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	reg.Seal()
	snap, _, _ := buildFlowSnapshot(t)
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
	if statuses["authz.idor.insecure-direct-object"].Status != detect.RuleStatusFailed {
		t.Fatalf("authz status %s, want failed (stub)", statuses["authz.idor.insecure-direct-object"].Status)
	}
	bizRes := statuses[ruleWorkflowStateTransition]
	if bizRes.Status != detect.RuleStatusSkipped {
		t.Fatalf("bizlogic status %s, want skipped (dep did not complete)", bizRes.Status)
	}
	if !strings.Contains(bizRes.SkipReason, `dependency "authz.idor.insecure-direct-object" did not complete`) {
		t.Fatalf("bizlogic skip reason %q, want dependency reason", bizRes.SkipReason)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("dep-skip run findings %d, want 0", len(rep.Findings))
	}
	// Empty snapshot: every rule census-skips, zero findings.
	reg2 := registerTriageAuthzBizlogic(t)
	cfg2 := detect.DefaultEngineConfig(reg2)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, detect.Snapshot{})
	if err != nil {
		t.Fatalf("Run empty: %v", err)
	}
	if rep2.Skipped != 14 {
		t.Fatalf("empty corpus: skipped %d, want 14 (8 triage + 3 apis + 2 authz + 1 bizlogic)", rep2.Skipped)
	}
	if len(rep2.Findings) != 0 {
		t.Fatalf("empty corpus findings %d, want 0", len(rep2.Findings))
	}
}

func TestBizlogicDetectorHonorsContext(t *testing.T) {
	reg := registerTriageAuthzBizlogic(t)
	snap, _, _ := buildFlowSnapshot(t)
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

func TestBizlogicDisabledConfig(t *testing.T) {
	reg := registerTriageAuthzBizlogic(t)
	snap, _, _ := buildFlowSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	cfg.Config = map[string]string{ruleWorkflowStateTransition + ".disabled": "true"}
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Pack convention: ".disabled" is detector-quiet (completed, no
	// findings), not an engine skip.
	for _, r := range rep.Rules {
		if r.RuleID == ruleWorkflowStateTransition && r.Status != detect.RuleStatusCompleted {
			t.Fatalf("disabled bizlogic status %s, want completed (quiet)", r.Status)
		}
	}
	if got := bizlogicFindings(rep); len(got) != 0 {
		t.Fatalf("disabled bizlogic findings %d, want 0", len(got))
	}
}

func TestBizlogicDeterminismGolden(t *testing.T) {
	reg := registerTriageAuthzBizlogic(t)
	snap, _, _ := buildFlowSnapshot(t)
	// Mixed corpus: the emitting flow plus decoys that must stay quiet —
	// a pagination-twin pair isolated on its own host (collapse, not
	// reachability, decides it), a safe endpoint, a cross-domain
	// singleton, and a graphql-mix pair with full paths (the mix gate
	// decides it).
	twinHost := mustHost(t, "twin.example.com")
	twin1 := mustEndpoint(t, "GET", "https://twin.example.com/cart?user_id=1&page=1")
	twin2 := mustEndpoint(t, "GET", "https://twin.example.com/cart?user_id=1&page=2")
	safe := mustEndpoint(t, "GET", "https://www.example.com/health?zzz=1")
	xdom := mustEndpoint(t, "GET", "https://api.other.com/profile?user_id=1")
	gql := mustEndpoint(t, "GET", "https://mix.example.com/graphql?user_id=1")
	rest := mustEndpoint(t, "GET", "https://mix.example.com/users?user_id=1")
	mixHost := mustHost(t, "mix.example.com")
	snap.Endpoints = append(snap.Endpoints, twin1, twin2, safe, xdom, gql, rest)
	snap.Assets = append(snap.Assets, twinHost.Identity(), mixHost.Identity())
	snap.Relationships = append(snap.Relationships, hostChain(t, twinHost, twin1)...)
	snap.Relationships = append(snap.Relationships, hostChain(t, twinHost, twin2)...)
	snap.Relationships = append(snap.Relationships, hostChain(t, mixHost, gql)...)
	snap.Relationships = append(snap.Relationships, hostChain(t, mixHost, rest)...)
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
	if got := bizlogicFindings(rep1); len(got) != 1 {
		t.Fatalf("golden corpus bizlogic findings %d, want 1 (decoys quiet)", len(got))
	}
	golden.Compare(t, "testdata/bizlogic_report.golden", b1)
}

func TestBizlogicRequiredAssetTypesSkipHonestly(t *testing.T) {
	reg := registerTriageAuthzBizlogic(t)
	host := mustHost(t, "www.example.com")
	snap := detect.Snapshot{Assets: []asset.Identity{host.Identity()}}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run host-only: %v", err)
	}
	for _, r := range rep.Rules {
		if r.RuleID == ruleWorkflowStateTransition {
			if r.Status != detect.RuleStatusSkipped {
				t.Fatalf("bizlogic status %s, want skipped (no endpoint)", r.Status)
			}
			if !strings.Contains(r.SkipReason, "required asset kind") {
				t.Fatalf("bizlogic skip reason %q", r.SkipReason)
			}
		}
	}
}
