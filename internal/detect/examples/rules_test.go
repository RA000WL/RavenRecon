package examples

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// fixedClock pins Now to a constant and fires After in real time — the same
// shape the engine's own determinism test uses — so the pack's reports are
// byte-for-byte reproducible under an injected Clock. It is stateless, so it
// is safe for concurrent use by the engine's workers.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time                         { return c.at }
func (c fixedClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// packConfig is the configuration every pipeline test run uses; it exercises
// the audit rule's config reading (the detail flag adds one log line per
// secret type).
var packConfig = map[string]string{"example.audit_detail": "true"}

// buildSnapshot returns the pack test corpus: at least one entry per Context
// domain, mirroring the fixture style of the detect package's own tests
// minus the testing.TB dependency (every error is returned). The
// https://www.example.com/api URL is deliberately NOT carried as an asset:
// the endpoint-coverage rule must then stay silent about it as a related
// asset (the observed-corpus rule).
func buildSnapshot() (detect.Snapshot, error) {
	prov := asset.Provenance{Source: "examples-test"}

	domain, err := asset.NewDomain("example.com", prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	host, err := asset.NewHost("www.example.com", prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	ip, err := asset.NewIP("192.0.2.1", prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	base, err := asset.ParseURL("https://www.example.com/", prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	login, err := asset.ParseURL("https://www.example.com/login", prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	api, err := asset.ParseURL("https://www.example.com/api", prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	script, err := asset.NewJavaScript("https://www.example.com/app.js", prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	tech, err := asset.NewTechnology("nginx", asset.CategoryServer, prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	ev, err := asset.NewEvidence(asset.MethodHeader, "header:server", "nginx", base.Identity(), prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	secret, err := asset.NewSecretCandidate(asset.SecretTypeJWT,
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.signature", script.Identity(), prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	endpointLogin, err := asset.NewEndpoint("GET", login.String(), prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	endpointAPI, err := asset.NewEndpoint("POST", api.String(), prov)
	if err != nil {
		return detect.Snapshot{}, err
	}
	relHostIP, err := asset.NewRelationship(host.Identity(), asset.RelationshipHostToIP, ip.Identity())
	if err != nil {
		return detect.Snapshot{}, err
	}
	relHostURL, err := asset.NewRelationship(host.Identity(), asset.RelationshipHostToURL, base.Identity())
	if err != nil {
		return detect.Snapshot{}, err
	}
	relURLToEP, err := asset.NewRelationship(base.Identity(), asset.RelationshipURLToEndpoint, endpointLogin.Identity())
	if err != nil {
		return detect.Snapshot{}, err
	}

	return detect.Snapshot{
		Assets: []asset.Identity{
			domain.Identity(), host.Identity(), ip.Identity(), base.Identity(), login.Identity(),
		},
		Relationships: []asset.Relationship{relHostIP, relHostURL, relURLToEP},
		Evidence:      []asset.Evidence{ev},
		Technologies:  []asset.Technology{tech},
		Secrets:       []asset.SecretCandidate{secret},
		JavaScript:    []asset.JavaScript{script},
		Endpoints:     []asset.Endpoint{endpointLogin, endpointAPI},
	}, nil
}

// registerPack registers every pack rule into a fresh registry and returns
// it, sealed, after full validation.
func registerPack(t *testing.T) *detect.Registry {
	t.Helper()
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
	if err := reg.Validate(); err != nil {
		t.Fatalf("registry Validate: %v", err)
	}
	reg.Seal()
	return reg
}

// TestPackRulesValidate registers every pack rule through the exported SDK:
// ValidateRule per rule, then Register + Registry.Validate for the pack as a
// graph (the dependency pair is what Validate checks). It also pins the
// content policy: "example." IDs and information/discovery categories only.
func TestPackRulesValidate(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 6 {
		t.Fatalf("pack carries %d rules, want 6", len(rules))
	}

	reg := detect.NewRegistry()
	for _, r := range rules {
		if !strings.HasPrefix(r.ID, "example.") {
			t.Fatalf("rule %q violates the ID policy (example. prefix)", r.ID)
		}
		if r.Category != detect.CategoryInformation && r.Category != detect.CategoryDiscovery {
			t.Fatalf("rule %q category %q violates the content policy", r.ID, r.Category)
		}
		if !r.Enabled {
			t.Fatalf("rule %q must be enabled", r.ID)
		}
		if err := detect.ValidateRule(r); err != nil {
			t.Fatalf("ValidateRule(%q): %v", r.ID, err)
		}
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register(%q): %v", r.ID, err)
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("registry Validate: %v", err)
	}
	if reg.Len() != 6 {
		t.Fatalf("registry holds %d rules, want 6", reg.Len())
	}

	// The dependency pair ships entirely inside the pack.
	dependent := ""
	for _, r := range rules {
		if len(r.Dependencies) == 1 && r.Dependencies[0] == ruleAssetsCensus {
			dependent = r.ID
		}
	}
	if dependent != ruleDegreeIndex {
		t.Fatalf("expected %q to depend on %q, found %q", ruleDegreeIndex, ruleAssetsCensus, dependent)
	}
}

// TestPackFullPipelineWithCache runs the pack end to end with a real cache:
// register -> validate -> seal -> cold run -> warm run. The cold run
// executes every rule fresh; the warm run must be served entirely from the
// cache (cache-before-execute), including the audit rule's EMPTY result —
// an empty hit is a hit.
func TestPackFullPipelineWithCache(t *testing.T) {
	snap, err := buildSnapshot()
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	reg := registerPack(t)

	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Cache = fs
	cfg.Clock = fixedClock{at: time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)}
	cfg.Config = packConfig

	cold, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("cold Run: %v", err)
	}
	assertColdRunShape(t, cold)
	if cold.CacheHits != 0 {
		t.Fatalf("cold run served %d cache hits, want 0", cold.CacheHits)
	}

	warm, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("warm Run: %v", err)
	}
	if warm.CacheHits != 6 {
		t.Fatalf("warm run served %d cache hits, want 6 (every deterministic rule)", warm.CacheHits)
	}
	for _, r := range warm.Rules {
		if !r.Cached {
			t.Fatalf("rule %q was not served from the cache on the warm run", r.RuleID)
		}
	}
	// The warm findings are identical to the cold findings (same identities,
	// same order).
	if len(warm.Findings) != len(cold.Findings) {
		t.Fatalf("warm findings %d differ from cold findings %d", len(warm.Findings), len(cold.Findings))
	}
	for i := range warm.Findings {
		if warm.Findings[i].ID() != cold.Findings[i].ID() {
			t.Fatalf("warm finding %d %s differs from cold %s", i, warm.Findings[i].ID(), cold.Findings[i].ID())
		}
	}
}

// assertColdRunShape pins the pack's deterministic output shape: every rule
// completes, the per-rule finding counts match the matrix, the endpoint
// coverage rule cites only observed URLs, and the audit rule's log lines
// surface on the report.
func assertColdRunShape(t *testing.T, rep detect.Report) {
	t.Helper()
	if rep.Outcome != detect.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed: %+v", rep.Outcome, rep)
	}
	if rep.Completed != 6 || rep.Failed != 0 || rep.Cancelled != 0 || rep.Skipped != 0 {
		t.Fatalf("status counts wrong: completed %d failed %d cancelled %d skipped %d",
			rep.Completed, rep.Failed, rep.Cancelled, rep.Skipped)
	}
	if len(rep.Findings) != 12 {
		t.Fatalf("findings %d, want 12", len(rep.Findings))
	}

	want := map[string]int{
		ruleAssetsCensus:    4, // domain, host, ip, url kinds present
		ruleDegreeIndex:     4, // host, ip, base url, login endpoint nodes
		ruleMethodInventory: 1, // one detection method: header
		ruleTechListing:     1, // one technology: nginx
		ruleEndpointCover:   2, // GET /login and POST /api
		ruleAuditSummary:    0, // empty output by design
	}
	for _, r := range rep.Rules {
		if r.Status != detect.RuleStatusCompleted {
			t.Fatalf("rule %q status %s, want completed", r.RuleID, r.Status)
		}
		if r.Findings != want[r.RuleID] {
			t.Fatalf("rule %q findings %d, want %d", r.RuleID, r.Findings, want[r.RuleID])
		}
	}

	// The endpoint-coverage rule cites the login URL (observed in the
	// corpus) as a related asset and stays silent about the /api URL (never
	// observed).
	coverage := map[string]asset.Finding{}
	for _, f := range rep.Findings {
		if f.RuleID == ruleEndpointCover {
			coverage[f.Subject.String()] = f
		}
	}
	loginFind, ok := coverage["endpoint:GET https://www.example.com/login"]
	if !ok {
		t.Fatalf("missing endpoint coverage finding for GET /login")
	}
	if len(loginFind.RelatedAssets) != 1 || loginFind.RelatedAssets[0].String() != "url:https://www.example.com/login" {
		t.Fatalf("login finding related assets wrong: %+v", loginFind.RelatedAssets)
	}
	apiFind, ok := coverage["endpoint:POST https://www.example.com/api"]
	if !ok {
		t.Fatalf("missing endpoint coverage finding for POST /api")
	}
	if len(apiFind.RelatedAssets) != 0 {
		t.Fatalf("api finding must cite no unobserved URL: %+v", apiFind.RelatedAssets)
	}

	// The audit rule's log lines surface on the report, deterministically
	// sorted: the summary line, then the per-type detail line.
	if len(rep.Logs) != 2 {
		t.Fatalf("audit rule logged %d entries, want 2: %+v", len(rep.Logs), rep.Logs)
	}
	if rep.Logs[0].Rule != ruleAuditSummary || rep.Logs[0].Level != detect.LevelInfo {
		t.Fatalf("log entry shape wrong: %+v", rep.Logs[0])
	}
	if rep.Logs[0].Message != "secret candidates: 1; types: 1; script assets: 1" {
		t.Fatalf("summary log line wrong: %q", rep.Logs[0].Message)
	}
	if rep.Logs[1].Message != "secret type jwt: 1" {
		t.Fatalf("detail log line wrong: %q", rep.Logs[1].Message)
	}
}

// TestDegreeIndexSkipsUnobservedNodes runs a snapshot whose relationship
// edge cites an identity the corpus never observed through the FULL
// pipeline — validate, register, Run. Such a snapshot is legal (relationships
// are validated for canonical form only, never for endpoint observability),
// but the degree rule must not emit a finding about the unobserved node: the
// engine rejects findings whose subject — and whose evidence source — was
// not observed. The rule therefore emits degree findings ONLY for nodes
// present in the observed corpus.
func TestDegreeIndexSkipsUnobservedNodes(t *testing.T) {
	prov := asset.Provenance{Source: "examples-test"}
	host, err := asset.NewHost("rel.example.com", prov)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	ip, err := asset.NewIP("192.0.2.99", prov)
	if err != nil {
		t.Fatalf("NewIP: %v", err)
	}
	rel, err := asset.NewRelationship(host.Identity(), asset.RelationshipHostToIP, ip.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	// The IP participates in the relationship but is carried in NO corpus
	// domain (not Assets, not Evidence, not Endpoints, ...): a legal
	// snapshot per the framework's canonical-form-only relationship
	// validation.
	snap := detect.Snapshot{
		Assets:        []asset.Identity{host.Identity()},
		Relationships: []asset.Relationship{rel},
	}

	cfg := detect.DefaultEngineConfig(registerPack(t))
	cfg.Clock = fixedClock{at: time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)}
	cfg.Config = packConfig

	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome != detect.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed: %+v", rep.Outcome, rep)
	}
	if rep.Failed != 0 || rep.Cancelled != 0 {
		t.Fatalf("run reports failed %d cancelled %d, want none: %+v", rep.Failed, rep.Cancelled, rep)
	}
	// Pipeline shape: census, degree-index, and method-inventory complete
	// (the latter against an empty evidence domain); the three rules with
	// RequiredAssetTypes are skipped honestly.
	if rep.Completed != 3 || rep.Skipped != 3 {
		t.Fatalf("completed %d skipped %d, want 3 and 3: %+v", rep.Completed, rep.Skipped, rep)
	}

	// Degree findings: exactly the OBSERVED node (the host, out_degree 1
	// via the edge to the unobserved IP); the unobserved IP node is skipped.
	var degree []asset.Finding
	for _, f := range rep.Findings {
		if f.RuleID == ruleDegreeIndex {
			degree = append(degree, f)
		}
	}
	if len(degree) != 1 {
		t.Fatalf("degree findings %d, want 1 (only the observed node): %+v", len(degree), rep.Findings)
	}
	if degree[0].Subject.String() != host.Identity().String() {
		t.Fatalf("degree finding subject %s, want observed host %s", degree[0].Subject, host.Identity())
	}
	if degree[0].Metadata["in_degree"] != "0" || degree[0].Metadata["out_degree"] != "1" {
		t.Fatalf("degree metadata wrong: %+v", degree[0].Metadata)
	}
	for _, r := range rep.Rules {
		if r.RuleID == ruleDegreeIndex && r.Status != detect.RuleStatusCompleted {
			t.Fatalf("degree rule status %s, want completed: %+v", r.Status, r)
		}
		if r.RuleID == ruleAssetsCensus && r.Status != detect.RuleStatusCompleted {
			t.Fatalf("census rule status %s, want completed: %+v", r.Status, r)
		}
	}
}

// TestPackDeterministicReports pins that two identical runs (fixed clock, no
// cache) produce byte-identical reports.
func TestPackDeterministicReports(t *testing.T) {
	snap, err := buildSnapshot()
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(registerPack(t))
		cfg.Clock = fixedClock{at: time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)}
		cfg.Config = packConfig
		rep, err := detect.Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}
	rep1, rep2 := run(), run()
	b1, err := json.Marshal(rep1)
	if err != nil {
		t.Fatalf("marshal rep1: %v", err)
	}
	b2, err := json.Marshal(rep2)
	if err != nil {
		t.Fatalf("marshal rep2: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("identical runs produced different reports")
	}
}

// TestPackUsesOnlyExportedSurface documents the milestone guarantee: this
// pack lives in a SIBLING package of the framework (examples imports detect,
// never the other way around), so the Go compiler itself proves that only
// exported detect symbols are used — there is no special-case code in the
// framework for this pack. This test carries that documentation into the
// runnable suite and pins the exported round-trip: every pack rule's version
// re-parses through the exported parser.
func TestPackUsesOnlyExportedSurface(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	for _, r := range rules {
		if _, _, _, err := detect.ParseRuleVersion(r.Version); err != nil {
			t.Fatalf("rule %q version %q does not parse: %v", r.ID, r.Version, err)
		}
	}
}
