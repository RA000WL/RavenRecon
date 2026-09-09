package web

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
	"github.com/RA000WL/RavenRecon/internal/golden"
)

// fixedClock pins Now to a constant for deterministic reports.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time                         { return c.at }
func (c fixedClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

var testClock = fixedClock{at: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)}

func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "web-test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

func mustURL(t testing.TB, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{Source: "web-test"})
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	return u
}

func mustEvidence(t testing.TB, method asset.DetectionMethod, indicator, value string, source asset.Identity) asset.Evidence {
	t.Helper()
	ev, err := asset.NewEvidence(method, indicator, value, source, asset.Provenance{Source: "web-test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	return ev
}

func mustTechnology(t testing.TB, name string, cat asset.TechnologyCategory) asset.Technology {
	t.Helper()
	tech, err := asset.NewTechnology(name, cat, asset.Provenance{Source: "web-test"})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	return tech
}

func mustEndpoint(t testing.TB, method, rawURL string) asset.Endpoint {
	t.Helper()
	ep, err := asset.NewEndpoint(method, rawURL, asset.Provenance{Source: "web-test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return ep
}

func mustJS(t testing.TB, rawURL string) asset.JavaScript {
	t.Helper()
	js, err := asset.NewJavaScript(rawURL, asset.Provenance{Source: "web-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	return js
}

// buildHostSnapshot returns a minimal corpus with one host (for missing-header rules).
func buildHostSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	host := mustHost(t, "www.example.com")
	return detect.Snapshot{
		Assets: []asset.Identity{host.Identity()},
	}
}

// buildCORSSnapshot returns a corpus with host + wildcard CORS evidence.
func buildCORSSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	host := mustHost(t, "www.example.com")
	ev := mustEvidence(t, asset.MethodHeader, "header:access-control-allow-origin", "*", host.Identity())
	return detect.Snapshot{
		Assets:   []asset.Identity{host.Identity()},
		Evidence: []asset.Evidence{ev},
	}
}

// buildRobotsSnapshot returns a corpus with endpoint /robots.txt.
func buildRobotsSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	host := mustHost(t, "www.example.com")
	ep := mustEndpoint(t, "GET", "https://www.example.com/robots.txt")
	return detect.Snapshot{
		Assets:    []asset.Identity{host.Identity()},
		Endpoints: []asset.Endpoint{ep},
	}
}

// buildSourcemapSnapshot returns a corpus with a .map JavaScript asset.
func buildSourcemapSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	host := mustHost(t, "www.example.com")
	js := mustJS(t, "https://www.example.com/app.js.map")
	return detect.Snapshot{
		Assets:     []asset.Identity{host.Identity()},
		JavaScript: []asset.JavaScript{js},
	}
}

// buildMixedSnapshot returns a corpus that triggers every web rule: host (CSP/HSTS missing),
// wildcard CORS, robots endpoint, and sourcemap JS.
func buildMixedSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	host := mustHost(t, "www.example.com")
	host2 := mustHost(t, "api.example.com")
	ev := mustEvidence(t, asset.MethodHeader, "header:access-control-allow-origin", "*", host.Identity())
	ep := mustEndpoint(t, "GET", "https://www.example.com/robots.txt")
	js := mustJS(t, "https://www.example.com/app.js.map")
	return detect.Snapshot{
		Assets:     []asset.Identity{host.Identity(), host2.Identity()},
		Evidence:   []asset.Evidence{ev},
		Endpoints:  []asset.Endpoint{ep},
		JavaScript: []asset.JavaScript{js},
	}
}

func registerWebPack(t testing.TB) *detect.Registry {
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
		t.Fatalf("Validate: %v", err)
	}
	reg.Seal()
	return reg
}

func TestWebPackCheckAPIVersion(t *testing.T) {
	if err := detect.CheckAPIVersion(2, 0); err != nil {
		t.Fatalf("CheckAPIVersion(2,0): %v", err)
	}
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 5 {
		t.Fatalf("pack carries %d rules, want 5", len(rules))
	}
}

func TestWebPackLoadsThroughSDK(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	reg := detect.NewRegistry()
	for _, r := range rules {
		if err := detect.ValidateRule(r); err != nil {
			t.Fatalf("ValidateRule(%q): %v", r.ID, err)
		}
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register(%q): %v", r.ID, err)
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate graph: %v", err)
	}
	// DeepCopy: mutate original after Register, Get should not reflect it.
	orig := rules[0]
	orig.Inputs[0] = detect.RuleInput("bogus")
	got, ok := reg.Get(orig.ID)
	if !ok {
		t.Fatalf("Get %q missing", orig.ID)
	}
	if got.Inputs[0] == detect.RuleInput("bogus") {
		t.Fatalf("deep copy broken: registered rule mutated through caller alias")
	}
	reg.Seal()
	if err := reg.Register(rules[0]); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("seal not enforced: %v", err)
	}
}

func TestWebPackMetadataDepsCompat(t *testing.T) {
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
		if !r.Category.Valid() {
			t.Fatalf("rule %q category %q invalid", r.ID, r.Category)
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
		if !strings.HasPrefix(r.ID, "web.") {
			t.Fatalf("rule %q ID policy violation", r.ID)
		}
		if len(r.Dependencies) > 0 {
			t.Fatalf("web pack should have no dependencies for now (found on %q)", r.ID)
		}
	}
}

func TestWebPackRequiredAssetTypesSkipHonestly(t *testing.T) {
	reg := registerWebPack(t)
	// Empty snapshot: no host, evidence, endpoint, js → every rule requires something, so all skipped.
	empty := detect.Snapshot{}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, empty)
	if err != nil {
		t.Fatalf("Run empty: %v", err)
	}
	if rep.Skipped != 5 {
		t.Fatalf("empty corpus: skipped %d, want 5 (all rules require asset kinds)", rep.Skipped)
	}
	if rep.Completed != 0 || rep.Failed != 0 {
		t.Fatalf("empty corpus: completed %d failed %d", rep.Completed, rep.Failed)
	}
	for _, r := range rep.Rules {
		if r.Status != detect.RuleStatusSkipped {
			t.Fatalf("rule %q status %s, want skipped", r.RuleID, r.Status)
		}
		if r.SkipReason == "" || !strings.Contains(r.SkipReason, "required asset kind") {
			t.Fatalf("rule %q skip reason %q", r.RuleID, r.SkipReason)
		}
	}
	// Host-only snapshot: CSP and HSTS should complete (they have hosts), CORS/robots/sourcemap skipped.
	hostSnap := buildHostSnapshot(t)
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, hostSnap)
	if err != nil {
		t.Fatalf("Run host: %v", err)
	}
	m := map[string]detect.RuleStatus{}
	for _, r := range rep2.Rules {
		m[r.RuleID] = r.Status
	}
	if m[ruleCSPMissing] != detect.RuleStatusCompleted {
		t.Fatalf("CSP with host: %s", m[ruleCSPMissing])
	}
	if m[ruleHSTSMissing] != detect.RuleStatusCompleted {
		t.Fatalf("HSTS with host: %s", m[ruleHSTSMissing])
	}
	if m[ruleCORSWildcard] != detect.RuleStatusSkipped {
		t.Fatalf("CORS without evidence: %s", m[ruleCORSWildcard])
	}
	if m[ruleRobotsExposed] != detect.RuleStatusSkipped {
		t.Fatalf("robots without endpoint: %s", m[ruleRobotsExposed])
	}
	if m[ruleSourceMapExposed] != detect.RuleStatusSkipped {
		t.Fatalf("sourcemap without js: %s", m[ruleSourceMapExposed])
	}
}

func TestWebPackDetectorsHonorContext(t *testing.T) {
	reg := registerWebPack(t)
	snap := buildHostSnapshot(t)
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

func TestWebPackFailuresIsolated(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	// Inject a panicking rule alongside the web pack.
	panicRule := detect.Rule{
		ID:            "web.test.panic",
		Name:          "Test Panic",
		Description:   "Synthetic panicking rule for isolation test",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "web-test",
		Enabled:       true,
		Detector: func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
			panic("synthetic panic for isolation")
		},
	}
	reg := detect.NewRegistry()
	for _, r := range rules {
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register %q: %v", r.ID, err)
		}
	}
	if err := reg.Register(panicRule); err != nil {
		t.Fatalf("Register panic: %v", err)
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	snap := buildMixedSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Panicking rule must be failed, others completed/skipped, overall outcome failed/incomplete not crashed.
	foundPanic := false
	for _, r := range rep.Rules {
		if r.RuleID == "web.test.panic" {
			foundPanic = true
			if r.Status != detect.RuleStatusFailed {
				t.Fatalf("panic rule status %s, want failed", r.Status)
			}
			if r.Err == nil || !strings.Contains(r.Err.Error(), "panicked") {
				t.Fatalf("panic rule err %v, want panicked", r.Err)
			}
		}
	}
	if !foundPanic {
		t.Fatalf("panic rule missing from report")
	}
	if rep.Failed == 0 {
		t.Fatalf("failed count %d, want >=1", rep.Failed)
	}
	if rep.Outcome == detect.OutcomeCancelled {
		t.Fatalf("outcome cancelled, want failed/incomplete")
	}
	// At least one web pack rule completed (CORS/robots/sourcemap with mixed snapshot)
	if rep.Completed == 0 {
		t.Fatalf("completed %d, want >0 (isolation)", rep.Completed)
	}
}

func TestWebPackCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerWebPack(t)
	snap := buildMixedSnapshot(t)
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
	// Warm run: same registry, same snapshot, same config → cache hits.
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
	for _, r := range warm.Rules {
		if r.Status == detect.RuleStatusCompleted && !r.Cached {
			t.Fatalf("rule %q not cached on warm", r.RuleID)
		}
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
	if warm.FindingsTruncated != cold.FindingsTruncated {
		t.Fatalf("FindingsTruncated drift: warm %v cold %v", warm.FindingsTruncated, cold.FindingsTruncated)
	}
}

func TestWebPackDeterminismGolden(t *testing.T) {
	reg := registerWebPack(t)
	snap := buildMixedSnapshot(t)
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Config = map[string]string{"web.csp.disabled": "false", "web.cors.disabled": "false"}
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
	// Golden pin: deterministic report must match committed golden.
	golden.Compare(t, "testdata/web_report.golden", b1)
}

func TestWebPackCORSRuleEmitsWildcard(t *testing.T) {
	reg := registerWebPack(t)
	snap := buildCORSSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.RuleID == ruleCORSWildcard {
			found = true
			if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
				t.Fatalf("CORS finding priority/status %s/%s", f.Priority, f.Status)
			}
			if f.Category != detect.CategoryMisconfig.String() {
				t.Fatalf("CORS category %s, want misconfiguration", f.Category)
			}
			if len(f.Evidence) == 0 {
				t.Fatalf("CORS finding no evidence")
			}
		}
	}
	if !found {
		t.Fatalf("CORS wildcard finding missing")
	}
}

func TestWebPackRobotsExposed(t *testing.T) {
	reg := registerWebPack(t)
	snap := buildRobotsSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var count int
	for _, f := range rep.Findings {
		if f.RuleID == ruleRobotsExposed {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("robots findings %d, want 1", count)
	}
}

// TestWebPackRobotsTypedCarriersOnly is the NEW-108 precision regression:
// the robots rule fires only on typed carriers — a /robots.txt endpoint, an
// evidence indicator/value naming robots.txt itself, or a technology whose
// name references robots.txt. Bare "robots" substrings (a "robots meta
// tag" observation, a crawler product named "...robots...") must NOT fire.
func TestWebPackRobotsTypedCarriersOnly(t *testing.T) {
	reg := registerWebPack(t)
	run := func(t *testing.T, snap detect.Snapshot) int {
		t.Helper()
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		rep, err := detect.Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		count := 0
		for _, f := range rep.Findings {
			if f.RuleID == ruleRobotsExposed {
				count++
			}
		}
		return count
	}

	t.Run("benign bare-robots carriers stay silent", func(t *testing.T) {
		host := mustHost(t, "www.example.com")
		src := mustHost(t, "api.example.com")
		snap := detect.Snapshot{
			Assets: []asset.Identity{host.Identity()},
			Evidence: []asset.Evidence{
				mustEvidence(t, asset.MethodMeta, "html:meta-robots", "robots meta tag: noindex", src.Identity()),
				mustEvidence(t, asset.MethodHeader, "header:user-agent", "friendly robots walker/1.0", src.Identity()),
			},
			Technologies: []asset.Technology{mustTechnology(t, "CrawlerBots Scanner", asset.CategoryServer)},
		}
		if got := run(t, snap); got != 0 {
			t.Fatalf("robots findings = %d, want 0 for bare-'robots' evidence and technology names", got)
		}
	})

	t.Run("typed robots.txt carriers still fire", func(t *testing.T) {
		host := mustHost(t, "www.example.com")
		snap := detect.Snapshot{
			Assets: []asset.Identity{host.Identity()},
			Evidence: []asset.Evidence{
				mustEvidence(t, asset.MethodHeader, "header:x-robots.txt", "disallowed: /admin", host.Identity()),
			},
			Endpoints: []asset.Endpoint{mustEndpoint(t, "GET", "https://www.example.com/robots.txt")},
		}
		// One finding per distinct subject: the /robots.txt endpoint and the
		// evidence source carrying a robots.txt-named indicator.
		if got := run(t, snap); got != 2 {
			t.Fatalf("robots findings = %d, want 2 (endpoint + typed evidence source)", got)
		}
	})
}

func TestWebPackSourcemapExposed(t *testing.T) {
	reg := registerWebPack(t)
	snap := buildSourcemapSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var count int
	for _, f := range rep.Findings {
		if f.RuleID == ruleSourceMapExposed {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("sourcemap findings %d, want 1", count)
	}
}

func TestWebPackCSPMissing(t *testing.T) {
	reg := registerWebPack(t)
	snap := buildHostSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var cspCount int
	for _, f := range rep.Findings {
		if f.RuleID == ruleCSPMissing {
			cspCount++
			if f.Category != detect.CategoryInformation.String() {
				t.Fatalf("CSP category %s", f.Category)
			}
			if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
				t.Fatalf("CSP finding priority/status %s/%s", f.Priority, f.Status)
			}
		}
	}
	if cspCount != 1 {
		t.Fatalf("CSP findings %d, want 1 (per host)", cspCount)
	}
	// Verify CSP present → no finding.
	host := mustHost(t, "www.example.com")
	prov := asset.Provenance{Source: "web-test"}
	ev := mustEvidence(t, asset.MethodHeader, "header:content-security-policy", "default-src 'self'", host.Identity())
	tech := mustTechnology(t, "content-security-policy", asset.CategoryServer)
	_ = prov
	snap2 := detect.Snapshot{
		Assets:       []asset.Identity{host.Identity()},
		Evidence:     []asset.Evidence{ev},
		Technologies: []asset.Technology{tech},
	}
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, snap2)
	if err != nil {
		t.Fatalf("Run2: %v", err)
	}
	for _, f := range rep2.Findings {
		if f.RuleID == ruleCSPMissing {
			t.Fatalf("CSP finding emitted even though CSP present")
		}
	}
}

func TestWebPackConfigDeterministic(t *testing.T) {
	reg := registerWebPack(t)
	snap := buildHostSnapshot(t)
	// Same logical config with keys in different insertion order should be deterministic.
	cfgMap1 := map[string]string{"web.csp.disabled": "false", "a": "1", "z": "2"}
	cfgMap2 := map[string]string{"z": "2", "web.csp.disabled": "false", "a": "1"}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	cfg.Config = cfgMap1
	rep1, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run1: %v", err)
	}
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	cfg2.Config = cfgMap2
	rep2, err := detect.Run(context.Background(), cfg2, snap)
	if err != nil {
		t.Fatalf("Run2: %v", err)
	}
	b1, _ := json.Marshal(rep1)
	b2, _ := json.Marshal(rep2)
	if string(b1) != string(b2) {
		t.Fatalf("config map order affected report determinism")
	}
	// Cache key must also respect config (different config → different key)
	dir := t.TempDir()
	fs, _ := cache.Open(dir)
	cfg3 := detect.DefaultEngineConfig(reg)
	cfg3.Clock = testClock
	cfg3.Cache = fs
	cfg3.Config = map[string]string{"web.csp.disabled": "true"}
	repCold, _ := detect.Run(context.Background(), cfg3, snap)
	// Second run with same disabled config should be cache hit; different config should miss.
	cfg4 := detect.DefaultEngineConfig(reg)
	cfg4.Clock = testClock
	cfg4.Cache = fs
	cfg4.Config = map[string]string{"web.csp.disabled": "true"}
	repWarm, _ := detect.Run(context.Background(), cfg4, snap)
	if repWarm.CacheHits == 0 {
		t.Fatalf("same config should be cache hit")
	}
	_ = repCold
}

// TestCapSubjectsContract pins the pack's NEW-135 cap helper: 300
// uniform-score subjects in reverse input order keep the 256 lowest
// identities with 44 dropped, and under-cap input passes through with
// zero dropped. Input order never decides the retained set.
func TestCapSubjectsContract(t *testing.T) {
	var subs []asset.Identity
	for i := 0; i < 300; i++ {
		subs = append(subs, asset.Identity{Kind: asset.KindHost, Value: fmt.Sprintf("host-%03d.example.test", i)})
	}
	rev := append([]asset.Identity(nil), subs...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	kept, dropped := capSubjects(rev, nil)
	if len(kept) != 256 || dropped != 44 {
		t.Fatalf("kept %d dropped %d, want 256/44", len(kept), dropped)
	}
	for i := range kept {
		if kept[i] != subs[i] {
			t.Fatalf("kept[%d] = %s, want %s (identity-ordered head)", i, kept[i], subs[i])
		}
	}
	kept, dropped = capSubjects(append([]asset.Identity(nil), subs[:10]...), nil)
	if len(kept) != 10 || dropped != 0 {
		t.Fatalf("under-cap kept %d dropped %d, want 10/0", len(kept), dropped)
	}
}
