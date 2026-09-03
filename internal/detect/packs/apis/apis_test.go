package apis

import (
	"context"
	"encoding/json"
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
	h, err := asset.NewHost(name, asset.Provenance{Source: "apis-test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

func mustEndpoint(t testing.TB, method, rawURL string) asset.Endpoint {
	t.Helper()
	ep, err := asset.NewEndpoint(method, rawURL, asset.Provenance{Source: "apis-test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return ep
}

func mustEvidence(t testing.TB, method asset.DetectionMethod, indicator, value string, source asset.Identity) asset.Evidence {
	t.Helper()
	ev, err := asset.NewEvidence(method, indicator, value, source, asset.Provenance{Source: "apis-test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	return ev
}

func mustTechnology(t testing.TB, name string, cat asset.TechnologyCategory) asset.Technology {
	t.Helper()
	tech, err := asset.NewTechnology(name, cat, asset.Provenance{Source: "apis-test"})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	return tech
}

func buildOpenAPISnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://www.example.com/openapi.json")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func buildIDORSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://www.example.com/api/v1/users/123/profile")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func buildUUIDSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://www.example.com/api/v1/users/550e8400-e29b-41d4-a716-446655440000")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func buildGraphQLSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://www.example.com/graphql")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func buildSafeSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://www.example.com/api/v1/health")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func buildMixedSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	host := mustHost(t, "www.example.com")
	ep1 := mustEndpoint(t, "GET", "https://www.example.com/openapi.json")
	ep2 := mustEndpoint(t, "GET", "https://www.example.com/api/v1/users/123")
	ep3 := mustEndpoint(t, "GET", "https://www.example.com/graphql")
	return detect.Snapshot{
		Assets:    []asset.Identity{host.Identity()},
		Endpoints: []asset.Endpoint{ep1, ep2, ep3},
	}
}

func registerApisPack(t testing.TB) *detect.Registry {
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

func TestApisPackCheckAPIVersion(t *testing.T) {
	if err := detect.CheckAPIVersion(2, 0); err != nil {
		t.Fatalf("CheckAPIVersion(2,0): %v", err)
	}
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("pack carries %d rules, want 3", len(rules))
	}
}

func TestApisPackLoadsThroughSDK(t *testing.T) {
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

func TestApisPackMetadataDepsCompat(t *testing.T) {
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
		if !strings.HasPrefix(r.ID, "api.") {
			t.Fatalf("rule %q ID policy violation", r.ID)
		}
		if len(r.Dependencies) > 0 {
			t.Fatalf("apis pack should have no dependencies for now (found on %q)", r.ID)
		}
	}
}

func TestApisPackRequiredAssetTypesSkipHonestly(t *testing.T) {
	reg := registerApisPack(t)
	empty := detect.Snapshot{}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, empty)
	if err != nil {
		t.Fatalf("Run empty: %v", err)
	}
	if rep.Skipped != 3 {
		t.Fatalf("empty corpus: skipped %d, want 3 (all rules require endpoint)", rep.Skipped)
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
	safeSnap := buildSafeSnapshot(t)
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, safeSnap)
	if err != nil {
		t.Fatalf("Run safe: %v", err)
	}
	for _, r := range rep2.Rules {
		if r.Status != detect.RuleStatusCompleted {
			t.Fatalf("safe corpus rule %q status %s, want completed (has endpoint but no API signal)", r.RuleID, r.Status)
		}
	}
	if len(rep2.Findings) != 0 {
		t.Fatalf("safe findings %d, want 0", len(rep2.Findings))
	}
}

func TestApisPackDetectorsHonorContext(t *testing.T) {
	reg := registerApisPack(t)
	snap := buildOpenAPISnapshot(t)
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

func TestApisPackFailuresIsolated(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	panicRule := detect.Rule{
		ID:            "api.test.panic",
		Name:          "Test Panic",
		Description:   "Synthetic panicking rule for isolation test",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputEndpoints},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "apis-test",
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
	foundPanic := false
	for _, r := range rep.Rules {
		if r.RuleID == "api.test.panic" {
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
	if rep.Completed == 0 {
		t.Fatalf("completed %d, want >0 (isolation)", rep.Completed)
	}
}

func TestApisPackCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerApisPack(t)
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

func TestApisPackDeterminismGolden(t *testing.T) {
	reg := registerApisPack(t)
	snap := buildMixedSnapshot(t)
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Config = map[string]string{"api.openapi.exposed.disabled": "false", "api.rest.idor-indicator.disabled": "false"}
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
	golden.Compare(t, "testdata/apis_report.golden", b1)
}

func TestApisPackOpenAPIExposed(t *testing.T) {
	reg := registerApisPack(t)
	snap := buildOpenAPISnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var count int
	for _, f := range rep.Findings {
		if f.RuleID == ruleOpenAPIExposed {
			count++
			if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
				t.Fatalf("openapi priority/status %s/%s", f.Priority, f.Status)
			}
			if f.Category != detect.CategoryInformation.String() {
				t.Fatalf("openapi category %s, want information", f.Category)
			}
			if len(f.Evidence) == 0 {
				t.Fatalf("openapi no evidence")
			}
			if f.Subject.Kind != asset.KindEndpoint && f.Subject.Kind != asset.KindTechnology && f.Subject.Kind != asset.KindEvidence {
				t.Fatalf("openapi subject kind %s", f.Subject.Kind)
			}
		}
	}
	if count != 1 {
		t.Fatalf("openapi findings %d, want 1", count)
	}
	// Also test swagger variant via evidence.
	host := mustHost(t, "www.example.com")
	ep := mustEndpoint(t, "GET", "https://www.example.com/api/v1/users")
	ev := mustEvidence(t, asset.MethodHeader, "header:x-swagger", "swagger: 2.0", host.Identity())
	snap2 := detect.Snapshot{
		Endpoints: []asset.Endpoint{ep},
		Evidence:  []asset.Evidence{ev},
	}
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, snap2)
	if err != nil {
		t.Fatalf("Run2: %v", err)
	}
	var count2 int
	for _, f := range rep2.Findings {
		if f.RuleID == ruleOpenAPIExposed {
			count2++
		}
	}
	if count2 != 1 {
		t.Fatalf("openapi via evidence findings %d, want 1", count2)
	}
}

func TestApisPackRestIDORIndicator(t *testing.T) {
	reg := registerApisPack(t)
	snap := buildIDORSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var count int
	for _, f := range rep.Findings {
		if f.RuleID == ruleRestIDORIndicator {
			count++
			if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
				t.Fatalf("idor priority/status %s/%s", f.Priority, f.Status)
			}
			if f.Category != detect.CategoryInformation.String() {
				t.Fatalf("idor category %s", f.Category)
			}
		}
	}
	if count != 1 {
		t.Fatalf("idor findings %d, want 1 (numeric segment)", count)
	}
	// UUID variant
	snap2 := buildUUIDSnapshot(t)
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, snap2)
	if err != nil {
		t.Fatalf("Run uuid: %v", err)
	}
	var count2 int
	for _, f := range rep2.Findings {
		if f.RuleID == ruleRestIDORIndicator {
			count2++
		}
	}
	if count2 != 1 {
		t.Fatalf("idor uuid findings %d, want 1", count2)
	}
	// Safe path should not emit.
	snap3 := buildSafeSnapshot(t)
	cfg3 := detect.DefaultEngineConfig(reg)
	cfg3.Clock = testClock
	rep3, err := detect.Run(context.Background(), cfg3, snap3)
	if err != nil {
		t.Fatalf("Run safe: %v", err)
	}
	for _, f := range rep3.Findings {
		if f.RuleID == ruleRestIDORIndicator {
			t.Fatalf("safe idor emitted unexpectedly")
		}
	}
}

func TestApisPackGraphQLIntrospection(t *testing.T) {
	reg := registerApisPack(t)
	snap := buildGraphQLSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var count int
	for _, f := range rep.Findings {
		if f.RuleID == ruleGraphQLIntrospection {
			count++
			if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
				t.Fatalf("graphql priority/status %s/%s", f.Priority, f.Status)
			}
			if f.Category != detect.CategoryAPI.String() {
				t.Fatalf("graphql category %s, want api", f.Category)
			}
			if len(f.Evidence) == 0 {
				t.Fatalf("graphql no evidence")
			}
		}
	}
	if count != 1 {
		t.Fatalf("graphql findings %d, want 1", count)
	}
}

func TestApisPackMixedPerRule(t *testing.T) {
	reg := registerApisPack(t)
	snap := buildMixedSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	counts := map[string]int{}
	for _, f := range rep.Findings {
		counts[f.RuleID]++
	}
	if counts[ruleOpenAPIExposed] != 1 {
		t.Fatalf("openapi %d, want 1", counts[ruleOpenAPIExposed])
	}
	if counts[ruleRestIDORIndicator] != 1 {
		t.Fatalf("idor %d, want 1", counts[ruleRestIDORIndicator])
	}
	if counts[ruleGraphQLIntrospection] != 1 {
		t.Fatalf("graphql %d, want 1", counts[ruleGraphQLIntrospection])
	}
}

func TestApisPackConfigDeterministic(t *testing.T) {
	reg := registerApisPack(t)
	snap := buildOpenAPISnapshot(t)
	cfgMap1 := map[string]string{"api.openapi.exposed.disabled": "false", "a": "1", "z": "2"}
	cfgMap2 := map[string]string{"z": "2", "api.openapi.exposed.disabled": "false", "a": "1"}
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
	dir := t.TempDir()
	fs, _ := cache.Open(dir)
	cfg3 := detect.DefaultEngineConfig(reg)
	cfg3.Clock = testClock
	cfg3.Cache = fs
	cfg3.Config = map[string]string{"api.openapi.exposed.disabled": "true"}
	repCold, _ := detect.Run(context.Background(), cfg3, snap)
	cfg4 := detect.DefaultEngineConfig(reg)
	cfg4.Clock = testClock
	cfg4.Cache = fs
	cfg4.Config = map[string]string{"api.openapi.exposed.disabled": "true"}
	repWarm, _ := detect.Run(context.Background(), cfg4, snap)
	if repWarm.CacheHits == 0 {
		t.Fatalf("same config should be cache hit")
	}
	_ = repCold
}
