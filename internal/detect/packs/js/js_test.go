package js

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

func mustJS(t testing.TB, rawURL string) asset.JavaScript {
	t.Helper()
	js, err := asset.NewJavaScript(rawURL, asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	return js
}

func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

func buildXSSSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	js := mustJS(t, "https://www.example.com/app_xss.js")
	return detect.Snapshot{JavaScript: []asset.JavaScript{js}}
}

func buildPostMessageSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	js := mustJS(t, "https://www.example.com/app_postmessage.js")
	return detect.Snapshot{JavaScript: []asset.JavaScript{js}}
}

func buildProtoSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	js := mustJS(t, "https://www.example.com/app_proto.js")
	return detect.Snapshot{JavaScript: []asset.JavaScript{js}}
}

func buildSafeSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	js := mustJS(t, "https://www.example.com/app_safe.js")
	return detect.Snapshot{JavaScript: []asset.JavaScript{js}}
}

func buildMixedSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	js1 := mustJS(t, "https://www.example.com/app_xss.js")
	js2 := mustJS(t, "https://www.example.com/app_postmessage.js")
	js3 := mustJS(t, "https://www.example.com/app_proto.js")
	host := mustHost(t, "www.example.com")
	return detect.Snapshot{
		Assets:     []asset.Identity{host.Identity()},
		JavaScript: []asset.JavaScript{js1, js2, js3},
	}
}

func registerJSPack(t testing.TB) *detect.Registry {
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

func TestJSPackCheckAPIVersion(t *testing.T) {
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

func TestJSPackLoadsThroughSDK(t *testing.T) {
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

func TestJSPackMetadataDepsCompat(t *testing.T) {
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
		if !strings.HasPrefix(r.ID, "js.") {
			t.Fatalf("rule %q ID policy violation", r.ID)
		}
		if len(r.Dependencies) > 0 {
			t.Fatalf("js pack should have no dependencies for now (found on %q)", r.ID)
		}
	}
}

func TestJSPackRequiredAssetTypesSkipHonestly(t *testing.T) {
	reg := registerJSPack(t)
	empty := detect.Snapshot{}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, empty)
	if err != nil {
		t.Fatalf("Run empty: %v", err)
	}
	if rep.Skipped != 3 {
		t.Fatalf("empty corpus: skipped %d, want 3 (all rules require javascript)", rep.Skipped)
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
	// Safe snapshot has javascript but no vulnerable sinks, so all rules complete with 0 findings (not skipped).
	for _, r := range rep2.Rules {
		if r.Status != detect.RuleStatusCompleted {
			t.Fatalf("safe corpus rule %q status %s, want completed (has js but no sink)", r.RuleID, r.Status)
		}
	}
	if len(rep2.Findings) != 0 {
		t.Fatalf("safe findings %d, want 0", len(rep2.Findings))
	}
}

func TestJSPackDetectorsHonorContext(t *testing.T) {
	reg := registerJSPack(t)
	snap := buildXSSSnapshot(t)
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

func TestJSPackFailuresIsolated(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	panicRule := detect.Rule{
		ID:            "js.test.panic",
		Name:          "Test Panic",
		Description:   "Synthetic panicking rule for isolation test",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputJavaScript},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "js-test",
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
		if r.RuleID == "js.test.panic" {
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

func TestJSPackCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerJSPack(t)
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

func TestJSPackDeterminismGolden(t *testing.T) {
	reg := registerJSPack(t)
	snap := buildMixedSnapshot(t)
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Config = map[string]string{"js.dom.xss.disabled": "false", "js.postmessage.no-origin-check.disabled": "false"}
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
	golden.Compare(t, "testdata/js_report.golden", b1)
}

func TestJSPackDomXSSEmits(t *testing.T) {
	reg := registerJSPack(t)
	snap := buildXSSSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var count int
	for _, f := range rep.Findings {
		if f.RuleID == ruleDomXSS {
			count++
		}
	}
	// R2-H2: URL-substring heuristics removed — app_xss.js no longer fires.
	// Without script body content, DOM XSS cannot be proven from URL alone.
	if count != 0 {
		t.Fatalf("DOM XSS findings %d, want 0 (URL heuristic removed)", count)
	}
}

func TestJSPackPostMessageEmits(t *testing.T) {
	reg := registerJSPack(t)
	snap := buildPostMessageSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var count int
	for _, f := range rep.Findings {
		if f.RuleID == rulePostMessage {
			count++
		}
	}
	// R2-H2: heuristic removed — app_postmessage.js no longer fires without body.
	if count != 0 {
		t.Fatalf("postmessage findings %d, want 0 (URL heuristic removed)", count)
	}
	// Safe postmessage (with origin check) should also not emit.
	safe := mustJS(t, "https://www.example.com/app_postmessage_safe.js")
	snap2 := detect.Snapshot{JavaScript: []asset.JavaScript{safe}}
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, snap2)
	if err != nil {
		t.Fatalf("Run safe postmessage: %v", err)
	}
	for _, f := range rep2.Findings {
		if f.RuleID == rulePostMessage {
			t.Fatalf("safe postmessage emitted finding unexpectedly")
		}
	}
}

func TestJSPackPrototypePollutionEmits(t *testing.T) {
	reg := registerJSPack(t)
	snap := buildProtoSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var count int
	for _, f := range rep.Findings {
		if f.RuleID == ruleProtoPollute {
			count++
		}
	}
	// R2-H2: heuristic removed — app_proto.js no longer fires.
	if count != 0 {
		t.Fatalf("proto pollution findings %d, want 0 (URL heuristic removed)", count)
	}
}

func TestJSPackMixedPerRule(t *testing.T) {
	reg := registerJSPack(t)
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
	if counts[ruleDomXSS] != 0 {
		t.Fatalf("dom xss %d, want 0", counts[ruleDomXSS])
	}
	if counts[rulePostMessage] != 0 {
		t.Fatalf("postmessage %d, want 0", counts[rulePostMessage])
	}
	if counts[ruleProtoPollute] != 0 {
		t.Fatalf("proto %d, want 0", counts[ruleProtoPollute])
	}
}

func TestJSPackConfigDeterministic(t *testing.T) {
	reg := registerJSPack(t)
	snap := buildXSSSnapshot(t)
	cfgMap1 := map[string]string{"js.dom.xss.disabled": "false", "a": "1", "z": "2"}
	cfgMap2 := map[string]string{"z": "2", "js.dom.xss.disabled": "false", "a": "1"}
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
	cfg3.Config = map[string]string{"js.dom.xss.disabled": "true"}
	repCold, _ := detect.Run(context.Background(), cfg3, snap)
	cfg4 := detect.DefaultEngineConfig(reg)
	cfg4.Clock = testClock
	cfg4.Cache = fs
	cfg4.Config = map[string]string{"js.dom.xss.disabled": "true"}
	repWarm, _ := detect.Run(context.Background(), cfg4, snap)
	if repWarm.CacheHits == 0 {
		t.Fatalf("same config should be cache hit")
	}
	_ = repCold
}
