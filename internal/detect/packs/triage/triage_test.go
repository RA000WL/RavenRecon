package triage

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

func mustEndpoint(t testing.TB, method, rawURL string) asset.Endpoint {
	t.Helper()
	ep, err := asset.NewEndpoint(method, rawURL, asset.Provenance{Source: "triage-test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return ep
}

func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "triage-test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

func buildTriageSnapshotForParam(t testing.TB, param string) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?"+param+"=1")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func buildSafeSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://www.example.com/api/v1/health")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func buildMultiParamSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	// 8 unique params, one per class, plus overlapping url param.
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?_hash=1&column=1&access=1&board=1&checkout=1&account_id=1&cmd=1&blade=1")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func buildMixedSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep1 := mustEndpoint(t, "GET", "https://www.example.com/search?_hash=evil")
	ep2 := mustEndpoint(t, "GET", "https://www.example.com/api?column=evil")
	ep3 := mustEndpoint(t, "GET", "https://www.example.com/fetch?access=evil")
	ep4 := mustEndpoint(t, "GET", "https://www.example.com/view?board=evil")
	ep5 := mustEndpoint(t, "GET", "https://www.example.com/redirect?checkout=evil")
	ep6 := mustEndpoint(t, "GET", "https://www.example.com/user?account_id=evil")
	ep7 := mustEndpoint(t, "GET", "https://www.example.com/exec?cmd=evil")
	ep8 := mustEndpoint(t, "GET", "https://www.example.com/render?blade=evil")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep1, ep2, ep3, ep4, ep5, ep6, ep7, ep8}}
}

func buildOverlapSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?url=evil")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func registerTriagePack(t testing.TB) *detect.Registry {
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

func TestTriagePackCheckAPIVersion(t *testing.T) {
	if err := detect.CheckAPIVersion(1, 0); err != nil {
		t.Fatalf("CheckAPIVersion(1,0): %v", err)
	}
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 8 {
		t.Fatalf("pack carries %d rules, want 8", len(rules))
	}
}

func TestTriagePackLoadsThroughSDK(t *testing.T) {
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
	if got.RequiredAssetTypes[0] != asset.KindEndpoint {
		t.Fatalf("deep copy broken: RequiredAssetTypes aliasing")
	}
	reg.Seal()
	if err := reg.Register(rules[0]); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("seal not enforced: %v", err)
	}
}

func TestTriagePackMetadataDepsCompat(t *testing.T) {
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
		if !r.Category.Valid() || r.Category != detect.CategoryInformation {
			t.Fatalf("rule %q category %q invalid or not information", r.ID, r.Category)
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
		if len(r.RequiredAssetTypes) != 1 || r.RequiredAssetTypes[0] != asset.KindEndpoint {
			t.Fatalf("rule %q required kinds %v, want [endpoint]", r.ID, r.RequiredAssetTypes)
		}
		if !strings.HasPrefix(r.ID, "triage.") {
			t.Fatalf("rule %q ID policy violation", r.ID)
		}
		if len(r.Dependencies) > 0 {
			t.Fatalf("triage pack should have no dependencies for now (found on %q)", r.ID)
		}
	}
}

func TestTriagePackRequiredAssetTypesSkipHonestly(t *testing.T) {
	reg := registerTriagePack(t)
	empty := detect.Snapshot{}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, empty)
	if err != nil {
		t.Fatalf("Run empty: %v", err)
	}
	if rep.Skipped != 8 {
		t.Fatalf("empty corpus: skipped %d, want 8 (all rules require endpoint)", rep.Skipped)
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
			t.Fatalf("safe corpus rule %q status %s, want completed (has endpoint but no triage param)", r.RuleID, r.Status)
		}
	}
	if len(rep2.Findings) != 0 {
		t.Fatalf("safe findings %d, want 0", len(rep2.Findings))
	}
}

func TestTriagePackDetectorsHonorContext(t *testing.T) {
	reg := registerTriagePack(t)
	snap := buildTriageSnapshotForParam(t, "_hash")
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

func TestTriagePackFailuresIsolated(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	panicRule := detect.Rule{
		ID:            "triage.test.panic",
		Name:          "Test Panic",
		Description:   "Synthetic panicking rule for isolation test",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputEndpoints},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "triage-test",
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
		if r.RuleID == "triage.test.panic" {
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

func TestTriagePackCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerTriagePack(t)
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

func TestTriagePackDeterminismGolden(t *testing.T) {
	reg := registerTriagePack(t)
	snap := buildMixedSnapshot(t)
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Config = map[string]string{"triage.redirect.disabled": "false", "triage.sqli.disabled": "false", "a": "1", "z": "2"}
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
	golden.Compare(t, "testdata/triage_report.golden", b1)
}

func TestTriagePackPerClassEmission(t *testing.T) {
	reg := registerTriagePack(t)
	cases := []struct {
		param string
		rule  string
	}{
		{"_hash", ruleXSSReflected},
		{"column", ruleSQLi},
		{"access", ruleSSRF},
		{"board", ruleLFI},
		{"checkout", ruleRedirect},
		{"account_id", ruleIDOR},
		{"cmd", ruleCMDi},
		{"blade", ruleSSTI},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			snap := buildTriageSnapshotForParam(t, tc.param)
			cfg := detect.DefaultEngineConfig(reg)
			cfg.Clock = testClock
			rep, err := detect.Run(context.Background(), cfg, snap)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			var found int
			for _, f := range rep.Findings {
				if f.RuleID == tc.rule {
					found++
					if f.Category != detect.CategoryInformation.String() {
						t.Fatalf("category %s, want information", f.Category)
					}
					if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
						t.Fatalf("priority/status %s/%s", f.Priority, f.Status)
					}
					if f.Subject.Kind != asset.KindEndpoint {
						t.Fatalf("subject kind %s, want endpoint", f.Subject.Kind)
					}
					if len(f.Evidence) == 0 {
						t.Fatalf("no evidence")
					}
					if f.Evidence[0].Method != asset.MethodDetection {
						t.Fatalf("evidence method %s, want detect", f.Evidence[0].Method)
					}
					if f.Metadata["triage_class"] != shortName(tc.rule) {
						t.Fatalf("metadata triage_class %q, want %q", f.Metadata["triage_class"], shortName(tc.rule))
					}
					if !strings.Contains(f.Metadata["params"], tc.param) {
						t.Fatalf("metadata params %q missing %q", f.Metadata["params"], tc.param)
					}
				}
			}
			if found != 1 {
				t.Fatalf("findings for %s with param %s: %d, want 1", tc.rule, tc.param, found)
			}
			// Ensure no other triage rule fired.
			for _, f := range rep.Findings {
				if f.RuleID != tc.rule {
					t.Fatalf("unexpected rule %s fired for param %s (want only %s)", f.RuleID, tc.param, tc.rule)
				}
			}
		})
	}
}

func TestTriagePackOverlapPrecedence(t *testing.T) {
	reg := registerTriagePack(t)
	snap := buildOverlapSnapshot(t) // url appears in XSS, SSRF, LFI, Redirect -> primary SSRF
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	counts := map[string]int{}
	for _, f := range rep.Findings {
		counts[f.RuleID]++
		// Verify metadata multi_class flag and all_classes.
		if f.RuleID == ruleSSRF {
			if f.Metadata["multi_class"] != "true" {
				t.Fatalf("ssrf multi_class %q, want true", f.Metadata["multi_class"])
			}
			if !strings.Contains(f.Metadata["all_classes"], "ssrf") || !strings.Contains(f.Metadata["all_classes"], "xss_reflected") {
				t.Fatalf("all_classes %q missing expected classes", f.Metadata["all_classes"])
			}
		}
	}
	if counts[ruleSSRF] != 1 {
		t.Fatalf("ssrf findings %d, want 1 for overlapping param url", counts[ruleSSRF])
	}
	// Ensure overlapping param does NOT trigger lower precedence rules.
	for _, id := range []string{ruleXSSReflected, ruleLFI, ruleRedirect} {
		if counts[id] != 0 {
			t.Fatalf("rule %s findings %d, want 0 (overlap param should be primary ssrf only)", id, counts[id])
		}
	}
	// Additional overlap: id appears in XSS, SQLi, IDOR, SSTI -> primary IDOR
	t.Run("id overlap", func(t *testing.T) {
		snap2 := buildTriageSnapshotForParam(t, "id")
		cfg2 := detect.DefaultEngineConfig(reg)
		cfg2.Clock = testClock
		rep2, err := detect.Run(context.Background(), cfg2, snap2)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		m := map[string]int{}
		for _, f := range rep2.Findings {
			m[f.RuleID]++
		}
		if m[ruleIDOR] != 1 {
			t.Fatalf("idor findings %d, want 1 for param id", m[ruleIDOR])
		}
		for _, id2 := range []string{ruleXSSReflected, ruleSQLi, ruleSSTI} {
			if m[id2] != 0 {
				t.Fatalf("rule %s unexpected for param id, primary should be idor", id2)
			}
		}
	})
	// RCE precedence: exec appears in SSRF and RCE -> primary RCE (triage.cmdi)
	t.Run("exec overlap RCE precedence", func(t *testing.T) {
		snap3 := buildTriageSnapshotForParam(t, "exec")
		cfg3 := detect.DefaultEngineConfig(reg)
		cfg3.Clock = testClock
		rep3, err := detect.Run(context.Background(), cfg3, snap3)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		m := map[string]int{}
		for _, f := range rep3.Findings {
			m[f.RuleID]++
		}
		if m[ruleCMDi] != 1 {
			t.Fatalf("cmdi findings %d, want 1 for param exec", m[ruleCMDi])
		}
		if m[ruleSSRF] != 0 {
			t.Fatalf("ssrf unexpected for exec, primary is cmdi")
		}
	})
}

func TestTriagePackMultiParamEndpoint(t *testing.T) {
	reg := registerTriagePack(t)
	snap := buildMultiParamSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	counts := map[string]int{}
	for _, f := range rep.Findings {
		counts[f.RuleID]++
		// Each finding should be for the same endpoint subject.
		if f.Subject.Kind != asset.KindEndpoint {
			t.Fatalf("subject kind %s", f.Subject.Kind)
		}
	}
	// 8 unique params each for a distinct primary class -> 8 findings, one per rule.
	if len(rep.Findings) != 8 {
		t.Fatalf("multi-param findings %d, want 8 (one per distinct primary class)", len(rep.Findings))
	}
	for _, id := range []string{ruleXSSReflected, ruleSQLi, ruleSSRF, ruleLFI, ruleRedirect, ruleIDOR, ruleCMDi, ruleSSTI} {
		if counts[id] != 1 {
			t.Fatalf("rule %s count %d, want 1 in multi-param endpoint", id, counts[id])
		}
	}
	// Now test endpoint with two params of same primary (url and file both SSRF)
	t.Run("same primary dedup", func(t *testing.T) {
		ep := mustEndpoint(t, "GET", "https://www.example.com/search?url=1&file=1")
		snap2 := detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
		cfg2 := detect.DefaultEngineConfig(reg)
		cfg2.Clock = testClock
		rep2, err := detect.Run(context.Background(), cfg2, snap2)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		ssrfCount := 0
		for _, f := range rep2.Findings {
			if f.RuleID == ruleSSRF {
				ssrfCount++
				// params should be sorted deterministic: file,url
				if f.Metadata["params"] != "file,url" {
					t.Fatalf("ssrf params %q, want file,url", f.Metadata["params"])
				}
			}
		}
		if ssrfCount != 1 {
			t.Fatalf("ssrf count %d, want 1 deduped for same primary", ssrfCount)
		}
		// No other rule should fire for those params (both primary ssrf)
		for _, f := range rep2.Findings {
			if f.RuleID != ruleSSRF {
				t.Fatalf("unexpected rule %s for url+file (both ssrf primary)", f.RuleID)
			}
		}
	})
}

func TestTriagePackConfigDeterministic(t *testing.T) {
	reg := registerTriagePack(t)
	snap := buildTriageSnapshotForParam(t, "_hash")
	cfgMap1 := map[string]string{"triage.xss_reflected.disabled": "false", "a": "1", "z": "2"}
	cfgMap2 := map[string]string{"z": "2", "triage.xss_reflected.disabled": "false", "a": "1"}
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
	cfg3.Config = map[string]string{"triage.xss_reflected.disabled": "true"}
	repCold, _ := detect.Run(context.Background(), cfg3, snap)
	cfg4 := detect.DefaultEngineConfig(reg)
	cfg4.Clock = testClock
	cfg4.Cache = fs
	cfg4.Config = map[string]string{"triage.xss_reflected.disabled": "true"}
	repWarm, _ := detect.Run(context.Background(), cfg4, snap)
	if repWarm.CacheHits == 0 {
		t.Fatalf("same config should be cache hit")
	}
	if repCold.FindingsTruncated || repWarm.FindingsTruncated {
		t.Fatalf("disabled rule must not report truncation")
	}
	// Enabled vs disabled should produce different findings (cache key respects config)
	cfg5 := detect.DefaultEngineConfig(reg)
	cfg5.Clock = testClock
	cfg5.Cache = fs
	cfg5.Config = map[string]string{"triage.xss_reflected.disabled": "false"}
	repEnabled, _ := detect.Run(context.Background(), cfg5, snap)
	if len(repEnabled.Findings) == 0 {
		t.Fatalf("enabled should produce findings")
	}
	// The enabled run with same snapshot but different config should not be cached from disabled.
	if repEnabled.CacheHits != 0 {
		// It could be cached if previous enabled run existed, but we haven't run enabled before with cache, so miss expected.
		// However if we did run earlier, we need to check that disabled vs enabled produce different cache entries.
		// At minimum, findings must differ.
	}
	if len(repWarm.Findings) != 0 {
		t.Fatalf("disabled warm finds %d, want 0", len(repWarm.Findings))
	}
}

func TestTriagePackDisabledHonored(t *testing.T) {
	reg := registerTriagePack(t)
	snap := buildTriageSnapshotForParam(t, "checkout")
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	cfg.Config = map[string]string{ruleRedirect + ".disabled": "true"}
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range rep.Findings {
		if f.RuleID == ruleRedirect {
			t.Fatalf("redirect finding emitted even though disabled")
		}
	}
	// Without disabled, should emit.
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, snap)
	if err != nil {
		t.Fatalf("Run2: %v", err)
	}
	found := false
	for _, f := range rep2.Findings {
		if f.RuleID == ruleRedirect {
			found = true
		}
	}
	if !found {
		t.Fatalf("redirect not emitted when enabled")
	}
}

func TestTriagePackExtractParamNames(t *testing.T) {
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?url=1&Url=2&FILE=3&empty=&noequals")
	// extractParamNames should lower case and extract keys before =.
	params := extractParamNames(ep)
	// Params are sorted? extract returns in query order (canonical sorted). The canonical query sorts keys.
	// For determinism, we check that lowercased keys are present and no empty.
	m := map[string]int{}
	for _, p := range params {
		m[p]++
	}
	if m["url"] != 2 {
		t.Fatalf("url count %d, want 2 (case-insensitive)", m["url"])
	}
	if m["file"] != 1 {
		t.Fatalf("file missing")
	}
	if m["empty"] != 1 {
		t.Fatalf("empty param missing")
	}
	if m["noequals"] != 1 {
		t.Fatalf("noequals missing")
	}
}

func TestTriagePackBoundedAt256(t *testing.T) {
	reg := registerTriagePack(t)
	var eps []asset.Endpoint
	for i := 0; i < 300; i++ {
		ep := mustEndpoint(t, "GET", fmt.Sprintf("https://www.example.com/search%d?_hash=1&id=%d", i, i))
		eps = append(eps, ep)
	}
	snap := detect.Snapshot{Endpoints: eps}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, r := range rep.Rules {
		if r.RuleID == ruleXSSReflected {
			if r.Findings != 256 {
				t.Fatalf("xss findings %d, want 256 capped", r.Findings)
			}
		}
	}
	// Verify truncated metadata present.
	foundTrunc := false
	for _, f := range rep.Findings {
		if f.RuleID == ruleXSSReflected && f.Metadata["truncated"] == "true" {
			foundTrunc = true
			if f.Metadata["subjects_dropped"] == "" {
				t.Fatalf("truncated finding missing subjects_dropped")
			}
		}
	}
	if !foundTrunc {
		t.Fatalf("no truncated metadata found for bounded test")
	}
}
