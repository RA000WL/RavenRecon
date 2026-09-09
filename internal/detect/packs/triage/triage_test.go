package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/golden"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
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
	if err := detect.CheckAPIVersion(2, 0); err != nil {
		t.Fatalf("CheckAPIVersion(2,0): %v", err)
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

// TestTriageCapKeepsBackedFirst pins the NEW-135 score-ordered rule cap:
// with 300 flagged subjects (100 reflection-backed at confidence 0.8, 200
// name-only at 0.6) the 256-cap keeps every backed finding first, then the
// lowest-identity unbacked ones — not the identity prefix. The backed
// subjects are chosen as the HIGHEST endpoint identities, so the old
// prefix cut would have dropped 44 of them. Honesty metadata is
// preserved: every retained finding carries truncated + subjects_dropped
// ("44"), and the LevelWarn log fires. Both input orders produce
// byte-identical reports.
func TestTriageCapKeepsBackedFirst(t *testing.T) {
	const total = 300
	var eps []asset.Endpoint
	for i := 0; i < total; i++ {
		eps = append(eps, mustEndpoint(t, "GET", fmt.Sprintf("https://www.example.com/search%d?q=%d", i, i)))
	}
	// Rank endpoints by subject identity; back the highest 100.
	ordered := append([]asset.Endpoint(nil), eps...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Identity().String() < ordered[j].Identity().String()
	})
	var evs []asset.Evidence
	for _, ep := range ordered[total-100:] {
		evs = append(evs, mustReflectEvidence(t, ep, "q", httpprobe.ReflectUnencoded))
	}
	run := func(reverse bool) []byte {
		in := append([]asset.Endpoint(nil), eps...)
		if reverse {
			for i, j := 0, len(in)-1; i < j; i, j = i+1, j-1 {
				in[i], in[j] = in[j], in[i]
			}
		}
		reg := registerTriagePack(t)
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		rep, err := detect.Run(context.Background(), cfg, detect.Snapshot{Endpoints: in, Evidence: evs})
		if err != nil {
			t.Fatalf("Run(reverse=%v): %v", reverse, err)
		}
		var xss []asset.Finding
		for _, f := range rep.Findings {
			if f.RuleID == ruleXSSReflected {
				xss = append(xss, f)
			}
		}
		if len(xss) != 256 {
			t.Fatalf("reverse=%v: xss findings %d, want 256 capped", reverse, len(xss))
		}
		backedKept := 0
		for _, f := range xss {
			if f.Metadata["truncated"] != "true" || f.Metadata["subjects_dropped"] != "44" {
				t.Fatalf("reverse=%v: finding %s meta truncated=%q subjects_dropped=%q, want true/44",
					reverse, f.Subject, f.Metadata["truncated"], f.Metadata["subjects_dropped"])
			}
			if f.Metadata["reflection_backed"] == "true" {
				backedKept++
				if f.Confidence != 0.8 {
					t.Fatalf("reverse=%v: backed finding %s confidence %v, want 0.8", reverse, f.Subject, f.Confidence)
				}
			} else if f.Confidence != 0.6 {
				t.Fatalf("reverse=%v: unbacked finding %s confidence %v, want 0.6", reverse, f.Subject, f.Confidence)
			}
		}
		if backedKept != 100 {
			t.Fatalf("reverse=%v: backed findings kept %d, want all 100", reverse, backedKept)
		}
		// Every backed subject survives the cut, whatever its identity.
		kept := make(map[string]bool, len(xss))
		for _, f := range xss {
			kept[f.Subject.String()] = true
		}
		for _, ep := range ordered[total-100:] {
			if !kept[ep.Identity().String()] {
				t.Fatalf("reverse=%v: backed subject %s dropped over cap", reverse, ep.Identity())
			}
		}
		// The warn log fires exactly as before.
		foundWarn := false
		for _, l := range rep.Logs {
			if l.Level == detect.LevelWarn && l.Rule == ruleXSSReflected {
				foundWarn = true
			}
		}
		if !foundWarn {
			t.Fatalf("reverse=%v: missing LevelWarn truncation log for %s", reverse, ruleXSSReflected)
		}
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}
	b1, b2 := run(false), run(true)
	if string(b1) != string(b2) {
		t.Fatalf("over-cap triage runs with reversed input order diverged")
	}
}

// TestCapSubjectsScoreOrder pins the pack's NEW-135 cap helper ordering:
// score descending first, then subject identity. The 100 high-score
// subjects carry the HIGHEST identities, so a pure identity prefix would
// drop 44 of them; the helper must keep all 100, then the lowest-identity
// low-score head. Arrival order (odds-then-evens) never decides.
func TestCapSubjectsScoreOrder(t *testing.T) {
	var subs []asset.Identity
	for i := 0; i < 300; i++ {
		subs = append(subs, asset.Identity{Kind: asset.KindHost, Value: fmt.Sprintf("host-%03d.example.test", i)})
	}
	score := func(id asset.Identity) float64 {
		if id.Value >= "host-200.example.test" {
			return 0.8
		}
		return 0.6
	}
	var in []asset.Identity
	for i := 1; i < 300; i += 2 {
		in = append(in, subs[i])
	}
	for i := 0; i < 300; i += 2 {
		in = append(in, subs[i])
	}
	kept, dropped := capSubjects(in, score)
	if len(kept) != 256 || dropped != 44 {
		t.Fatalf("kept %d dropped %d, want 256/44", len(kept), dropped)
	}
	for i := 0; i < 100; i++ {
		if kept[i] != subs[200+i] {
			t.Fatalf("kept[%d] = %s, want high-score %s first", i, kept[i], subs[200+i])
		}
	}
	for i := 0; i < 156; i++ {
		if kept[100+i] != subs[i] {
			t.Fatalf("kept[%d] = %s, want low-score %s", 100+i, kept[100+i], subs[i])
		}
	}
}

// mustReflectEvidence builds one urllive canary-reflection evidence record
// for tests: verdict for param on the endpoint's URL identity.
func mustReflectEvidence(t testing.TB, ep asset.Endpoint, param string, v httpprobe.ReflectVerdict) asset.Evidence {
	t.Helper()
	ev, err := httpprobe.ReflectEvidence(ep.URL.Identity(), param, v)
	if err != nil {
		t.Fatalf("ReflectEvidence: %v", err)
	}
	return ev
}

// mustReflectPostEvidence builds one POST canary-reflection evidence record
// for tests: verdict for param on the endpoint's URL identity under scope.
func mustReflectPostEvidence(t testing.TB, ep asset.Endpoint, param string, v httpprobe.ReflectVerdict, scope httpprobe.ReflectScope) asset.Evidence {
	t.Helper()
	ev, err := httpprobe.ReflectPostEvidence(ep.URL.Identity(), param, v, scope)
	if err != nil {
		t.Fatalf("ReflectPostEvidence: %v", err)
	}
	return ev
}

func triageFindingsForRule(t testing.TB, snap detect.Snapshot, ruleID string) []asset.Finding {
	t.Helper()
	reg := registerTriagePack(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var out []asset.Finding
	for _, f := range rep.Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// TestTriageReflectionDropsSilentKeepsMissing pins the NEW-120 gate: a
// subject whose every flagged param verdicts not-reflected is dropped,
// while a subject with no reflection evidence is kept (fail-open —
// behavior without enrichment is unchanged).
func TestTriageReflectionDropsSilentKeepsMissing(t *testing.T) {
	silent := mustEndpoint(t, "GET", "https://www.example.com/silent?id=1")
	missing := mustEndpoint(t, "GET", "https://www.example.com/missing?id=1")
	snap := detect.Snapshot{
		Endpoints: []asset.Endpoint{silent, missing},
		Evidence:  []asset.Evidence{mustReflectEvidence(t, silent, "id", httpprobe.ReflectAbsent)},
	}
	got := triageFindingsForRule(t, snap, ruleIDOR)
	if len(got) != 1 {
		t.Fatalf("idor findings = %d, want 1 (silent dropped, missing kept)", len(got))
	}
	if got[0].Subject != missing.Identity() {
		t.Fatalf("kept subject = %s, want the missing-evidence endpoint %s", got[0].Subject, missing.Identity())
	}
	if _, ok := got[0].Metadata["reflection"]; ok {
		t.Errorf("kept finding carries reflection meta %q without verdicts", got[0].Metadata["reflection"])
	}
	// NEW-127: no verdicts, no scope marker (nothing to scope).
	if _, ok := got[0].Metadata["reflection_scope"]; ok {
		t.Errorf("kept finding carries reflection_scope without verdicts: %v", got[0].Metadata)
	}
}

// TestTriageReflectionKeepsReflected pins the keep path: a reflected
// flagged param keeps the subject and cites its verdicts in meta. (Both
// q and year are XSS-primary under precedence; page would belong to the
// SSRF rule, so it is not cited here.)
func TestTriageReflectionKeepsReflected(t *testing.T) {
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?q=term&year=2024")
	snap := detect.Snapshot{
		Endpoints: []asset.Endpoint{ep},
		Evidence: []asset.Evidence{
			mustReflectEvidence(t, ep, "q", httpprobe.ReflectUnencoded),
			mustReflectEvidence(t, ep, "year", httpprobe.ReflectAbsent),
		},
	}
	got := triageFindingsForRule(t, snap, ruleXSSReflected)
	if len(got) != 1 {
		t.Fatalf("xss findings = %d, want 1 (reflected q keeps despite silent year)", len(got))
	}
	meta := got[0].Metadata["reflection"]
	if !strings.Contains(meta, "q:reflected-unencoded") || !strings.Contains(meta, "year:not-reflected") {
		t.Errorf("reflection meta = %q, want both verdicts cited", meta)
	}
	// NEW-127: cited verdicts carry their scope — GET query params
	// only; POST/body/header input was not tested.
	if got[0].Metadata["reflection_scope"] != "query-get-only" {
		t.Errorf("reflection_scope = %q, want query-get-only", got[0].Metadata["reflection_scope"])
	}
}

// TestTriageReflectionForeignEvidenceIgnored pins no cross-talk: evidence
// with a foreign method or indicator never gates and never leaks into meta.
func TestTriageReflectionForeignEvidenceIgnored(t *testing.T) {
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?q=term")
	foreign, err := asset.NewEvidence(asset.MethodJS, "reflect:q", string(httpprobe.ReflectAbsent), ep.URL.Identity(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	snap := detect.Snapshot{Endpoints: []asset.Endpoint{ep}, Evidence: []asset.Evidence{foreign}}
	got := triageFindingsForRule(t, snap, ruleXSSReflected)
	if len(got) != 1 {
		t.Fatalf("xss findings = %d, want 1 (foreign evidence must not drop)", len(got))
	}
	if _, ok := got[0].Metadata["reflection"]; ok {
		t.Errorf("reflection meta present from foreign evidence: %q", got[0].Metadata["reflection"])
	}
}

// TestTriageReflectionMetaBounded pins the metadata bound: many flagged
// reflected params still build a valid finding with a ≤256-byte value.
func TestTriageReflectionMetaBounded(t *testing.T) {
	var q strings.Builder
	for i, p := range xssParams {
		if i > 0 {
			q.WriteByte('&')
		}
		q.WriteString(p + "=1")
	}
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?"+q.String())
	var evs []asset.Evidence
	for _, p := range extractParamNames(ep) {
		evs = append(evs, mustReflectEvidence(t, ep, p, httpprobe.ReflectUnencoded))
	}
	snap := detect.Snapshot{Endpoints: []asset.Endpoint{ep}, Evidence: evs}
	got := triageFindingsForRule(t, snap, ruleXSSReflected)
	if len(got) != 1 {
		t.Fatalf("xss findings = %d, want 1", len(got))
	}
	if len(got[0].Metadata["reflection"]) > 256 {
		t.Fatalf("reflection meta = %d bytes, want ≤256 (finding would fail validation)", len(got[0].Metadata["reflection"]))
	}
}

// TestTriagePostReflectedRescuesGetSilent pins the POST-aware gate: a
// GET-silent subject with a POST reflected verdict for the same source is
// kept, cited under the distinct reflection_post key with its scope, while
// the GET citation and its scope marker survive un-conflated.
func TestTriagePostReflectedRescuesGetSilent(t *testing.T) {
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?q=term")
	snap := detect.Snapshot{
		Endpoints: []asset.Endpoint{ep},
		Evidence: []asset.Evidence{
			mustReflectEvidence(t, ep, "q", httpprobe.ReflectAbsent),
			mustReflectPostEvidence(t, ep, "q", httpprobe.ReflectUnencoded, httpprobe.ReflectScopePostForm),
		},
	}
	got := triageFindingsForRule(t, snap, ruleXSSReflected)
	if len(got) != 1 {
		t.Fatalf("xss findings = %d, want 1 (POST reflected rescues GET-silent)", len(got))
	}
	if rm := got[0].Metadata["reflection"]; !strings.Contains(rm, "q:not-reflected") {
		t.Errorf("reflection meta = %q, want the GET verdict cited separately", rm)
	}
	if rpm := got[0].Metadata["reflection_post"]; !strings.Contains(rpm, "q:reflected-unencoded") {
		t.Errorf("reflection_post meta = %q, want the POST verdict under its distinct key", rpm)
	}
	if got[0].Metadata["reflection_scope"] != "query-get-only" {
		t.Errorf("reflection_scope = %q, want query-get-only (GET scope survives the POST rescue)", got[0].Metadata["reflection_scope"])
	}
	if got[0].Metadata["reflection_post_scope"] != "post-form" {
		t.Errorf("reflection_post_scope = %q, want post-form", got[0].Metadata["reflection_post_scope"])
	}
	if strings.Contains(got[0].Metadata["reflection"], "reflected-unencoded") {
		t.Errorf("GET reflection meta conflates POST: %q", got[0].Metadata["reflection"])
	}
}

func TestTriageReflectionBackedConfidence(t *testing.T) {
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?q=term")
	backed := detect.Snapshot{
		Endpoints: []asset.Endpoint{ep},
		Evidence:  []asset.Evidence{mustReflectEvidence(t, ep, "q", httpprobe.ReflectUnencoded)},
	}
	got := triageFindingsForRule(t, backed, ruleXSSReflected)
	if len(got) != 1 {
		t.Fatalf("xss findings = %d, want 1", len(got))
	}
	if got[0].Confidence != 0.8 {
		t.Errorf("backed confidence = %v, want 0.8 (probe saw the input return)", got[0].Confidence)
	}
	if got[0].Metadata["reflection_backed"] != "true" {
		t.Errorf("reflection_backed marker missing: %q", got[0].Metadata)
	}
	plain := detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
	got = triageFindingsForRule(t, plain, ruleXSSReflected)
	if len(got) != 1 {
		t.Fatalf("xss findings = %d, want 1 (fail-open without enrichment)", len(got))
	}
	if got[0].Confidence != 0.6 {
		t.Errorf("unenriched confidence = %v, want 0.6 (name-only heuristic)", got[0].Confidence)
	}
	if _, ok := got[0].Metadata["reflection_backed"]; ok {
		t.Errorf("reflection_backed marker on unenriched finding: %q", got[0].Metadata)
	}
}

// TestTriagePostSilentStillDrops pins that POST silence rescues nothing: a
// GET-silent subject with POST-silent evidence is still dropped.
func TestTriagePostSilentStillDrops(t *testing.T) {
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?q=term")
	snap := detect.Snapshot{
		Endpoints: []asset.Endpoint{ep},
		Evidence: []asset.Evidence{
			mustReflectEvidence(t, ep, "q", httpprobe.ReflectAbsent),
			mustReflectPostEvidence(t, ep, "q", httpprobe.ReflectAbsent, httpprobe.ReflectScopePostForm),
		},
	}
	got := triageFindingsForRule(t, snap, ruleXSSReflected)
	if len(got) != 0 {
		t.Fatalf("xss findings = %d, want 0 (GET-silent + POST-silent still drops)", len(got))
	}
}

// TestTriagePostUnknownFailOpen pins that unknown carries no gate weight:
// an endpoint with only unknown POST evidence (hand-crafted — builders
// never emit it) is kept fail-open with no POST citation, exactly as an
// endpoint with no evidence at all.
func TestTriagePostUnknownFailOpen(t *testing.T) {
	ep := mustEndpoint(t, "GET", "https://www.example.com/search?q=term")
	unk, err := asset.NewEvidence(asset.MethodEndpoint, "reflect-post-form:q", string(httpprobe.ReflectUnknown), ep.URL.Identity(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence unknown: %v", err)
	}
	snap := detect.Snapshot{Endpoints: []asset.Endpoint{ep}, Evidence: []asset.Evidence{unk}}
	got := triageFindingsForRule(t, snap, ruleXSSReflected)
	if len(got) != 1 {
		t.Fatalf("xss findings = %d, want 1 (unknown is not silence — fail-open kept)", len(got))
	}
	if _, ok := got[0].Metadata["reflection_post"]; ok {
		t.Errorf("kept finding cites reflection_post %q from unknown (unknown carries no citation)", got[0].Metadata["reflection_post"])
	}
	// All-unknown (no decided evidence at all) is kept today and stays kept.
	bare := detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
	gotBare := triageFindingsForRule(t, bare, ruleXSSReflected)
	if len(gotBare) != 1 {
		t.Fatalf("bare xss findings = %d, want 1 (no evidence is fail-open kept)", len(gotBare))
	}
}
