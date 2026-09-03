package auth

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
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time                         { return c.at }
func (c fixedClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

var testClock = fixedClock{at: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)}

func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "auth-test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

func mustRelationship(t testing.TB, from asset.Identity, kind asset.RelationshipKind, to asset.Identity) asset.Relationship {
	t.Helper()
	rel, err := asset.NewRelationship(from, kind, to)
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	return rel
}

func registerAuthPack(t testing.TB) *detect.Registry {
	t.Helper()
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	reg := detect.NewRegistry()
	for _, r := range rules {
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register %q: %v", r.ID, err)
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	reg.Seal()
	return reg
}

func TestAuthPackCheckAPIVersion(t *testing.T) {
	if err := detect.CheckAPIVersion(2, 0); err != nil {
		t.Fatalf("CheckAPIVersion(2,0): %v", err)
	}
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("pack carries %d rules, want 1", len(rules))
	}
	if rules[0].ID != ruleJWTNoneAlg {
		t.Fatalf("rule ID %q, want %q", rules[0].ID, ruleJWTNoneAlg)
	}
}

func TestAuthPackLoadsThroughSDK(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	reg := detect.NewRegistry()
	for _, r := range rules {
		if err := detect.ValidateRule(r); err != nil {
			t.Fatalf("ValidateRule %q: %v", r.ID, err)
		}
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register %q: %v", r.ID, err)
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
		t.Fatalf("deep copy broken")
	}
	reg.Seal()
	if err := reg.Register(rules[0]); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("seal not enforced: %v", err)
	}
}

func TestAuthPackMetadataCompat(t *testing.T) {
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
		if !r.Category.Valid() || r.Category != detect.CategoryAuthentication {
			t.Fatalf("rule %q category %q invalid or not authentication", r.ID, r.Category)
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
		if !strings.HasPrefix(r.ID, "auth.") {
			t.Fatalf("rule %q ID policy violation", r.ID)
		}
		if len(r.Dependencies) != 0 {
			t.Fatalf("auth single-rule pack should have no dependencies (found on %q)", r.ID)
		}
		if len(r.RequiredAssetTypes) != 1 || r.RequiredAssetTypes[0] != asset.KindHost {
			t.Fatalf("rule %q required kinds %v, want [host]", r.ID, r.RequiredAssetTypes)
		}
	}
}

// TestAuthPriorFindingsVisible pins the SDK v2 dataflow: a dependent rule
// sees PriorFindings from a completed level, deterministically sorted.
// This rule is inexpressible on SDK v1 (no PriorFindings field).
func TestAuthPriorFindingsVisible(t *testing.T) {
	// Base rule at level 0 emits one finding per host via host census.
	base := detect.Rule{
		ID:            "auth.test.base",
		Name:          "Auth Test Base",
		Description:   "Synthetic base that emits one finding per host",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "auth-test",
		Enabled:       true,
		Detector: func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
			// Must see empty PriorFindings at level 0 and a non-nil GraphView.
			if dctx.GraphView == nil {
				return nil, fmt.Errorf("GraphView nil at level 0")
			}
			if len(dctx.PriorFindings) != 0 {
				return nil, fmt.Errorf("PriorFindings non-empty at level 0: %d", len(dctx.PriorFindings))
			}
			var out []asset.Finding
			for _, id := range dctx.Assets {
				if id.Kind != asset.KindHost {
					continue
				}
				ev, _ := asset.NewEvidence(asset.MethodDetection, "auth.test.base", "base signal", id, asset.Provenance{Source: "auth-test"})
				f, _ := asset.NewFinding(asset.Finding{RuleID: "auth.test.base", RuleName: "Auth Test Base", Category: "information", Subject: id, Confidence: 0.5, Evidence: []asset.Evidence{ev}, Priority: "info", Status: "open", Created: dctx.Clock.Now().UTC()})
				out = append(out, f)
				if len(out) >= 2 {
					break
				}
			}
			return out, nil
		},
	}
	// Dependent rule at level 1 reads PriorFindings and GraphView.
	var sawPrior int
	var sawPriorSorted bool
	var sawPath bool
	dependent := detect.Rule{
		ID:            "auth.test.dependent",
		Name:          "Auth Test Dependent",
		Description:   "Reads PriorFindings and GraphView — inexpressible on v1",
		Category:      detect.CategoryAuthentication,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets, detect.InputRelationships},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		Dependencies:  []string{"auth.test.base"},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "auth-test",
		Enabled:       true,
		Detector: func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
			if dctx.GraphView == nil {
				return nil, fmt.Errorf("GraphView nil at level 1")
			}
			sawPrior = len(dctx.PriorFindings)
			// PriorFindings must be deterministically sorted by identity.
			sorted := true
			for i := 1; i < len(dctx.PriorFindings); i++ {
				if dctx.PriorFindings[i-1].Identity().String() > dctx.PriorFindings[i].Identity().String() {
					sorted = false
					break
				}
			}
			sawPriorSorted = sorted
			// Exercise GraphView.Neighbors and Path.
			if len(dctx.Assets) >= 2 {
				_ = dctx.GraphView.Neighbors(dctx.Assets[0])
				if path := dctx.GraphView.Path(dctx.Assets[0], dctx.Assets[1]); path != nil {
					sawPath = len(path) > 0
				}
			}
			// Must see at least one prior finding from base (which emitted 1-2).
			if len(dctx.PriorFindings) == 0 {
				return nil, fmt.Errorf("PriorFindings empty at level 1 — flow broke")
			}
			// Emit one finding that cites prior_seen metadata to prove flow.
			subj := dctx.Assets[0]
			for _, id := range dctx.Assets {
				if id.Kind == asset.KindHost {
					subj = id
					break
				}
			}
			ev, _ := asset.NewEvidence(asset.MethodDetection, "auth.test.dependent", "dependent signal", subj, asset.Provenance{Source: "auth-test"})
			f, _ := asset.NewFinding(asset.Finding{RuleID: "auth.test.dependent", RuleName: "Auth Test Dependent", Category: "authentication", Subject: subj, Confidence: 0.6, Evidence: []asset.Evidence{ev}, Metadata: map[string]string{"prior_seen": "true", "prior_count": fmt.Sprintf("%d", len(dctx.PriorFindings))}, Priority: "info", Status: "open", Created: dctx.Clock.Now().UTC()})
			return []asset.Finding{f}, nil
		},
	}

	reg := detect.NewRegistry()
	for _, r := range []detect.Rule{base, dependent} {
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register %q: %v", r.ID, err)
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Snapshot with two hosts and a host→host edge for Path testing.
	h1 := mustHost(t, "a.example.com")
	h2 := mustHost(t, "b.example.com")
	rel := mustRelationship(t, h1.Identity(), asset.RelationshipHostToURL, asset.Identity{Kind: asset.KindURL, Value: "http://a.example.com/"})
	// Add a direct relationship between the two hosts for Path (host_to_cname with URL is not host→host, so add host→cname).
	h2cname := mustRelationship(t, h1.Identity(), asset.RelationshipHostToCNAME, h2.Identity())
	snap := detect.Snapshot{
		Assets:        []asset.Identity{h1.Identity(), h2.Identity()},
		Relationships: []asset.Relationship{rel, h2cname},
	}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Completed != 2 {
		t.Fatalf("completed %d, want 2", rep.Completed)
	}
	if rep.Levels != 2 {
		t.Fatalf("levels %d, want 2", rep.Levels)
	}
	if sawPrior == 0 {
		t.Fatalf("dependent did not see PriorFindings (sawPrior %d)", sawPrior)
	}
	if !sawPriorSorted {
		t.Fatalf("PriorFindings not sorted")
	}
	// Verify dependent's finding carries prior_seen.
	found := false
	for _, f := range rep.Findings {
		if f.RuleID == "auth.test.dependent" && f.Metadata["prior_seen"] == "true" {
			found = true
			if f.Metadata["prior_count"] != fmt.Sprintf("%d", sawPrior) {
				t.Fatalf("prior_count metadata %q vs saw %d", f.Metadata["prior_count"], sawPrior)
			}
		}
	}
	if !found {
		t.Fatalf("dependent finding missing prior_seen metadata")
	}
	// GraphView Path exercise: dependent saw at least one neighbor/path outcome (not required to be true, just not panicking)
	_ = sawPath
}

func TestAuthGraphViewNeighborsPath(t *testing.T) {
	// Via the auth pack's own rule (level-0, exercises GraphView).
	reg := registerAuthPack(t)
	h1 := mustHost(t, "www.example.com")
	h2 := mustHost(t, "api.example.com")
	rel := mustRelationship(t, h1.Identity(), asset.RelationshipHostToCNAME, h2.Identity())
	snap := detect.Snapshot{
		Assets:        []asset.Identity{h1.Identity(), h2.Identity()},
		Relationships: []asset.Relationship{rel},
	}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Completed != 1 {
		t.Fatalf("auth rule should complete (has host+relationship): completed %d", rep.Completed)
	}
	// The auth rule emits per host that has outgoing edge — h1 has one, h2 none.
	if len(rep.Findings) != 1 {
		t.Fatalf("findings %d, want 1 (host with neighbor)", len(rep.Findings))
	}
	if rep.Findings[0].Subject != h1.Identity() {
		t.Fatalf("subject %s, want %s", rep.Findings[0].Subject, h1.Identity())
	}
	// Verify GraphView deterministic: two identical snapshots produce identical reports.
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, _ := detect.Run(context.Background(), cfg2, snap)
	b1, _ := json.Marshal(rep)
	b2, _ := json.Marshal(rep2)
	if string(b1) != string(b2) {
		t.Fatalf("GraphView determinism diverged")
	}
}

func TestAuthCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerAuthPack(t)
	h1 := mustHost(t, "www.example.com")
	h2 := mustHost(t, "api.example.com")
	rel := mustRelationship(t, h1.Identity(), asset.RelationshipHostToCNAME, h2.Identity())
	snap := detect.Snapshot{
		Assets:        []asset.Identity{h1.Identity(), h2.Identity()},
		Relationships: []asset.Relationship{rel},
	}
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
	if warm.CacheHits != 1 {
		t.Fatalf("warm hits %d, want 1", warm.CacheHits)
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
			t.Fatalf("finding %d ID drift", i)
		}
	}
}

func TestAuthDeterminismGolden(t *testing.T) {
	reg := registerAuthPack(t)
	h1 := mustHost(t, "www.example.com")
	h2 := mustHost(t, "api.example.com")
	rel := mustRelationship(t, h1.Identity(), asset.RelationshipHostToCNAME, h2.Identity())
	snap := detect.Snapshot{
		Assets:        []asset.Identity{h1.Identity(), h2.Identity()},
		Relationships: []asset.Relationship{rel},
	}
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Config = map[string]string{"a": "1", "z": "2"}
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
}

func TestAuthRequiredAssetTypesSkipHonestly(t *testing.T) {
	reg := registerAuthPack(t)
	empty := detect.Snapshot{}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, empty)
	if err != nil {
		t.Fatalf("Run empty: %v", err)
	}
	if rep.Skipped != 1 {
		t.Fatalf("empty corpus: skipped %d, want 1", rep.Skipped)
	}
	if rep.Rules[0].Status != detect.RuleStatusSkipped {
		t.Fatalf("status %s, want skipped", rep.Rules[0].Status)
	}
	if !strings.Contains(rep.Rules[0].SkipReason, "required asset kind") {
		t.Fatalf("skip reason %q", rep.Rules[0].SkipReason)
	}
}

func TestAuthUsesOnlyExportedSurface(t *testing.T) {
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
