package takeover

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
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
)

// fixedClock pins Now to a constant for deterministic reports.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time                         { return c.at }
func (c fixedClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

var testClock = fixedClock{at: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)}

func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "takeover-test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

func mustEndpoint(t testing.TB, method, rawURL string) asset.Endpoint {
	t.Helper()
	ep, err := asset.NewEndpoint(method, rawURL, asset.Provenance{Source: "takeover-test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return ep
}

func mustRelationship(t testing.TB, from asset.Identity, kind asset.RelationshipKind, to asset.Identity) asset.Relationship {
	t.Helper()
	rel, err := asset.NewRelationship(from, kind, to)
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	return rel
}

// buildUnclaimedSnapshot returns a corpus with a host that CNAMEs to an unclaimed provider and no IP for target.
func buildUnclaimedSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	src := mustHost(t, "sub.example.com")
	tgt := mustHost(t, "unclaimed.github.io")
	// Both hosts as assets (target is observed via DNS depth 1).
	cname := mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())
	return detect.Snapshot{
		Assets:        []asset.Identity{src.Identity(), tgt.Identity()},
		Relationships: []asset.Relationship{cname},
	}
}

// buildDanglingSnapshot returns a corpus with a host that CNAMEs to a generic dangling target (non-provider) and no IP.
func buildDanglingSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	src := mustHost(t, "legacy.example.com")
	tgt := mustHost(t, "old-service.example.net")
	cname := mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())
	return detect.Snapshot{
		Assets:        []asset.Identity{src.Identity(), tgt.Identity()},
		Relationships: []asset.Relationship{cname},
	}
}

// buildNonDanglingSnapshot returns a corpus where CNAME target has an IP (not dangling).
func buildNonDanglingSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	src := mustHost(t, "www.example.com")
	tgt := mustHost(t, "claimed.github.io")
	cname := mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())
	tgtIP, err := asset.NewIP("192.0.2.1", asset.Provenance{Source: "takeover-test"})
	if err != nil {
		t.Fatalf("NewIP: %v", err)
	}
	ipRel := mustRelationship(t, tgt.Identity(), asset.RelationshipHostToIP, tgtIP.Identity())
	return detect.Snapshot{
		Assets:        []asset.Identity{src.Identity(), tgt.Identity(), tgtIP.Identity()},
		Relationships: []asset.Relationship{cname, ipRel},
	}
}

// buildS3Snapshot returns a corpus with an S3 bucket endpoint.
func buildS3Snapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://my-bucket.s3.amazonaws.com/backup.zip")
	return detect.Snapshot{
		Endpoints: []asset.Endpoint{ep},
	}
}

// buildMixedSnapshot returns a corpus that triggers all three takeover rules.
func buildMixedSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	src1 := mustHost(t, "takeover1.example.com")
	tgt1 := mustHost(t, "unclaimed.herokuapp.com")
	cname1 := mustRelationship(t, src1.Identity(), asset.RelationshipHostToCNAME, tgt1.Identity())
	src2 := mustHost(t, "takeover2.example.com")
	tgt2 := mustHost(t, "dangling.example.net")
	cname2 := mustRelationship(t, src2.Identity(), asset.RelationshipHostToCNAME, tgt2.Identity())
	ep := mustEndpoint(t, "GET", "https://assets.example.com.s3.amazonaws.com/file.txt")
	return detect.Snapshot{
		Assets: []asset.Identity{
			src1.Identity(), tgt1.Identity(),
			src2.Identity(), tgt2.Identity(),
		},
		Relationships: []asset.Relationship{cname1, cname2},
		Endpoints:     []asset.Endpoint{ep},
	}
}

// buildSafeSnapshot returns a corpus with no takeover signals.
func buildSafeSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	h := mustHost(t, "www.example.com")
	ep := mustEndpoint(t, "GET", "https://www.example.com/api/v1/health")
	return detect.Snapshot{
		Assets:    []asset.Identity{h.Identity()},
		Endpoints: []asset.Endpoint{ep},
	}
}

func registerTakeoverPack(t testing.TB) *detect.Registry {
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

func TestTakeoverPackCheckAPIVersion(t *testing.T) {
	if err := detect.CheckAPIVersion(2, 0); err != nil {
		t.Fatalf("CheckAPIVersion(2,0): %v", err)
	}
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 4 {
		t.Fatalf("pack carries %d rules, want 4", len(rules))
	}
}

func TestTakeoverPackLoadsThroughSDK(t *testing.T) {
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
	if got.RequiredAssetTypes[0] != asset.KindHost {
		t.Fatalf("deep copy broken: RequiredAssetTypes aliasing, got %v", got.RequiredAssetTypes)
	}
	reg.Seal()
	if err := reg.Register(rules[0]); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("seal not enforced: %v", err)
	}
}

func TestTakeoverPackMetadataDepsCompat(t *testing.T) {
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
		if !strings.HasPrefix(r.ID, "takeover.") {
			t.Fatalf("rule %q ID policy violation", r.ID)
		}
		if len(r.Dependencies) > 0 && r.ID != ruleCNAMEProviderConfirmed {
			t.Fatalf("only the provider-confirmed enrichment may carry dependencies (found on %q)", r.ID)
		}
		if r.ID == ruleCNAMEProviderConfirmed {
			if len(r.Dependencies) != 1 || r.Dependencies[0] != ruleCNAMEUnclaimed {
				t.Fatalf("enrichment dependencies %v, want [%s]", r.Dependencies, ruleCNAMEUnclaimed)
			}
		}
	}
	// Check required kinds.
	m := map[string]asset.Kind{
		ruleCNAMEUnclaimed:         asset.KindHost,
		ruleCNAMEDangling:          asset.KindHost,
		ruleS3Bucket:               asset.KindEndpoint,
		ruleCNAMEProviderConfirmed: asset.KindHost,
	}
	for _, r := range rules {
		want, ok := m[r.ID]
		if !ok {
			t.Fatalf("unexpected rule %q", r.ID)
		}
		if len(r.RequiredAssetTypes) != 1 || r.RequiredAssetTypes[0] != want {
			t.Fatalf("rule %q required kinds %v, want [%s]", r.ID, r.RequiredAssetTypes, want)
		}
	}
}

func TestTakeoverPackRequiredAssetTypesSkipHonestly(t *testing.T) {
	reg := registerTakeoverPack(t)
	empty := detect.Snapshot{}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, empty)
	if err != nil {
		t.Fatalf("Run empty: %v", err)
	}
	if rep.Skipped != 4 {
		t.Fatalf("empty corpus: skipped %d, want 4", rep.Skipped)
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
	// Host-only snapshot with no CNAME: cname rules complete with zero findings, s3 skipped.
	host := mustHost(t, "www.example.com")
	snap := detect.Snapshot{Assets: []asset.Identity{host.Identity()}}
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, snap)
	if err != nil {
		t.Fatalf("Run host: %v", err)
	}
	statuses := map[string]detect.RuleStatus{}
	for _, r := range rep2.Rules {
		statuses[r.RuleID] = r.Status
	}
	if statuses[ruleCNAMEUnclaimed] != detect.RuleStatusCompleted {
		t.Fatalf("cname.unclaimed status %s, want completed (has host, no trigger)", statuses[ruleCNAMEUnclaimed])
	}
	if statuses[ruleCNAMEDangling] != detect.RuleStatusCompleted {
		t.Fatalf("cname.dangling status %s, want completed", statuses[ruleCNAMEDangling])
	}
	if statuses[ruleS3Bucket] != detect.RuleStatusSkipped {
		t.Fatalf("s3.bucket status %s, want skipped (no endpoint)", statuses[ruleS3Bucket])
	}
	if statuses[ruleCNAMEProviderConfirmed] != detect.RuleStatusCompleted {
		t.Fatalf("provider-confirmed status %s, want completed (has host, silent without priors)", statuses[ruleCNAMEProviderConfirmed])
	}
	if len(rep2.Findings) != 0 {
		t.Fatalf("safe findings %d, want 0", len(rep2.Findings))
	}
}

func TestTakeoverPackDetectorsHonorContext(t *testing.T) {
	reg := registerTakeoverPack(t)
	snap := buildUnclaimedSnapshot(t)
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

func TestTakeoverPackFailuresIsolated(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	panicRule := detect.Rule{
		ID:            "takeover.test.panic",
		Name:          "Test Panic",
		Description:   "Synthetic panicking rule for isolation test",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "takeover-test",
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
		if r.RuleID == "takeover.test.panic" {
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

func TestTakeoverPackCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerTakeoverPack(t)
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

func TestTakeoverPackDeterminismGolden(t *testing.T) {
	reg := registerTakeoverPack(t)
	snap := buildMixedSnapshot(t)
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Config = map[string]string{"takeover.cname.unclaimed.disabled": "false", "a": "1", "z": "2"}
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
	golden.Compare(t, "testdata/takeover_report.golden", b1)
}

func TestTakeoverCNAMEUnclaimedEmits(t *testing.T) {
	reg := registerTakeoverPack(t)
	snap := buildUnclaimedSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var found int
	for _, f := range rep.Findings {
		if f.RuleID == ruleCNAMEUnclaimed {
			found++
			if f.Category != detect.CategoryInformation.String() {
				t.Fatalf("category %s, want information", f.Category)
			}
			if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
				t.Fatalf("priority/status %s/%s", f.Priority, f.Status)
			}
			if f.Subject.Kind != asset.KindHost {
				t.Fatalf("subject kind %s, want host", f.Subject.Kind)
			}
			if len(f.Evidence) == 0 || f.Evidence[0].Method != asset.MethodDetection {
				t.Fatalf("evidence method wrong")
			}
			if f.Metadata["provider"] == "" || f.Metadata["cname_target"] == "" {
				t.Fatalf("metadata missing provider/cname_target: %+v", f.Metadata)
			}
			if f.Metadata["signal"] != "takeover_cname_unclaimed" {
				t.Fatalf("signal %q", f.Metadata["signal"])
			}
		}
	}
	if found != 1 {
		t.Fatalf("unclaimed findings %d, want 1", found)
	}
	// Ensure dangling does NOT also fire on provider-matched host (sets disjoint).
	for _, f := range rep.Findings {
		if f.RuleID == ruleCNAMEDangling {
			t.Fatalf("dangling should not fire on provider-matched CNAME (unclaimed handles it)")
		}
	}
}

func TestTakeoverCNAMEDanglingEmits(t *testing.T) {
	reg := registerTakeoverPack(t)
	snap := buildDanglingSnapshot(t)
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
	if counts[ruleCNAMEDangling] != 1 {
		t.Fatalf("dangling findings %d, want 1", counts[ruleCNAMEDangling])
	}
	if counts[ruleCNAMEUnclaimed] != 0 {
		t.Fatalf("unclaimed should be 0 for non-provider dangling")
	}
}

func TestTakeoverCNAMENotFiringWhenHasIP(t *testing.T) {
	reg := registerTakeoverPack(t)
	snap := buildNonDanglingSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range rep.Findings {
		if f.RuleID == ruleCNAMEUnclaimed || f.RuleID == ruleCNAMEDangling {
			t.Fatalf("no CNAME finding expected when target has IP, got %q", f.RuleID)
		}
	}
}

func TestTakeoverS3BucketEmits(t *testing.T) {
	reg := registerTakeoverPack(t)
	snap := buildS3Snapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var found int
	for _, f := range rep.Findings {
		if f.RuleID == ruleS3Bucket {
			found++
			if f.Category != detect.CategoryInformation.String() {
				t.Fatalf("category %s", f.Category)
			}
			if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
				t.Fatalf("priority/status %s/%s", f.Priority, f.Status)
			}
			if f.Subject.Kind != asset.KindEndpoint {
				t.Fatalf("subject kind %s, want endpoint", f.Subject.Kind)
			}
			if f.Metadata["provider"] != "s3" {
				t.Fatalf("provider %q", f.Metadata["provider"])
			}
		}
	}
	if found != 1 {
		t.Fatalf("s3 findings %d, want 1", found)
	}
}

func TestTakeoverS3BucketNoFalsePositiveOnPlainHost(t *testing.T) {
	reg := registerTakeoverPack(t)
	ep := mustEndpoint(t, "GET", "https://www.example.com/api/v1/health")
	snap := detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range rep.Findings {
		if f.RuleID == ruleS3Bucket {
			t.Fatalf("s3 finding on plain host should be 0")
		}
	}
}

func TestTakeoverMixedPerRule(t *testing.T) {
	reg := registerTakeoverPack(t)
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
	if counts[ruleCNAMEUnclaimed] != 1 {
		t.Fatalf("unclaimed %d, want 1", counts[ruleCNAMEUnclaimed])
	}
	if counts[ruleCNAMEDangling] != 1 {
		t.Fatalf("dangling %d, want 1", counts[ruleCNAMEDangling])
	}
	if counts[ruleS3Bucket] != 1 {
		t.Fatalf("s3 %d, want 1", counts[ruleS3Bucket])
	}
	if counts[ruleCNAMEProviderConfirmed] != 1 {
		t.Fatalf("provider-confirmed %d, want 1 (sibling unclaimed + CNAME→provider graph edge)", counts[ruleCNAMEProviderConfirmed])
	}
}

func TestTakeoverConfigDeterministic(t *testing.T) {
	reg := registerTakeoverPack(t)
	snap := buildUnclaimedSnapshot(t)
	cfgMap1 := map[string]string{"takeover.cname.unclaimed.disabled": "false", "a": "1", "z": "2"}
	cfgMap2 := map[string]string{"z": "2", "takeover.cname.unclaimed.disabled": "false", "a": "1"}
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
	cfg3.Config = map[string]string{"takeover.cname.unclaimed.disabled": "true"}
	repCold, _ := detect.Run(context.Background(), cfg3, snap)
	cfg4 := detect.DefaultEngineConfig(reg)
	cfg4.Clock = testClock
	cfg4.Cache = fs
	cfg4.Config = map[string]string{"takeover.cname.unclaimed.disabled": "true"}
	repWarm, _ := detect.Run(context.Background(), cfg4, snap)
	if repWarm.CacheHits == 0 {
		t.Fatalf("same config should be cache hit")
	}
	if repCold.FindingsTruncated || repWarm.FindingsTruncated {
		t.Fatalf("disabled rule must not report truncation")
	}
}

func TestTakeoverBoundedAt256(t *testing.T) {
	reg := registerTakeoverPack(t)
	var rels []asset.Relationship
	var assets []asset.Identity
	for i := 0; i < 300; i++ {
		src := mustHost(t, fmt.Sprintf("sub%d.example.com", i))
		tgt := mustHost(t, fmt.Sprintf("unclaimed%d.github.io", i))
		assets = append(assets, src.Identity(), tgt.Identity())
		rels = append(rels, mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity()))
	}
	snap := detect.Snapshot{Assets: assets, Relationships: rels}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, r := range rep.Rules {
		if r.RuleID == ruleCNAMEUnclaimed {
			if r.Findings != 256 {
				t.Fatalf("unclaimed findings %d, want 256 capped", r.Findings)
			}
		}
	}
	foundTrunc := false
	for _, f := range rep.Findings {
		if f.RuleID == ruleCNAMEUnclaimed && f.Metadata["truncated"] == "true" {
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

// mustConfirmEvidence builds one confirmation evidence record for tests:
// the github-pages fingerprint observed on the subject host.
func mustConfirmEvidence(t testing.TB, subject asset.Identity) asset.Evidence {
	t.Helper()
	ev, err := httpprobe.TakeoverEvidence(subject, "github-pages", "There isn't a GitHub Pages site here.")
	if err != nil {
		t.Fatalf("TakeoverEvidence: %v", err)
	}
	return ev
}

func takeoverFindingsForRule(t testing.TB, snap detect.Snapshot, ruleID string) []asset.Finding {
	t.Helper()
	reg := registerTakeoverPack(t)
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

// TestTakeoverCNAMEConfirmedMeta pins NEW-122: a confirmed subject cites
// it (confirmed=true + provider), while an unconfirmed subject keeps
// its DNS-shape finding without confirmation keys (fail-open).
func TestTakeoverCNAMEConfirmedMeta(t *testing.T) {
	src := mustHost(t, "sub.example.com")
	tgt := mustHost(t, "unclaimed.github.io")
	cname := mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())
	base := detect.Snapshot{
		Assets:        []asset.Identity{src.Identity(), tgt.Identity()},
		Relationships: []asset.Relationship{cname},
	}
	confirmed := base
	confirmed.Evidence = []asset.Evidence{mustConfirmEvidence(t, src.Identity())}
	got := takeoverFindingsForRule(t, confirmed, ruleCNAMEUnclaimed)
	if len(got) != 1 {
		t.Fatalf("unclaimed findings = %d, want 1", len(got))
	}
	if got[0].Metadata["confirmed"] != "true" || got[0].Metadata["confirmed_provider"] != "github-pages" {
		t.Errorf("meta = %v, want confirmed=true + confirmed_provider=github-pages", got[0].Metadata)
	}
	// The DNS-suffix provider attribution must survive alongside.
	if got[0].Metadata["provider"] != "github.io" {
		t.Errorf("meta provider = %q, want github.io (DNS attribution preserved)", got[0].Metadata["provider"])
	}

	plain := takeoverFindingsForRule(t, base, ruleCNAMEUnclaimed)
	if len(plain) != 1 {
		t.Fatalf("unconfirmed findings = %d, want 1 (fail-open preserved)", len(plain))
	}
	if _, ok := plain[0].Metadata["confirmed"]; ok {
		t.Errorf("unconfirmed finding carries confirmed meta: %v", plain[0].Metadata)
	}
}

// TestTakeoverCNAMEConfirmedDangling pins the gate on the generic
// dangling rule (no provider suffix involved).
func TestTakeoverCNAMEConfirmedDangling(t *testing.T) {
	src := mustHost(t, "legacy.example.com")
	tgt := mustHost(t, "old-service.example.net")
	cname := mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())
	ev, err := httpprobe.TakeoverEvidence(src.Identity(), "heroku", "No such app")
	if err != nil {
		t.Fatalf("TakeoverEvidence: %v", err)
	}
	snap := detect.Snapshot{
		Assets:        []asset.Identity{src.Identity(), tgt.Identity()},
		Relationships: []asset.Relationship{cname},
		Evidence:      []asset.Evidence{ev},
	}
	got := takeoverFindingsForRule(t, snap, ruleCNAMEDangling)
	if len(got) != 1 {
		t.Fatalf("dangling findings = %d, want 1", len(got))
	}
	if got[0].Metadata["confirmed"] != "true" || got[0].Metadata["confirmed_provider"] != "heroku" {
		t.Errorf("meta = %v, want confirmed=true + confirmed_provider=heroku", got[0].Metadata)
	}
}

// TestTakeoverConfirmationForeignIgnored pins no cross-talk: foreign
// evidence never gates and never leaks confirmation keys.
func TestTakeoverConfirmationForeignIgnored(t *testing.T) {
	snap := buildUnclaimedSnapshot(t)
	foreign, err := asset.NewEvidence(asset.MethodEndpoint, "reflect:q", "reflected-unencoded",
		mustHost(t, "sub.example.com").Identity(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	snap.Evidence = []asset.Evidence{foreign}
	got := takeoverFindingsForRule(t, snap, ruleCNAMEUnclaimed)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1 (foreign evidence must not drop)", len(got))
	}
	if _, ok := got[0].Metadata["confirmed"]; ok {
		t.Errorf("confirmed meta present from foreign evidence: %v", got[0].Metadata)
	}
}

// TestTakeoverCNAMEVersions pins the content-bump contract: the gating
// meta changes findings, so both CNAME rules bump to 1.1.0 (old cached
// findings never replay); the untouched S3 rule stays 1.0.0.
func TestTakeoverCNAMEVersions(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	want := map[string]string{
		ruleCNAMEUnclaimed:         "1.1.0",
		ruleCNAMEDangling:          "1.1.0",
		ruleS3Bucket:               "1.0.0",
		ruleCNAMEProviderConfirmed: "1.0.0",
	}
	if len(rules) != len(want) {
		t.Fatalf("pack carries %d rules, want %d", len(rules), len(want))
	}
	for _, r := range rules {
		if want[r.ID] != r.Version {
			t.Errorf("rule %q version %q, want %q", r.ID, r.Version, want[r.ID])
		}
	}
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
