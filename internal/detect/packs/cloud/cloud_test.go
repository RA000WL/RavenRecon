package cloud

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
	h, err := asset.NewHost(name, asset.Provenance{Source: "cloud-test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

func mustEndpoint(t testing.TB, method, rawURL string) asset.Endpoint {
	t.Helper()
	ep, err := asset.NewEndpoint(method, rawURL, asset.Provenance{Source: "cloud-test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return ep
}

func mustEvidence(t testing.TB, method asset.DetectionMethod, indicator, value string, source asset.Identity) asset.Evidence {
	t.Helper()
	ev, err := asset.NewEvidence(method, indicator, value, source, asset.Provenance{Source: "cloud-test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	return ev
}

func mustTechnology(t testing.TB, name string, cat asset.TechnologyCategory) asset.Technology {
	t.Helper()
	tech, err := asset.NewTechnology(name, cat, asset.Provenance{Source: "cloud-test"})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	return tech
}

func mustSecret(t testing.TB, typ asset.SecretType, value string, source asset.Identity) asset.SecretCandidate {
	t.Helper()
	sec, err := asset.NewSecretCandidate(typ, value, source, asset.Provenance{Source: "cloud-test"})
	if err != nil {
		t.Fatalf("NewSecretCandidate: %v", err)
	}
	return sec
}

// Synthetic fixtures only: AKIAABCDEFGHIJKLMNOP is a shape-valid but
// non-real access-key ID used across this repo's tests; EXAMPLE-convention
// values are AWS's own published examples.
const (
	syntheticKeyID = "AKIAABCDEFGHIJKLMNOP"
	exampleKeyID   = "AKIAIOSFODNN7EXAMPLE" // AWS documented example; suppressed
)

func buildAWSKeySnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	host := mustHost(t, "www.example.com")
	sec := mustSecret(t, asset.SecretTypeAWS, syntheticKeyID, host.Identity())
	return detect.Snapshot{Secrets: []asset.SecretCandidate{sec}}
}

func buildBucketSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://data.example.com.s3.amazonaws.com/backup.zip")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func buildFirebaseSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	host := mustHost(t, "www.example.com")
	ev := mustEvidence(t, asset.MethodHeader, "header:x-firebase-database",
		"https://synthetic-demo.firebaseio.com/.json", host.Identity())
	return detect.Snapshot{Evidence: []asset.Evidence{ev}}
}

func buildSafeSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	ep := mustEndpoint(t, "GET", "https://www.example.com/api/v1/health")
	return detect.Snapshot{Endpoints: []asset.Endpoint{ep}}
}

func buildMixedSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	host := mustHost(t, "www.example.com")
	ep1 := mustEndpoint(t, "GET", "https://www.example.com/")
	ep2 := mustEndpoint(t, "GET", "https://media.example.com.s3.amazonaws.com/assets.tar.gz")
	sec := mustSecret(t, asset.SecretTypeAWS, syntheticKeyID, host.Identity())
	ev1 := mustEvidence(t, asset.MethodJS, "js:synthetic-config-blob",
		`access_key: "`+syntheticKeyID+`"`, host.Identity())
	ev2 := mustEvidence(t, asset.MethodHeader, "header:x-firebase-database",
		"https://synthetic-demo.firebaseio.com/.json", host.Identity())
	return detect.Snapshot{
		Assets:    []asset.Identity{host.Identity()},
		Endpoints: []asset.Endpoint{ep1, ep2},
		Secrets:   []asset.SecretCandidate{sec},
		Evidence:  []asset.Evidence{ev1, ev2},
	}
}

func registerCloudPack(t testing.TB) *detect.Registry {
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

func TestCloudPackCheckAPIVersion(t *testing.T) {
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

func TestCloudPackLoadsThroughSDK(t *testing.T) {
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
	if got.RequiredAssetTypes[0] != asset.KindSecretCandidate {
		t.Fatalf("deep copy broken: RequiredAssetTypes slice aliasing")
	}
	reg.Seal()
	if err := reg.Register(rules[0]); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("seal not enforced: %v", err)
	}
}

func TestCloudPackMetadataDepsCompat(t *testing.T) {
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
		if !r.Category.Valid() || r.Category != detect.CategoryCloud {
			t.Fatalf("rule %q category %q invalid or not cloud", r.ID, r.Category)
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
		if len(r.RequiredAssetTypes) != 1 {
			t.Fatalf("rule %q required kinds %v, want exactly one primary kind", r.ID, r.RequiredAssetTypes)
		}
		if !strings.HasPrefix(r.ID, "cloud.") {
			t.Fatalf("rule %q ID policy violation", r.ID)
		}
		if len(r.Dependencies) > 0 {
			t.Fatalf("cloud pack should have no dependencies for now (found on %q)", r.ID)
		}
	}
}

func TestCloudPackRequiredAssetTypesSkipHonestly(t *testing.T) {
	reg := registerCloudPack(t)
	empty := detect.Snapshot{}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, empty)
	if err != nil {
		t.Fatalf("Run empty: %v", err)
	}
	if rep.Skipped != 3 {
		t.Fatalf("empty corpus: skipped %d, want 3 (each rule requires its primary kind)", rep.Skipped)
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
	// Endpoint-only corpus: bucket rule runs (completes with zero findings —
	// the host is not a storage endpoint), the other two skip honestly.
	safeSnap := buildSafeSnapshot(t)
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, safeSnap)
	if err != nil {
		t.Fatalf("Run safe: %v", err)
	}
	statuses := map[string]detect.RuleStatus{}
	for _, r := range rep2.Rules {
		statuses[r.RuleID] = r.Status
	}
	if statuses[ruleBucketURL] != detect.RuleStatusCompleted {
		t.Fatalf("bucket rule status %s on endpoint-only corpus, want completed", statuses[ruleBucketURL])
	}
	if statuses[ruleAWSKeyIndicator] != detect.RuleStatusSkipped {
		t.Fatalf("aws rule status %s, want skipped (no secret candidates)", statuses[ruleAWSKeyIndicator])
	}
	if statuses[ruleFirebaseIndicator] != detect.RuleStatusSkipped {
		t.Fatalf("firebase rule status %s, want skipped (no evidence)", statuses[ruleFirebaseIndicator])
	}
	if len(rep2.Findings) != 0 {
		t.Fatalf("safe findings %d, want 0", len(rep2.Findings))
	}
}

func TestCloudPackDetectorsHonorContext(t *testing.T) {
	reg := registerCloudPack(t)
	snap := buildMixedSnapshot(t)
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

func TestCloudPackFailuresIsolated(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	panicRule := detect.Rule{
		ID:            "cloud.test.panic",
		Name:          "Test Panic",
		Description:   "Synthetic panicking rule for isolation test",
		Category:      detect.CategoryCloud,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputEndpoints},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2 * time.Second,
		Author:        "cloud-test",
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
		if r.RuleID == "cloud.test.panic" {
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

func TestCloudPackCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerCloudPack(t)
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

func TestCloudPackDeterminismGolden(t *testing.T) {
	reg := registerCloudPack(t)
	snap := buildMixedSnapshot(t)
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Config = map[string]string{"cloud.bucket.url.disabled": "false", "z": "2", "a": "1"}
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
	golden.Compare(t, "testdata/cloud_report.golden", b1)
}

func TestCloudPackAWSKeyIndicator(t *testing.T) {
	reg := registerCloudPack(t)
	host := mustHost(t, "www.example.com")
	typed := mustSecret(t, asset.SecretTypeAWS, syntheticKeyID, host.Identity())
	example := mustSecret(t, asset.SecretTypeAWS, exampleKeyID, host.Identity()) // suppressed
	mistyped := mustSecret(t, asset.SecretTypeGeneric, strings.ToUpper(syntheticKeyID)+"X", host.Identity())
	ev := mustEvidence(t, asset.MethodJS, "js:synthetic-config-blob",
		`access_key: "`+syntheticKeyID+`"`, host.Identity())
	snap := detect.Snapshot{
		Assets:    []asset.Identity{host.Identity()},
		Secrets:   []asset.SecretCandidate{typed, example, mistyped},
		Evidence:  []asset.Evidence{ev},
		Endpoints: []asset.Endpoint{mustEndpoint(t, "GET", "https://www.example.com/")},
	}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var awsFindings []asset.Finding
	for _, f := range rep.Findings {
		if f.RuleID == ruleAWSKeyIndicator {
			awsFindings = append(awsFindings, f)
			if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
				t.Fatalf("aws priority/status %s/%s", f.Priority, f.Status)
			}
			if f.Category != detect.CategoryCloud.String() {
				t.Fatalf("aws category %s, want cloud", f.Category)
			}
			if len(f.Evidence) == 0 {
				t.Fatalf("aws finding without evidence")
			}
			// The pack itself must never copy candidate material into its
			// own fields (the subject IDENTITY encoding is the asset model's
			// canonical representation of the observed asset).
			for _, ev := range f.Evidence {
				if strings.Contains(ev.Value, syntheticKeyID) || strings.Contains(ev.Indicator, syntheticKeyID) {
					t.Fatalf("aws finding evidence leaks candidate material")
				}
			}
			for k, v := range f.Metadata {
				if strings.Contains(k+v, syntheticKeyID) {
					t.Fatalf("aws finding metadata leaks candidate material")
				}
			}
		}
	}
	if len(awsFindings) != 2 {
		t.Fatalf("aws findings %d, want 2 (typed candidate + evidence source; example/mistyped suppressed)", len(awsFindings))
	}
	seenKinds := map[asset.Kind]string{}
	for _, f := range awsFindings {
		seenKinds[f.Subject.Kind] = f.Metadata["observed_in"]
		if seenKinds[f.Subject.Kind] == "" {
			t.Fatalf("aws finding missing observed_in metadata: %+v", f.Metadata)
		}
	}
	if seenKinds[asset.KindSecretCandidate] != "secret_candidate" || seenKinds[asset.KindHost] != "evidence" {
		t.Fatalf("carrier metadata wrong: %v", seenKinds)
	}
}

func TestCloudPackBucketURL(t *testing.T) {
	reg := registerCloudPack(t)
	snap := detect.Snapshot{Endpoints: []asset.Endpoint{
		mustEndpoint(t, "GET", "https://data.example.com.s3.amazonaws.com/backup.zip"),
		mustEndpoint(t, "GET", "https://s3.amazonaws.com/other-bucket/list"),
		mustEndpoint(t, "GET", "https://storage.googleapis.com/synthetic-bucket/file.txt"),
		mustEndpoint(t, "GET", "https://syntheticacct.blob.core.windows.net/container/blob"),
		mustEndpoint(t, "GET", "https://www.example.com/api/v1/health"),
	}}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	providers := map[string]string{}
	for _, f := range rep.Findings {
		if f.RuleID != ruleBucketURL {
			continue
		}
		if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
			t.Fatalf("bucket priority/status %s/%s", f.Priority, f.Status)
		}
		if f.Category != detect.CategoryCloud.String() {
			t.Fatalf("bucket category %s, want cloud", f.Category)
		}
		if f.Subject.Kind != asset.KindEndpoint {
			t.Fatalf("bucket subject kind %s, want endpoint", f.Subject.Kind)
		}
		p := f.Metadata["provider"]
		if p == "" {
			t.Fatalf("bucket finding missing provider metadata")
		}
		providers[f.Subject.Value] = p
	}
	if len(providers) != 4 {
		t.Fatalf("bucket findings %d, want 4 (one per storage shape; plain host excluded)", len(providers))
	}
	counts := map[string]int{"s3": 0, "gcs": 0, "azure": 0}
	for _, p := range providers {
		counts[p]++
	}
	if counts["s3"] != 2 || counts["gcs"] != 1 || counts["azure"] != 1 {
		t.Fatalf("provider split wrong: %v", counts)
	}
}

func TestCloudPackFirebaseIndicator(t *testing.T) {
	reg := registerCloudPack(t)
	host := mustHost(t, "www.example.com")
	snap := detect.Snapshot{
		Assets: []asset.Identity{host.Identity()},
		Endpoints: []asset.Endpoint{
			mustEndpoint(t, "GET", "https://synthetic-demo.firebaseio.com/.json"),
		},
		Technologies: []asset.Technology{mustTechnology(t, "Firebase", asset.CategoryStorage)},
		Evidence: []asset.Evidence{
			mustEvidence(t, asset.MethodHeader, "header:x-firebase-database",
				"https://synthetic-demo.firebaseio.com/.json", host.Identity()),
			mustEvidence(t, asset.MethodHTML, "body:text",
				"plain prose mentioning firebase without service hosts", host.Identity()),
		},
	}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var firebaseFindings int
	for _, f := range rep.Findings {
		if f.RuleID != ruleFirebaseIndicator {
			continue
		}
		firebaseFindings++
		if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
			t.Fatalf("firebase priority/status %s/%s", f.Priority, f.Status)
		}
		if f.Category != detect.CategoryCloud.String() {
			t.Fatalf("firebase category %s, want cloud", f.Category)
		}
		switch f.Metadata["carrier"] {
		case "endpoint", "technology", "evidence":
		default:
			t.Fatalf("firebase carrier metadata %q invalid", f.Metadata["carrier"])
		}
	}
	// Three subjects fire: the firebaseio endpoint, the technology, and the
	// evidence SOURCE host. Plain-prose evidence mentions do NOT add a fourth
	// (the same host dedupes; free-text "firebase" values never fire alone).
	if firebaseFindings != 3 {
		t.Fatalf("firebase findings %d, want 3", firebaseFindings)
	}
}

func TestCloudPackMixedPerRule(t *testing.T) {
	reg := registerCloudPack(t)
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
	if counts[ruleAWSKeyIndicator] != 2 {
		t.Fatalf("aws %d, want 2 (candidate + evidence source)", counts[ruleAWSKeyIndicator])
	}
	if counts[ruleBucketURL] != 1 {
		t.Fatalf("bucket %d, want 1", counts[ruleBucketURL])
	}
	if counts[ruleFirebaseIndicator] != 1 {
		t.Fatalf("firebase %d, want 1", counts[ruleFirebaseIndicator])
	}
}

func TestCloudPackConfigDeterministic(t *testing.T) {
	reg := registerCloudPack(t)
	snap := buildBucketSnapshot(t)
	cfgMap1 := map[string]string{"cloud.bucket.url.disabled": "false", "a": "1", "z": "2"}
	cfgMap2 := map[string]string{"z": "2", "cloud.bucket.url.disabled": "false", "a": "1"}
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
	cfg3.Config = map[string]string{"cloud.bucket.url.disabled": "true"}
	repCold, _ := detect.Run(context.Background(), cfg3, snap)
	cfg4 := detect.DefaultEngineConfig(reg)
	cfg4.Clock = testClock
	cfg4.Cache = fs
	cfg4.Config = map[string]string{"cloud.bucket.url.disabled": "true"}
	repWarm, _ := detect.Run(context.Background(), cfg4, snap)
	if repWarm.CacheHits == 0 {
		t.Fatalf("same config should be cache hit")
	}
	if repCold.FindingsTruncated || repWarm.FindingsTruncated {
		t.Fatalf("disabled rule must not report truncation")
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
