package adapt

import (
	"context"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

func TestDetectStageWithJsPackLoadsJsPack(t *testing.T) {
	if got := len(pipeline.AllStages()); got != 12 {
		t.Fatalf("AllStages = %d, want 12 (packs must not mutate pipeline order)", got)
	}
	stage, err := NewDetectStageWithJsPack(nil)
	if err != nil {
		t.Fatalf("NewDetectStageWithJsPack(nil): %v", err)
	}
	if stage.Name() != pipeline.StageDetect {
		t.Fatalf("Name %q, want %q", stage.Name(), pipeline.StageDetect)
	}
	js, err := asset.NewJavaScript("https://www.example.com/app_xss.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	in := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Hosts:   []asset.Host{mustHost(t, "www.example.com")},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	in.Results.JavaScript = []asset.JavaScript{js}
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemsProcessed < 1 {
		t.Fatalf("ItemsProcessed %d, want >=1 (js pack should attempt at least one rule)", res.ItemsProcessed)
	}
	// nil→empty still holds: bare NewDetectStage(nil) with empty corpus+empty registry is vacuous completed.
	emptyIn := pipeline.StageInput{
		Target: mustDomain(t, "example.com"),
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res2, err := NewDetectStage(nil).Run(context.Background(), emptyIn)
	if err != nil {
		t.Fatalf("NewDetectStage(nil) empty: %v", err)
	}
	if res2.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("empty outcome %s, want completed (nil→empty)", res2.Outcome)
	}
	if res2.ItemsProcessed != 0 {
		t.Fatalf("empty ItemsProcessed %d, want 0", res2.ItemsProcessed)
	}
	// deepCopy→Validate→Seal: verify the helper path's registry is sealed and deep-copied.
	reg := detect.NewRegistry()
	if err := LoadJsPack(reg); err != nil {
		t.Fatalf("LoadJsPack for deepCopy check: %v", err)
	}
	// Validate already called by LoadJsPack; re-validate should still pass.
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate after LoadJsPack: %v", err)
	}
	// Deep copy: Get returns a copy; mutating it must not affect registry.
	// Get a registered rule and try to mutate the copy; a second Get must be unchanged.
	got, ok := reg.Get("js.dom.xss")
	if !ok {
		t.Fatalf("js.dom.xss missing after LoadJsPack")
	}
	origID := got.ID
	got.ID = "mutated"
	got2, ok := reg.Get(origID)
	if !ok {
		t.Fatalf("Get after mutation missing")
	}
	if got2.ID != origID {
		t.Fatalf("deep copy broken: registry mutated through Get alias")
	}
}

func TestDetectStageWithAllPacksLoadsBoth(t *testing.T) {
	if got := len(pipeline.AllStages()); got != 12 {
		t.Fatalf("AllStages = %d, want 12", got)
	}
	reg := detect.NewRegistry()
	stage, err := NewDetectStageWithAllPacks(reg)
	if err != nil {
		t.Fatalf("NewDetectStageWithAllPacks: %v", err)
	}
	if reg.Len() != 14 {
		t.Fatalf("registry len %d, want 14 (5 web + 3 js + 3 apis + 3 cloud)", reg.Len())
	}
	if _, ok := reg.Get("web.csp.missing"); !ok {
		t.Fatalf("web.csp.missing missing (web family not loaded)")
	}
	if _, ok := reg.Get("js.dom.xss"); !ok {
		t.Fatalf("js.dom.xss missing (js family not loaded)")
	}
	if _, ok := reg.Get("js.postmessage.no-origin-check"); !ok {
		t.Fatalf("js.postmessage.no-origin-check missing")
	}
	if _, ok := reg.Get("js.prototype.pollution"); !ok {
		t.Fatalf("js.prototype.pollution missing")
	}
	if _, ok := reg.Get("api.openapi.exposed"); !ok {
		t.Fatalf("api.openapi.exposed missing (apis family not loaded)")
	}
	if _, ok := reg.Get("api.graphql.introspection"); !ok {
		t.Fatalf("api.graphql.introspection missing")
	}
	if _, ok := reg.Get("cloud.aws.key-indicator"); !ok {
		t.Fatalf("cloud.aws.key-indicator missing (cloud family not loaded)")
	}
	if _, ok := reg.Get("cloud.bucket.url"); !ok {
		t.Fatalf("cloud.bucket.url missing")
	}
	if _, ok := reg.Get("cloud.firebase.indicator"); !ok {
		t.Fatalf("cloud.firebase.indicator missing")
	}
	// Validate graph still passes after both packs.
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate after both packs: %v", err)
	}
	// Registry should be sealed.
	custom := detect.Rule{
		ID:            "custom.test.both",
		Name:          "Custom Both",
		Description:   "Custom test rule for Seal check",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       1000000000,
		Author:        "test",
		Enabled:       true,
		Detector:      func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) { return nil, nil },
	}
	if err := reg.Register(custom); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("sealed not enforced: %v", err)
	}
	// Stage should run with all four families: provide JS + host + endpoints +
	// evidence + a secret candidate so every pack has work (web.csp/hsts need
	// host, web.robots/apis need endpoint, web.sourcemap/js need javascript,
	// web.cors needs evidence, cloud.aws needs secrets, cloud.firebase needs
	// evidence, cloud.bucket needs endpoints).
	host := mustHost(t, "www.example.com")
	js, err := asset.NewJavaScript("https://www.example.com/app_xss.js", asset.Provenance{Source: "js-test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	ep, err := asset.NewEndpoint("GET", "https://www.example.com/api/v1/users/123", asset.Provenance{Source: "apis-test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	ev, err := asset.NewEvidence(asset.MethodHeader, "header:access-control-allow-origin", "*", host.Identity(), asset.Provenance{Source: "apis-test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	sec, err := asset.NewSecretCandidate(asset.SecretTypeGeneric, "synthetic-not-a-secret-value", host.Identity(), asset.Provenance{Source: "cloud-test"})
	if err != nil {
		t.Fatalf("NewSecretCandidate: %v", err)
	}
	in := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Hosts:   []asset.Host{host},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	in.Results.JavaScript = []asset.JavaScript{js}
	in.Results.Endpoints = []asset.Endpoint{ep}
	in.Results.Evidence = []asset.Evidence{ev}
	in.Results.Secrets = []asset.SecretCandidate{sec}
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run with both packs: %v", err)
	}
	if res.ItemsProcessed < 14 {
		t.Fatalf("ItemsProcessed %d, want 14 (all rules from all packs attempted)", res.ItemsProcessed)
	}
	// Also verify nil-registry path still yields 14 and is sealed.
	stage2, err := NewDetectStageWithAllPacks(nil)
	if err != nil {
		t.Fatalf("NewDetectStageWithAllPacks(nil): %v", err)
	}
	_ = stage2
	if got := len(pipeline.AllStages()); got != 12 {
		t.Fatalf("AllStages after nil AllPacks = %d, want 12", got)
	}
}

func TestLoadJsPackHelper(t *testing.T) {
	if got := len(pipeline.AllStages()); got != 12 {
		t.Fatalf("AllStages = %d, want 12", got)
	}
	reg := detect.NewRegistry()
	if err := LoadJsPack(reg); err != nil {
		t.Fatalf("LoadJsPack: %v", err)
	}
	if reg.Len() != 3 {
		t.Fatalf("len %d, want 3 (js pack)", reg.Len())
	}
	if _, ok := reg.Get("js.dom.xss"); !ok {
		t.Fatalf("js.dom.xss missing")
	}
	if _, ok := reg.Get("js.postmessage.no-origin-check"); !ok {
		t.Fatalf("js.postmessage.no-origin-check missing")
	}
	if _, ok := reg.Get("js.prototype.pollution"); !ok {
		t.Fatalf("js.prototype.pollution missing")
	}
	// Validate still passes (deepCopy→Validate).
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Deep copy: Get returns a copy; mutating it does not affect registry.
	got, ok := reg.Get("js.dom.xss")
	if !ok {
		t.Fatalf("Get js.dom.xss missing for deepCopy check")
	}
	got.ID = "mutated"
	got2, ok := reg.Get("js.dom.xss")
	if !ok || got2.ID != "js.dom.xss" {
		t.Fatalf("deep copy broken via Get alias: got2.ID=%q", got2.ID)
	}
	// Seal: further Register must fail.
	custom := detect.Rule{
		ID:            "custom.test.js",
		Name:          "Custom JS Test",
		Description:   "Custom",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       1000000000,
		Author:        "test",
		Enabled:       true,
		Detector:      func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) { return nil, nil },
	}
	if err := reg.Register(custom); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("sealed not enforced after LoadJsPack: %v", err)
	}
	if err := LoadJsPack(nil); err == nil {
		t.Fatalf("nil registry should fail")
	}
}

func TestLoadCloudPackHelper(t *testing.T) {
	if got := len(pipeline.AllStages()); got != 12 {
		t.Fatalf("AllStages = %d, want 12", got)
	}
	reg := detect.NewRegistry()
	if err := LoadCloudPack(reg); err != nil {
		t.Fatalf("LoadCloudPack: %v", err)
	}
	if reg.Len() != 3 {
		t.Fatalf("len %d, want 3 (cloud pack)", reg.Len())
	}
	if _, ok := reg.Get("cloud.aws.key-indicator"); !ok {
		t.Fatalf("cloud.aws.key-indicator missing")
	}
	if _, ok := reg.Get("cloud.bucket.url"); !ok {
		t.Fatalf("cloud.bucket.url missing")
	}
	if _, ok := reg.Get("cloud.firebase.indicator"); !ok {
		t.Fatalf("cloud.firebase.indicator missing")
	}
	// Validate still passes (deepCopy→Validate).
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Deep copy: Get returns a copy; mutating it does not affect registry.
	got, ok := reg.Get("cloud.aws.key-indicator")
	if !ok {
		t.Fatalf("Get cloud.aws.key-indicator missing for deepCopy check")
	}
	got.ID = "mutated"
	got2, ok := reg.Get("cloud.aws.key-indicator")
	if !ok || got2.ID != "cloud.aws.key-indicator" {
		t.Fatalf("deep copy broken via Get alias: got2.ID=%q", got2.ID)
	}
	// Seal: further Register must fail.
	custom := detect.Rule{
		ID:            "custom.test.cloud",
		Name:          "Custom Cloud Test",
		Description:   "Custom",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       1000000000,
		Author:        "test",
		Enabled:       true,
		Detector:      func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) { return nil, nil },
	}
	if err := reg.Register(custom); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("sealed not enforced after LoadCloudPack: %v", err)
	}
	if err := LoadCloudPack(nil); err == nil {
		t.Fatalf("nil registry should fail")
	}
	stage, err := NewDetectStageWithCloudPack(nil)
	if err != nil {
		t.Fatalf("NewDetectStageWithCloudPack(nil): %v", err)
	}
	if stage.Name() != pipeline.StageDetect {
		t.Fatalf("Name %q, want %q", stage.Name(), pipeline.StageDetect)
	}
}
