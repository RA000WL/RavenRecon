package adapt

import (
	"context"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

func TestDetectStageWithPacksLoadsWebPack(t *testing.T) {
	stage, err := NewDetectStageWithPacks(nil)
	if err != nil {
		t.Fatalf("NewDetectStageWithPacks(nil): %v", err)
	}
	if stage.Name() != pipeline.StageDetect {
		t.Fatalf("Name %q", stage.Name())
	}
	// Verify registry has 5 web rules via stage's underlying report.
	in := pipeline.StageInput{
		Target:  mustDomain(t, "example.com"),
		Domains: []asset.Domain{mustDomain(t, "example.com")},
		Hosts:   []asset.Host{mustHost(t, "www.example.com")},
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
	}
	res, err := stage.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// With a host and no WC/CSP/etc, at least CSP/HSTS will fire, so ItemsProcessed should be 5 (all attempted) or at least 2.
	if res.ItemsProcessed < 2 {
		t.Fatalf("ItemsProcessed %d, want >=2", res.ItemsProcessed)
	}
}

func TestDetectStageWithPacksProvidedRegistry(t *testing.T) {
	reg := detect.NewRegistry()
	// Pre-register a custom rule.
	custom := detect.Rule{
		ID:            "custom.test",
		Name:          "Custom Test",
		Description:   "Custom",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       2000000000,
		Author:        "test",
		Enabled:       true,
		Detector:      func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) { return nil, nil },
	}
	if err := reg.Register(custom); err != nil {
		t.Fatalf("Register custom: %v", err)
	}
	stage, err := NewDetectStageWithPacks(reg)
	if err != nil {
		t.Fatalf("NewDetectStageWithPacks: %v", err)
	}
	if reg.Len() != 6 {
		t.Fatalf("registry len %d, want 6 (1 custom +5 web)", reg.Len())
	}
	if _, ok := reg.Get("web.csp.missing"); !ok {
		t.Fatalf("web.csp.missing missing")
	}
	// Registry should be sealed.
	if err := reg.Register(custom); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("sealed not enforced: %v", err)
	}
	_ = stage
}

func TestDetectStageEmptyStillEmpty(t *testing.T) {
	// Original behavior: nil → empty registry → vacuous completed when empty corpus.
	in := pipeline.StageInput{
		Target: mustDomain(t, "example.com"),
		Bounds: pipeline.DefaultStageConfig(),
		Clock:  fixedClock{now: fixedTime},
	}
	res, err := NewDetectStage(nil).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("NewDetectStage(nil) empty: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("empty outcome %s", res.Outcome)
	}
	if res.ItemsProcessed != 0 {
		t.Fatalf("ItemsProcessed %d", res.ItemsProcessed)
	}
}

func TestLoadWebPackHelper(t *testing.T) {
	reg := detect.NewRegistry()
	if err := LoadWebPack(reg); err != nil {
		t.Fatalf("LoadWebPack: %v", err)
	}
	if reg.Len() != 5 {
		t.Fatalf("len %d", reg.Len())
	}
	if err := LoadWebPack(nil); err == nil {
		t.Fatalf("nil registry should fail")
	}
}
