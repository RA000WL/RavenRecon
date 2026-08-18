// Package detect_test is the external test package of the detection
// framework: it can use ONLY the exported SDK surface, so the Example
// functions below double as the milestone proof that the SDK examples
// compile and run against the released interfaces (they are executed by go
// test and their output is compared against the "Output:" comments).
package detect_test

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// ExampleDetector shows the minimal shape of a rule: immutable metadata plus
// a Detector that reads the Context and returns one canonical finding about
// the first corpus asset. A finding is built through asset.NewFinding with
// the rule's own ID, name, and category, a subject drawn from the observed
// corpus, and at least one evidence record observed on that subject.
func ExampleDetector() {
	det := func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(dctx.Assets) == 0 {
			return nil, nil
		}
		subject := dctx.Assets[0]
		ev, err := asset.NewEvidence(asset.MethodDetection, "example.detector",
			"observed corpus asset", subject, asset.Provenance{Source: "example"})
		if err != nil {
			return nil, err
		}
		f, err := asset.NewFinding(asset.Finding{
			RuleID:     "example.detector",
			RuleName:   "Example Detector",
			Category:   detect.CategoryDiscovery.String(),
			Subject:    subject,
			Confidence: 0.9,
			Evidence:   []asset.Evidence{ev},
			Priority:   detect.PriorityInfo.String(),
			Status:     detect.StatusOpen.String(),
			Created:    dctx.Clock.Now().UTC(),
		})
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}

	u, err := asset.ParseURL("https://example.com/", asset.Provenance{Source: "example"})
	if err != nil {
		fmt.Println("parse url:", err)
		return
	}
	reg := detect.NewRegistry()
	err = reg.Register(detect.Rule{
		ID:            "example.detector",
		Name:          "Example Detector",
		Description:   "Minimal SDK example: reports the first corpus asset.",
		Category:      detect.CategoryDiscovery,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       time.Second,
		Author:        "RavenRecon SDK examples",
		Enabled:       true,
		Detector:      det,
	})
	if err != nil {
		fmt.Println("register:", err)
		return
	}
	rep, err := detect.Run(context.Background(), detect.DefaultEngineConfig(reg),
		detect.Snapshot{Assets: []asset.Identity{u.Identity()}})
	if err != nil {
		fmt.Println("run:", err)
		return
	}
	fmt.Printf("outcome %s, findings %d\n", rep.Outcome, len(rep.Findings))
	// Output: outcome completed, findings 1
}

// ExampleRegistry_Register shows the startup pattern: rules are registered,
// the registry is sealed to confine registration to startup, and any later
// registration fails with the documented error.
func ExampleRegistry_Register() {
	reg := detect.NewRegistry()
	for _, id := range []string{"example.one", "example.two"} {
		if err := reg.Register(exampleRule(id)); err != nil {
			fmt.Println("register:", err)
			return
		}
	}
	reg.Seal()
	err := reg.Register(exampleRule("example.three"))
	fmt.Printf("registered %d; late register: %v\n", reg.Len(), err)
	// Output: registered 2; late register: detect: registry is sealed
}

// ExampleRun shows a complete end-to-end run: a tiny corpus snapshot, a
// registered rule, and cache-before-execute through a real filesystem cache
// — the second run is served entirely from the cache (zero detector
// executions).
func ExampleRun() {
	u, err := asset.ParseURL("https://example.com/", asset.Provenance{Source: "example"})
	if err != nil {
		fmt.Println("parse url:", err)
		return
	}
	reg := detect.NewRegistry()
	if err := reg.Register(exampleRule("example.run")); err != nil {
		fmt.Println("register:", err)
		return
	}

	dir, err := os.MkdirTemp("", "ravenrecon-example-run")
	if err != nil {
		fmt.Println("temp dir:", err)
		return
	}
	defer os.RemoveAll(dir)
	fs, err := cache.Open(dir)
	if err != nil {
		fmt.Println("cache open:", err)
		return
	}

	cfg := detect.DefaultEngineConfig(reg)
	cfg.Cache = fs
	snap := detect.Snapshot{Assets: []asset.Identity{u.Identity()}}
	if _, err := detect.Run(context.Background(), cfg, snap); err != nil {
		fmt.Println("cold run:", err)
		return
	}
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		fmt.Println("warm run:", err)
		return
	}
	fmt.Printf("outcome %s, findings %d, cache hits %d\n", rep.Outcome, len(rep.Findings), rep.CacheHits)
	// Output: outcome completed, findings 1, cache hits 1
}

// exampleRule builds a minimal valid rule whose detector emits one
// informational finding about the first corpus asset.
func exampleRule(id string) detect.Rule {
	return detect.Rule{
		ID:            id,
		Name:          "Example rule " + id,
		Description:   "Synthetic rule for the SDK examples.",
		Category:      detect.CategoryInformation,
		Version:       "1.0.0",
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		EstimatedCost: detect.CostLow,
		Timeout:       time.Second,
		Author:        "RavenRecon SDK examples",
		Enabled:       true,
		Detector: func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if len(dctx.Assets) == 0 {
				return nil, nil
			}
			subject := dctx.Assets[0]
			ev, err := asset.NewEvidence(asset.MethodDetection, id,
				"observed corpus asset", subject, asset.Provenance{Source: "example"})
			if err != nil {
				return nil, err
			}
			f, err := asset.NewFinding(asset.Finding{
				RuleID:     id,
				RuleName:   "Example rule " + id,
				Category:   detect.CategoryInformation.String(),
				Subject:    subject,
				Confidence: 0.9,
				Evidence:   []asset.Evidence{ev},
				Priority:   detect.PriorityInfo.String(),
				Status:     detect.StatusOpen.String(),
				Created:    dctx.Clock.Now().UTC(),
			})
			if err != nil {
				return nil, err
			}
			return []asset.Finding{f}, nil
		},
	}
}
