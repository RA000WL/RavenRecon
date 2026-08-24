package report

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/priority"
)

// richInteriorContext builds a deterministic Context with rich interior slices
// for deep-clone isolation testing: surfaces with Factors+Evidence, groups
// with Members/Factors/Evidence and SharedIndicators, attack paths with
// Steps+Evidence, and derived recommendations with Evidence.
func richInteriorContext(t *testing.T) Context {
	t.Helper()
	host := hostAsset(t, "www.example.com")
	otherHost := hostAsset(t, "api.example.com")
	url1 := urlAsset(t, "https://www.example.com/admin")
	url2 := urlAsset(t, "https://api.example.com/v1/users")

	surf1 := priority.SurfaceAsset{
		Identity:        url1.Identity(),
		Kind:            asset.KindURL,
		Score:           0.9,
		Level:           priority.LevelHigh,
		Interestingness: 0.6,
		Confidence:      0.5,
		Factors: []priority.Factor{
			{
				Name:           "interestingness:admin",
				Weight:         0.5,
				Evidence:       []string{url1.Identity().String(), host.Identity().String()},
				Reason:         "admin panel observed",
				Recommendation: "Inventory admin interfaces",
			},
			{
				Name:           "risk:exposed",
				Weight:         0.3,
				Evidence:       []string{url1.Identity().String()},
				Reason:         "exposed endpoint",
				Recommendation: "Review exposure",
			},
		},
		FirstSeen: fixedTime,
		ScoredAt:  fixedTime,
	}
	surf2 := priority.SurfaceAsset{
		Identity:        url2.Identity(),
		Kind:            asset.KindURL,
		Score:           0.7,
		Level:           priority.LevelMedium,
		Interestingness: 0.4,
		Confidence:      0.4,
		Factors: []priority.Factor{
			{
				Name:           "interestingness:admin",
				Weight:         0.4,
				Evidence:       []string{url2.Identity().String()},
				Reason:         "admin panel observed on api",
				Recommendation: "Inventory admin interfaces",
			},
		},
		FirstSeen: fixedTime,
		ScoredAt:  fixedTime,
	}

	group := priority.Group{
		Anchor:           host.Identity(),
		Members:          []priority.SurfaceAsset{surf1, surf2},
		SharedIndicators: []string{"interestingness:admin"},
		Score:            0.85,
		Confidence:       0.5,
		Level:            priority.LevelHigh,
	}

	attackPath := priority.AttackPath{
		Root: host.Identity(),
		Steps: []priority.PathStep{
			{
				Identity: host.Identity(),
				Kind:     asset.KindHost,
				Reason:   "correlation root: 2 surfaces group under this anchor",
				Evidence: []string{surf1.Identity.String(), surf2.Identity.String()},
			},
			{
				Identity:   surf1.Identity,
				Kind:       asset.KindURL,
				FactorName: "interestingness:admin",
				Reason:     "admin panel observed",
				Evidence:   []string{url1.Identity().String()},
			},
			{
				Identity:   surf2.Identity,
				Kind:       asset.KindURL,
				FactorName: "interestingness:admin",
				Reason:     "admin panel observed on api",
				Evidence:   []string{url2.Identity().String()},
			},
		},
		Score: 0.85,
		Level: priority.LevelHigh,
	}

	// Keep minimal corpus so digest stays stable; only the priority outputs
	// carry the interior slices under test.
	return Context{
		Target:      "example.com",
		StartedAt:   fixedTime,
		EndedAt:     fixedTime.Add(90 * 1000000000), // 90s
		Domains:     []asset.Domain{{Name: "example.com", Prov: fixedProv("discovery")}},
		Hosts:       []asset.Host{host, otherHost},
		URLs:        []asset.URL{url1, url2},
		Surfaces:    []priority.SurfaceAsset{surf1, surf2},
		Groups:      []priority.Group{group},
		AttackPaths: []priority.AttackPath{attackPath},
	}
}

// TestCloneModelDeepInteriorIsolation is a direct unit test for cloneModel's
// deep-copy guarantees: mutating a clone's interior slices must not affect the
// original Model. It covers every interior slice the reviewer flagged.
func TestCloneModelDeepInteriorIsolation(t *testing.T) {
	base := richInteriorContext(t)
	orig, err := NewModel(base)
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}

	// Capture expected values before cloning.
	if len(orig.Surfaces) == 0 || len(orig.Surfaces[0].Factors) == 0 || len(orig.Surfaces[0].Factors[0].Evidence) == 0 {
		t.Fatalf("precondition: surfaces/factors/evidence empty")
	}
	if len(orig.Groups) == 0 || len(orig.Groups[0].Members) == 0 || len(orig.Groups[0].Members[0].Factors) == 0 || len(orig.Groups[0].Members[0].Factors[0].Evidence) == 0 {
		t.Fatalf("precondition: groups/members/factors/evidence empty")
	}
	if len(orig.Groups[0].SharedIndicators) == 0 {
		t.Fatalf("precondition: shared indicators empty")
	}
	if len(orig.AttackPaths) == 0 || len(orig.AttackPaths[0].Steps) == 0 || len(orig.AttackPaths[0].Steps[0].Evidence) == 0 {
		t.Fatalf("precondition: attack path steps/evidence empty")
	}
	if len(orig.Recommendations) == 0 || len(orig.Recommendations[0].Evidence) == 0 {
		t.Fatalf("precondition: recommendations/evidence empty")
	}

	origSurfFactorName := orig.Surfaces[0].Factors[0].Name
	origSurfEvidence := orig.Surfaces[0].Factors[0].Evidence[0]
	origSurfFactorsLen := len(orig.Surfaces[0].Factors)
	origGroupShared := orig.Groups[0].SharedIndicators[0]
	origGroupMemberFactorName := orig.Groups[0].Members[0].Factors[0].Name
	origGroupMemberEvidence := orig.Groups[0].Members[0].Factors[0].Evidence[0]
	origAttackStepEvidence := orig.AttackPaths[0].Steps[0].Evidence[0]
	origRecEvidence := orig.Recommendations[0].Evidence[0]
	origRecLen := len(orig.Recommendations[0].Evidence)

	clone := cloneModel(orig)
	if clone == nil {
		t.Fatalf("cloneModel returned nil")
	}

	// Mutate clone's interior slices heavily.
	clone.Surfaces[0].Factors[0].Name = "evil-factor"
	clone.Surfaces[0].Factors[0].Evidence[0] = "evil-evidence"
	clone.Surfaces[0].Factors = append(clone.Surfaces[0].Factors, priority.Factor{Name: "injected", Weight: 0.1, Reason: "injected", Evidence: []string{"injected"}})

	clone.Groups[0].SharedIndicators[0] = "evil-indicator"
	clone.Groups[0].SharedIndicators = append(clone.Groups[0].SharedIndicators, "injected-indicator")
	clone.Groups[0].Members[0].Factors[0].Name = "evil-member-factor"
	clone.Groups[0].Members[0].Factors[0].Evidence[0] = "evil-member-evidence"
	clone.Groups[0].Members = append(clone.Groups[0].Members, clone.Groups[0].Members[0])

	clone.AttackPaths[0].Steps[0].Evidence[0] = "evil-step-evidence"
	clone.AttackPaths[0].Steps[1].Evidence[0] = "evil-step-evidence-2"
	clone.AttackPaths[0].Steps = append(clone.AttackPaths[0].Steps, priority.PathStep{Identity: clone.AttackPaths[0].Root, Reason: "injected", Evidence: []string{"injected"}})

	clone.Recommendations[0].Evidence[0] = "evil-rec-evidence"
	clone.Recommendations[0].Evidence = append(clone.Recommendations[0].Evidence, "injected-rec")

	// Assert original is untouched.

	// Surfaces
	if orig.Surfaces[0].Factors[0].Name != origSurfFactorName {
		t.Fatalf("surface factor name mutated in original: got %q want %q", orig.Surfaces[0].Factors[0].Name, origSurfFactorName)
	}
	if orig.Surfaces[0].Factors[0].Evidence[0] != origSurfEvidence {
		t.Fatalf("surface factor evidence mutated in original: got %q want %q", orig.Surfaces[0].Factors[0].Evidence[0], origSurfEvidence)
	}
	if len(orig.Surfaces[0].Factors) != origSurfFactorsLen {
		t.Fatalf("surface factors len mutated in original: got %d want %d", len(orig.Surfaces[0].Factors), origSurfFactorsLen)
	}
	// Groups shared indicators
	if orig.Groups[0].SharedIndicators[0] != origGroupShared {
		t.Fatalf("group shared indicator mutated in original: got %q want %q", orig.Groups[0].SharedIndicators[0], origGroupShared)
	}
	if len(orig.Groups[0].SharedIndicators) != 1 {
		t.Fatalf("group shared indicators len mutated in original: got %d want 1", len(orig.Groups[0].SharedIndicators))
	}
	// Groups members
	if orig.Groups[0].Members[0].Factors[0].Name != origGroupMemberFactorName {
		t.Fatalf("group member factor name mutated in original: got %q want %q", orig.Groups[0].Members[0].Factors[0].Name, origGroupMemberFactorName)
	}
	if orig.Groups[0].Members[0].Factors[0].Evidence[0] != origGroupMemberEvidence {
		t.Fatalf("group member evidence mutated in original: got %q want %q", orig.Groups[0].Members[0].Factors[0].Evidence[0], origGroupMemberEvidence)
	}
	if len(orig.Groups[0].Members) != 2 {
		t.Fatalf("group members len mutated in original: got %d want 2", len(orig.Groups[0].Members))
	}
	// Attack paths
	if orig.AttackPaths[0].Steps[0].Evidence[0] != origAttackStepEvidence {
		t.Fatalf("attack path step evidence mutated in original: got %q want %q", orig.AttackPaths[0].Steps[0].Evidence[0], origAttackStepEvidence)
	}
	if len(orig.AttackPaths[0].Steps) != 3 {
		t.Fatalf("attack path steps len mutated in original: got %d want 3", len(orig.AttackPaths[0].Steps))
	}
	if orig.AttackPaths[0].Steps[1].Evidence[0] == "evil-step-evidence-2" {
		t.Fatalf("attack path second step evidence mutated in original")
	}
	// Recommendations
	if orig.Recommendations[0].Evidence[0] != origRecEvidence {
		t.Fatalf("recommendation evidence mutated in original: got %q want %q", orig.Recommendations[0].Evidence[0], origRecEvidence)
	}
	if len(orig.Recommendations[0].Evidence) != origRecLen {
		t.Fatalf("recommendation evidence len mutated in original: got %d want %d", len(orig.Recommendations[0].Evidence), origRecLen)
	}

	// Also verify clone actually mutated (test is not vacuously passing).
	if clone.Surfaces[0].Factors[0].Name == origSurfFactorName {
		t.Fatalf("clone mutation did not take effect")
	}

	// Nil safety: cloneModel(nil) must return nil without panic.
	if cloneModel(nil) != nil {
		t.Fatalf("cloneModel(nil) should return nil")
	}

	// Empty slices: cloning a model with empty interior should not panic and
	// should preserve nil vs empty semantics for isolation.
	emptyCtx := Context{Target: "example.com"}
	emptyModel, err := NewModel(emptyCtx)
	if err != nil {
		t.Fatalf("empty model: %v", err)
	}
	emptyClone := cloneModel(emptyModel)
	if emptyClone == nil {
		t.Fatalf("empty clone nil")
	}
	if len(emptyClone.Surfaces) != 0 || len(emptyClone.Groups) != 0 || len(emptyClone.AttackPaths) != 0 || len(emptyClone.Recommendations) != 0 {
		t.Fatalf("empty clone should have empty priority slices")
	}
}

// TestModelInteriorIsolation verifies per-render interior isolation through
// the engine's concurrent reporter path: a hostile reporter that mutates
// interior slices (m.Surfaces[0].Factors[0].Name etc.) must not affect a peer's
// view. This is the acceptance-criteria test for OPT-P1-2 interior gap.
func TestModelInteriorIsolation(t *testing.T) {
	base := richInteriorContext(t)
	origModel, err := NewModel(base)
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}
	// Capture expected values from the normalized model (the model Run will
	// build internally is identical).
	if len(origModel.Surfaces) == 0 || len(origModel.Surfaces[0].Factors) == 0 {
		t.Fatalf("precondition: surfaces empty")
	}
	expectedSurfFactorName := origModel.Surfaces[0].Factors[0].Name
	expectedSurfEvidence := origModel.Surfaces[0].Factors[0].Evidence[0]
	expectedSurfFactorsLen := len(origModel.Surfaces[0].Factors)
	expectedGroupShared := ""
	if len(origModel.Groups) > 0 && len(origModel.Groups[0].SharedIndicators) > 0 {
		expectedGroupShared = origModel.Groups[0].SharedIndicators[0]
	}
	expectedGroupMemberFactorName := ""
	expectedGroupMemberEvidence := ""
	if len(origModel.Groups) > 0 && len(origModel.Groups[0].Members) > 0 && len(origModel.Groups[0].Members[0].Factors) > 0 {
		expectedGroupMemberFactorName = origModel.Groups[0].Members[0].Factors[0].Name
		if len(origModel.Groups[0].Members[0].Factors[0].Evidence) > 0 {
			expectedGroupMemberEvidence = origModel.Groups[0].Members[0].Factors[0].Evidence[0]
		}
	}
	expectedAttackStepEvidence := ""
	if len(origModel.AttackPaths) > 0 && len(origModel.AttackPaths[0].Steps) > 0 && len(origModel.AttackPaths[0].Steps[0].Evidence) > 0 {
		expectedAttackStepEvidence = origModel.AttackPaths[0].Steps[0].Evidence[0]
	}
	expectedRecEvidence := ""
	expectedRecLen := 0
	if len(origModel.Recommendations) > 0 && len(origModel.Recommendations[0].Evidence) > 0 {
		expectedRecEvidence = origModel.Recommendations[0].Evidence[0]
		expectedRecLen = len(origModel.Recommendations[0].Evidence)
	}
	// Use asset import to avoid unused import error in some builds (richInteriorContext already uses it,
	// but keep reference for clarity).
	_ = asset.KindURL

	mutatedCh := make(chan struct{})
	observedCh := make(chan struct{})
	var seenMutated atomic.Bool
	var reason atomic.Value

	mutID := "mutator-interior"
	obsID := "observer-interior"

	mutReporter := Reporter{
		ID:          mutID,
		Name:        "MutatorInterior",
		Description: "mutates interior slices",
		Version:     "1.0.0",
		Format:      FormatJSON,
		Enabled:     true,
		Render: func(ctx context.Context, m *Model, s Sink) error {
			// Mutate every interior slice flagged in the review.
			if len(m.Surfaces) > 0 && len(m.Surfaces[0].Factors) > 0 {
				m.Surfaces[0].Factors[0].Name = "evil-factor"
				if len(m.Surfaces[0].Factors[0].Evidence) > 0 {
					m.Surfaces[0].Factors[0].Evidence[0] = "evil-evidence"
				}
				m.Surfaces[0].Factors = append(m.Surfaces[0].Factors, priority.Factor{Name: "injected", Weight: 0.1, Reason: "injected", Evidence: []string{"injected"}})
			}
			if len(m.Groups) > 0 {
				if len(m.Groups[0].SharedIndicators) > 0 {
					m.Groups[0].SharedIndicators[0] = "evil-indicator"
				}
				m.Groups[0].SharedIndicators = append(m.Groups[0].SharedIndicators, "injected-indicator")
				if len(m.Groups[0].Members) > 0 && len(m.Groups[0].Members[0].Factors) > 0 {
					m.Groups[0].Members[0].Factors[0].Name = "evil-member-factor"
					if len(m.Groups[0].Members[0].Factors[0].Evidence) > 0 {
						m.Groups[0].Members[0].Factors[0].Evidence[0] = "evil-member-evidence"
					}
				}
				if len(m.Groups[0].Members) > 0 {
					m.Groups[0].Members = append(m.Groups[0].Members, m.Groups[0].Members[0])
				}
			}
			if len(m.AttackPaths) > 0 && len(m.AttackPaths[0].Steps) > 0 {
				if len(m.AttackPaths[0].Steps[0].Evidence) > 0 {
					m.AttackPaths[0].Steps[0].Evidence[0] = "evil-step-evidence"
				}
				if len(m.AttackPaths[0].Steps) > 1 && len(m.AttackPaths[0].Steps[1].Evidence) > 0 {
					m.AttackPaths[0].Steps[1].Evidence[0] = "evil-step-evidence-2"
				}
				m.AttackPaths[0].Steps = append(m.AttackPaths[0].Steps, priority.PathStep{Identity: m.AttackPaths[0].Root, Reason: "injected", Evidence: []string{"injected"}})
			}
			if len(m.Recommendations) > 0 && len(m.Recommendations[0].Evidence) > 0 {
				m.Recommendations[0].Evidence[0] = "evil-rec-evidence"
				m.Recommendations[0].Evidence = append(m.Recommendations[0].Evidence, "injected-rec")
			}
			close(mutatedCh)
			<-observedCh
			w, _ := s.Writer("")
			if w != nil {
				w.Write([]byte("{}"))
				w.Close()
			}
			return nil
		},
	}

	obsReporter := Reporter{
		ID:          obsID,
		Name:        "ObserverInterior",
		Description: "observes interior slices",
		Version:     "1.0.0",
		Format:      FormatJSON,
		Enabled:     true,
		Render: func(ctx context.Context, m *Model, s Sink) error {
			<-mutatedCh
			// Check Surfaces
			if len(m.Surfaces) > 0 && len(m.Surfaces[0].Factors) > 0 {
				if m.Surfaces[0].Factors[0].Name == "evil-factor" {
					seenMutated.Store(true)
					reason.Store("Surfaces[0].Factors[0].Name mutated visible")
				}
				if m.Surfaces[0].Factors[0].Name != expectedSurfFactorName {
					seenMutated.Store(true)
					reason.Store("Surfaces[0].Factors[0].Name not expected")
				}
				if len(m.Surfaces[0].Factors[0].Evidence) > 0 && m.Surfaces[0].Factors[0].Evidence[0] == "evil-evidence" {
					seenMutated.Store(true)
					reason.Store("Surfaces[0].Factors[0].Evidence mutated visible")
				}
				if len(m.Surfaces[0].Factors[0].Evidence) > 0 && m.Surfaces[0].Factors[0].Evidence[0] != expectedSurfEvidence {
					seenMutated.Store(true)
					reason.Store("Surfaces[0].Factors[0].Evidence not expected")
				}
				if len(m.Surfaces[0].Factors) != expectedSurfFactorsLen {
					seenMutated.Store(true)
					reason.Store("Surfaces[0].Factors len mutated visible")
				}
			}
			// Groups
			if len(m.Groups) > 0 {
				if len(m.Groups[0].SharedIndicators) > 0 {
					if m.Groups[0].SharedIndicators[0] == "evil-indicator" {
						seenMutated.Store(true)
						reason.Store("Groups[0].SharedIndicators mutated visible")
					}
					if m.Groups[0].SharedIndicators[0] != expectedGroupShared {
						seenMutated.Store(true)
						reason.Store("Groups[0].SharedIndicators not expected")
					}
					for _, v := range m.Groups[0].SharedIndicators {
						if v == "injected-indicator" {
							seenMutated.Store(true)
							reason.Store("Groups[0].SharedIndicators appended visible")
						}
					}
				}
				if len(m.Groups[0].Members) > 0 && len(m.Groups[0].Members[0].Factors) > 0 {
					if m.Groups[0].Members[0].Factors[0].Name == "evil-member-factor" {
						seenMutated.Store(true)
						reason.Store("Groups[0].Members[0].Factors[0].Name mutated visible")
					}
					if m.Groups[0].Members[0].Factors[0].Name != expectedGroupMemberFactorName {
						seenMutated.Store(true)
						reason.Store("Groups[0].Members[0].Factors[0].Name not expected")
					}
					if len(m.Groups[0].Members[0].Factors[0].Evidence) > 0 && m.Groups[0].Members[0].Factors[0].Evidence[0] == "evil-member-evidence" {
						seenMutated.Store(true)
						reason.Store("Groups[0].Members[0].Factors[0].Evidence mutated visible")
					}
					if len(m.Groups[0].Members[0].Factors[0].Evidence) > 0 && m.Groups[0].Members[0].Factors[0].Evidence[0] != expectedGroupMemberEvidence {
						seenMutated.Store(true)
						reason.Store("Groups[0].Members[0].Factors[0].Evidence not expected")
					}
				}
				// Members slice append should not be visible.
				if len(m.Groups[0].Members) != 2 {
					seenMutated.Store(true)
					reason.Store("Groups[0].Members len mutated visible")
				}
			}
			// AttackPaths
			if len(m.AttackPaths) > 0 && len(m.AttackPaths[0].Steps) > 0 {
				if len(m.AttackPaths[0].Steps[0].Evidence) > 0 && m.AttackPaths[0].Steps[0].Evidence[0] == "evil-step-evidence" {
					seenMutated.Store(true)
					reason.Store("AttackPaths[0].Steps[0].Evidence mutated visible")
				}
				if len(m.AttackPaths[0].Steps[0].Evidence) > 0 && m.AttackPaths[0].Steps[0].Evidence[0] != expectedAttackStepEvidence {
					seenMutated.Store(true)
					reason.Store("AttackPaths[0].Steps[0].Evidence not expected")
				}
				if len(m.AttackPaths[0].Steps) != 3 {
					seenMutated.Store(true)
					reason.Store("AttackPaths[0].Steps len mutated visible")
				}
				if len(m.AttackPaths[0].Steps) > 1 && len(m.AttackPaths[0].Steps[1].Evidence) > 0 && m.AttackPaths[0].Steps[1].Evidence[0] == "evil-step-evidence-2" {
					seenMutated.Store(true)
					reason.Store("AttackPaths[0].Steps[1].Evidence mutated visible")
				}
			}
			// Recommendations
			if len(m.Recommendations) > 0 && len(m.Recommendations[0].Evidence) > 0 {
				if m.Recommendations[0].Evidence[0] == "evil-rec-evidence" {
					seenMutated.Store(true)
					reason.Store("Recommendations[0].Evidence mutated visible")
				}
				if m.Recommendations[0].Evidence[0] != expectedRecEvidence {
					seenMutated.Store(true)
					reason.Store("Recommendations[0].Evidence not expected")
				}
				if len(m.Recommendations[0].Evidence) != expectedRecLen {
					seenMutated.Store(true)
					reason.Store("Recommendations[0].Evidence len mutated visible")
				}
				for _, v := range m.Recommendations[0].Evidence {
					if v == "injected-rec" {
						seenMutated.Store(true)
						reason.Store("Recommendations[0].Evidence appended visible")
					}
				}
			}
			close(observedCh)
			w, _ := s.Writer("")
			if w != nil {
				w.Write([]byte("{}"))
				w.Close()
			}
			return nil
		},
	}

	reg := NewRegistry()
	if err := reg.Register(mutReporter); err != nil {
		t.Fatalf("register mutator: %v", err)
	}
	if err := reg.Register(obsReporter); err != nil {
		t.Fatalf("register observer: %v", err)
	}
	dir := t.TempDir()
	cfg := DefaultEngineConfig(reg, dir)
	cfg.Concurrency = 2
	cfg.Reports = []string{mutID, obsID}

	_, err = Run(context.Background(), cfg, base)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if seenMutated.Load() {
		r, _ := reason.Load().(string)
		t.Fatalf("interior model isolation violated: %s (peer saw mutator's interior writes; cloneModel missing deep copy)", r)
	}
}
