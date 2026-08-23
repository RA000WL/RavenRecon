package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// failingStage is a hermetic stage that always fails with a structured
// error (NEW-90 test double).
type failingStage struct{ name StageName }

func (f failingStage) Name() StageName { return f.name }

func (f failingStage) Run(ctx context.Context, in StageInput) (StageResult, error) {
	return StageResult{Outcome: OutcomeFailed}, errors.New("boom: engine exploded")
}

// okStage is a hermetic stage that completes without doing anything. It
// records the StageErrors slice it received, mirroring what the report
// stage consumes.
type okStage struct {
	name     StageName
	observed *[]StageError
}

func (s okStage) Name() StageName { return s.name }

func (s okStage) Run(ctx context.Context, in StageInput) (StageResult, error) {
	if s.observed != nil {
		*s.observed = in.StageErrors
	}
	return StageResult{Outcome: OutcomeCompleted}, nil
}

// TestRunCollectsFailingStageErrIntoReport pins NEW-90 at the runner level:
// a failing stage's structured error reaches RunReport.StageErrors AND the
// input of every later stage; a passing run carries none.
func TestRunCollectsFailingStageErrIntoReport(t *testing.T) {
	var observed []StageError
	target := mustDomainT(t, "example.com")
	cfg := ScanConfig{
		Target: target,
		Stages: []StageName{"discover", "dns"},
	}
	rep, err := Run(context.Background(), cfg, nil, newFakeClock(testTime), []Stage{
		failingStage{name: "discover"},
		okStage{name: "dns", observed: &observed},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if n := len(rep.StageErrors); n != 1 {
		t.Fatalf("StageErrors = %d entries, want 1", n)
	}
	se := rep.StageErrors[0]
	if se.Name != "discover" {
		t.Errorf("entry name = %q, want %q", se.Name, "discover")
	}
	if se.Err == nil || se.Err.Error() != "boom: engine exploded" {
		t.Errorf("entry err = %v, want the structured failure detail", se.Err)
	}
	if rep.Stages[0].Outcome != OutcomeFailed {
		t.Errorf("stage outcome = %q, want failed (collection must not alter records)", rep.Stages[0].Outcome)
	}

	// The LATER stage must have observed the earlier failure through its
	// input — that is exactly what the report stage consumes.
	if len(observed) != 1 || observed[0].Name != "discover" {
		t.Fatalf("later stage saw %v, want the discover failure", observed)
	}

	// A passing run carries NO collected errors (byte-stable serialization).
	rep2, err := Run(context.Background(), ScanConfig{
		Target: target,
		Stages: []StageName{"dns"},
	}, nil, newFakeClock(testTime), []Stage{okStage{name: "dns"}})
	if err != nil {
		t.Fatalf("clean Run: %v", err)
	}
	if rep2.StageErrors != nil {
		t.Errorf("passing run StageErrors = %v, want nil", rep2.StageErrors)
	}
}

// TestRunCollectsCancelledStagesToo pins that never-run stages recorded
// cancelled WITH an error also fold into the summary: with a pre-cancelled
// context every stage records Err = ctx.Err() and each contributes one
// collected entry.
func TestRunCollectsCancelledStagesToo(t *testing.T) {
	target := mustDomainT(t, "example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := Run(ctx, ScanConfig{
		Target: target,
		Stages: []StageName{"discover", "dns"},
	}, nil, newFakeClock(testTime), []Stage{
		failingStage{name: "discover"},
		okStage{name: "dns"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(rep.StageErrors); n != 2 {
		t.Fatalf("StageErrors = %d entries, want 2 (one per cancelled stage)", n)
	}
	for _, se := range rep.StageErrors {
		if !errors.Is(se.Err, context.Canceled) {
			t.Errorf("stage %q err = %v, want context.Canceled", se.Name, se.Err)
		}
	}
}

func mustDomainT(t *testing.T, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain(%q): %v", name, err)
	}
	return d
}

var _ runtime.Clock = (*fakeClock)(nil)
