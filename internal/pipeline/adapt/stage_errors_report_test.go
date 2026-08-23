package adapt

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/report"
)

// failingDiscoverStage is a hermetic stand-in for any stage family: it
// always records failed with a structured engine-style error.
type failingDiscoverStage struct{}

func (failingDiscoverStage) Name() pipeline.StageName { return pipeline.StageDiscover }

func (failingDiscoverStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
		errors.New("discovery pool drained before every source completed")
}

// TestReportStageFoldsStageErrorsIntoSummary pins NEW-90 end to end: a
// failed stage followed by the report stage — the rendered MODEL carries an
// error summary with at least one record naming the failing stage, instead
// of total=0 while the stages table says failed.
func TestReportStageFoldsStageErrorsIntoSummary(t *testing.T) {
	reg := report.NewRegistry()
	var summary report.ErrorSummary
	rep := captureReporter("summary-capture", func(m *report.Model) {
		summary = m.Errors
	})
	if err := reg.Register(rep); err != nil {
		t.Fatalf("register: %v", err)
	}

	cfg := pipeline.ScanConfig{
		Target:    discoveryMustDomain(t, "example.com"),
		Stages:    []pipeline.StageName{pipeline.StageDiscover, pipeline.StageReport},
		OutputDir: t.TempDir(),
	}
	run, err := pipeline.Run(context.Background(), cfg, nil, fakeClock{}, []pipeline.Stage{
		failingDiscoverStage{},
		NewReportStage(reg),
	})
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	if run.Outcome == pipeline.OutcomeCompleted && len(run.Stages) != 2 {
		t.Fatalf("run shape unexpected: outcome=%s stages=%d", run.Outcome, len(run.Stages))
	}
	if run.Stages[0].Outcome != pipeline.OutcomeFailed {
		t.Fatalf("discover outcome = %s, want failed", run.Stages[0].Outcome)
	}
	if len(run.StageErrors) != 1 || run.StageErrors[0].Name != pipeline.StageDiscover {
		t.Fatalf("RunReport.StageErrors = %+v, want exactly the discover failure", run.StageErrors)
	}

	if summary.Total == 0 {
		t.Fatal("model error summary total = 0, want >= 1 (stage failures must reach the operator-facing summary)")
	}
	found := false
	for _, cat := range summary.Categories {
		for _, s := range cat.Samples {
			if s.Stage == string(pipeline.StageDiscover) &&
				strings.Contains(s.Message, "discovery pool drained") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no summary sample names the failing stage with its detail; summary = %+v", summary)
	}
}
