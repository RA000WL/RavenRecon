package adapt

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/report"
)

// reportInput builds a StageInput for the report stage with the resolved
// default bounds, the deterministic fixed clock the package's dns tests
// share, and the given output directory.
func reportInput(target asset.Domain, domains []asset.Domain, hosts []asset.Host, urls []asset.URL, outputDir string, c cache.Cache) pipeline.StageInput {
	return pipeline.StageInput{
		Target:    target,
		Domains:   domains,
		Hosts:     hosts,
		URLs:      urls,
		Bounds:    pipeline.DefaultStageConfig(),
		Clock:     fixedClock{now: fixedTime},
		Cache:     c,
		OutputDir: outputDir,
	}
}

// captureReporter builds a hermetic single-part reporter whose Render
// records the canonical model it received and writes a minimal valid part
// (the engine's default post-render validation requires a non-empty file).
func captureReporter(id string, capture func(*report.Model)) report.Reporter {
	return report.Reporter{
		ID:          id,
		Name:        "capture reporter " + id,
		Description: "hermetic capture reporter",
		Version:     "1.0.0",
		Format:      report.FormatJSON,
		Enabled:     true,
		Render: func(ctx context.Context, m *report.Model, s report.Sink) error {
			if capture != nil {
				capture(m)
			}
			w, err := s.Writer("")
			if err != nil {
				return err
			}
			if _, err := io.WriteString(w, "captured"); err != nil {
				w.Close()
				return err
			}
			return w.Close()
		},
	}
}

// newReportRegistry registers every reporter into a fresh hermetic registry,
// failing the test on the first rejection.
func newReportRegistry(t *testing.T, reporters ...report.Reporter) *report.Registry {
	t.Helper()
	reg := report.NewRegistry()
	for _, r := range reporters {
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register(%q): %v", r.ID, err)
		}
	}
	return reg
}

// reportCorpus builds the canonical in-scope corpus the happy-path tests
// share.
func reportCorpus(t *testing.T) ([]asset.Domain, []asset.Host, []asset.URL) {
	t.Helper()
	domains := []asset.Domain{mustDomain(t, "example.com")}
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	urls := []asset.URL{mustURL(t, "https://www.example.com/login")}
	return domains, hosts, urls
}

// TestReportStageName pins the stage's pipeline identity.
func TestReportStageName(t *testing.T) {
	if got := NewReportStage(nil).Name(); got != pipeline.StageReport {
		t.Fatalf("Name() = %q, want %q", got, pipeline.StageReport)
	}
}

// TestReportStageHappyPath pins the full default-registry run: the four
// builtin reporters (json, csv, markdown, html) each render and commit a
// file into OutputDir with cache-before-execute around every render (one Get
// and one Put per report), the honest counters, and NO corpus additions.
func TestReportStageHappyPath(t *testing.T) {
	domains, hosts, urls := reportCorpus(t)
	dir := t.TempDir()
	c := &recordingCache{}
	in := reportInput(mustDomain(t, "example.com"), domains, hosts, urls, dir, c)

	res, err := NewReportStage(nil).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 4 {
		t.Errorf("ItemsProcessed = %d, want 4 (json, csv, markdown, html)", res.ItemsProcessed)
	}
	if res.ItemsFailed != 0 {
		t.Errorf("ItemsFailed = %d, want 0", res.ItemsFailed)
	}
	if res.Truncated {
		t.Error("Truncated = true, want false (the report engine reports no truncation signals)")
	}
	if res.Err != nil {
		t.Errorf("Err = %v, want nil", res.Err)
	}
	if len(res.Additions.Domains) != 0 || len(res.Additions.Hosts) != 0 || len(res.Additions.URLs) != 0 {
		t.Errorf("Additions = %+v, want empty (the report engine writes files, not corpus)", res.Additions)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	if len(entries) < 4 {
		t.Errorf("committed files = %d, want >= 4", len(entries))
	}
	if got, want := len(c.getKeys()), 4; got != want {
		t.Errorf("cache Gets = %d, want %d (one render lookup per reporter)", got, want)
	}
	if got, want := c.putCount(), 4; got != want {
		t.Errorf("cache Puts = %d, want %d (every fresh render stored)", got, want)
	}
}

// TestReportStageEmptyCorpus pins the never-short-circuit rule: rendering the
// (empty) report IS the stage's work — an empty corpus still renders a valid
// empty report and commits files.
func TestReportStageEmptyCorpus(t *testing.T) {
	dir := t.TempDir()
	in := reportInput(mustDomain(t, "example.com"), nil, nil, nil, dir, nil)

	res, err := NewReportStage(nil).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed (an empty report is valid)", res.Outcome)
	}
	if res.ItemsProcessed != 4 {
		t.Errorf("ItemsProcessed = %d, want 4", res.ItemsProcessed)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	if len(entries) == 0 {
		t.Error("no committed files: the empty report must still render")
	}
}

// TestReportStageContextComposition pins the Context the stage composes:
// the declared target, the single honest "now" from the injected clock for
// both bracket ends (equal — the pipeline tracks no run bracket yet), and
// only the in-scope filtered corpus — out-of-domain entries never reach the
// model.
func TestReportStageContextComposition(t *testing.T) {
	var m *report.Model
	reg := newReportRegistry(t, captureReporter("capture", func(got *report.Model) { m = got }))
	domains := []asset.Domain{mustDomain(t, "example.com")}
	hosts := []asset.Host{
		mustHost(t, "www.example.com"),
		mustHost(t, "evil.com"),
	}
	urls := []asset.URL{
		mustURL(t, "https://www.example.com/login"),
		mustURL(t, "https://evil.com/x"),
	}
	in := reportInput(mustDomain(t, "example.com"), domains, hosts, urls, t.TempDir(), nil)

	res, err := NewReportStage(reg).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if m == nil {
		t.Fatal("reporter never ran")
	}
	if m.Target != "example.com" {
		t.Errorf("model.Target = %q, want %q", m.Target, "example.com")
	}
	if !m.StartedAt.Equal(fixedTime) || !m.EndedAt.Equal(fixedTime) {
		t.Errorf("run bracket = %v..%v, want %v..%v (the stage's single honest now)",
			m.StartedAt, m.EndedAt, fixedTime, fixedTime)
	}
	requireEqualStrings(t, "model hosts", hostNames(m.Hosts), []string{"www.example.com"})
	requireEqualStrings(t, "model URLs", urlStrings(m.URLs), []string{"https://www.example.com/login"})
	if len(m.Domains) != 1 || m.Domains[0].Name != "example.com" {
		t.Errorf("model domains = %+v, want [example.com]", m.Domains)
	}
}

// TestReportStageEmptyOutputDir pins the engine's validation path: an empty
// OutputDir is the engine's config error, surfaced as a failed outcome with
// the wrapped engine error.
func TestReportStageEmptyOutputDir(t *testing.T) {
	domains, _, _ := reportCorpus(t)
	in := reportInput(mustDomain(t, "example.com"), domains, nil, nil, "", nil)

	res, err := NewReportStage(nil).Run(context.Background(), in)
	if err == nil {
		t.Fatal("Run: nil error, want the engine's output-directory error")
	}
	if !strings.Contains(err.Error(), "stage report:") || !strings.Contains(err.Error(), "output directory") {
		t.Errorf("error %q, want stage-prefixed engine error", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("outcome %s, want failed", res.Outcome)
	}
	if res.Err == nil || res.Err.Error() != err.Error() {
		t.Errorf("res.Err = %v, want the returned error", res.Err)
	}
}

// TestReportStageEngineConfigError pins the engine's negative-timeout
// validation path: a negative bound surfaces as a failed outcome with the
// wrapped engine error (the report engine DEFAULTS zero Concurrency and
// Timeout instead of rejecting them, so this is its config-error route).
func TestReportStageEngineConfigError(t *testing.T) {
	domains, _, _ := reportCorpus(t)
	in := reportInput(mustDomain(t, "example.com"), domains, nil, nil, t.TempDir(), nil)
	in.Bounds.Timeout = -1

	res, err := NewReportStage(nil).Run(context.Background(), in)
	if err == nil {
		t.Fatal("Run: nil error, want the engine's timeout error")
	}
	if !strings.Contains(err.Error(), "stage report:") || !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error %q, want stage-prefixed engine error", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("outcome %s, want failed", res.Outcome)
	}
}

// TestReportStagePreCancelled pins the pre-cancelled-context path: the engine
// reports cancelled per-report statuses, and the stage reports cancelled with
// the context error attached and a nil Go error return — the outcome, not
// the error field, carries cancellation.
func TestReportStagePreCancelled(t *testing.T) {
	domains, _, _ := reportCorpus(t)
	in := reportInput(mustDomain(t, "example.com"), domains, nil, nil, t.TempDir(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := NewReportStage(nil).Run(ctx, in)
	if err != nil {
		t.Fatalf("Run: %v, want nil Go error (the outcome carries cancellation)", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("outcome %s, want cancelled", res.Outcome)
	}
	if !isContextError(res.Err) {
		t.Errorf("res.Err = %v, want the context error", res.Err)
	}
}

// TestReportStageEngineErrorAndFiredCtx pins the dominant-signal mapping: an
// engine error while the stage context is firing reports cancelled with the
// context error errors.Join-ed with the engine's detail — nothing is lost.
func TestReportStageEngineErrorAndFiredCtx(t *testing.T) {
	domains, _, _ := reportCorpus(t)
	in := reportInput(mustDomain(t, "example.com"), domains, nil, nil, t.TempDir(), nil)
	in.Bounds.Timeout = -1
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := NewReportStage(nil).Run(ctx, in)
	if err != nil {
		t.Fatalf("Run: %v, want nil Go error (cancelled outcome carries the detail)", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("outcome %s, want cancelled (dominant signal)", res.Outcome)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Errorf("res.Err = %v, want joined context error", res.Err)
	}
	if !strings.Contains(res.Err.Error(), "timeout") {
		t.Errorf("res.Err = %v, want the engine detail joined in", res.Err)
	}
}

// TestReportStageNilContext pins the nil-context guard (T2c review LOW-2).
func TestReportStageNilContext(t *testing.T) {
	in := reportInput(mustDomain(t, "example.com"), nil, nil, nil, t.TempDir(), nil)

	res, err := NewReportStage(nil).Run(nil, in)
	if err == nil || !strings.Contains(err.Error(), "context must not be nil") {
		t.Fatalf("Run: err = %v, want the nil-context error", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("outcome %s, want failed", res.Outcome)
	}
}

// TestReportStageNilCache pins the caching-disabled path: a nil cache is a
// no-op for the engine and the stage still completes.
func TestReportStageNilCache(t *testing.T) {
	domains, _, _ := reportCorpus(t)
	in := reportInput(mustDomain(t, "example.com"), domains, nil, nil, t.TempDir(), nil)

	res, err := NewReportStage(nil).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 4 {
		t.Errorf("ItemsProcessed = %d, want 4", res.ItemsProcessed)
	}
}

// TestReportStageSyntheticRegistry pins the constructor seam: a hermetic
// single-reporter registry drives the engine, the stage maps the honest
// counters, and the render commits exactly one file into OutputDir.
func TestReportStageSyntheticRegistry(t *testing.T) {
	reg := newReportRegistry(t, captureReporter("capture", nil))
	domains, _, _ := reportCorpus(t)
	dir := t.TempDir()
	in := reportInput(mustDomain(t, "example.com"), domains, nil, nil, dir, nil)

	res, err := NewReportStage(reg).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 1 {
		t.Errorf("ItemsProcessed = %d, want 1", res.ItemsProcessed)
	}
	if res.ItemsFailed != 0 {
		t.Errorf("ItemsFailed = %d, want 0", res.ItemsFailed)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	if len(entries) != 1 {
		t.Errorf("committed files = %d, want 1", len(entries))
	}
}

// TestReportStageFoldTable pins the aggregate-outcome mapping table
// (documented on reportStage.Run): the engine folds per-report statuses
// itself, and the stage maps the engine's outcome vocabulary verbatim.
func TestReportStageFoldTable(t *testing.T) {
	table := []struct {
		engine report.Outcome
		want   pipeline.Outcome
	}{
		{report.OutcomeCompleted, pipeline.OutcomeCompleted},
		{report.OutcomeIncomplete, pipeline.OutcomePartial},
		{report.OutcomeFailed, pipeline.OutcomeFailed},
		{report.OutcomeCancelled, pipeline.OutcomeCancelled},
		{report.Outcome("bogus"), pipeline.OutcomeFailed}, // contract violation never masked
	}
	for _, row := range table {
		if got := foldReportRunOutcome(row.engine); got != row.want {
			t.Errorf("foldReportRunOutcome(%q) = %s, want %s", row.engine, got, row.want)
		}
	}
}

// TestReportStageCounters pins the honest counters: processed counts every
// report the engine ATTEMPTED (completed + failed + cancelled), failed counts
// the failed reports, and skipped reports are excluded from both.
func TestReportStageCounters(t *testing.T) {
	s := &reportStage{}
	res := report.RunResult{
		Outcome: report.OutcomeIncomplete,
		Reports: []report.ReportResult{
			{ReporterID: "a", Status: report.ReportStatusCompleted},
			{ReporterID: "b", Status: report.ReportStatusCompleted},
			{ReporterID: "c", Status: report.ReportStatusFailed},
			{ReporterID: "d", Status: report.ReportStatusCancelled},
			{ReporterID: "e", Status: report.ReportStatusSkipped},
		},
	}

	got := s.buildReportResult(res, foldReportRunOutcome(res.Outcome), nil)
	if got.Outcome != pipeline.OutcomePartial {
		t.Fatalf("outcome %s, want partial", got.Outcome)
	}
	if got.ItemsProcessed != 4 {
		t.Errorf("ItemsProcessed = %d, want 4 (2+1+1; the skipped report is not processed)", got.ItemsProcessed)
	}
	if got.ItemsFailed != 1 {
		t.Errorf("ItemsFailed = %d, want 1", got.ItemsFailed)
	}
}
