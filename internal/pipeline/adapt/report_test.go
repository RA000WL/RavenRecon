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
	"github.com/RA000WL/RavenRecon/internal/priority"
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
// the declared target, and — on the LEGACY path (no StageInput.RunStartedAt,
// i.e. direct engine use outside the runner) — the single honest "now" from
// the injected clock for both bracket ends (equal values are valid), plus
// only the in-scope filtered corpus — out-of-domain entries never reach the
// model. The runner-driven honest bracket is pinned by
// TestReportStageRunBracket below.
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

// TestReportStageContextEveryChannel pins the T3d full-Context
// composition: every results channel the earlier stages produced reaches
// the report model (the engine re-normalizes, so each channel is asserted
// by membership and count, never by order).
func TestReportStageContextEveryChannel(t *testing.T) {
	var m *report.Model
	reg := newReportRegistry(t, captureReporter("capture", func(got *report.Model) { m = got }))

	host := mustHost(t, "www.example.com")
	ip, err := asset.NewIP("192.168.1.10", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewIP: %v", err)
	}
	port, err := asset.NewPort(443, "tcp", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewPort: %v", err)
	}
	svc, err := asset.NewService("https", port, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ep, err := asset.NewEndpoint("GET", "https://www.example.com/login", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	js, err := asset.NewJavaScript("https://www.example.com/app.js", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	param, err := asset.NewParameter("q", "query", "v", "url", fixedTime, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewParameter: %v", err)
	}
	tech, err := asset.NewTechnology("nginx", asset.CategoryServer, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	sec, err := asset.NewSecretCandidate(asset.SecretTypeAWS, "AKIA0123456789ABCDEF", host.Identity(), asset.Provenance{})
	if err != nil {
		t.Fatalf("NewSecretCandidate: %v", err)
	}
	ev, err := asset.NewEvidence(asset.MethodHeader, "x-nginx-version", "1.25", host.Identity(), asset.Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	f, err := asset.NewFinding(asset.Finding{
		RuleID:     "test.rule",
		RuleName:   "Test Rule",
		Category:   "exposure",
		Subject:    host.Identity(),
		Confidence: 0.9,
		Evidence:   []asset.Evidence{ev},
		Priority:   "info",
		Status:     "open",
		Created:    fixedTime,
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	cert, err := asset.NewTLSCertificate("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewTLSCertificate: %v", err)
	}
	sm, err := asset.NewSourceMap("https://www.example.com/app.js.map", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewSourceMap: %v", err)
	}
	rel, err := asset.NewRelationship(host.Identity(), asset.RelationshipHostToIP, ip.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	surf := priority.SurfaceAsset{Identity: host.Identity(), Kind: asset.KindHost, Score: 0.5, Level: priority.LevelLow}
	group := priority.Group{Anchor: host.Identity(), Members: []priority.SurfaceAsset{surf}, Score: 0.5, Level: priority.LevelLow}
	path := priority.AttackPath{
		Root:  host.Identity(),
		Steps: []priority.PathStep{{Identity: host.Identity(), Kind: asset.KindHost, FactorName: "test-factor", Reason: "test reason", Evidence: []string{"test evidence"}}},
		Score: 0.5,
		Level: priority.LevelLow,
	}

	in := reportInput(mustDomain(t, "example.com"), nil, nil, nil, t.TempDir(), nil)
	in.Results = pipeline.Results{
		IPs:             []asset.IP{ip},
		Ports:           []asset.Port{port},
		Services:        []asset.Service{svc},
		Endpoints:       []asset.Endpoint{ep},
		JavaScript:      []asset.JavaScript{js},
		Parameters:      []asset.Parameter{param},
		Technologies:    []asset.Technology{tech},
		Secrets:         []asset.SecretCandidate{sec},
		Evidence:        []asset.Evidence{ev},
		Findings:        []asset.Finding{f},
		TLSCertificates: []asset.TLSCertificate{cert},
		SourceMaps:      []asset.SourceMap{sm},
		Relationships:   []asset.Relationship{rel},
		Surfaces:        []priority.SurfaceAsset{surf},
		Groups:          []priority.Group{group},
		AttackPaths:     []priority.AttackPath{path},
	}

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
	channels := []struct {
		name  string
		count int
	}{
		{"IPs", len(m.IPs)}, {"Ports", len(m.Ports)}, {"Services", len(m.Services)},
		{"Endpoints", len(m.Endpoints)}, {"JavaScript", len(m.JavaScript)},
		{"Parameters", len(m.Parameters)}, {"Technologies", len(m.Technologies)},
		{"Secrets", len(m.Secrets)}, {"Evidence", len(m.Evidence)},
		{"Findings", len(m.Findings)}, {"TLSCertificates", len(m.TLSCertificates)},
		{"SourceMaps", len(m.SourceMaps)}, {"Relationships", len(m.Relationships)},
		{"Surfaces", len(m.Surfaces)}, {"Groups", len(m.Groups)},
		{"AttackPaths", len(m.AttackPaths)},
	}
	for _, ch := range channels {
		if ch.count != 1 {
			t.Errorf("model %s = %d, want 1 (the results channel value reaches the Context)", ch.name, ch.count)
		}
	}
	// Spot-check the values survived the normalization.
	if m.IPs[0].Identity().String() != ip.Identity().String() {
		t.Errorf("model IPs = %+v, want %s", m.IPs, ip.Identity())
	}
	if m.Groups[0].Anchor.String() != host.Identity().String() {
		t.Errorf("model Groups anchor = %s, want %s", m.Groups[0].Anchor, host.Identity())
	}
	if m.Findings[0].RuleID != "test.rule" {
		t.Errorf("model Findings = %+v, want rule %q", m.Findings, "test.rule")
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
