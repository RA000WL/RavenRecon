package adapt

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// detectInput builds a StageInput for the detect stage with the resolved
// default bounds and the deterministic fixed clock the package's dns tests
// share.
func detectInput(target asset.Domain, domains []asset.Domain, hosts []asset.Host, urls []asset.URL, c cache.Cache) pipeline.StageInput {
	return pipeline.StageInput{
		Target:  target,
		Domains: domains,
		Hosts:   hosts,
		URLs:    urls,
		Bounds:  pipeline.DefaultStageConfig(),
		Clock:   fixedClock{now: fixedTime},
		Cache:   c,
	}
}

// newDetectRule builds one valid synthetic rule for the hermetic registry. A
// nil detector becomes the no-op detector (the registry rejects a nil one).
func newDetectRule(t *testing.T, id string, fn detect.Detector) detect.Rule {
	t.Helper()
	if fn == nil {
		fn = func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) { return nil, nil }
	}
	return detect.Rule{
		ID:            id,
		Name:          "synthetic rule " + id,
		Description:   "hermetic test rule",
		Category:      detect.CategoryExposure,
		Inputs:        []detect.RuleInput{detect.InputAssets},
		Outputs:       []detect.RuleOutput{detect.OutputFindings},
		Version:       "1.0.0",
		EstimatedCost: detect.CostLow,
		Timeout:       time.Second,
		Author:        "test",
		Enabled:       true,
		Detector:      fn,
	}
}

// newDetectRegistry registers every rule into a fresh hermetic registry,
// failing the test on the first rejection (the registry validates).
func newDetectRegistry(t *testing.T, rules ...detect.Rule) *detect.Registry {
	t.Helper()
	reg := detect.NewRegistry()
	for _, r := range rules {
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register(%q): %v", r.ID, err)
		}
	}
	return reg
}

// captureAssetsRule returns a detector that records the snapshot's asset
// identity strings it received and completes cleanly — the hermetic way to
// observe what the stage put into the engine snapshot.
func captureAssetsRule(captured *[]string) detect.Detector {
	return func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
		for _, a := range dctx.Assets {
			*captured = append(*captured, a.String())
		}
		return nil, nil
	}
}

// TestDetectStageName pins the stage's pipeline identity.
func TestDetectStageName(t *testing.T) {
	if got := NewDetectStage(nil).Name(); got != pipeline.StageDetect {
		t.Fatalf("Name() = %q, want %q", got, pipeline.StageDetect)
	}
}

// TestDetectStageEmptyRegistryShortCircuit pins the D2 default: the nil
// registry seam is the EMPTY registry, and an empty filtered corpus with an
// empty registry short-circuits to vacuous completed (zero cache
// interaction — the engine never runs).
func TestDetectStageEmptyRegistryShortCircuit(t *testing.T) {
	c := &recordingCache{}
	in := detectInput(mustDomain(t, "example.com"), nil, nil, nil, c)

	res, err := NewDetectStage(nil).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
		t.Errorf("counters = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
	}
	if got := len(c.getKeys()); got != 0 {
		t.Errorf("cache Gets = %d, want 0 (short-circuit never reaches the engine)", got)
	}
}

// TestDetectStageHappyPath pins the D2 production default through the
// engine: a non-empty corpus with the EMPTY registry yields the engine's
// vacuous completed run (zero rules, nothing attempted) with honest zero
// counters.
func TestDetectStageHappyPath(t *testing.T) {
	c := &recordingCache{}
	domains := []asset.Domain{mustDomain(t, "example.com")}
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	urls := []asset.URL{mustURL(t, "https://www.example.com/login")}
	in := detectInput(mustDomain(t, "example.com"), domains, hosts, urls, c)

	res, err := NewDetectStage(nil).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
		t.Errorf("counters = %d/%d, want 0/0 (no rules registered)", res.ItemsProcessed, res.ItemsFailed)
	}
	if res.Truncated {
		t.Error("Truncated = true, want false")
	}
	if got := len(c.getKeys()); got != 0 {
		t.Errorf("cache Gets = %d, want 0 (no rules to look up)", got)
	}
	if len(res.Additions.Domains) != 0 || len(res.Additions.Hosts) != 0 || len(res.Additions.URLs) != 0 {
		t.Errorf("Additions = %+v, want empty (findings are results, not corpus)", res.Additions)
	}
}

// TestDetectStageRuleHappyPath pins the rule-driven path with the
// cache-before-execute proof: one rule runs against the in-scope snapshot
// (one cache Get and one Put per executed rule), completes, and reports the
// honest counters.
func TestDetectStageRuleHappyPath(t *testing.T) {
	c := &recordingCache{}
	reg := newDetectRegistry(t, newDetectRule(t, "test.rule", nil))
	domains := []asset.Domain{mustDomain(t, "example.com")}
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	urls := []asset.URL{mustURL(t, "https://www.example.com/login")}
	in := detectInput(mustDomain(t, "example.com"), domains, hosts, urls, c)

	res, err := NewDetectStage(reg).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 1 {
		t.Errorf("ItemsProcessed = %d, want 1 (one executed rule)", res.ItemsProcessed)
	}
	if res.ItemsFailed != 0 {
		t.Errorf("ItemsFailed = %d, want 0", res.ItemsFailed)
	}
	if got, want := len(c.getKeys()), 1; got != want {
		t.Errorf("cache Gets = %d, want %d (one lookup per rule)", got, want)
	}
	if got, want := c.putCount(), 1; got != want {
		t.Errorf("cache Puts = %d, want %d (the completed execution is stored)", got, want)
	}
}

// TestDetectStageEmptyCorpusWithRules pins the NO-short-circuit rule: an
// empty corpus alone never skips the engine — a rule without
// RequiredAssetTypes genuinely executes against the empty snapshot (real
// work: the detector runs), while a rule with a required kind that is
// absent is skipped with an honest reason and excluded from the counters.
func TestDetectStageEmptyCorpusWithRules(t *testing.T) {
	executed := false
	unconstrained := newDetectRule(t, "test.unconstrained", func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
		executed = true
		return nil, nil
	})
	required := newDetectRule(t, "test.required-kind", nil)
	required.RequiredAssetTypes = []asset.Kind{asset.KindTechnology}
	reg := newDetectRegistry(t, unconstrained, required)

	in := detectInput(mustDomain(t, "example.com"), nil, nil, nil, nil)
	res, err := NewDetectStage(reg).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !executed {
		t.Error("unconstrained rule did not execute: the stage must not short-circuit an empty corpus with rules")
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed (skips never force non-completed)", res.Outcome)
	}
	if res.ItemsProcessed != 1 {
		t.Errorf("ItemsProcessed = %d, want 1 (only the executed rule)", res.ItemsProcessed)
	}
	if res.ItemsFailed != 0 {
		t.Errorf("ItemsFailed = %d, want 0", res.ItemsFailed)
	}
}

// TestDetectStageOutOfDomainFilter pins the mandatory input-side boundary
// filter: only in-scope identities enter the engine snapshot — out-of-domain
// hosts and URLs are never seen by the rules.
func TestDetectStageOutOfDomainFilter(t *testing.T) {
	var captured []string
	reg := newDetectRegistry(t, newDetectRule(t, "test.capture", captureAssetsRule(&captured)))
	domains := []asset.Domain{mustDomain(t, "example.com")}
	hosts := []asset.Host{
		mustHost(t, "www.example.com"),
		mustHost(t, "evil.com"),
	}
	urls := []asset.URL{
		mustURL(t, "https://www.example.com/login"),
		mustURL(t, "https://evil.com/x"),
	}
	in := detectInput(mustDomain(t, "example.com"), domains, hosts, urls, nil)

	res, err := NewDetectStage(reg).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	requireEqualStrings(t, "snapshot assets", captured,
		[]string{
			mustDomain(t, "example.com").Identity().String(),
			mustHost(t, "www.example.com").Identity().String(),
			mustURL(t, "https://www.example.com/login").Identity().String(),
		})
}

// TestDetectStageNonCanonicalTargetFallThrough pins the canonicality gate:
// a non-canonical target with a non-empty registry falls through to the
// engine with an empty snapshot — the unconstrained rule genuinely executes
// (observed through the capture), so the gate never masks engine behavior.
func TestDetectStageNonCanonicalTargetFallThrough(t *testing.T) {
	executed := false
	reg := newDetectRegistry(t, newDetectRule(t, "test.unconstrained", func(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
		executed = true
		return nil, nil
	}))
	in := detectInput(asset.Domain{Name: "Example.COM"}, nil, nil, nil, nil)

	res, err := NewDetectStage(reg).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !executed {
		t.Error("rule did not execute: the canonicality gate must fall through to the engine, not short-circuit")
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 1 {
		t.Errorf("ItemsProcessed = %d, want 1", res.ItemsProcessed)
	}
}

// TestDetectStageEngineConfigError pins the direct-caller zero-bounds path:
// the engine's own config validation (Concurrency must be > 0) surfaces as a
// failed outcome with the wrapped engine error.
func TestDetectStageEngineConfigError(t *testing.T) {
	reg := newDetectRegistry(t, newDetectRule(t, "test.rule", nil))
	domains := []asset.Domain{mustDomain(t, "example.com")}
	in := detectInput(mustDomain(t, "example.com"), domains, nil, nil, nil)
	in.Bounds = pipeline.StageConfig{} // zero bounds reach the engine verbatim

	res, err := NewDetectStage(reg).Run(context.Background(), in)
	if err == nil {
		t.Fatal("Run: nil error, want the engine's config-validation error")
	}
	if !strings.Contains(err.Error(), "stage detect:") || !strings.Contains(err.Error(), "Concurrency") {
		t.Errorf("error %q, want stage-prefixed engine config error", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("outcome %s, want failed", res.Outcome)
	}
	if res.Err == nil || res.Err.Error() != err.Error() {
		t.Errorf("res.Err = %v, want the returned error", res.Err)
	}
}

// TestDetectStagePreCancelled pins the pre-cancelled-context path: the stage
// reports cancelled with the context error attached and a nil Go error
// return — the outcome, not the error field, carries cancellation.
func TestDetectStagePreCancelled(t *testing.T) {
	reg := newDetectRegistry(t, newDetectRule(t, "test.rule", nil))
	domains := []asset.Domain{mustDomain(t, "example.com")}
	in := detectInput(mustDomain(t, "example.com"), domains, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := NewDetectStage(reg).Run(ctx, in)
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

// TestDetectStageEngineErrorAndFiredCtx pins the dominant-signal mapping: an
// engine error while the stage context is firing reports cancelled with the
// context error errors.Join-ed with the engine's detail — nothing is lost.
func TestDetectStageEngineErrorAndFiredCtx(t *testing.T) {
	reg := newDetectRegistry(t, newDetectRule(t, "test.rule", nil))
	domains := []asset.Domain{mustDomain(t, "example.com")}
	in := detectInput(mustDomain(t, "example.com"), domains, nil, nil, nil)
	in.Bounds = pipeline.StageConfig{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := NewDetectStage(reg).Run(ctx, in)
	if err != nil {
		t.Fatalf("Run: %v, want nil Go error (cancelled outcome carries the detail)", err)
	}
	if res.Outcome != pipeline.OutcomeCancelled {
		t.Fatalf("outcome %s, want cancelled (dominant signal)", res.Outcome)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Errorf("res.Err = %v, want joined context error", res.Err)
	}
	if !strings.Contains(res.Err.Error(), "Concurrency") {
		t.Errorf("res.Err = %v, want the engine detail joined in", res.Err)
	}
}

// TestDetectStageNilContext pins the nil-context guard (T2c review LOW-2).
func TestDetectStageNilContext(t *testing.T) {
	reg := newDetectRegistry(t, newDetectRule(t, "test.rule", nil))
	in := detectInput(mustDomain(t, "example.com"), nil, nil, nil, nil)

	res, err := NewDetectStage(reg).Run(nil, in)
	if err == nil || !strings.Contains(err.Error(), "context must not be nil") {
		t.Fatalf("Run: err = %v, want the nil-context error", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("outcome %s, want failed", res.Outcome)
	}
}

// TestDetectStageNilCache pins the caching-disabled path: a nil cache is a
// no-op for the engine and the stage still completes.
func TestDetectStageNilCache(t *testing.T) {
	reg := newDetectRegistry(t, newDetectRule(t, "test.rule", nil))
	domains := []asset.Domain{mustDomain(t, "example.com")}
	in := detectInput(mustDomain(t, "example.com"), domains, nil, nil, nil)

	res, err := NewDetectStage(reg).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 1 {
		t.Errorf("ItemsProcessed = %d, want 1", res.ItemsProcessed)
	}
}

// TestDetectStageFoldTable pins the aggregate-outcome mapping table
// (documented on detectStage.Run): the engine folds per-rule statuses itself,
// and the stage maps the engine's outcome vocabulary verbatim.
func TestDetectStageFoldTable(t *testing.T) {
	table := []struct {
		engine detect.Outcome
		want   pipeline.Outcome
	}{
		{detect.OutcomeCompleted, pipeline.OutcomeCompleted},
		{detect.OutcomeIncomplete, pipeline.OutcomePartial},
		{detect.OutcomeFailed, pipeline.OutcomeFailed},
		{detect.OutcomeCancelled, pipeline.OutcomeCancelled},
		{detect.Outcome("bogus"), pipeline.OutcomeFailed}, // contract violation never masked
	}
	for _, row := range table {
		if got := foldDetectOutcome(row.engine); got != row.want {
			t.Errorf("foldDetectOutcome(%q) = %s, want %s", row.engine, got, row.want)
		}
	}
}

// TestDetectStageCounters pins the honest counters: processed counts every
// rule the engine ATTEMPTED (completed + cancelled + failed), failed counts
// the failed rules, and skipped rules are excluded from both.
func TestDetectStageCounters(t *testing.T) {
	s := &detectStage{}
	rep := detect.Report{Outcome: detect.OutcomeIncomplete, Completed: 3, Failed: 1, Cancelled: 2, Skipped: 1}

	res := s.buildDetectResult(rep, foldDetectOutcome(rep.Outcome), nil)
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("outcome %s, want partial", res.Outcome)
	}
	if res.ItemsProcessed != 6 {
		t.Errorf("ItemsProcessed = %d, want 6 (3+1+2; the skipped rule is not processed)", res.ItemsProcessed)
	}
	if res.ItemsFailed != 1 {
		t.Errorf("ItemsFailed = %d, want 1", res.ItemsFailed)
	}
	if res.Truncated {
		t.Error("Truncated = true, want false (no truncation signal in this report)")
	}
}

// TestDetectStageTruncationMapping pins the never-swallowed truncation
// mapping: the engine's FindingsTruncated signal (findings cut at the fixed
// maxFindingsPerRun) sets Truncated and the detect_findings_truncated sticky
// flag (AGENTS §0.6), whatever the mapped outcome is.
func TestDetectStageTruncationMapping(t *testing.T) {
	s := &detectStage{}
	rep := detect.Report{Outcome: detect.OutcomeIncomplete, FindingsTruncated: true}

	res := s.buildDetectResult(rep, foldDetectOutcome(rep.Outcome), nil)
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("outcome %s, want partial (the engine reports a truncated run as incomplete)", res.Outcome)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true (truncation is never swallowed)")
	}
	if !res.StickyFlags[detectFindingsTruncatedFlag] {
		t.Errorf("StickyFlags = %v, want %s set", res.StickyFlags, detectFindingsTruncatedFlag)
	}
}

// TestDetectStageFoldAndTruncationIndependent pins that the sticky flag
// follows the engine signal regardless of the mapped outcome — the flag,
// never the outcome alone, marks the retained set incomplete.
func TestDetectStageFoldAndTruncationIndependent(t *testing.T) {
	s := &detectStage{}
	rep := detect.Report{Outcome: detect.OutcomeCompleted, FindingsTruncated: true}

	res := s.buildDetectResult(rep, foldDetectOutcome(rep.Outcome), nil)
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed (mapping is faithful)", res.Outcome)
	}
	if !res.Truncated || !res.StickyFlags[detectFindingsTruncatedFlag] {
		t.Errorf("Truncated=%v StickyFlags=%v, want the flag set alongside Truncated", res.Truncated, res.StickyFlags)
	}
}
