package adapt

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/priority"
)

// priorityInput builds a StageInput for the priority stage with the resolved
// default bounds (through the runner these are never zero — the engine's own
// validation requires positive Concurrency/QueueSize) and the deterministic
// fixed clock the package's dns tests share.
func priorityInput(target asset.Domain, domains []asset.Domain, hosts []asset.Host, urls []asset.URL, c cache.Cache) pipeline.StageInput {
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

// priorityCatalogs builds the hermetic catalogs the priority tests share: an
// interestingness entry matching the hostname label "admin" and a risk entry
// matching the URL path "/admin".
func priorityCatalogs(t *testing.T) (*priority.Catalog, *priority.Catalog) {
	t.Helper()
	interesting, err := priority.CompileForTest("interestingness", []priority.Indicator{
		{ID: "test-admin", Category: "interestingness", Weight: 0.9,
			Field: priority.FieldHost, Terms: []string{"admin"},
			Reason: "admin host %s", Recommendation: "test guidance %s"},
	})
	if err != nil {
		t.Fatalf("CompileForTest(interestingness): %v", err)
	}
	risk, err := priority.CompileForTest("risk", []priority.Indicator{
		{ID: "test-admin-path", Category: "risk", Weight: 0.7,
			Field: priority.FieldPath, Terms: []string{"/admin"},
			Reason: "admin path %s", Recommendation: "test guidance %s"},
	})
	if err != nil {
		t.Fatalf("CompileForTest(risk): %v", err)
	}
	return interesting, risk
}

// mustURL builds a canonical URL asset, failing the test on any error.
func mustURL(t testing.TB, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u
}

// priorityCorpus builds the canonical in-scope corpus the happy-path tests
// share: the declared domain itself, an "admin" subdomain (matches the
// interestingness catalog), and a URL on that subdomain.
func priorityCorpus(t *testing.T) ([]asset.Domain, []asset.Host, []asset.URL) {
	t.Helper()
	domains := []asset.Domain{mustDomain(t, "example.com")}
	hosts := []asset.Host{
		mustHost(t, "admin.example.com"),
		mustHost(t, "www.example.com"),
	}
	urls := []asset.URL{
		mustURL(t, "https://admin.example.com/login?token=1&id=2"),
	}
	return domains, hosts, urls
}

// TestPriorityStageName pins the stage's pipeline identity.
func TestPriorityStageName(t *testing.T) {
	if got := NewPriorityStage(nil, nil).Name(); got != pipeline.StagePriority {
		t.Fatalf("Name() = %q, want %q", got, pipeline.StagePriority)
	}
}

// TestPriorityStageHappyPath pins the full fresh run: one signal per in-scope
// corpus asset, cache-before-execute around every asset (one Get and one Put
// per scored asset), the honest counters, and NO corpus additions (surfaces
// are results — T3).
func TestPriorityStageHappyPath(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	domains, hosts, urls := priorityCorpus(t)
	c := &recordingCache{}
	in := priorityInput(mustDomain(t, "example.com"), domains, hosts, urls, c)

	res, err := NewPriorityStage(interesting, risk).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 4 {
		t.Errorf("ItemsProcessed = %d, want 4 (1 domain + 2 hosts + 1 URL)", res.ItemsProcessed)
	}
	if res.ItemsFailed != 0 {
		t.Errorf("ItemsFailed = %d, want 0", res.ItemsFailed)
	}
	if res.Truncated {
		t.Error("Truncated = true, want false (the priority engine reports no truncation signals)")
	}
	if res.Err != nil {
		t.Errorf("Err = %v, want nil", res.Err)
	}
	if len(res.Additions.Domains) != 0 || len(res.Additions.Hosts) != 0 || len(res.Additions.URLs) != 0 {
		t.Errorf("Additions = %+v, want empty (surfaces are results, not corpus)", res.Additions)
	}
	if got, want := len(c.getKeys()), 4; got != want {
		t.Errorf("cache Gets = %d, want %d (one lookup per asset)", got, want)
	}
	if got, want := c.putCount(), 4; got != want {
		t.Errorf("cache Puts = %d, want %d (every completed asset stored)", got, want)
	}
}

// TestPriorityStageEmptyCorpusShortCircuit pins the vacuous-completed
// short-circuit: an empty filtered corpus with a canonical target never
// reaches the engine (zero cache interaction) and reports completed.
func TestPriorityStageEmptyCorpusShortCircuit(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	c := &recordingCache{}
	in := priorityInput(mustDomain(t, "example.com"), nil, nil, nil, c)

	res, err := NewPriorityStage(interesting, risk).Run(context.Background(), in)
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

// TestPriorityStageNonCanonicalTargetFallThrough pins the canonicality gate:
// a non-canonical target makes the scope filter unsound, so the stage runs
// the engine with an empty (closed) signal channel instead of claiming a
// completed short-circuit — the engine's own honest vacuous completed.
func TestPriorityStageNonCanonicalTargetFallThrough(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	c := &recordingCache{}
	bad := asset.Domain{Name: "Example.COM"}
	in := priorityInput(bad, nil, nil, nil, c)

	res, err := NewPriorityStage(interesting, risk).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed (vacuous engine run)", res.Outcome)
	}
	if res.ItemsProcessed != 0 || res.ItemsFailed != 0 {
		t.Errorf("counters = %d/%d, want 0/0", res.ItemsProcessed, res.ItemsFailed)
	}
}

// TestPriorityStageOutOfDomainFilter pins the mandatory input-side boundary
// filter: out-of-domain hosts and URLs never reach the engine — only the
// in-scope corpus entries are scored.
func TestPriorityStageOutOfDomainFilter(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	c := &recordingCache{}
	domains := []asset.Domain{mustDomain(t, "example.com")}
	hosts := []asset.Host{
		mustHost(t, "admin.example.com"),
		mustHost(t, "evil.com"),
	}
	urls := []asset.URL{
		mustURL(t, "https://admin.example.com/login"),
		mustURL(t, "https://evil.com/x"),
	}
	in := priorityInput(mustDomain(t, "example.com"), domains, hosts, urls, c)

	res, err := NewPriorityStage(interesting, risk).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", res.Outcome)
	}
	if res.ItemsProcessed != 3 {
		t.Errorf("ItemsProcessed = %d, want 3 (evil.com host and URL filtered)", res.ItemsProcessed)
	}
	if got, want := len(c.getKeys()), 3; got != want {
		t.Errorf("cache Gets = %d, want %d", got, want)
	}
}

// TestPriorityStageEngineConfigError pins the direct-caller zero-bounds path:
// the engine's own config validation (Concurrency must be > 0) surfaces as a
// failed outcome with the wrapped engine error.
func TestPriorityStageEngineConfigError(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	domains, _, _ := priorityCorpus(t)
	in := priorityInput(mustDomain(t, "example.com"), domains, nil, nil, nil)
	in.Bounds = pipeline.StageConfig{} // zero bounds reach the engine verbatim

	res, err := NewPriorityStage(interesting, risk).Run(context.Background(), in)
	if err == nil {
		t.Fatal("Run: nil error, want the engine's config-validation error")
	}
	if !strings.Contains(err.Error(), "stage priority:") || !strings.Contains(err.Error(), "Concurrency") {
		t.Errorf("error %q, want stage-prefixed engine config error", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("outcome %s, want failed", res.Outcome)
	}
	if res.Err == nil || res.Err.Error() != err.Error() {
		t.Errorf("res.Err = %v, want the returned error", res.Err)
	}
}

// TestPriorityStagePreCancelled pins the pre-cancelled-context path: the
// engine drains to an (empty) report, and the stage's own context check
// drives the cancelled outcome — the outcome, not the error field, carries
// cancellation (nil Go error return).
func TestPriorityStagePreCancelled(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	domains, _, _ := priorityCorpus(t)
	in := priorityInput(mustDomain(t, "example.com"), domains, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := NewPriorityStage(interesting, risk).Run(ctx, in)
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

// TestPriorityStageEngineErrorAndFiredCtx pins the dominant-signal mapping: an
// engine error while the stage context is firing reports cancelled with the
// context error errors.Join-ed with the engine's detail — nothing is lost.
func TestPriorityStageEngineErrorAndFiredCtx(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	domains, _, _ := priorityCorpus(t)
	in := priorityInput(mustDomain(t, "example.com"), domains, nil, nil, nil)
	in.Bounds = pipeline.StageConfig{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := NewPriorityStage(interesting, risk).Run(ctx, in)
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

// TestPriorityStageNilContext pins the nil-context guard (T2c review LOW-2).
func TestPriorityStageNilContext(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	in := priorityInput(mustDomain(t, "example.com"), nil, nil, nil, nil)

	res, err := NewPriorityStage(interesting, risk).Run(nil, in)
	if err == nil || !strings.Contains(err.Error(), "context must not be nil") {
		t.Fatalf("Run: err = %v, want the nil-context error", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("outcome %s, want failed", res.Outcome)
	}
}

// TestPriorityStageNilCache pins the caching-disabled path: a nil cache is a
// no-op for the engine (every asset scored fresh) and the stage still
// completes.
func TestPriorityStageNilCache(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	domains, hosts, urls := priorityCorpus(t)
	in := priorityInput(mustDomain(t, "example.com"), domains, hosts, urls, nil)

	res, err := NewPriorityStage(interesting, risk).Run(context.Background(), in)
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

// TestPriorityStageProductionCatalogs pins the nil/nil seam: the engine's
// compiled-in production tables load and the stage completes (the load is
// hermetic — the tables are Go literals, no I/O).
func TestPriorityStageProductionCatalogs(t *testing.T) {
	domains, _, _ := priorityCorpus(t)
	in := priorityInput(mustDomain(t, "example.com"), domains, nil, nil, nil)

	res, err := NewPriorityStage(nil, nil).Run(context.Background(), in)
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

// TestPriorityStageSingleCatalogSeam pins the seam completion rule: a single
// provided catalog never mixes with a production table — the missing
// counterpart is an explicit EMPTY catalog, and the engine still runs (its
// digest check requires both catalogs non-nil).
func TestPriorityStageSingleCatalogSeam(t *testing.T) {
	interesting, _ := priorityCatalogs(t)
	domains, _, _ := priorityCorpus(t)
	in := priorityInput(mustDomain(t, "example.com"), domains, nil, nil, nil)

	res, err := NewPriorityStage(interesting, nil).Run(context.Background(), in)
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

// TestPriorityStageFoldTable pins the aggregate-outcome mapping table
// (documented on priorityStage.Run): the engine folds per-asset statuses
// itself, and the stage maps the engine's outcome vocabulary verbatim.
func TestPriorityStageFoldTable(t *testing.T) {
	table := []struct {
		engine priority.Outcome
		want   pipeline.Outcome
	}{
		{priority.OutcomeCompleted, pipeline.OutcomeCompleted},
		{priority.OutcomeIncomplete, pipeline.OutcomePartial},
		{priority.OutcomeFailed, pipeline.OutcomeFailed},
		{priority.OutcomeCancelled, pipeline.OutcomeCancelled},
		{priority.Outcome("bogus"), pipeline.OutcomeFailed}, // contract violation never masked
	}
	for _, row := range table {
		if got := foldPriorityOutcome(row.engine); got != row.want {
			t.Errorf("foldPriorityOutcome(%q) = %s, want %s", row.engine, got, row.want)
		}
	}
}

// TestPriorityStageCounters pins the honest counters: processed counts every
// asset the engine processed (completed + cancelled + failed), failed counts
// the unscorable ones.
func TestPriorityStageCounters(t *testing.T) {
	s := &priorityStage{}
	rep := priority.Report{Outcome: priority.OutcomeIncomplete, Completed: 3, Failed: 1, Cancelled: 2}

	res := s.buildPriorityResult(rep, foldPriorityOutcome(rep.Outcome), nil)
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("outcome %s, want partial", res.Outcome)
	}
	if res.ItemsProcessed != 6 {
		t.Errorf("ItemsProcessed = %d, want 6 (3+1+2)", res.ItemsProcessed)
	}
	if res.ItemsFailed != 1 {
		t.Errorf("ItemsFailed = %d, want 1", res.ItemsFailed)
	}
}
