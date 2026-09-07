package adapt

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
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

// TestPriorityStageResultsChannel pins the T3d results wiring on the fresh
// happy path: one surface per completed asset result (canonical engine
// values, never rebuilt), the deterministic correlation groups and attack
// paths derived from those surfaces, and NO truncation flag (the corpus
// anchors in one group, far below the engine's fixed group cap).
func TestPriorityStageResultsChannel(t *testing.T) {
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
	if res.Truncated {
		t.Error("Truncated = true, want false (one group is below the correlation cut)")
	}
	if len(res.StickyFlags) != 0 {
		t.Errorf("StickyFlags = %v, want empty", res.StickyFlags)
	}

	// One surface per completed asset — all 4 corpus assets score cleanly.
	if got := len(res.Results.Surfaces); got != 4 {
		t.Fatalf("Surfaces = %d, want 4 (one per completed asset)", got)
	}
	wantIds := map[string]bool{
		asset.Identity{Kind: asset.KindDomain, Value: "example.com"}.String():          true,
		asset.Identity{Kind: asset.KindHost, Value: "admin.example.com"}.String():      true,
		asset.Identity{Kind: asset.KindHost, Value: "www.example.com"}.String():        true,
		mustURL(t, "https://admin.example.com/login?token=1&id=2").Identity().String(): true,
	}
	for _, s := range res.Results.Surfaces {
		if !wantIds[s.Identity.String()] {
			t.Errorf("surface identity %s not in the corpus set", s.Identity)
		}
	}

	// All four surfaces derive to the declared domain anchor — one group.
	if got := len(res.Results.Groups); got != 1 {
		t.Fatalf("Groups = %d, want 1 (all corpus assets anchor at example.com)", got)
	}
	g := res.Results.Groups[0]
	if got := g.Anchor.String(); got != "domain:example.com" {
		t.Errorf("group anchor = %s, want domain:example.com", got)
	}
	if got := len(g.Members); got != 4 {
		t.Errorf("group members = %d, want 4", got)
	}
	if g.Truncated {
		t.Error("group Truncated = true, want false (4 members are below the member cap)")
	}

	// The group carries factor-carrying members (the admin host and the URL
	// both match the interestingness catalog on their hostname), so one
	// attack-path hypothesis derives from it.
	if got := len(res.Results.AttackPaths); got != 1 {
		t.Fatalf("AttackPaths = %d, want 1 (one factor-carrying group)", got)
	}
	if got := res.Results.AttackPaths[0].Root.String(); got != "domain:example.com" {
		t.Errorf("attack path root = %s, want domain:example.com", got)
	}
}

// TestPriorityStageErrorPathMergesResults pins the every-path contract: an
// engine-error outcome still merges the report's honest completed assets
// through the results channel (surfaces, groups, attack paths) — a failed
// stage's retained results are never dropped.
func TestPriorityStageErrorPathMergesResults(t *testing.T) {
	s := &priorityStage{}
	rep := priority.Report{
		Outcome: priority.OutcomeFailed,
		Assets: []priority.AssetResult{
			{
				Status: priority.StatusCompleted,
				Surface: &priority.SurfaceAsset{
					Identity: asset.Identity{Kind: asset.KindHost, Value: "admin.example.com"},
				},
			},
			{
				Status: priority.StatusFailed, // never surfaces
				Surface: &priority.SurfaceAsset{
					Identity: asset.Identity{Kind: asset.KindHost, Value: "broken.example.com"},
				},
			},
		},
	}
	res := s.buildPriorityResult(rep, pipeline.OutcomeFailed, errors.New("engine failed"))
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("outcome %s, want failed", res.Outcome)
	}
	if res.Err == nil {
		t.Fatal("Err = nil, want the engine error carried on the result")
	}
	if got := len(res.Results.Surfaces); got != 1 {
		t.Fatalf("Surfaces = %d, want 1 (only the completed asset)", got)
	}
	if got := res.Results.Surfaces[0].Identity.String(); got != "host:admin.example.com" {
		t.Errorf("surface identity = %s, want host:admin.example.com", got)
	}
	if got := len(res.Results.Groups); got != 1 {
		t.Errorf("Groups = %d, want 1 (singleton group for the completed asset)", got)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Errorf("Truncated=%v StickyFlags=%v, want no truncation (one group, no cut)", res.Truncated, res.StickyFlags)
	}
}

// TestPriorityStageCorrelationCutFlag pins the never-swallowed correlation
// cut: a corpus whose surfaces exceed the engine's fixed maxCorrelationGroups
// distinct anchors yields the capped group set, Truncated, and the
// priority_groups_truncated sticky flag (AGENTS §0.6) — the flag, never the
// outcome alone, marks the retained set incomplete.
func TestPriorityStageCorrelationCutFlag(t *testing.T) {
	interesting, risk := priorityCatalogs(t)
	// 1025 in-scope hosts, each with a distinct parent-domain anchor
	// (x.pN.example.com anchors at pN.example.com). The priority engine's
	// Correlate retains at most maxCorrelationGroups = 1024 groups.
	var hosts []asset.Host
	for i := 0; i < 1025; i++ {
		hosts = append(hosts, mustHost(t, fmt.Sprintf("x.p%d.example.com", i)))
	}
	in := priorityInput(mustDomain(t, "example.com"), nil, hosts, nil, &recordingCache{})

	res, err := NewPriorityStage(interesting, risk).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome %s, want completed (every asset scored; only the group set was cut)", res.Outcome)
	}
	if got := len(res.Results.Surfaces); got != 1025 {
		t.Fatalf("Surfaces = %d, want 1025 (the correlation cut never drops surfaces)", got)
	}
	if got := len(res.Results.Groups); got != 1024 {
		t.Fatalf("Groups = %d, want 1024 (the fixed group cap)", got)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true (groups were cut)")
	}
	if !res.StickyFlags[priorityGroupsTruncated] {
		t.Errorf("StickyFlags = %v, want %s set", res.StickyFlags, priorityGroupsTruncated)
	}
}

func TestQueryParamNamesSkipsValuelessKeys(t *testing.T) {
	// NEW-14 alignment: "?flag" and "?flag=" carry no observed value, so
	// they yield no name — the same rule urlintel's extractParams applies.
	names, truncated := queryParamNames("a=1&flag&b=2&empty=&c=3")
	if got, want := strings.Join(names, ","), "a,b,c"; got != want {
		t.Errorf("names = %q, want %q", got, want)
	}
	if truncated {
		t.Error("truncated = true, want false (well under the bound)")
	}

	names, truncated = queryParamNames("")
	if names != nil || truncated {
		t.Errorf("empty query = %v/%v, want nil/false", names, truncated)
	}
}

func TestPriorityStageParamOverflowTruncatesNotFails(t *testing.T) {
	// NEW-14: a URL with 70 parameters must NOT fail engine validation —
	// the derivation retains the first 64 canonical (sorted) names and the
	// stage reports Truncated + priority_params_truncated; the asset still
	// scores (completed).
	interesting, risk := priorityCatalogs(t)
	domains := []asset.Domain{mustDomain(t, "example.com")}
	var q []string
	for i := 0; i < 70; i++ {
		q = append(q, fmt.Sprintf("p%02d=%d", i, i))
	}
	urls := []asset.URL{mustURL(t, "https://admin.example.com/x?"+strings.Join(q, "&"))}
	in := priorityInput(mustDomain(t, "example.com"), domains, nil, urls, &recordingCache{})

	res, err := NewPriorityStage(interesting, risk).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcome = %s, want completed (truncation degrades the input, never fails the asset)", res.Outcome)
	}
	if res.ItemsProcessed != 2 || res.ItemsFailed != 0 {
		t.Errorf("counters = %d/%d, want 2/0 (declared domain + URL)", res.ItemsProcessed, res.ItemsFailed)
	}
	if !res.Truncated {
		t.Error("Truncated = true required")
	}
	if !res.StickyFlags[priorityParamsTruncated] {
		t.Errorf("StickyFlags = %v, want %q set", res.StickyFlags, priorityParamsTruncated)
	}
	if len(res.Results.Surfaces) != 2 {
		t.Fatalf("surfaces = %d, want 2 (the domain and the scored URL)", len(res.Results.Surfaces))
	}

	// Unit-level: the derivation itself retains exactly the bound and
	// reports the cut.
	names, truncated := queryParamNames(strings.Join(q, "&"))
	if len(names) != priority.MaxParamsPerSignal || !truncated {
		t.Errorf("derivation = %d names (trunc=%v), want exactly %d with truncation", len(names), truncated, priority.MaxParamsPerSignal)
	}
	if names[0] != "p00" || names[len(names)-1] != "p63" {
		t.Errorf("retained names not the first bound-many in canonical order: %q..%q", names[0], names[len(names)-1])
	}
}

// enrichFixtures builds one URL's enrichment results: a technology, a
// secret, two endpoints (GET + GQL), a JavaScript asset, a live record
// with headers, and the url→technology / url→secret_candidate edges.
func enrichFixtures(t testing.TB, rawURL string) (asset.URL, pipeline.Results) {
	t.Helper()
	u := mustURL(t, rawURL)
	tech, err := asset.NewTechnology("synthetic-tech", asset.CategoryFramework, asset.Provenance{Source: "test", Confidence: 0.9})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	secret, err := asset.NewSecretCandidate(asset.SecretTypeAWS, "AKIAIOSFODNN7EXAMPLE", u.Identity(), asset.Provenance{Source: "test", Confidence: 0.8})
	if err != nil {
		t.Fatalf("NewSecretCandidate: %v", err)
	}
	epGet, err := asset.NewEndpoint("GET", rawURL, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEndpoint GET: %v", err)
	}
	epGQL, err := asset.NewEndpoint("GQL", rawURL, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEndpoint GQL: %v", err)
	}
	js, err := asset.NewJavaScript(rawURL, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	js, err = asset.WithSize(js, 2048)
	if err != nil {
		t.Fatalf("WithSize: %v", err)
	}
	relTech, err := asset.NewRelationship(u.Identity(), asset.RelationshipURLToTechnology, tech.Identity())
	if err != nil {
		t.Fatalf("NewRelationship tech: %v", err)
	}
	relSecret, err := asset.NewRelationship(u.Identity(), asset.RelationshipURLToSecretCandidate, secret.Identity())
	if err != nil {
		t.Fatalf("NewRelationship secret: %v", err)
	}
	res := pipeline.Results{
		Technologies: []asset.Technology{tech},
		Secrets:      []asset.SecretCandidate{secret},
		Endpoints:    []asset.Endpoint{epGet, epGQL},
		JavaScript:   []asset.JavaScript{js},
		LiveRecords: []httpprobe.LiveRecord{{
			URL:     u,
			Status:  200,
			Headers: http.Header{"X-Powered-By": {"Express"}, "Server": {"nginx"}},
		}},
		Relationships: []asset.Relationship{relTech, relSecret},
	}
	return u, res
}

func findURLSignal(t testing.TB, sigs []priority.Signal, id asset.Identity) priority.Signal {
	t.Helper()
	for _, s := range sigs {
		if s.Identity == id {
			return s
		}
	}
	t.Fatalf("no signal for %s", id)
	return priority.Signal{}
}

// TestPrioritySignalsURLEnrichment pins NEW-119: URL signals carry the
// observed technologies, secrets, headers, JS bundle size, and endpoint
// method resolved from the results channel by URL identity —
// deterministically ordered, with the most specific endpoint method
// winning over plain GET.
func TestPrioritySignalsURLEnrichment(t *testing.T) {
	u, res := enrichFixtures(t, "https://www.example.com/app.js")
	sigs, paramsTruncated, signalsTruncated := buildPrioritySignals(nil, nil, []asset.URL{u}, res)
	if paramsTruncated || signalsTruncated {
		t.Fatalf("truncation = %v/%v, want false/false (well under every bound)", paramsTruncated, signalsTruncated)
	}
	if len(sigs) != 1 {
		t.Fatalf("signals = %d, want 1", len(sigs))
	}
	sig := sigs[0]
	if len(sig.Technologies) != 1 || sig.Technologies[0].Name != "synthetic-tech" ||
		sig.Technologies[0].Category != "framework" || sig.Technologies[0].Confidence != 0.9 ||
		sig.Technologies[0].Identity != "framework/synthetic%2Dtech" {
		t.Errorf("technologies = %+v, want [{synthetic-tech framework 0.9 framework/synthetic%%2Dtech}] (canonical identity value, hyphen percent-encoded)", sig.Technologies)
	}
	if len(sig.Secrets) != 1 || sig.Secrets[0].Type != asset.SecretTypeAWS || sig.Secrets[0].Confidence != 0.8 {
		t.Errorf("secrets = %+v, want the bound AWS candidate at 0.8", sig.Secrets)
	}
	wantHeaders := []string{"server: nginx", "x-powered-by: Express"}
	if len(sig.Headers) != len(wantHeaders) {
		t.Fatalf("headers = %q, want %q (sorted lowercased key: value lines)", sig.Headers, wantHeaders)
	}
	for i := range wantHeaders {
		if sig.Headers[i] != wantHeaders[i] {
			t.Errorf("headers = %q, want %q", sig.Headers, wantHeaders)
			break
		}
	}
	if sig.JSBundleBytes != 2048 {
		t.Errorf("jsBundleBytes = %d, want 2048", sig.JSBundleBytes)
	}
	if sig.EndpointMethod != "GQL" {
		t.Errorf("endpointMethod = %q, want GQL (most specific method wins over GET)", sig.EndpointMethod)
	}
	if sig.Path != "/app.js" || sig.Hostname != "www.example.com" {
		t.Errorf("path/hostname = %q/%q, want /app.js/www.example.com (existing fields intact)", sig.Path, sig.Hostname)
	}
}

// TestPrioritySignalsCaps pins the derivation bounds: over-bound families
// retain a deterministic sorted head and report the cut — an asset never
// fails engine validation for bounded upstream data.
func TestPrioritySignalsCaps(t *testing.T) {
	u := mustURL(t, "https://www.example.com/app.js")
	var techs []asset.Technology
	var rels []asset.Relationship
	for i := 0; i < 33; i++ {
		tech, err := asset.NewTechnology(fmt.Sprintf("tech-%02d", i), asset.CategoryFramework, asset.Provenance{Confidence: 0.5})
		if err != nil {
			t.Fatalf("NewTechnology: %v", err)
		}
		techs = append(techs, tech)
		r, err := asset.NewRelationship(u.Identity(), asset.RelationshipURLToTechnology, tech.Identity())
		if err != nil {
			t.Fatalf("NewRelationship: %v", err)
		}
		rels = append(rels, r)
	}
	headers := http.Header{}
	for i := 0; i < 129; i++ {
		headers[fmt.Sprintf("X-Test-%03d", i)] = []string{"v"}
	}
	headers["X-Big"] = []string{strings.Repeat("v", 600)}
	res := pipeline.Results{
		Technologies:  techs,
		Relationships: rels,
		LiveRecords:   []httpprobe.LiveRecord{{URL: u, Status: 200, Headers: headers}},
	}
	sigs, _, truncated := buildPrioritySignals(nil, nil, []asset.URL{u}, res)
	if !truncated {
		t.Fatal("truncated = false, want true (techs 33>32, headers 130>128, one overlong line)")
	}
	sig := findURLSignal(t, sigs, u.Identity())
	if len(sig.Technologies) != 32 {
		t.Errorf("technologies = %d, want 32 (sorted head)", len(sig.Technologies))
	}
	if sig.Technologies[0].Name != "tech-00" || sig.Technologies[31].Name != "tech-31" {
		t.Errorf("technology head not the sorted-first 32: %q..%q", sig.Technologies[0].Name, sig.Technologies[31].Name)
	}
	if len(sig.Headers) != 128 {
		t.Errorf("headers = %d, want 128", len(sig.Headers))
	}
	for _, h := range sig.Headers {
		if len(h) > 512 {
			t.Errorf("header line %d bytes, want ≤512 (truncated)", len(h))
		}
	}
}

// TestPrioritySignalsInvalidFiltered pins defensive filtering: corrupt
// upstream entries (empty names, NaN/out-of-range confidences, unknown
// secret types) are skipped without failing the asset or flagging a cut.
func TestPrioritySignalsInvalidFiltered(t *testing.T) {
	u := mustURL(t, "https://www.example.com/app.js")
	badTech := asset.Technology{Name: "", Category: asset.CategoryFramework, Prov: asset.Provenance{Confidence: 0.5}}
	nanTech, _ := asset.NewTechnology("nan-tech", asset.CategoryFramework, asset.Provenance{Confidence: math.NaN()})
	badSecret := asset.SecretCandidate{Type: asset.SecretType("bogus"), Prov: asset.Provenance{Confidence: 0.5}}
	rels := []asset.Relationship{}
	for _, id := range []asset.Identity{badTech.Identity(), nanTech.Identity(), badSecret.Identity()} {
		kind := asset.RelationshipURLToTechnology
		if id.Kind == asset.KindSecretCandidate {
			kind = asset.RelationshipURLToSecretCandidate
		}
		r, err := asset.NewRelationship(u.Identity(), kind, id)
		if err != nil {
			t.Fatalf("NewRelationship: %v", err)
		}
		rels = append(rels, r)
	}
	res := pipeline.Results{
		Technologies:  []asset.Technology{badTech, nanTech},
		Secrets:       []asset.SecretCandidate{badSecret},
		Relationships: rels,
	}
	sigs, _, truncated := buildPrioritySignals(nil, nil, []asset.URL{u}, res)
	if truncated {
		t.Error("truncated = true, want false (filtering corrupt entries is not a cut)")
	}
	sig := findURLSignal(t, sigs, u.Identity())
	if len(sig.Technologies) != 0 || len(sig.Secrets) != 0 {
		t.Errorf("technologies/secrets = %+v/%+v, want both empty (corrupt entries filtered)", sig.Technologies, sig.Secrets)
	}
}

// TestPriorityStageEnrichedScoring pins the end-to-end effect: the same
// corpus scores higher with enrichment than without, and warm runs replay
// it identically (signal-fingerprint cache keys cover every enriched
// field by construction).
func TestPriorityStageEnrichedScoring(t *testing.T) {
	interesting, err := priority.CompileForTest("interestingness", []priority.Indicator{
		{ID: "test-tech", Category: "interestingness", Weight: 0.9,
			Field: priority.FieldTechName, Terms: []string{"synthetic-tech"},
			Reason: "tech %s", Recommendation: "test guidance %s"},
	})
	if err != nil {
		t.Fatalf("CompileForTest: %v", err)
	}
	risk, err := priority.CompileForTest("risk", []priority.Indicator{
		{ID: "test-header", Category: "risk", Weight: 0.7,
			Field: priority.FieldHeader, Terms: []string{"x-powered-by: express"},
			Reason: "header %s", Recommendation: "test guidance %s"},
	})
	if err != nil {
		t.Fatalf("CompileForTest: %v", err)
	}
	u, res := enrichFixtures(t, "https://www.example.com/app.js")
	target := mustDomain(t, "example.com")
	c := &recordingCache{}

	bare, err := NewPriorityStage(interesting, risk).Run(context.Background(), priorityInput(target, nil, nil, []asset.URL{u}, c))
	if err != nil {
		t.Fatalf("bare Run: %v", err)
	}
	enrichedIn := priorityInput(target, nil, nil, []asset.URL{u}, c)
	enrichedIn.Results = res
	enriched, err := NewPriorityStage(interesting, risk).Run(context.Background(), enrichedIn)
	if err != nil {
		t.Fatalf("enriched Run: %v", err)
	}
	if enriched.Outcome != pipeline.OutcomeCompleted || bare.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("outcomes = %q/%q, want completed/completed", enriched.Outcome, bare.Outcome)
	}
	bareScore := surfaceScoreFor(t, bare, u.Identity())
	enrichedScore := surfaceScoreFor(t, enriched, u.Identity())
	if !(enrichedScore > bareScore) {
		t.Errorf("enriched score %v <= bare score %v (enrichment must add factors)", enrichedScore, bareScore)
	}
	// Warm parity: identical inputs replay identical surfaces.
	warmIn := priorityInput(target, nil, nil, []asset.URL{u}, c)
	warmIn.Results = res
	warm, err := NewPriorityStage(interesting, risk).Run(context.Background(), warmIn)
	if err != nil {
		t.Fatalf("warm Run: %v", err)
	}
	if len(warm.Results.Surfaces) != len(enriched.Results.Surfaces) {
		t.Fatalf("warm surfaces = %d, enriched = %d", len(warm.Results.Surfaces), len(enriched.Results.Surfaces))
	}
	for i := range enriched.Results.Surfaces {
		if warm.Results.Surfaces[i].Score != enriched.Results.Surfaces[i].Score {
			t.Errorf("warm surface[%d] score %v != enriched %v", i, warm.Results.Surfaces[i].Score, enriched.Results.Surfaces[i].Score)
		}
	}
}

func surfaceScoreFor(t testing.TB, res pipeline.StageResult, id asset.Identity) float64 {
	t.Helper()
	for _, s := range res.Results.Surfaces {
		if s.Identity == id {
			return s.Score
		}
	}
	t.Fatalf("no surface for %s", id)
	return 0
}
