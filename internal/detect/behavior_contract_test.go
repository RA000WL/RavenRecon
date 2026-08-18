// Behavior contract tests for the frozen SDK surface (milestone v1.2.5,
// T5b): nine semantic contracts pin the Level-1 "SDK v1 (Core)" freeze
// described in api.go and doc.go — Registry seal and post-seal reads,
// registration deep-copying, deterministic graph validation, API
// versioning, the fixed vocabularies and parsers, the run outcome
// vocabulary, run determinism, and the Context immutability boundary.
//
// Every test is deterministic and hermetic: no sleeps, no timers, no
// network, synthetic input only. Fixtures and helpers are reused from the
// sibling test files (testSnapshot, makeRule, newTestRegistry, resultOf,
// fixedClock in fixtures_test.go / engine_test.go) — nothing here is
// reinvented.
package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// ---------------------------------------------------------------------------
// Contract 1 — the seal contract: Register → Seal → Register fails.
// ---------------------------------------------------------------------------

// Contract: registration is confined to startup. A Register that follows a
// Seal fails with exactly "detect: registry is sealed", and the sealed
// check precedes per-rule validation — an invalid rule after Seal reports
// the same sealed error, per Registry.Register's doc.
func TestContractSealRejectsLateRegistration(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(makeRule(t, "a.b", nil)); err != nil {
		t.Fatalf("register before seal: %v", err)
	}
	reg.Seal()

	err := reg.Register(makeRule(t, "c.d", nil))
	if err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("register after seal = %v, want exactly %q", err, "detect: registry is sealed")
	}
	// The sealed check precedes validation (report parity).
	if err := reg.Register(Rule{}); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("invalid rule after seal must still report the sealed error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Contract 2 — the post-seal reads contract: Get/Rules/Len/Validate work.
// ---------------------------------------------------------------------------

// Contract: Seal freezes writes only, never reads. Get (hit and miss),
// Rules (deterministic ID-sorted copies), Len, and Validate keep working
// after Seal, including Validate over a dependency graph.
func TestContractPostSealReadsStillWork(t *testing.T) {
	reg := NewRegistry()
	for _, r := range []Rule{
		makeRule(t, "a.parent", nil),
		makeRule(t, "b.child", &ruleOptions{deps: []string{"a.parent"}}),
		makeRule(t, "c.other", nil),
	} {
		if err := reg.Register(r); err != nil {
			t.Fatalf("register %q: %v", r.ID, err)
		}
	}
	reg.Seal()

	if got, ok := reg.Get("b.child"); !ok ||
		got.ID != "b.child" || len(got.Dependencies) != 1 || got.Dependencies[0] != "a.parent" {
		t.Fatalf("Get after seal failed: %+v (ok %v)", got, ok)
	}
	if _, ok := reg.Get("no.such.rule"); ok {
		t.Fatalf("Get must report a miss after seal")
	}
	rules := reg.Rules()
	if len(rules) != 3 ||
		rules[0].ID != "a.parent" || rules[1].ID != "b.child" || rules[2].ID != "c.other" {
		t.Fatalf("Rules after seal wrong shape/order: %+v", rules)
	}
	if reg.Len() != 3 {
		t.Fatalf("Len after seal = %d, want 3", reg.Len())
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate after seal: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Contract 3 — the deep-copy contract: Register copies, aliases are inert.
// ---------------------------------------------------------------------------

// Contract: the Registry stores immutable deep copies. Mutating the
// caller's Rule after Register leaves the registered copy pristine — proven
// both by inspection through Registry.Get and by a run: had the registered
// dependency graph been corrupted through the caller's alias, Validate
// (and therefore Run) would have failed.
func TestContractRegisterDeepCopiesRule(t *testing.T) {
	reg := NewRegistry()
	parent := makeRule(t, "dep.parent", nil)
	child := makeRule(t, "dep.child", &ruleOptions{deps: []string{"dep.parent"}})
	child.Inputs = []RuleInput{InputAssets, InputEndpoints}
	child.Outputs = []RuleOutput{OutputFindings}
	child.RequiredAssetTypes = []asset.Kind{asset.KindURL}
	if err := reg.Register(parent); err != nil {
		t.Fatalf("register parent: %v", err)
	}
	if err := reg.Register(child); err != nil {
		t.Fatalf("register child: %v", err)
	}

	// Mutate every caller-held alias after registration.
	child.Dependencies[0] = "zzz.missing"
	child.Inputs[0] = RuleInput("bogus")
	child.Outputs[0] = RuleOutput("bogus")
	child.RequiredAssetTypes[0] = asset.Kind("bogus")
	child.Name = "Tampered"
	child.Detector = nil

	// Inspection through Registry.Get: the registered copy is pristine.
	got, ok := reg.Get("dep.child")
	if !ok {
		t.Fatalf("Get after registration failed")
	}
	if got.Name != "Rule dep.child" || got.Detector == nil {
		t.Fatalf("registered copy corrupted through the caller alias: %+v", got)
	}
	if len(got.Dependencies) != 1 || got.Dependencies[0] != "dep.parent" {
		t.Fatalf("registered dependencies corrupted: %+v", got.Dependencies)
	}
	if len(got.Inputs) != 2 || got.Inputs[0] != InputAssets || got.Inputs[1] != InputEndpoints {
		t.Fatalf("registered inputs corrupted: %+v", got.Inputs)
	}
	if len(got.Outputs) != 1 || got.Outputs[0] != OutputFindings {
		t.Fatalf("registered outputs corrupted: %+v", got.Outputs)
	}
	if len(got.RequiredAssetTypes) != 1 || got.RequiredAssetTypes[0] != asset.KindURL {
		t.Fatalf("registered required kinds corrupted: %+v", got.RequiredAssetTypes)
	}

	// A run over the registry proves the stored copy is usable: a corrupted
	// copy would fail Validate (unregistered dependency) or validation.
	rep, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t))
	if err != nil {
		t.Fatalf("Run over the aliased registry must succeed: %v", err)
	}
	if rep.Outcome != OutcomeCompleted {
		t.Fatalf("outcome %s, want completed", rep.Outcome)
	}
	if resultOf(t, rep, "dep.parent").Status != RuleStatusCompleted ||
		resultOf(t, rep, "dep.child").Status != RuleStatusCompleted {
		t.Fatalf("both rules must complete against the pristine copies: %+v", rep.Rules)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("findings %d, want 2", len(rep.Findings))
	}
}

// ---------------------------------------------------------------------------
// Contract 4 — the graph validation contract: deterministic errors.
// ---------------------------------------------------------------------------

// Contract: missing-dependency and cycle graphs fail Registry.Validate with
// deterministic, exact error strings. A missing dependency names the
// offending rule and its FIRST undeclared dependency; a cycle names the
// smallest-ID rule on the cycle (the scheduler's deterministic choice), and
// the same error is returned on every call.
func TestContractGraphValidationDeterministic(t *testing.T) {
	// Missing dependency: exactly one rule carries missing deps, so the
	// reported rule is deterministic regardless of map iteration order; the
	// reported dependency is the first declared one (deterministic per
	// rule).
	reg := NewRegistry()
	if err := reg.Register(makeRule(t, "ok.rule", nil)); err != nil {
		t.Fatalf("register ok.rule: %v", err)
	}
	if err := reg.Register(makeRule(t, "a.missing", &ruleOptions{deps: []string{"z.dep", "a.dep"}})); err != nil {
		t.Fatalf("register a.missing: %v", err)
	}
	wantMissing := `detect: rule "a.missing" depends on unregistered rule "z.dep"`
	if err := reg.Validate(); err == nil || err.Error() != wantMissing {
		t.Fatalf("missing-dependency error = %v, want exactly %q", err, wantMissing)
	}

	// Cycle: a.z → b.a → a.z with an outside rule. All dependencies are
	// registered, so the graph check fails on the cycle; the error names
	// the smallest-ID cycle member ("a.z", not the entry point or the
	// first rule in map order) and is identical on every call.
	reg2 := NewRegistry()
	for _, r := range []Rule{
		makeRule(t, "a.z", &ruleOptions{deps: []string{"b.a"}}),
		makeRule(t, "b.a", &ruleOptions{deps: []string{"a.z"}}),
		makeRule(t, "outside.x", nil),
	} {
		if err := reg2.Register(r); err != nil {
			t.Fatalf("register %q: %v", r.ID, err)
		}
	}
	wantCycle := `detect: dependency cycle detected (rule "a.z" is on a cycle)`
	for i := 0; i < 2; i++ {
		if err := reg2.Validate(); err == nil || err.Error() != wantCycle {
			t.Fatalf("cycle error (call %d) = %v, want exactly %q", i+1, err, wantCycle)
		}
	}
}

// ---------------------------------------------------------------------------
// Contract 5 — the versioning contract: CheckAPIVersion boundaries.
// ---------------------------------------------------------------------------

// Contract: CheckAPIVersion(1,0) passes; (1,1), (2,0), and (0,0) fail. Every
// error names the SDK ("detect SDK") and BOTH version numbers — the pack's
// required version and this build's provided version — and distinguishes
// the two failure classes: a too-new required minor (this build predates
// the pack) versus a major mismatch (the pack must be recompiled).
func TestContractAPIVersioning(t *testing.T) {
	if APIMajor != 1 || APIMinor != 0 {
		t.Fatalf("frozen API level is %d.%d, want 1.0", APIMajor, APIMinor)
	}
	if err := CheckAPIVersion(1, 0); err != nil {
		t.Fatalf("CheckAPIVersion(1,0) must pass: %v", err)
	}

	rejected := []struct {
		name   string
		maj    int
		min    int
		marker string // the failure-class marker the error must carry
	}{
		{"future minor", 1, 1, "predates"},
		{"future major", 2, 0, "major version mismatch"},
		{"zero major", 0, 0, "major version mismatch"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAPIVersion(tc.maj, tc.min)
			if err == nil {
				t.Fatalf("CheckAPIVersion(%d,%d) must fail", tc.maj, tc.min)
			}
			msg := err.Error()
			if !strings.Contains(msg, "detect SDK") {
				t.Fatalf("error must name the SDK: %q", msg)
			}
			if !strings.Contains(msg, fmt.Sprintf("%d.%d", tc.maj, tc.min)) {
				t.Fatalf("error must name the required version: %q", msg)
			}
			if !strings.Contains(msg, fmt.Sprintf("%d.%d", APIMajor, APIMinor)) {
				t.Fatalf("error must name this build's version: %q", msg)
			}
			if !strings.Contains(msg, tc.marker) {
				t.Fatalf("error must carry the %q failure class: %q", tc.marker, msg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Contract 6 — the vocabulary contract: full sets, round-trip, no dead vocab.
// ---------------------------------------------------------------------------

// Contract: every Category, RuleInput, RuleOutput, FindingPriority, and
// FindingStatus constant round-trips through its Parse function and Valid(),
// and the surfaced sets (Categories, KnownRuleInputs, KnownRuleOutputs) are
// EXACTLY the documented constant sets — no dead vocabulary (a constant
// Valid rejects or Parse refuses), no missing vocabulary (a documented
// constant absent from the surfaced set).
//
// Limitation, documented: Category/Input/Output completeness is pinned by
// comparing the surfaced Known*/Categories() sets against the constant
// list; Priority/Status expose no Known* function, so their completeness is
// pinned by enumerating every exported constant here — adding a constant
// requires extending this test (a compile-time prompt).
func TestContractVocabularyCompletenessAndRoundTrip(t *testing.T) {
	set := func(list []string) map[string]bool {
		out := make(map[string]bool, len(list))
		for _, s := range list {
			out[s] = true
		}
		return out
	}

	// Category: 14 constants.
	expectedCategories := []Category{
		CategoryInformation, CategoryMisconfig, CategoryExposure,
		CategoryAuthentication, CategoryAuthorization, CategoryConfiguration,
		CategoryDiscovery, CategoryCloud, CategoryAPI, CategoryJavaScript,
		CategorySecrets, CategoryInfrastructure, CategoryBusinessLogic,
		CategoryCustom,
	}
	check := func(name string, got []string, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: surfaced %d entries, want %d", name, len(got), len(want))
		}
		wantSet := set(want)
		for _, s := range got {
			if !wantSet[s] {
				t.Fatalf("%s: undocumented surfaced entry %q", name, s)
			}
		}
	}
	cats := Categories()
	catLabels := make([]string, len(cats))
	for i, c := range cats {
		catLabels[i] = c.String()
	}
	catWants := make([]string, len(expectedCategories))
	for i, c := range expectedCategories {
		catWants[i] = c.String()
	}
	check("Categories()", catLabels, catWants)
	// Canonical sorted order.
	for i := 1; i < len(cats); i++ {
		if cats[i-1] >= cats[i] {
			t.Fatalf("Categories() not sorted at %d", i)
		}
	}
	// Round-trip every constant: Valid and Parse agree with the constant.
	for _, c := range expectedCategories {
		if !c.Valid() {
			t.Fatalf("category %q is dead vocabulary (Valid rejects it)", c)
		}
		if parsed, err := ParseCategory(c.String()); err != nil || parsed != c {
			t.Fatalf("category %q does not round-trip through ParseCategory: %v, %v", c, parsed, err)
		}
	}
	if _, err := ParseCategory("bogus"); err == nil {
		t.Fatalf("ParseCategory must reject unknown labels")
	}

	// RuleInput: 7 constants; the surfaced set is exactly them.
	expectedInputs := []RuleInput{
		InputAssets, InputRelationships, InputEvidence, InputTechnology,
		InputSecrets, InputJavaScript, InputEndpoints,
	}
	knownInputs := KnownRuleInputs()
	inLabels := make([]string, len(knownInputs))
	for i, in := range knownInputs {
		inLabels[i] = string(in)
	}
	inWants := make([]string, len(expectedInputs))
	for i, in := range expectedInputs {
		inWants[i] = string(in)
	}
	check("KnownRuleInputs()", inLabels, inWants)
	for _, in := range expectedInputs {
		if !in.Valid() {
			t.Fatalf("input %q is dead vocabulary", in)
		}
	}
	if RuleInput("bogus").Valid() {
		t.Fatalf("unknown input reported valid")
	}

	// RuleOutput: exactly the single findings output.
	expectedOutputs := []RuleOutput{OutputFindings}
	knownOutputs := KnownRuleOutputs()
	outLabels := make([]string, len(knownOutputs))
	for i, out := range knownOutputs {
		outLabels[i] = string(out)
	}
	outWants := make([]string, len(expectedOutputs))
	for i, out := range expectedOutputs {
		outWants[i] = string(out)
	}
	check("KnownRuleOutputs()", outLabels, outWants)
	for _, out := range expectedOutputs {
		if !out.Valid() {
			t.Fatalf("output %q is dead vocabulary", out)
		}
	}
	if RuleOutput("bogus").Valid() {
		t.Fatalf("unknown output reported valid")
	}

	// FindingPriority: 5 constants, weakest → strongest.
	expectedPriorities := []FindingPriority{
		PriorityInfo, PriorityLow, PriorityMedium, PriorityHigh, PriorityCritical,
	}
	for _, p := range expectedPriorities {
		if !p.Valid() {
			t.Fatalf("priority %q is dead vocabulary", p)
		}
		if parsed, err := ParseFindingPriority(p.String()); err != nil || parsed != p {
			t.Fatalf("priority %q does not round-trip through ParseFindingPriority: %v, %v", p, parsed, err)
		}
	}
	if _, err := ParseFindingPriority("urgent"); err == nil {
		t.Fatalf("ParseFindingPriority must reject unknown labels")
	}

	// FindingStatus: exactly open and dismissed.
	expectedStatuses := []FindingStatus{StatusOpen, StatusDismissed}
	for _, s := range expectedStatuses {
		if !s.Valid() {
			t.Fatalf("status %q is dead vocabulary", s)
		}
		if parsed, err := ParseFindingStatus(s.String()); err != nil || parsed != s {
			t.Fatalf("status %q does not round-trip through ParseFindingStatus: %v, %v", s, parsed, err)
		}
	}
	if _, err := ParseFindingStatus("closed"); err == nil {
		t.Fatalf("ParseFindingStatus must reject unknown labels")
	}
}

// ---------------------------------------------------------------------------
// Contract 7 — the outcome vocabulary contract: reports use only the
// documented vocabularies.
// ---------------------------------------------------------------------------

// Contract: every run Report carries an Outcome from the documented set
// {completed, incomplete, failed, cancelled}, and every RuleResult carries a
// Status from the documented set {completed, failed, cancelled, skipped}.
// The aggregate outcome follows the documented derivation (any cancelled
// rule → cancelled; failed alongside completed → incomplete; every attempted
// rule failed → failed; otherwise completed), and the report's per-status
// counters agree with the per-rule statuses.
func TestContractReportOutcomeVocabulary(t *testing.T) {
	documentedOutcomes := []Outcome{OutcomeCompleted, OutcomeIncomplete, OutcomeFailed, OutcomeCancelled}
	documentedStatuses := []RuleStatus{RuleStatusCompleted, RuleStatusFailed, RuleStatusCancelled, RuleStatusSkipped}
	assertVocabulary := func(t *testing.T, rep Report) {
		t.Helper()
		ok := false
		for _, o := range documentedOutcomes {
			if rep.Outcome == o {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("undocumented run outcome %q (documented: %v)", rep.Outcome, documentedOutcomes)
		}
		tally := map[RuleStatus]int{}
		for _, r := range rep.Rules {
			ok := false
			for _, s := range documentedStatuses {
				if r.Status == s {
					ok = true
					break
				}
			}
			if !ok {
				t.Fatalf("undocumented rule status %q (documented: %v)", r.Status, documentedStatuses)
			}
			tally[r.Status]++
		}
		if tally[RuleStatusCompleted] != rep.Completed ||
			tally[RuleStatusFailed] != rep.Failed ||
			tally[RuleStatusCancelled] != rep.Cancelled ||
			tally[RuleStatusSkipped] != rep.Skipped {
			t.Fatalf("status counters disagree with the per-rule statuses: %+v vs %+v", tally, rep)
		}
	}

	t.Run("mixed completed failed skipped", func(t *testing.T) {
		failing := makeRule(t, "bad.d", &ruleOptions{detector: func(context.Context, *Context) ([]asset.Finding, error) {
			return nil, errors.New("synthetic detector failure")
		}})
		reg := newTestRegistry(t,
			makeRule(t, "ok.a", nil),
			makeRuleDisabled(t, "off.b"),
			makeRule(t, "kind.c", &ruleOptions{required: []asset.Kind{asset.KindJavaScript}}),
			failing,
			makeRule(t, "dep.e", &ruleOptions{deps: []string{"bad.d"}}),
		)
		rep, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if rep.Outcome != OutcomeIncomplete {
			t.Fatalf("outcome %s, want incomplete (failed alongside completed)", rep.Outcome)
		}
		if rep.Completed != 1 || rep.Failed != 1 || rep.Skipped != 3 || rep.Cancelled != 0 {
			t.Fatalf("counts wrong: %+v", rep)
		}
		assertVocabulary(t, rep)
	})

	t.Run("every attempted rule failed", func(t *testing.T) {
		mk := func(id string) Rule {
			return makeRule(t, id, &ruleOptions{detector: func(context.Context, *Context) ([]asset.Finding, error) {
				return nil, errors.New("synthetic detector failure")
			}})
		}
		reg := newTestRegistry(t, mk("f.one"), mk("f.two"))
		rep, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if rep.Outcome != OutcomeFailed {
			t.Fatalf("outcome %s, want failed", rep.Outcome)
		}
		if rep.Failed != 2 || rep.Completed != 0 || rep.Cancelled != 0 || rep.Skipped != 0 {
			t.Fatalf("counts wrong: %+v", rep)
		}
		assertVocabulary(t, rep)
	})

	t.Run("cancelled run", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // pre-cancelled: every enabled rule reports cancelled
		reg := newTestRegistry(t, makeRule(t, "c.a", nil), makeRule(t, "c.b", nil))
		rep, err := Run(ctx, DefaultEngineConfig(reg), testSnapshot(t))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if rep.Outcome != OutcomeCancelled {
			t.Fatalf("outcome %s, want cancelled", rep.Outcome)
		}
		if rep.Cancelled != 2 || rep.Completed != 0 || rep.Failed != 0 || rep.Skipped != 0 {
			t.Fatalf("counts wrong: %+v", rep)
		}
		for _, r := range rep.Rules {
			if r.Status != RuleStatusCancelled {
				t.Fatalf("rule %q must report cancelled, got %s", r.RuleID, r.Status)
			}
		}
		assertVocabulary(t, rep)
	})

	// A clean run closes the loop on the completed outcome.
	t.Run("completed run", func(t *testing.T) {
		reg := newTestRegistry(t, makeRule(t, "ok.a", nil))
		rep, err := Run(context.Background(), DefaultEngineConfig(reg), testSnapshot(t))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if rep.Outcome != OutcomeCompleted {
			t.Fatalf("outcome %s, want completed", rep.Outcome)
		}
		assertVocabulary(t, rep)
	})
}

// ---------------------------------------------------------------------------
// Contract 8 — the run determinism contract: byte-identical reports.
// ---------------------------------------------------------------------------

// Contract: two identical runs — the same registry, the same snapshot, the
// same EngineConfig, the cache disabled — produce byte-identical Reports.
// This reuses the deterministic comparison of TestRunDeterminism
// (engine_test.go): the canonical JSON form, which excludes only the
// non-serialized per-rule error fields (nil on a completed run).
func TestContractRunDeterminismByteIdentical(t *testing.T) {
	clock := fixedClock{at: time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)}
	logging := makeRule(t, "c.x", &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		dctx.Logger.Log(LevelInfo, "c.x", "deterministic log line")
		f, err := testFinding(dctx, "c.x", "Rule c.x", CategoryInformation, 0)
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}})
	reg := newTestRegistry(t,
		makeRule(t, "a.x", nil),
		makeRule(t, "b.x", &ruleOptions{deps: []string{"a.x"}}),
		logging,
	)
	snap := testSnapshot(t)
	cfg := DefaultEngineConfig(reg)
	cfg.Clock = clock // Cache stays nil: cache disabled.

	run := func() Report {
		rep, err := Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}
	rep1, rep2 := run(), run()

	b1, err := json.Marshal(rep1)
	if err != nil {
		t.Fatalf("marshal rep1: %v", err)
	}
	b2, err := json.Marshal(rep2)
	if err != nil {
		t.Fatalf("marshal rep2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("identical runs produced different reports:\n%s\nvs\n%s", b1, b2)
	}
	// The deterministic shape is part of the contract: dependency levels,
	// the completed outcome, and every rule's finding.
	if rep1.Outcome != OutcomeCompleted || rep1.Completed != 3 || rep1.Levels != 2 {
		t.Fatalf("deterministic shape wrong: %+v", rep1)
	}
	if len(rep1.Findings) != 3 || len(rep1.Logs) != 1 {
		t.Fatalf("findings/logs wrong: %d findings, %d logs", len(rep1.Findings), len(rep1.Logs))
	}
}

// ---------------------------------------------------------------------------
// Contract 9 — the immutability contract: Context mutation cannot change
// the run outcome, and the caller's snapshot is pristine.
// ---------------------------------------------------------------------------

// Contract, honest boundary: Context is "immutable by contract, not
// enforcement" (context.go: "Rules must not mutate the Context; the engine
// shares one Context across every rule of a run"). What the engine actually
// guarantees:
//
//  1. Context storage is engine-owned copies: normalizeSnapshot rebuilds
//     every domain into fresh allocations before the run, so no detector-
//     reachable mutation can touch the caller's Snapshot (the detector has
//     no Snapshot reference at all — Context is its entire view).
//  2. The finding-validation corpus (the observed set) is built once before
//     the run and never exposed through the Context, so Context mutation
//     cannot change what findings validate, and a single-rule run's outcome
//     is unchanged.
//  3. The engine does NOT defend the shared Context against same-run
//     siblings: a mutating rule CAN corrupt what a later rule of the same
//     run observes. The framework's protection is downstream — the
//     corrupted observation still cannot reach the report as a finding
//     about an unobserved asset.
//
// All three points are pinned below.
func TestContractContextImmutabilityHonestBoundary(t *testing.T) {
	clock := fixedClock{at: time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)}

	// The mutator tries to corrupt every Context domain it can reach.
	mutator := func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dctx.Assets[0] = asset.Identity{Kind: asset.KindHost, Value: "tampered.example.net"}
		dctx.Assets = append(dctx.Assets, asset.Identity{Kind: asset.KindHost, Value: "extra.example.net"})
		dctx.Relationships = append(dctx.Relationships, asset.Relationship{})
		if len(dctx.Evidence) > 0 {
			dctx.Evidence[0].Value = "tampered"
		}
		if len(dctx.Technologies) > 0 {
			dctx.Technologies[0].Name = "tampered"
		}
		if len(dctx.Secrets) > 0 {
			dctx.Secrets[0].Value = "tampered"
		}
		if len(dctx.JavaScript) > 0 {
			dctx.JavaScript[0] = asset.JavaScript{}
		}
		if len(dctx.Endpoints) > 0 {
			dctx.Endpoints[0].Method = "POST"
		}
		if dctx.Config != nil {
			dctx.Config["tampered"] = "yes"
		}
		dctx.Logger.Log(LevelWarn, "mut.x", "tampering attempt logged")
		// The finding is about the observed subject; it validates against
		// the immutable corpus, not against the mutated Context.
		f, err := testFinding(dctx, "mut.x", "Rule mut.x", CategoryInformation, 0)
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}
	// The control detector performs no mutation but produces the identical
	// report (same finding, same log line), so byte-comparison pins that
	// the mutation changed NOTHING about the run outcome.
	control := func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dctx.Logger.Log(LevelWarn, "mut.x", "tampering attempt logged")
		f, err := testFinding(dctx, "mut.x", "Rule mut.x", CategoryInformation, 0)
		if err != nil {
			return nil, err
		}
		return []asset.Finding{f}, nil
	}

	snap := testSnapshot(t)
	run := func(det Detector) Report {
		reg := newTestRegistry(t, makeRule(t, "mut.x", &ruleOptions{detector: det}))
		cfg := DefaultEngineConfig(reg)
		cfg.Clock = clock
		rep, err := Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}

	repMut := run(mutator)
	if repMut.Outcome != OutcomeCompleted {
		t.Fatalf("outcome %s, want completed despite Context mutation", repMut.Outcome)
	}
	if r := resultOf(t, repMut, "mut.x"); r.Status != RuleStatusCompleted || r.Findings != 1 {
		t.Fatalf("mutating rule must complete with one finding: %+v", r)
	}
	if len(repMut.Findings) != 1 || repMut.Findings[0].Subject.Value != testSubjectURL {
		t.Fatalf("the finding must cite the observed subject: %+v", repMut.Findings)
	}
	// The run outcome and report are byte-identical to a pristine run.
	bMut, err := json.Marshal(repMut)
	if err != nil {
		t.Fatalf("marshal mutated report: %v", err)
	}
	bCtrl, err := json.Marshal(run(control))
	if err != nil {
		t.Fatalf("marshal control report: %v", err)
	}
	if !bytes.Equal(bMut, bCtrl) {
		t.Fatalf("Context mutation changed the run outcome:\n%s\nvs\n%s", bMut, bCtrl)
	}
	// The caller's snapshot is pristine: Context storage is engine-owned
	// copies, so no detector-side mutation could reach it.
	bSnap, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	bFresh, err := json.Marshal(testSnapshot(t))
	if err != nil {
		t.Fatalf("marshal fresh snapshot: %v", err)
	}
	if !bytes.Equal(bSnap, bFresh) {
		t.Fatalf("the caller's snapshot was corrupted by the run")
	}

	// The honest boundary, pinned: the engine shares ONE Context per run
	// and does not enforce immutability — a mutating rule CAN corrupt what
	// a same-run sibling observes (the dependency ordering makes this
	// deterministic: reads.x runs only after mut.x completed). The
	// framework's protection is downstream: the corrupted observation can
	// never reach the report as a finding about an unobserved asset.
	readsRule := makeRule(t, "reads.x", &ruleOptions{
		deps: []string{"mut.x"},
		detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
			subject := dctx.Assets[0] // observes the tampered corpus
			f, err := subjectFinding(dctx, "reads.x", "Rule reads.x", CategoryInformation, subject, 0)
			if err != nil {
				return nil, err
			}
			return []asset.Finding{f}, nil
		},
	})
	reg := newTestRegistry(t,
		makeRule(t, "mut.x", &ruleOptions{detector: mutator}),
		readsRule,
	)
	cfg := DefaultEngineConfig(reg)
	cfg.Clock = clock
	rep, err := Run(context.Background(), cfg, testSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r := resultOf(t, rep, "mut.x"); r.Status != RuleStatusCompleted {
		t.Fatalf("mutating rule must complete: %+v", r)
	}
	rReads := resultOf(t, rep, "reads.x")
	if rReads.Status != RuleStatusFailed || rReads.Err == nil ||
		!strings.Contains(rReads.Err.Error(), "not observed in the corpus") {
		t.Fatalf("sibling must fail on the corrupted observation: %+v", rReads)
	}
	if rep.Outcome != OutcomeIncomplete {
		t.Fatalf("outcome %s, want incomplete", rep.Outcome)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("the corrupted observation must never reach the report findings")
	}
}
