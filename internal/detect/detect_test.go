package detect

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

func TestCategoryVocabulary(t *testing.T) {
	cats := Categories()
	if len(cats) != 14 {
		t.Fatalf("Categories has %d entries, want 14", len(cats))
	}
	seen := map[Category]bool{}
	for _, c := range cats {
		if seen[c] {
			t.Fatalf("duplicate category %q", c)
		}
		seen[c] = true
		if !c.Valid() {
			t.Fatalf("category %q in Categories is not Valid", c)
		}
	}
	for i := 1; i < len(cats); i++ {
		if cats[i-1] >= cats[i] {
			t.Fatalf("Categories not sorted at %d", i)
		}
	}
	if _, err := ParseCategory("bogus"); err == nil {
		t.Fatalf("ParseCategory must reject unknown labels")
	}
	if Category("bogus").Valid() {
		t.Fatalf("unknown category reported valid")
	}
}

func TestValidateRuleAcceptsFixture(t *testing.T) {
	r := makeRule(t, "exposure.admin-panel", nil)
	if err := validateRule(r); err != nil {
		t.Fatalf("validateRule: %v", err)
	}
}

func TestValidateRuleRejections(t *testing.T) {
	cases := []struct {
		name string
		mut  func(r *Rule)
	}{
		{"empty id", func(r *Rule) { r.ID = "" }},
		{"uppercase id", func(r *Rule) { r.ID = "Bad-ID" }},
		{"space in id", func(r *Rule) { r.ID = "bad id" }},
		{"oversized id", func(r *Rule) { r.ID = strings.Repeat("a", maxRuleIDBytes+1) }},
		{"empty name", func(r *Rule) { r.Name = "" }},
		{"empty description", func(r *Rule) { r.Description = "" }},
		{"unknown category", func(r *Rule) { r.Category = Category("bogus") }},
		{"bad version", func(r *Rule) { r.Version = "1.0" }},
		{"non-numeric version", func(r *Rule) { r.Version = "1.x.0" }},
		{"no inputs", func(r *Rule) { r.Inputs = nil }},
		{"unknown input", func(r *Rule) { r.Inputs = []RuleInput{"bogus"} }},
		{"duplicate input", func(r *Rule) { r.Inputs = []RuleInput{InputAssets, InputAssets} }},
		{"no outputs", func(r *Rule) { r.Outputs = nil }},
		{"unknown output", func(r *Rule) { r.Outputs = []RuleOutput{"bogus"} }},
		{"self dependency", func(r *Rule) { r.Dependencies = []string{"a.b"}; r.ID = "a.b" }},
		{"duplicate dependency", func(r *Rule) { r.Dependencies = []string{"x.y", "x.y"} }},
		{"too many dependencies", func(r *Rule) {
			deps := make([]string, maxRuleDependencies+1)
			for i := range deps {
				deps[i] = fmtDep(i)
			}
			r.Dependencies = deps
		}},
		{"unknown required kind", func(r *Rule) { r.RequiredAssetTypes = []asset.Kind{"bogus"} }},
		{"unknown cost", func(r *Rule) { r.EstimatedCost = Cost("extreme") }},
		{"zero timeout", func(r *Rule) { r.Timeout = 0 }},
		{"negative timeout", func(r *Rule) { r.Timeout = -time.Second }},
		{"oversized timeout", func(r *Rule) { r.Timeout = maxRuleTimeout + time.Second }},
		{"empty author", func(r *Rule) { r.Author = "" }},
		{"nil detector", func(r *Rule) { r.Detector = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := makeRule(t, "a.b", nil)
			tc.mut(&r)
			if err := validateRule(r); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func fmtDep(i int) string {
	if i < 10 {
		return "d.0" + string(rune('0'+i))
	}
	return "d." + string(rune('0'+i/10)) + string(rune('0'+i%10))
}

func TestRegistryRegisterAndDuplicates(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(makeRule(t, "a.b", nil)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Register(makeRule(t, "a.b", nil)); err == nil {
		t.Fatalf("duplicate id must be rejected")
	}
	// Duplicate name (case-insensitive), different ID.
	dup := makeRule(t, "c.d", &ruleOptions{name: "RULE A.B"})
	if err := reg.Register(dup); err == nil {
		t.Fatalf("duplicate name must be rejected")
	}
	if reg.Len() != 1 {
		t.Fatalf("registry holds %d rules, want 1", reg.Len())
	}
	got, ok := reg.Get("a.b")
	if !ok || got.ID != "a.b" {
		t.Fatalf("Get failed")
	}
	rules := reg.Rules()
	if len(rules) != 1 || rules[0].ID != "a.b" {
		t.Fatalf("Rules failed")
	}
}

func TestRegistryImmutableAfterRegister(t *testing.T) {
	reg := NewRegistry()
	mutable := makeRule(t, "a.b", nil)
	deps := []string{"x.y"}
	mutable.Dependencies = deps
	if err := reg.Register(mutable); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Mutate every caller-held alias.
	mutable.Dependencies[0] = "zzz"
	mutable.Inputs[0] = RuleInput("bogus")
	got, _ := reg.Get("a.b")
	if got.Dependencies[0] != "x.y" {
		t.Fatalf("registered rule mutated through caller alias")
	}
	if got.Inputs[0] != InputAssets {
		t.Fatalf("registered rule inputs mutated through caller alias")
	}
	// Mutate the copy handed back by Get.
	got.Dependencies[0] = "zzz"
	again, _ := reg.Get("a.b")
	if again.Dependencies[0] != "x.y" {
		t.Fatalf("registered rule mutated through returned copy")
	}
}

func TestRegistryValidateMissingDependency(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(makeRule(t, "a.b", &ruleOptions{deps: []string{"missing.rule"}})); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Validate(); err == nil {
		t.Fatalf("missing dependency must be rejected")
	}
}

func TestRegistryValidateCycle(t *testing.T) {
	reg := NewRegistry()
	rules := []Rule{
		makeRule(t, "a.b", &ruleOptions{deps: []string{"c.d"}}),
		makeRule(t, "c.d", &ruleOptions{deps: []string{"e.f"}}),
		makeRule(t, "e.f", &ruleOptions{deps: []string{"a.b"}}),
		makeRule(t, "outside.x", nil),
	}
	for _, r := range rules {
		if err := reg.Register(r); err != nil {
			t.Fatalf("register %q: %v", r.ID, err)
		}
	}
	err := reg.Validate()
	if err == nil {
		t.Fatalf("cycle must be rejected")
	}
	if !strings.Contains(err.Error(), "a.b") {
		t.Fatalf("cycle error should name the smallest offending rule: %v", err)
	}
}

func TestScheduleLevels(t *testing.T) {
	rules := map[string]Rule{
		"d.root":  makeRule(t, "d.root", nil),
		"a.child": makeRule(t, "a.child", &ruleOptions{deps: []string{"d.root"}}),
		"b.child": makeRule(t, "b.child", &ruleOptions{deps: []string{"d.root"}}),
		"c.grand": makeRule(t, "c.grand", &ruleOptions{deps: []string{"a.child", "b.child"}}),
	}
	levels, err := scheduleLevels(rules)
	if err != nil {
		t.Fatalf("scheduleLevels: %v", err)
	}
	if len(levels) != 3 {
		t.Fatalf("got %d levels, want 3: %v", len(levels), levels)
	}
	if len(levels[0]) != 1 || levels[0][0] != "d.root" {
		t.Fatalf("level 0 = %v", levels[0])
	}
	if len(levels[1]) != 2 || levels[1][0] != "a.child" || levels[1][1] != "b.child" {
		t.Fatalf("level 1 = %v (want sorted a.child, b.child)", levels[1])
	}
	if len(levels[2]) != 1 || levels[2][0] != "c.grand" {
		t.Fatalf("level 2 = %v", levels[2])
	}
}

func TestNormalizeSnapshot(t *testing.T) {
	snap := testSnapshot(t)
	// Duplicate entries across domains; normalization must dedupe and sort.
	snap.Assets = append(snap.Assets, snap.Assets...)
	c, err := normalizeSnapshot(snap)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	if len(c.context.Assets) != 2 {
		t.Fatalf("assets not deduplicated: %d", len(c.context.Assets))
	}
	for i := 1; i < len(c.context.Assets); i++ {
		if c.context.Assets[i-1].String() >= c.context.Assets[i].String() {
			t.Fatalf("assets not sorted")
		}
	}
	// The observed set covers every domain.
	for _, id := range c.context.Assets {
		if _, ok := c.observed[id]; !ok {
			t.Fatalf("asset %s missing from the observed set", id)
		}
	}
	for _, ev := range c.context.Evidence {
		if _, ok := c.observed[ev.Identity()]; !ok {
			t.Fatalf("evidence missing from the observed set")
		}
	}
	if c.kinds[asset.KindURL] == 0 || c.kinds[asset.KindHost] == 0 ||
		c.kinds[asset.KindEvidence] == 0 || c.kinds[asset.KindTechnology] == 0 ||
		c.kinds[asset.KindEndpoint] == 0 {
		t.Fatalf("kind census incomplete: %v", c.kinds)
	}
}

func TestNormalizeSnapshotRejections(t *testing.T) {
	snap := testSnapshot(t)
	big := make([]asset.Identity, maxSnapshotAssets+1)
	if _, err := normalizeSnapshot(Snapshot{Assets: big}); err == nil {
		t.Fatalf("over-bound assets must be rejected")
	}
	bad := snap
	bad.Assets = append([]asset.Identity{}, snap.Assets...)
	bad.Assets[0] = asset.Identity{}
	if _, err := normalizeSnapshot(bad); err == nil {
		t.Fatalf("zero identity must be rejected")
	}
	badKind := snap
	badKind.Assets = append([]asset.Identity{}, snap.Assets...)
	badKind.Assets[0] = asset.Identity{Kind: asset.Kind("bogus"), Value: "x"}
	if _, err := normalizeSnapshot(badKind); err == nil {
		t.Fatalf("unknown kind must be rejected")
	}
	badEvidence := snap
	badEvidence.Evidence = append([]asset.Evidence{}, snap.Evidence...)
	badEvidence.Evidence[0].Method = "bogus"
	if _, err := normalizeSnapshot(badEvidence); err == nil {
		t.Fatalf("non-canonical evidence must be rejected")
	}
}

func TestValidateConfig(t *testing.T) {
	if err := validateConfig(map[string]string{"k": "v"}); err != nil {
		t.Fatalf("validateConfig: %v", err)
	}
	if err := validateConfig(nil); err != nil {
		t.Fatalf("nil config must be valid: %v", err)
	}
	tooMany := make(map[string]string)
	for i := 0; i < maxContextConfigEntries+1; i++ {
		tooMany[string(rune('a'+i%26))+string(rune('0'+i/26))] = "v"
	}
	if err := validateConfig(tooMany); err == nil {
		t.Fatalf("over-bound config must be rejected")
	}
	if err := validateConfig(map[string]string{"": "v"}); err == nil {
		t.Fatalf("empty key must be rejected")
	}
	if err := validateConfig(map[string]string{"k": strings.Repeat("v", maxContextConfigValueBytes+1)}); err == nil {
		t.Fatalf("oversized value must be rejected")
	}
}

func TestBoundedLogger(t *testing.T) {
	l := newBoundedLogger()
	for i := 0; i < maxLogEntries+50; i++ {
		l.Log(LevelInfo, "a.b", "message")
	}
	entries, dropped := l.snapshot()
	if len(entries) != maxLogEntries {
		t.Fatalf("retained %d entries, want %d", len(entries), maxLogEntries)
	}
	if dropped != 50 {
		t.Fatalf("dropped %d, want 50", dropped)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Rule > entries[i].Rule ||
			(entries[i-1].Rule == entries[i].Rule && entries[i-1].Level > entries[i].Level) ||
			(entries[i-1].Rule == entries[i].Rule && entries[i-1].Level == entries[i].Level && entries[i-1].Message > entries[i].Message) {
			t.Fatalf("entries not deterministically sorted")
		}
	}
	// Unknown levels normalize; oversized messages are truncated.
	l2 := newBoundedLogger()
	l2.Log(LogLevel("bogus"), "a.b", strings.Repeat("x", maxLogMessageBytes+10))
	e, _ := l2.snapshot()
	if e[0].Level != LevelInfo || len(e[0].Message) != maxLogMessageBytes {
		t.Fatalf("level/message normalization failed: %+v", e[0])
	}
}

func TestValidateFindingContract(t *testing.T) {
	snap := testSnapshot(t)
	corpus, err := normalizeSnapshot(snap)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	rule := makeRule(t, "a.b", nil)

	// The fixture detector's finding is valid.
	f, err := testFinding(nil, rule.ID, rule.Name, rule.Category, 0)
	if err != nil {
		t.Fatalf("testFinding: %v", err)
	}
	if err := validateFinding(f, rule, corpus.observed); err != nil {
		t.Fatalf("validateFinding: %v", err)
	}

	// Wrong rule metadata (the finding-corruption guard).
	f2, _ := testFinding(nil, "other.rule", rule.Name, rule.Category, 0)
	if err := validateFinding(f2, rule, corpus.observed); err == nil {
		t.Fatalf("foreign rule id must be rejected")
	}
	f3, _ := testFinding(nil, rule.ID, "Another Name", rule.Category, 0)
	if err := validateFinding(f3, rule, corpus.observed); err == nil {
		t.Fatalf("foreign rule name must be rejected")
	}
	f4, _ := testFinding(nil, rule.ID, rule.Name, CategoryExposure, 0)
	if err := validateFinding(f4, rule, corpus.observed); err == nil {
		t.Fatalf("foreign category must be rejected")
	}

	// Unknown vocabulary.
	f5, _ := testFinding(nil, rule.ID, rule.Name, rule.Category, 0)
	f5.Priority = "urgent"
	if err := validateFinding(f5, rule, corpus.observed); err == nil {
		t.Fatalf("unknown priority must be rejected")
	}
	f6, _ := testFinding(nil, rule.ID, rule.Name, rule.Category, 0)
	f6.Status = "closed"
	if err := validateFinding(f6, rule, corpus.observed); err == nil {
		t.Fatalf("unknown status must be rejected")
	}

	// Unobserved subject.
	f7, _ := testFinding(nil, rule.ID, rule.Name, rule.Category, 0)
	f7.Subject = asset.Identity{Kind: asset.KindURL, Value: "https://elsewhere.example.net/"}
	if err := validateFinding(f7, rule, corpus.observed); err == nil {
		t.Fatalf("unobserved subject must be rejected")
	}

	// Unobserved related asset.
	f8, _ := testFinding(nil, rule.ID, rule.Name, rule.Category, 0)
	f8.RelatedAssets = []asset.Identity{{Kind: asset.KindHost, Value: "unobserved.example.net"}}
	if err := validateFinding(f8, rule, corpus.observed); err == nil {
		t.Fatalf("unobserved related asset must be rejected")
	}

	// Unobserved evidence source: the finding is rebuilt canonically with
	// an evidence record observed on an asset the corpus never saw.
	f8b, _ := testFinding(nil, rule.ID, rule.Name, rule.Category, 0)
	unobservedSource := asset.Identity{Kind: asset.KindURL, Value: "https://unobserved.example.net/"}
	badEv, err := asset.NewEvidence(asset.MethodDetection, rule.ID, "synthetic signal",
		unobservedSource, asset.Provenance{Source: "detect"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	f8b.Evidence = []asset.Evidence{badEv}
	f8b, err = asset.NewFinding(f8b)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if err := validateFinding(f8b, rule, corpus.observed); err == nil {
		t.Fatalf("unobserved evidence source must be rejected")
	}

	// Wrong rule_version metadata.
	f9, _ := testFinding(nil, rule.ID, rule.Name, rule.Category, 0)
	f9.Metadata = map[string]string{"rule_version": "9.9.9"}
	if err := validateFinding(f9, rule, corpus.observed); err == nil {
		t.Fatalf("wrong rule_version must be rejected")
	}

	// Non-canonical finding (hand-rolled, bypassing NewFinding).
	f10, _ := testFinding(nil, rule.ID, rule.Name, rule.Category, 0)
	f10.Confidence = 2
	if err := validateFinding(f10, rule, corpus.observed); err == nil {
		t.Fatalf("non-canonical finding must be rejected")
	}
}

func TestMetricsCounters(t *testing.T) {
	var nilMetrics *Metrics
	nilMetrics.recordExecution("a.b", time.Second, 2)
	if sn := nilMetrics.Snapshot(); sn.Executions != 0 {
		t.Fatalf("nil Metrics must be a no-op")
	}

	m := &Metrics{}
	m.recordExecution("a.b", time.Second, 2)
	m.recordExecution("a.b", 2*time.Second, 1)
	m.recordFailure("a.b", "error")
	m.recordFailure("c.d", "timeout")
	m.recordFailure("c.d", "panic")
	m.recordCache("a.b", true)
	m.recordCache("a.b", false)

	sn := m.Snapshot()
	if sn.Executions != 2 || sn.Findings != 3 || sn.Errors != 1 || sn.Timeouts != 1 || sn.Panics != 1 {
		t.Fatalf("aggregate counters wrong: %+v", sn)
	}
	if sn.CacheHits != 1 || sn.CacheMisses != 1 {
		t.Fatalf("cache counters wrong: %+v", sn)
	}
	if len(sn.Rules) != 2 || sn.Rules[0].ID != "a.b" || sn.Rules[1].ID != "c.d" {
		t.Fatalf("per-rule stats missing or unsorted: %+v", sn.Rules)
	}
	if sn.Rules[0].TotalTime != 3*time.Second || sn.Rules[1].Timeouts != 1 {
		t.Fatalf("per-rule stats wrong: %+v", sn.Rules)
	}

	// Fold merges a finished run into a caller-provided Metrics.
	caller := &Metrics{}
	caller.fold(sn)
	got := caller.Snapshot()
	if got.Executions != 2 || got.Timeouts != 1 || got.Panics != 1 || got.Findings != 3 {
		t.Fatalf("fold lost counters: %+v", got)
	}
	if len(got.Rules) != 2 {
		t.Fatalf("fold lost per-rule stats")
	}
}

func TestRuleKeyInputs(t *testing.T) {
	snap := testSnapshot(t)
	corpus, err := normalizeSnapshot(snap)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	fp, err := fingerprintSnapshot(corpus)
	if err != nil {
		t.Fatalf("fingerprintSnapshot: %v", err)
	}
	rule := makeRule(t, "a.b", nil)

	base, err := ruleKey(rule, fp, nil)
	if err != nil {
		t.Fatalf("ruleKey: %v", err)
	}

	// Different rule → different key.
	other := makeRule(t, "c.d", nil)
	k2, _ := ruleKey(other, fp, nil)
	if base == k2 {
		t.Fatalf("different rules share a key")
	}

	// Different version → different key (the bump contract).
	bumped := rule
	bumped.Version = "1.0.1"
	k3, _ := ruleKey(bumped, fp, nil)
	if base == k3 {
		t.Fatalf("version bump must change the key")
	}

	// Different configuration → different key.
	k4, _ := ruleKey(rule, fp, map[string]string{"threshold": "0.5"})
	if base == k4 {
		t.Fatalf("configuration must enter the key")
	}

	// Different snapshot → different key.
	snap2 := testSnapshot(t)
	snap2.Technologies[0].Version = "1.25.3"
	corpus2, _ := normalizeSnapshot(snap2)
	fp2, _ := fingerprintSnapshot(corpus2)
	k5, _ := ruleKey(rule, fp2, nil)
	if base == k5 {
		t.Fatalf("snapshot change must change the key")
	}

	// Same input → same key (determinism).
	k6, _ := ruleKey(rule, fp, nil)
	if base != k6 {
		t.Fatalf("key is not deterministic")
	}

	// A changed technology Prov.Confidence is a changed rule input → a
	// different key.
	snapConf := testSnapshot(t)
	snapConf.Technologies[0].Prov.Confidence = 0.9
	corpusConf, err := normalizeSnapshot(snapConf)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	fpConf, err := fingerprintSnapshot(corpusConf)
	if err != nil {
		t.Fatalf("fingerprintSnapshot: %v", err)
	}
	if fp == fpConf {
		t.Fatalf("technology provenance confidence must change the fingerprint")
	}
	kConf, _ := ruleKey(rule, fpConf, nil)
	if base == kConf {
		t.Fatalf("technology provenance confidence must change the key")
	}

	// A changed provenance Reference is a changed rule input → a different
	// key (technology and evidence forms both carry it).
	snapRef := testSnapshot(t)
	snapRef.Technologies[0].Prov.Reference = "scan-42"
	snapRef.Evidence[0].Prov.Reference = "scan-42"
	corpusRef, err := normalizeSnapshot(snapRef)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	fpRef, err := fingerprintSnapshot(corpusRef)
	if err != nil {
		t.Fatalf("fingerprintSnapshot: %v", err)
	}
	if fp == fpRef {
		t.Fatalf("provenance reference must change the fingerprint")
	}
	kRef, _ := ruleKey(rule, fpRef, nil)
	if base == kRef {
		t.Fatalf("provenance reference must change the key")
	}

	// Provenance timestamps do NOT change the fingerprint — not for
	// evidence, not for technologies.
	snap3 := testSnapshot(t)
	snap3.Evidence[0].Prov.DiscoveredAt = time.Now().Add(time.Hour)
	snap3.Technologies[0].Prov.DiscoveredAt = time.Now().Add(2 * time.Hour)
	corpus3, _ := normalizeSnapshot(snap3)
	fp3, _ := fingerprintSnapshot(corpus3)
	if fp != fp3 {
		t.Fatalf("provenance timestamps must not change the fingerprint")
	}
	k7, _ := ruleKey(rule, fp3, nil)
	if base != k7 {
		t.Fatalf("provenance timestamps must not change the key")
	}
}

func TestStoredFindingsRoundTripAndTampering(t *testing.T) {
	snap := testSnapshot(t)
	corpus, err := normalizeSnapshot(snap)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	rule := makeRule(t, "a.b", nil)
	f, err := testFinding(nil, rule.ID, rule.Name, rule.Category, 0)
	if err != nil {
		t.Fatalf("testFinding: %v", err)
	}

	rec, err := encodeStoredFindings(rule.ID, []asset.Finding{f}, time.Now())
	if err != nil {
		t.Fatalf("encodeStoredFindings: %v", err)
	}
	if rec.Status != cache.StatusCompleted {
		t.Fatalf("record status %q", rec.Status)
	}
	decoded, err := decodeStoredFindings(rec, rule, corpus.observed)
	if err != nil {
		t.Fatalf("decodeStoredFindings: %v", err)
	}
	if len(decoded) != 1 || decoded[0].ID() != f.ID() {
		t.Fatalf("decoded findings wrong")
	}

	// Tampered payloads are rejected: foreign rule attribution.
	bad := rec
	bad.Target = "rule:other.rule"
	if _, err := decodeStoredFindings(bad, rule, corpus.observed); err == nil {
		t.Fatalf("foreign target must be rejected")
	}
	// Tampered payload version.
	bad2 := rec
	bad2.Data = []byte(`{"version":999,"findings":[]}`)
	if _, err := decodeStoredFindings(bad2, rule, corpus.observed); err == nil {
		t.Fatalf("foreign payload version must be rejected")
	}
	// Tampered finding content (unobserved subject survives only as a
	// violation).
	foreign, _ := testFinding(nil, "other.rule", rule.Name, rule.Category, 0)
	bad3, _ := encodeStoredFindings("a.b", []asset.Finding{foreign}, time.Now())
	if _, err := decodeStoredFindings(bad3, rule, corpus.observed); err == nil {
		t.Fatalf("foreign-rule findings must be rejected")
	}
}

func TestBenchmarkDetector(t *testing.T) {
	rule := makeRule(t, "a.b", nil)
	snap := testSnapshot(t)

	res, err := BenchmarkDetector(context.Background(), rule, snap, 5, nil)
	if err != nil {
		t.Fatalf("BenchmarkDetector: %v", err)
	}
	if res.Iterations != 5 || res.Findings != 5 {
		t.Fatalf("result wrong: %+v", res)
	}
	if res.Median < 0 || res.Mean < 0 || res.Max < res.Min {
		t.Fatalf("duration summary wrong: %+v", res)
	}

	if _, err := BenchmarkDetector(context.Background(), rule, snap, 0, nil); err == nil {
		t.Fatalf("zero iterations must be rejected")
	}
	bad := makeRule(t, "a.b", &ruleOptions{detector: func(context.Context, *Context) ([]asset.Finding, error) {
		return nil, errors.New("boom")
	}})
	if _, err := BenchmarkDetector(context.Background(), bad, snap, 3, nil); err == nil {
		t.Fatalf("all-failing benchmark must return an error")
	}
	panicking := makeRule(t, "a.b", &ruleOptions{detector: func(context.Context, *Context) ([]asset.Finding, error) {
		panic("kaboom")
	}})
	res, err = BenchmarkDetector(context.Background(), panicking, snap, 2, nil)
	if err == nil {
		t.Fatalf("every iteration panicked must surface an error")
	}
	if res.Panics != 2 {
		t.Fatalf("panics not counted: %+v", res)
	}
}
