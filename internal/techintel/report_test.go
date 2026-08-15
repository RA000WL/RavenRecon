package techintel

import (
	"reflect"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// testTechResult builds a TechnologyResult with the given score and level.
func testTechResult(t *testing.T, name string, score float64, lvl ConfidenceLevel, version string) TechnologyResult {
	t.Helper()
	tech, err := asset.NewTechnology(name, asset.CategoryServer, testProv())
	if err != nil {
		t.Fatal(err)
	}
	if version != "" {
		tech, err = asset.WithVersion(tech, version)
		if err != nil {
			t.Fatal(err)
		}
	}
	return TechnologyResult{Technology: tech, Score: score, Level: lvl}
}

func testEvidence(t *testing.T, indicator, value string) asset.Evidence {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodHeader, indicator, value, mustURL(t, "https://ok.example/").Identity(), testProv())
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestAccumulator(t *testing.T) {
	a := newAccumulator()
	o1 := newObs(t, "https://ok.example/")
	o1.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
	o2 := newObs(t, "https://other.example/")

	a.preRegister(o1)
	a.preRegister(o2)
	a.addMalformed()
	a.addMalformed()

	entries, malformed := a.snapshot()
	if malformed != 2 {
		t.Errorf("malformed = %d, want 2", malformed)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2 placeholders", len(entries))
	}
	if entries[0].Status != StatusCancelled || entries[1].Status != StatusCancelled {
		t.Errorf("placeholders must be cancelled: %v/%v", entries[0].Status, entries[1].Status)
	}
	// Snapshot is sorted by identity.
	if entries[0].ID.String() > entries[1].ID.String() {
		t.Error("snapshot entries must be sorted by identity")
	}

	// A completed merge replaces the placeholder for its identity.
	e1 := testCompletedEntry(t, o1)
	a.merge(o1.identity().String(), &e1)
	entries, _ = a.snapshot()
	for i := range entries {
		if entries[i].ID.String() == o1.identity().String() {
			if entries[i].Status != StatusCompleted {
				t.Fatalf("merged entry status = %q, want completed", entries[i].Status)
			}
		}
	}

	// A second merge of the same identity folds into the first.
	mergedAgain := e1
	mergedAgain.Conflicts = 3
	a.merge(o1.identity().String(), &mergedAgain)
	entries, _ = a.snapshot()
	for i := range entries {
		if entries[i].ID.String() == o1.identity().String() {
			if entries[i].Conflicts != 3 {
				t.Errorf("conflicts after second merge = %d, want 3", entries[i].Conflicts)
			}
			// Technologies dedupe by identity: still one nginx.
			if n := len(entries[i].Technologies); n != 1 {
				t.Errorf("technologies = %d, want 1", n)
			}
		}
	}
}

func TestMergeEntriesStatusResolution(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	cancelled := cancelledEntry(o)
	completed := cancelled
	completed.Status = StatusCompleted
	failed := cancelled
	failed.Status = StatusFailed
	failed.Err = errTest("key failure")

	m, err := mergeEntries(&cancelled, &completed)
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != StatusCompleted {
		t.Errorf("cancelled+completed = %q, want completed", m.Status)
	}

	m, err = mergeEntries(&completed, &failed)
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != StatusFailed || m.Err == nil || m.Err.Error() != "key failure" {
		t.Errorf("completed+failed = %q/%v, want failed with Err", m.Status, m.Err)
	}

	m, err = mergeEntries(&cancelled, &cancelled)
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != StatusCancelled {
		t.Errorf("cancelled+cancelled = %q, want cancelled", m.Status)
	}

	if _, err := mergeEntries(nil, nil); err == nil {
		t.Error("merge of two nil entries must error")
	}
	m, err = mergeEntries(nil, &completed)
	if err != nil || m.Status != StatusCompleted {
		t.Errorf("nil+a = %v/%v", m, err)
	}
}

func TestMergeEntriesSemantics(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	now := fixedTime

	a := ReportEntry{
		ID:        o.identity(),
		URL:       o.URL,
		Status:    StatusCompleted,
		FirstSeen: now,
		LastSeen:  now.Add(2 * time.Minute),
		Conflicts: 1,
		Truncated: true,
		Overflow:  Overflow{Cookies: true},
		Cached:    true,
		Technologies: []TechnologyResult{
			testTechResult(t, "nginx", 0.9, LevelMedium, "1.25.3"),
			testTechResult(t, "apache", 0.5, LevelMedium, ""),
		},
		Evidence: []asset.Evidence{testEvidence(t, "header:server: nginx", "Server: nginx/1.25.3")},
	}
	b := ReportEntry{
		ID:        o.identity(),
		URL:       o.URL,
		Status:    StatusCompleted,
		FirstSeen: now.Add(-time.Minute),
		LastSeen:  now.Add(5 * time.Minute),
		Conflicts: 2,
		Overflow:  Overflow{Indicators: true},
		Technologies: []TechnologyResult{
			testTechResult(t, "nginx", 0.7, LevelMedium, "2.0.0"),
			testTechResult(t, "iis", 0.8, LevelHigh, ""),
		},
		Evidence: []asset.Evidence{
			testEvidence(t, "header:server: nginx", "Server: nginx/1.25.3"),
			testEvidence(t, "header:server: microsoft-iis", "Server: Microsoft-IIS/10.0"),
		},
	}
	m, err := mergeEntries(&a, &b)
	if err != nil {
		t.Fatal(err)
	}
	if !m.FirstSeen.Equal(now.Add(-time.Minute)) {
		t.Errorf("FirstSeen = %v, want earliest", m.FirstSeen)
	}
	if !m.LastSeen.Equal(now.Add(5 * time.Minute)) {
		t.Errorf("LastSeen = %v, want latest", m.LastSeen)
	}
	if m.Conflicts != 3 {
		t.Errorf("Conflicts = %d, want 3", m.Conflicts)
	}
	if !m.Truncated || !m.Cached || !m.Overflow.Cookies || !m.Overflow.Indicators {
		t.Errorf("sticky flags lost: %+v", m)
	}
	if len(m.Technologies) != 3 {
		t.Fatalf("Technologies = %d, want 3", len(m.Technologies))
	}
	// nginx: a's higher score (0.9) wins the quality, and the version
	// survives with its contributor.
	nginx := findTech(m.Technologies, "nginx")
	if nginx == nil {
		t.Fatal("nginx missing")
	}
	if nginx.Score != 0.9 || nginx.Technology.Version != "1.25.3" {
		t.Errorf("nginx = score %v version %q, want 0.9 / 1.25.3", nginx.Score, nginx.Technology.Version)
	}
	// Evidence dedupes by identity.
	if len(m.Evidence) != 2 {
		t.Errorf("Evidence = %d, want 2 deduplicated", len(m.Evidence))
	}
	// Deterministic technology order: score desc, name asc.
	if m.Technologies[0].Technology.Name != "nginx" || m.Technologies[2].Technology.Name != "apache" {
		t.Errorf("technology order = %v", m.Technologies)
	}
}

func TestMergeTechnologyResultsVersionSurvival(t *testing.T) {
	// Higher score wins the version too when the winner has its own.
	a := []TechnologyResult{testTechResult(t, "nginx", 0.9, LevelHigh, "1.0.0")}
	b := []TechnologyResult{testTechResult(t, "nginx", 0.7, LevelMedium, "2.0.0")}
	out := mergeTechnologyResults(a, b)
	if len(out) != 1 || out[0].Technology.Version != "1.0.0" {
		t.Errorf("out = %v, want nginx 1.0.0", out)
	}

	// Higher score without a version inherits the lower's version.
	b = []TechnologyResult{testTechResult(t, "nginx", 0.95, LevelHigh, "")}
	out = mergeTechnologyResults(a, b)
	if len(out) != 1 || out[0].Technology.Version != "1.0.0" {
		t.Errorf("out = %v, want nginx 1.0.0 (inherited)", out)
	}
}

func TestNormalizeEntry(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	entry := ReportEntry{
		ID:     o.identity(),
		URL:    o.URL,
		Status: StatusCompleted,
		Technologies: []TechnologyResult{
			testTechResult(t, "apache", 0.5, LevelMedium, ""),
			testTechResult(t, "nginx", 0.9, LevelHigh, ""),
			testTechResult(t, "iis", 0.9, LevelHigh, ""),
		},
		Evidence: []asset.Evidence{
			testEvidence(t, "header:x: y", "b"),
			testEvidence(t, "header:x: a", "a"),
		},
	}
	normalizeEntry(&entry)
	if entry.Technologies[0].Technology.Name != "iis" || entry.Technologies[1].Technology.Name != "nginx" ||
		entry.Technologies[2].Technology.Name != "apache" {
		t.Errorf("technology order = %v", entry.Technologies)
	}
	if entry.Evidence[0].Indicator >= entry.Evidence[1].Indicator {
		t.Errorf("evidence order = %v", entry.Evidence)
	}
}

func TestBuildReport(t *testing.T) {
	o1 := newObs(t, "https://a.example/")
	o2 := newObs(t, "https://b.example/")
	evA := testEvidence(t, "header:server: nginx", "Server: nginx/1.25.3")
	evB := testEvidence(t, "header:x: y", "z")

	completed1 := ReportEntry{
		ID:        o1.identity(),
		URL:       o1.URL,
		Status:    StatusCompleted,
		FirstSeen: fixedTime,
		LastSeen:  fixedTime,
		Conflicts: 2,
		Truncated: true,
		Technologies: []TechnologyResult{
			testTechResult(t, "nginx", 0.9, LevelHigh, "1.25.3"),
			testTechResult(t, "apache", 0.7, LevelMedium, ""),
		},
		Evidence: []asset.Evidence{evA},
	}
	completed2 := ReportEntry{
		ID:        o2.identity(),
		URL:       o2.URL,
		Status:    StatusCompleted,
		FirstSeen: fixedTime,
		LastSeen:  fixedTime,
		Conflicts: 1,
		Technologies: []TechnologyResult{
			testTechResult(t, "nginx", 0.5, LevelLow, ""),
		},
		Evidence: []asset.Evidence{evA, evB},
	}
	cancelled := ReportEntry{ID: mustURL(t, "https://c.example/").Identity(), Status: StatusCancelled}
	failed := ReportEntry{ID: mustURL(t, "https://d.example/").Identity(), Status: StatusFailed}

	entries := []ReportEntry{completed1, completed2, cancelled, failed}
	rep := buildReport(entries, 3, MetricsSnapshot{Observations: 4, Analyzed: 2})

	if rep.Observations.Completed != 2 || rep.Observations.Cancelled != 1 ||
		rep.Observations.Failed != 1 || rep.Observations.Malformed != 3 {
		t.Errorf("counts = %+v", rep.Observations)
	}
	if rep.Conflicts != 3 || !rep.Truncated {
		t.Errorf("conflicts/truncated = %d/%v", rep.Conflicts, rep.Truncated)
	}
	if rep.Metrics.Observations != 4 || rep.Metrics.Analyzed != 2 {
		t.Errorf("metrics = %+v", rep.Metrics)
	}
	if len(rep.Technologies) != 2 {
		t.Fatalf("technologies = %d, want 2 merged", len(rep.Technologies))
	}
	// Technologies sorted by name; nginx carries the max score and its
	// contributor's level; version survives from the first contributor.
	if rep.Technologies[0].Name != "apache" || rep.Technologies[1].Name != "nginx" {
		t.Errorf("technology order = %v", rep.Technologies)
	}
	nginx := rep.Technologies[1]
	if nginx.Prov.Confidence != 0.9 || nginx.Version != "1.25.3" {
		t.Errorf("nginx = %+v", nginx)
	}
	if rep.Levels[nginx.ID()] != LevelHigh {
		t.Errorf("nginx level = %q, want high", rep.Levels[nginx.ID()])
	}
	if len(rep.Evidence) != 2 {
		t.Errorf("evidence = %d, want 2 deduplicated", len(rep.Evidence))
	}
	for i := 1; i < len(rep.Evidence); i++ {
		if rep.Evidence[i-1].ID() >= rep.Evidence[i].ID() {
			t.Errorf("evidence not sorted: %v", rep.Evidence)
		}
	}
}

func TestHostOrZero(t *testing.T) {
	u := mustURL(t, "https://ok.example/")
	if h := hostOrZero(u); h.Identity().String() != "host:ok.example" {
		t.Errorf("host = %q", h.Identity().String())
	}
	u = mustURL(t, "https://ok.example:8443/x")
	if h := hostOrZero(u); h.Identity().String() != "host:ok.example" {
		t.Errorf("host with port = %q", h.Identity().String())
	}
	u = mustURL(t, "https://1.2.3.4/")
	if h := hostOrZero(u); !h.Identity().IsZero() {
		t.Errorf("IP literal must not produce a host edge: %q", h.Identity().String())
	}
	if h := hostOrZero(asset.URL{}); !h.Identity().IsZero() {
		t.Errorf("zero URL must not produce a host")
	}
}

func TestGraphOf(t *testing.T) {
	o := newObs(t, "https://ok.example/app")
	ep, err := asset.NewEndpoint("GET", o.URL.String(), testProv())
	if err != nil {
		t.Fatal(err)
	}
	o.Endpoint = &ep

	ev := testEvidence(t, "header:server: nginx", "Server: nginx/1.25.3")
	tr := testTechResult(t, "nginx", 0.9, LevelMedium, "")
	tr2 := testTechResult(t, "apache", 0.5, LevelMedium, "")
	techEvidence := map[string][]string{
		tr.Technology.ID():  {ev.ID()},
		tr2.Technology.ID(): {},
	}

	rels := graphOf(o, []TechnologyResult{tr, tr2}, techEvidence)
	if len(rels) != 7 {
		t.Fatalf("relationships = %d, want 7", len(rels))
	}
	kinds := map[asset.RelationshipKind]int{}
	for _, r := range rels {
		kinds[r.Kind]++
	}
	want := map[asset.RelationshipKind]int{
		asset.RelationshipHostToTechnology:     2,
		asset.RelationshipURLToTechnology:      2,
		asset.RelationshipEndpointToTechnology: 2,
		asset.RelationshipTechnologyToEvidence: 1,
	}
	if !reflect.DeepEqual(kinds, want) {
		t.Errorf("relationship kinds = %v, want %v", kinds, want)
	}
	// Deterministic: tech->evidence links only for retained technologies.
	found := false
	for _, r := range rels {
		if r.Kind == asset.RelationshipTechnologyToEvidence && r.To.Value == ev.ID() {
			found = true
		}
	}
	if !found {
		t.Error("technology->evidence edge missing")
	}
}

// TestMergeTechnologyTieBreakChainOrder is the L2 regression test: the
// equal-score per-identity merge tie-break is a strict total order — a
// version-bearing contributor outranks a version-less one, then the
// earliest ObservedAt, then the lowest source name, then the lowest DB
// ordinal of the version-bearing indicator, then the lowest version string,
// then the lowest level — so merging in either order folds to the SAME
// contributor, on every rung of the chain.
func TestMergeTechnologyTieBreakChainOrder(t *testing.T) {
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	// mk builds a same-identity nginx contributor with explicit tie-break
	// keys (same 0.5 score everywhere, so every fold is a score tie).
	mk := func(source string, at time.Time, ordinal int, version string, lvl ConfidenceLevel) TechnologyResult {
		tr := testTechResult(t, "nginx", 0.5, lvl, version)
		tr.Technology.Prov = asset.Provenance{Source: source, DiscoveredAt: at}
		tr.versionOrdinal = ordinal
		return tr
	}

	// winner ties with loser on every EARLIER rung and differs only on the
	// rung under test.
	cases := []struct {
		name   string
		winner TechnologyResult
		loser  TechnologyResult
	}{
		{"version-bearing outranks version-less",
			mk("src", base, 1, "1.0", LevelLow),
			mk("src", base, 1, "", LevelLow)},
		{"earliest ObservedAt wins",
			mk("src", base, 0, "", LevelLow),
			mk("src", base.Add(time.Hour), 0, "", LevelLow)},
		{"lowest source name wins",
			mk("a-src", base, 0, "", LevelLow),
			mk("z-src", base, 0, "", LevelLow)},
		{"lowest version-bearing indicator DB order wins",
			mk("src", base, 2, "1.0", LevelLow),
			mk("src", base, 7, "1.0", LevelLow)},
		{"lowest version string wins",
			mk("src", base, 1, "1.0", LevelLow),
			mk("src", base, 1, "2.0", LevelLow)},
		{"lowest level wins",
			mk("src", base, 1, "1.0", LevelHigh),
			mk("src", base, 1, "1.0", LevelMedium)},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if !technologyChainBetter(tt.winner, tt.loser) {
				t.Error("chain must prefer the winner contributor")
			}
			if technologyChainBetter(tt.loser, tt.winner) {
				t.Error("chain must not prefer the loser contributor")
			}

			// Merge-order independence: a score tie folds to the SAME
			// contributor no matter which side arrives first.
			got := mergeTechnologyResults([]TechnologyResult{tt.loser}, []TechnologyResult{tt.winner})
			rev := mergeTechnologyResults([]TechnologyResult{tt.winner}, []TechnologyResult{tt.loser})
			if !techResultEqual(got, rev, 1) {
				t.Fatalf("merge order changed the result: %+v vs %+v", got, rev)
			}
			if !techResultEqual(got, []TechnologyResult{tt.winner}, 1) {
				t.Errorf("merged contributor = %+v, want the chain winner %+v", got, tt.winner)
			}
		})
	}
}

// techResultEqual asserts that got and want hold the same single
// TechnologyResult across every tie-break-relevant field (the chain keys
// plus score and identity).
func techResultEqual(got, want []TechnologyResult, n int) bool {
	if len(got) != n || len(want) != n {
		return false
	}
	for i := range got {
		g, w := got[i], want[i]
		if g.Technology.ID() != w.Technology.ID() ||
			g.Technology.Version != w.Technology.Version ||
			g.Technology.Prov.Source != w.Technology.Prov.Source ||
			!g.Technology.Prov.DiscoveredAt.Equal(w.Technology.Prov.DiscoveredAt) ||
			g.Score != w.Score || g.Level != w.Level || g.versionOrdinal != w.versionOrdinal {
			return false
		}
	}
	return true
}

// errTest builds a plain error for tests.
func errTest(msg string) error { return errString(msg) }

type errString string

func (e errString) Error() string { return string(e) }
