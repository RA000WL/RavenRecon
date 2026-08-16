package jsintel

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func testEntry(rawURL string, status Status) JSEntry {
	return JSEntry{URL: mustURL(tb(), rawURL), Status: status}
}

// tb is a package-level testing.TB stand-in for testEntry's URL builder.
// testEntry is only used by tests; the URL normalization cannot fail for the
// literal strings passed below.
var tb = func() testing.TB { return nil } // replaced by tests via tEntry

// tEntry builds an entry whose URL parses or fails the test.
func tEntry(t *testing.T, rawURL string, status Status) JSEntry {
	t.Helper()
	return JSEntry{URL: mustURL(t, rawURL), Status: status}
}

func TestMergePriority(t *testing.T) {
	u := "http://e.com/x.js"
	completed := tEntry(t, u, StatusCompleted)
	incomplete := tEntry(t, u, StatusIncomplete)
	failed := tEntry(t, u, StatusFailed)
	cancelled := tEntry(t, u, StatusCancelled)
	cfg := normalizeCaps(Config{})

	// completed wins over everything.
	dst := completed
	mergeEntries(&dst, failed, cfg)
	if dst.Status != StatusCompleted {
		t.Errorf("completed + failed = %s, want completed", dst.Status)
	}
	dst = failed
	mergeEntries(&dst, completed, cfg)
	if dst.Status != StatusCompleted {
		t.Errorf("failed + completed = %s, want completed", dst.Status)
	}

	// incomplete beats failed and cancelled.
	dst = incomplete
	mergeEntries(&dst, failed, cfg)
	if dst.Status != StatusIncomplete {
		t.Errorf("incomplete + failed = %s, want incomplete", dst.Status)
	}
	dst = failed
	mergeEntries(&dst, incomplete, cfg)
	if dst.Status != StatusIncomplete {
		t.Errorf("failed + incomplete = %s, want incomplete", dst.Status)
	}

	// failed beats cancelled.
	dst = cancelled
	mergeEntries(&dst, failed, cfg)
	if dst.Status != StatusFailed {
		t.Errorf("cancelled + failed = %s, want failed", dst.Status)
	}
	dst = failed
	mergeEntries(&dst, cancelled, cfg)
	if dst.Status != StatusFailed {
		t.Errorf("failed + cancelled = %s, want failed", dst.Status)
	}
}

func TestMergePlaceholders(t *testing.T) {
	u := "http://e.com/x.js"
	cfg := normalizeCaps(Config{})

	placeholder := JSEntry{URL: mustURL(t, u), Status: StatusCancelled, Sources: []string{"a"}}
	if !isPlaceholder(placeholder) {
		t.Fatal("a source-only cancelled entry must be a placeholder")
	}
	real := tEntry(t, u, StatusCompleted)
	real.FirstSeen = fixedTime
	real.LastSeen = fixedTime
	real.Sources = []string{"b"}

	// A placeholder dst is replaced wholesale by a real observation.
	dst := placeholder
	mergeEntries(&dst, real, cfg)
	if dst.Status != StatusCompleted || len(dst.Sources) != 1 || dst.Sources[0] != "b" {
		t.Errorf("placeholder dst: %+v, want wholesale replacement", dst)
	}

	// A placeholder src keeps its discovery sources only.
	dst = real
	mergeEntries(&dst, placeholder, cfg)
	if dst.Status != StatusCompleted {
		t.Errorf("placeholder src must not change the status: %s", dst.Status)
	}
	if len(dst.Sources) != 2 || dst.Sources[0] != "b" || dst.Sources[1] != "a" {
		t.Errorf("sources = %v, want [b a]", dst.Sources)
	}
	if !dst.FirstSeen.Equal(fixedTime) || !dst.LastSeen.Equal(fixedTime) {
		t.Errorf("timestamps = %v/%v, want unchanged %v", dst.FirstSeen, dst.LastSeen, fixedTime)
	}

	// An entry with a cause is a REAL cancelled entry, not a placeholder.
	cancelled := JSEntry{URL: mustURL(t, u), Status: StatusCancelled, Sources: []string{"a"}, Err: errors.New("cancel")}
	if isPlaceholder(cancelled) {
		t.Error("a cancelled entry with a cause must not be a placeholder")
	}
}

func TestMergeSourcesAndTimestamps(t *testing.T) {
	cfg := normalizeCaps(Config{})
	t0 := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	tMinus := t0.Add(-time.Hour)
	tPlus := t0.Add(time.Hour)

	dst := tEntry(t, "http://e.com/x.js", StatusCompleted)
	dst.Sources = []string{"a"}
	dst.FirstSeen, dst.LastSeen = t0, t0
	src := tEntry(t, "http://e.com/x.js", StatusCompleted)
	src.Sources = []string{"a", "b"}
	src.FirstSeen, src.LastSeen = tMinus, tPlus

	mergeEntries(&dst, src, cfg)
	if len(dst.Sources) != 2 || dst.Sources[0] != "a" || dst.Sources[1] != "b" {
		t.Errorf("sources = %v, want [a b] in first-observation order", dst.Sources)
	}
	if !dst.FirstSeen.Equal(tMinus) || !dst.LastSeen.Equal(tPlus) {
		t.Errorf("FirstSeen/LastSeen = %v/%v, want %v/%v", dst.FirstSeen, dst.LastSeen, tMinus, tPlus)
	}
}

func TestMergeCachedSticky(t *testing.T) {
	cfg := normalizeCaps(Config{})
	dst := tEntry(t, "http://e.com/x.js", StatusCompleted)
	src := tEntry(t, "http://e.com/x.js", StatusCompleted)
	src.Cached = true
	mergeEntries(&dst, src, cfg)
	if !dst.Cached {
		t.Error("Cached must be sticky (OR) across merges")
	}
}

func TestMergeListsDedup(t *testing.T) {
	cfg := normalizeCaps(Config{})
	a := asset.Identity{Kind: asset.KindJavaScript, Value: "http://e.com/a.js"}
	b := asset.Identity{Kind: asset.KindJavaScript, Value: "http://e.com/b.js"}
	c := asset.Identity{Kind: asset.KindJavaScript, Value: "http://e.com/c.js"}
	e1, err := asset.NewRelationship(a, asset.RelationshipJavaScriptToJavaScript, b)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := asset.NewRelationship(a, asset.RelationshipJavaScriptToJavaScript, c)
	if err != nil {
		t.Fatal(err)
	}

	dst := tEntry(t, "http://e.com/a.js", StatusCompleted)
	dst.Imports = []asset.Relationship{e1}
	dst.Relationships = []asset.Relationship{e1}
	dst.BareImports = []string{"b", "a"}
	dst.Exports = []string{"x"}
	src := tEntry(t, "http://e.com/a.js", StatusCompleted)
	src.Imports = []asset.Relationship{e1, e2}
	src.Relationships = []asset.Relationship{e2, e1}
	src.BareImports = []string{"c", "a"}
	src.Exports = []string{"x", "y"}

	mergeEntries(&dst, src, cfg)
	if len(dst.Imports) != 2 || dst.Imports[0].ID() != e1.ID() || dst.Imports[1].ID() != e2.ID() {
		t.Errorf("imports = %v, want the two distinct edges", dst.Imports)
	}
	if len(dst.Relationships) != 2 {
		t.Errorf("relationships = %v, want deduplicated edges", dst.Relationships)
	}
	if len(dst.BareImports) != 3 || dst.BareImports[0] != "a" || dst.BareImports[1] != "b" || dst.BareImports[2] != "c" {
		t.Errorf("bare imports = %v, want sorted [a b c]", dst.BareImports)
	}
	if len(dst.Exports) != 2 || dst.Exports[0] != "x" || dst.Exports[1] != "y" {
		t.Errorf("exports = %v, want [x y]", dst.Exports)
	}
}

func TestMergeSourceMaps(t *testing.T) {
	m1 := asset.SourceMap{
		URL:  mustURL(t, "http://e.com/app.js.map"),
		Prov: asset.Provenance{Source: "a", DiscoveredAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)},
	}
	m1Later := asset.SourceMap{
		URL:  mustURL(t, "http://e.com/app.js.map"),
		Prov: asset.Provenance{Source: "b", DiscoveredAt: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)},
	}
	m2 := asset.SourceMap{
		URL:  mustURL(t, "http://e.com/other.js.map"),
		Prov: asset.Provenance{Source: "a", DiscoveredAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)},
	}

	// Same identity: merged into one (earliest provenance wins).
	dst := tEntry(t, "http://e.com/app.js", StatusCompleted)
	dst.SourceMaps = []asset.SourceMap{m1}
	src := tEntry(t, "http://e.com/app.js", StatusCompleted)
	src.SourceMaps = []asset.SourceMap{m1Later}
	mergeEntries(&dst, src, normalizeCaps(Config{}))
	if len(dst.SourceMaps) != 1 {
		t.Fatalf("source maps = %d, want 1 (same identity merged)", len(dst.SourceMaps))
	}
	if dst.SourceMaps[0].Prov.Source != "a" {
		t.Errorf("merged provenance source = %q, want the earliest observation", dst.SourceMaps[0].Prov.Source)
	}

	// Distinct identities beyond the per-entry cap are dropped.
	cfg := normalizeCaps(Config{MaxSourceMapsPerFile: 1})
	dst2 := tEntry(t, "http://e.com/app.js", StatusCompleted)
	dst2.SourceMaps = []asset.SourceMap{m1}
	src2 := tEntry(t, "http://e.com/app.js", StatusCompleted)
	src2.SourceMaps = []asset.SourceMap{m2}
	mergeEntries(&dst2, src2, cfg)
	if len(dst2.SourceMaps) != 1 {
		t.Errorf("source maps = %d, want 1 (cap 1)", len(dst2.SourceMaps))
	}
}

func TestReportSortedAndNormalized(t *testing.T) {
	acc := NewAccumulator(Config{})
	acc.merge(JSEntry{URL: mustURL(t, "http://e.com/c.js"), Status: StatusCompleted,
		BareImports: []string{"z", "a"}, Exports: []string{"y", "x"}})
	acc.merge(JSEntry{URL: mustURL(t, "http://e.com/a.js"), Status: StatusCompleted})
	acc.merge(JSEntry{URL: mustURL(t, "http://e.com/b.js"), Status: StatusFailed})

	rep := acc.Report()
	if len(rep.Entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(rep.Entries))
	}
	// Entries sorted by canonical URL.
	wantOrder := []string{"http://e.com/a.js", "http://e.com/b.js", "http://e.com/c.js"}
	for i, w := range wantOrder {
		if rep.Entries[i].URL.String() != w {
			t.Errorf("entry %d = %q, want %q", i, rep.Entries[i].URL, w)
		}
	}
	// Variable-length slices normalized.
	c := rep.Entries[2]
	if len(c.BareImports) != 2 || c.BareImports[0] != "a" || c.BareImports[1] != "z" {
		t.Errorf("bare imports = %v, want sorted [a z]", c.BareImports)
	}
	if len(c.Exports) != 2 || c.Exports[0] != "x" || c.Exports[1] != "y" {
		t.Errorf("exports = %v, want sorted [x y]", c.Exports)
	}
}

func TestReportStatusCounts(t *testing.T) {
	rep := Report{Entries: []JSEntry{
		tEntry(t, "http://e.com/a.js", StatusCompleted),
		tEntry(t, "http://e.com/b.js", StatusCompleted),
		tEntry(t, "http://e.com/c.js", StatusIncomplete),
		tEntry(t, "http://e.com/d.js", StatusFailed),
		tEntry(t, "http://e.com/e.js", StatusCancelled),
	}}
	counts := rep.StatusCounts()
	want := map[Status]int{StatusCompleted: 2, StatusIncomplete: 1, StatusFailed: 1, StatusCancelled: 1}
	for _, s := range []Status{StatusCompleted, StatusIncomplete, StatusFailed, StatusCancelled} {
		if counts[s] != want[s] {
			t.Errorf("counts[%s] = %d, want %d", s, counts[s], want[s])
		}
	}
	// Empty report still carries all four keys.
	empty := Report{}.StatusCounts()
	for _, s := range []Status{StatusCompleted, StatusIncomplete, StatusFailed, StatusCancelled} {
		if _, ok := empty[s]; !ok {
			t.Errorf("empty report is missing the %s key", s)
		}
	}
}

func TestReportAccessors(t *testing.T) {
	jsA, err := asset.NewJavaScript("http://e.com/a.js", asset.Provenance{Source: "s"})
	if err != nil {
		t.Fatal(err)
	}
	jsB, err := asset.NewJavaScript("http://e.com/b.js", asset.Provenance{Source: "s"})
	if err != nil {
		t.Fatal(err)
	}
	smA := asset.SourceMap{URL: mustURL(t, "http://e.com/b.js.map"), Prov: asset.Provenance{Source: "s"}}
	smB := asset.SourceMap{URL: mustURL(t, "http://e.com/a.js.map"), Prov: asset.Provenance{Source: "s"}}

	from := jsA.Identity()
	to := asset.Identity{Kind: asset.KindJavaScript, Value: "http://e.com/b.js"}
	rel, err := asset.NewRelationship(from, asset.RelationshipJavaScriptToJavaScript, to)
	if err != nil {
		t.Fatal(err)
	}

	rep := Report{Entries: []JSEntry{
		{URL: jsA.URL, Status: StatusCompleted, JS: &jsA,
			SourceMaps: []asset.SourceMap{smB}, Relationships: []asset.Relationship{rel}},
		{URL: jsB.URL, Status: StatusCompleted, JS: &jsB,
			SourceMaps: []asset.SourceMap{smA}, Relationships: []asset.Relationship{rel}},
	}}

	allJS := rep.AllJavaScript()
	if len(allJS) != 2 || allJS[0].URL.String() != "http://e.com/a.js" || allJS[1].URL.String() != "http://e.com/b.js" {
		t.Errorf("AllJavaScript = %v, want both assets sorted by URL", allJS)
	}
	allMaps := rep.AllSourceMaps()
	if len(allMaps) != 2 || allMaps[0].URL.String() != "http://e.com/a.js.map" || allMaps[1].URL.String() != "http://e.com/b.js.map" {
		t.Errorf("AllSourceMaps = %v, want both maps sorted by URL", allMaps)
	}
	// The duplicate edge appears once, sorted.
	allRels := rep.AllRelationships()
	if len(allRels) != 1 || allRels[0].ID() != rel.ID() {
		t.Errorf("AllRelationships = %v, want the single deduplicated edge", allRels)
	}
}

func TestReportMetricsSnapshot(t *testing.T) {
	m := &Metrics{}
	if got := m.Snapshot(); got != (Snapshot{}) {
		t.Errorf("fresh metrics = %+v, want zero", got)
	}
	m.addLine()
	m.addCandidate()
	m.addFetch()
	m.addRead()
	m.addStore()
	m.addParse()
	m.addMalformed(3)
	m.addTruncated()
	m.addSkipped(2)
	m.addSecretLine()
	snap := m.Snapshot()
	want := Snapshot{Lines: 1, Candidates: 1, Fetches: 1, Reads: 1, Stores: 1, Parses: 1,
		Malformed: 3, Truncated: 1, Skipped: 2, SecretLines: 1}
	if snap != want {
		t.Errorf("snapshot = %+v, want %+v", snap, want)
	}
	// A nil Metrics is legal everywhere.
	var nilM *Metrics
	if got := nilM.Snapshot(); got != (Snapshot{}) {
		t.Errorf("nil metrics snapshot = %+v, want zero", got)
	}
}

func TestJoinEntryErrors(t *testing.T) {
	cfg := normalizeCaps(Config{})
	dst := tEntry(t, "http://e.com/x.js", StatusFailed)
	dst.Err = errors.New("e0")
	for i := 1; i <= 11; i++ {
		src := tEntry(t, "http://e.com/x.js", StatusFailed)
		src.Err = fmt.Errorf("e%d", i)
		mergeEntries(&dst, src, cfg)
	}
	if dst.Status != StatusFailed {
		t.Errorf("status = %s, want failed", dst.Status)
	}
	errStr := dst.Err.Error()
	for _, want := range []string{"e0", "e7"} {
		if !strings.Contains(errStr, want) {
			t.Errorf("error %q does not contain %q", errStr, want)
		}
	}
	if !strings.Contains(errStr, "... and 4 more error(s)") {
		t.Errorf("error %q does not report the bounded excess", errStr)
	}
	var be *boundedErrs
	if !errors.As(dst.Err, &be) {
		t.Fatal("Err must be the bounded join")
	}
	if len(be.errs) != 8 || be.excess != 4 {
		t.Errorf("bounded join = %d kept / %d excess, want 8/4", len(be.errs), be.excess)
	}
	if !errors.Is(dst.Err, errors.New("e0")) == false {
		// errors.Is against a fresh error never matches; this guard exists
		// only to exercise the Unwrap traversal without a matcher panic.
	}
	// Unwrap exposes the retained errors.
	if len(be.Unwrap()) != 8 {
		t.Errorf("Unwrap = %d errors, want 8", len(be.Unwrap()))
	}
}

func TestAccumulatorMalformed(t *testing.T) {
	acc := NewAccumulator(Config{})
	if acc.Malformed() != 0 {
		t.Errorf("malformed = %d, want 0", acc.Malformed())
	}
	acc.addMalformed(2)
	acc.addMalformed(0) // ignored
	if acc.Malformed() != 2 {
		t.Errorf("malformed = %d, want 2", acc.Malformed())
	}
	rep := acc.Report()
	if rep.Malformed != 2 {
		t.Errorf("report malformed = %d, want 2", rep.Malformed)
	}
}
