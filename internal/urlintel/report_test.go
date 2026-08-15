package urlintel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestStatusLabels pins the stable status labels.
func TestStatusLabels(t *testing.T) {
	if StatusCompleted.String() != "completed" || StatusCancelled.String() != "cancelled" || StatusFailed.String() != "failed" {
		t.Fatalf("status labels changed: %q %q %q",
			StatusCompleted, StatusCancelled, StatusFailed)
	}
}

// entryFor builds a completed observation for raw at time at with the given
// adapter, using the real extraction path.
func entryFor(raw, adapter string, at time.Time) URLEntry {
	u, err := asset.ParseURL(raw, asset.Provenance{Source: adapter, DiscoveredAt: at})
	if err != nil {
		panic(err) // test helper: malformed fixture is a test bug
	}
	return extractURL(u, adapter, true, at)
}

// TestMergeEntriesRules pins the merge-at-emit rules: placeholder
// replacement, status precedence, source/timestamp union, endpoint and
// relationship dedup, host fill, and sticky Overflow/Err/Cached.
func TestMergeEntriesRules(t *testing.T) {
	u := mustURL(t, "http://example.com/p?a=1")
	at := fixedTime
	adapter := "test-adapter"
	completed := entryFor("http://example.com/p?a=1", adapter, at)
	cancelled := URLEntry{URL: u, Status: StatusCancelled, Err: context.Canceled}
	failed := URLEntry{URL: u, Status: StatusFailed, Err: errors.New("boom")}
	placeholder := URLEntry{URL: u, Status: StatusCancelled}

	t.Run("placeholder replaced wholesale", func(t *testing.T) {
		dst := placeholder
		mergeEntries(&dst, completed)
		if dst.Status != StatusCompleted || len(dst.Sources) != 1 || dst.FirstSeen.IsZero() {
			t.Fatalf("dst = %+v, want the real observation wholesale", dst)
		}
	})

	t.Run("placeholder keeps the cancellation cause", func(t *testing.T) {
		dst := placeholder
		mergeEntries(&dst, cancelled)
		if dst.Status != StatusCancelled || dst.Err == nil {
			t.Fatalf("dst = %+v, want cancelled with the cause", dst)
		}
	})

	t.Run("cancelled never downgrades completed", func(t *testing.T) {
		dst := completed
		mergeEntries(&dst, cancelled)
		if dst.Status != StatusCompleted {
			t.Fatalf("status = %s, want completed", dst.Status)
		}
	})

	t.Run("completed wins over failed", func(t *testing.T) {
		dst := failed
		mergeEntries(&dst, completed)
		if dst.Status != StatusCompleted {
			t.Fatalf("status = %s, want completed", dst.Status)
		}
		// The real observation fills the timestamps a failed entry lacks.
		if dst.FirstSeen.IsZero() || dst.LastSeen.IsZero() {
			t.Fatalf("timestamps not filled: %+v", dst)
		}
	})

	t.Run("failed wins over cancelled", func(t *testing.T) {
		dst := cancelled
		mergeEntries(&dst, failed)
		if dst.Status != StatusFailed {
			t.Fatalf("status = %s, want failed", dst.Status)
		}
	})

	t.Run("sources unioned in first-observation order", func(t *testing.T) {
		a := entryFor("http://example.com/p?a=1", "adapter-a", at)
		b := entryFor("http://example.com/p?a=1", "adapter-b", at)
		b.Sources = append([]string{"adapter-a"}, b.Sources...) // re-observation
		mergeEntries(&a, b)
		requireEqualStrings(t, "sources", a.Sources, []string{"adapter-a", "adapter-b"})
	})

	t.Run("timestamps min/max", func(t *testing.T) {
		early := entryFor("http://example.com/p?a=1", adapter, fixedTime)
		late := entryFor("http://example.com/p?a=1", adapter, fixedTime.Add(3*time.Hour))
		mergeEntries(&early, late)
		if !early.FirstSeen.Equal(fixedTime) || !early.LastSeen.Equal(fixedTime.Add(3*time.Hour)) {
			t.Fatalf("FirstSeen/LastSeen = %v/%v", early.FirstSeen, early.LastSeen)
		}
	})

	t.Run("endpoints deduplicated by identity", func(t *testing.T) {
		dst := completed
		mergeEntries(&dst, completed)
		if len(dst.Endpoints) != 1 {
			t.Fatalf("endpoints = %d, want 1", len(dst.Endpoints))
		}
	})

	t.Run("relationships deduplicated by edge identity", func(t *testing.T) {
		dst := completed
		mergeEntries(&dst, completed)
		if len(dst.Relationships) != 4 {
			t.Fatalf("relationships = %d, want 4", len(dst.Relationships))
		}
	})

	t.Run("parameters merged by identity", func(t *testing.T) {
		a := entryFor("http://example.com/p?a=1", adapter, fixedTime)
		b := entryFor("http://example.com/p?a=1", adapter, fixedTime.Add(time.Hour))
		// Same canonical URL, so the same value: the merge deduplicates the
		// value and unions nothing new.
		mergeEntries(&a, b)
		if len(a.Parameters) != 1 || len(a.Parameters[0].ObservedValues) != 1 {
			t.Fatalf("parameters = %+v", a.Parameters)
		}
		// Different observations of the same parameter (hand-built, as the
		// pipeline itself does via WithValue) union values in order.
		p1 := mustParam(t, "q", "query", "one", adapter, fixedTime)
		p2 := mustParam(t, "q", "query", "two", adapter, fixedTime.Add(time.Hour))
		dst := URLEntry{URL: u, Status: StatusCompleted, Sources: []string{adapter}, Parameters: []asset.Parameter{p1}}
		src := URLEntry{URL: u, Status: StatusCompleted, Sources: []string{adapter}, Parameters: []asset.Parameter{p2}}
		mergeEntries(&dst, src)
		if len(dst.Parameters) != 1 {
			t.Fatalf("parameters = %d, want 1 merged", len(dst.Parameters))
		}
		requireEqualStrings(t, "merged values", dst.Parameters[0].ObservedValues, []string{"one", "two"})
	})

	t.Run("overflow sticky", func(t *testing.T) {
		dst := completed
		src := completed
		src.Overflow = true
		mergeEntries(&dst, src)
		if !dst.Overflow {
			t.Fatal("Overflow not sticky")
		}
	})

	t.Run("cached sticky", func(t *testing.T) {
		dst := completed
		src := completed
		src.Cached = true
		mergeEntries(&dst, src)
		if !dst.Cached {
			t.Fatal("Cached not sticky")
		}
	})

	t.Run("errors joined", func(t *testing.T) {
		dst := failed
		mergeEntries(&dst, URLEntry{URL: u, Status: StatusFailed, Err: errors.New("second")})
		if dst.Err == nil || !strings.Contains(dst.Err.Error(), "second") {
			t.Fatalf("Err = %v, want both causes joined", dst.Err)
		}
	})

	t.Run("host filled when absent", func(t *testing.T) {
		dst := URLEntry{URL: u, Status: StatusCompleted, Sources: []string{adapter}}
		mergeEntries(&dst, completed)
		if dst.Host.String() != "example.com" {
			t.Fatalf("Host = %q, want example.com", dst.Host.String())
		}
	})
}

// TestMergeEntriesErrBounded pins the per-entry Err cap at the merge site: an
// entry merged across more than maxErrorsPerEntry observations, each carrying
// an Err, retains exactly the first maxErrorsPerEntry errors plus one count
// tail — the Err string is bounded regardless of how many observations merge,
// so a stream repeating one URL with a persistently failing cache Put can
// never accumulate an unboundedly growing joined error (regression test for
// the O(N²)-copying errors.Join at the merge site).
func TestMergeEntriesErrBounded(t *testing.T) {
	u := mustURL(t, "http://example.com/p")
	adapter := "test-adapter"
	at := fixedTime
	obs := func(err error) URLEntry {
		return URLEntry{URL: u, Status: StatusCompleted, Sources: []string{adapter}, FirstSeen: at, LastSeen: at, Err: err}
	}
	// errText makes each error long enough that an unbounded join of 12
	// errors would exceed the assertion bound while the capped one stays
	// far below it.
	errText := func(i int) string {
		return fmt.Sprintf("cache put failure number %d: %s", i, strings.Repeat("x", 60))
	}

	// 12 observations total, every one carrying an Err.
	dst := URLEntry{URL: u, Status: StatusCompleted}
	for i := 0; i <= maxErrorsPerEntry+3; i++ {
		mergeEntries(&dst, obs(errors.New(errText(i))))
	}

	msg := dst.Err.Error()
	// The first maxErrorsPerEntry causes are retained, in arrival order...
	for i := 0; i < maxErrorsPerEntry; i++ {
		if !strings.Contains(msg, errText(i)) {
			t.Fatalf("Err = %q, want retained error %q", msg, errText(i))
		}
	}
	// ...every further cause is dropped, never retained...
	for i := maxErrorsPerEntry; i <= maxErrorsPerEntry+3; i++ {
		if strings.Contains(msg, errText(i)) {
			t.Fatalf("Err = %q, want dropped error %q absent", msg, errText(i))
		}
	}
	// ...and a single tail line reports the dropped count.
	if !strings.Contains(msg, "more error(s)") {
		t.Fatalf("Err = %q, want the count tail", msg)
	}
	if len(msg) >= 1024 {
		t.Fatalf("Err length = %d, want < 1024 (bounded regardless of observation count)", len(msg))
	}

	// errors.Is still walks into the retained causes through the cap.
	first := errors.New("first retained cause")
	dst = URLEntry{URL: u, Status: StatusCompleted}
	mergeEntries(&dst, obs(first))
	for i := 0; i < maxErrorsPerEntry; i++ {
		mergeEntries(&dst, obs(errors.New(errText(i))))
	}
	if !errors.Is(dst.Err, first) {
		t.Fatalf("Err = %v, want errors.Is to reach the first retained cause", dst.Err)
	}
	if errors.Is(dst.Err, errors.New("never merged in")) {
		t.Fatal("errors.Is matched an error that was never merged")
	}
}

// TestMergeEntriesParameterCap pins that merge-at-emit re-enforces
// maxParametersPerURL on the MERGED list, mirroring extractParams: two
// observations whose disjoint parameter sets exceed the per-URL cap yield
// exactly maxParametersPerURL parameters with the entry flagged Overflow,
// and the flag stays false when the union fits within the cap. This is the
// regression test for the documented memory bound ("each entry's payload is
// bounded by the per-URL caps") holding for merged entries too.
func TestMergeEntriesParameterCap(t *testing.T) {
	u := mustURL(t, "http://example.com/p")
	at := fixedTime
	adapter := "test-adapter"
	// params builds n disjoint parameters named p<start>..p<start+n-1>
	// (identity = name within the query location, so disjoint names are
	// disjoint identities).
	params := func(start, n int) []asset.Parameter {
		out := make([]asset.Parameter, 0, n)
		for i := start; i < start+n; i++ {
			out = append(out, mustParam(t, fmt.Sprintf("p%d", i), "query", "v", adapter, at))
		}
		return out
	}
	entry := func(ps []asset.Parameter) URLEntry {
		return URLEntry{URL: u, Status: StatusCompleted, Sources: []string{adapter}, Parameters: ps}
	}

	t.Run("split boundary: 255 + 2 appends exactly one", func(t *testing.T) {
		// dst already holds 255 distinct parameters (one below the cap); src
		// adds two NEW disjoint identities. Exactly one append fits (256 =
		// the cap), the second is dropped, and the entry is flagged.
		dst := entry(params(0, maxParametersPerURL-1))
		src := entry(params(maxParametersPerURL-1, 2))
		mergeEntries(&dst, src)
		if len(dst.Parameters) != maxParametersPerURL {
			t.Fatalf("parameters = %d, want %d (one appended, one dropped)", len(dst.Parameters), maxParametersPerURL)
		}
		if !dst.Overflow {
			t.Fatal("Overflow = false, want true (one new identity was dropped)")
		}
		// The appended parameter is the first new identity, in first-seen
		// order; the second never entered the list.
		last := dst.Parameters[len(dst.Parameters)-1]
		if last.Name != fmt.Sprintf("p%d", maxParametersPerURL-1) {
			t.Fatalf("last retained parameter = %q, want p%d (the append boundary parameter)", last.Name, maxParametersPerURL-1)
		}
		for _, p := range dst.Parameters {
			if p.Name == fmt.Sprintf("p%d", maxParametersPerURL) {
				t.Fatalf("dropped parameter p%d is present in the retained set", maxParametersPerURL)
			}
		}
	})

	t.Run("union exceeds the cap", func(t *testing.T) {
		dst := entry(params(0, maxParametersPerURL))
		src := entry(params(maxParametersPerURL, maxParametersPerURL))
		mergeEntries(&dst, src)
		if len(dst.Parameters) != maxParametersPerURL {
			t.Fatalf("parameters = %d, want %d (cap re-enforced at merge)", len(dst.Parameters), maxParametersPerURL)
		}
		if !dst.Overflow {
			t.Fatal("Overflow = false, want true (new identities dropped past the cap)")
		}
		// The retained set is the first observation's, in first-seen order:
		// every merged parameter is one of the 256 already held, never an
		// appended duplicate.
		if dst.Parameters[0].Name != "p0" || dst.Parameters[len(dst.Parameters)-1].Name != fmt.Sprintf("p%d", maxParametersPerURL-1) {
			t.Fatalf("retained parameters = %+v, want p0..p%d", dst.Parameters, maxParametersPerURL-1)
		}
	})

	t.Run("union fits within the cap", func(t *testing.T) {
		dst := entry(params(0, 128))
		src := entry(params(128, 128))
		mergeEntries(&dst, src)
		if len(dst.Parameters) != maxParametersPerURL {
			t.Fatalf("parameters = %d, want %d (the union fits exactly)", len(dst.Parameters), maxParametersPerURL)
		}
		if dst.Overflow {
			t.Fatal("Overflow = true, want false (no parameter was dropped)")
		}
	})

	t.Run("same-identity merge never overflows", func(t *testing.T) {
		// 256 parameters present in BOTH observations: identity merges only
		// union values, never the list, so the cap is never hit.
		dst := entry(params(0, maxParametersPerURL))
		src := entry(params(0, maxParametersPerURL))
		mergeEntries(&dst, src)
		if len(dst.Parameters) != maxParametersPerURL {
			t.Fatalf("parameters = %d, want %d", len(dst.Parameters), maxParametersPerURL)
		}
		if dst.Overflow {
			t.Fatal("Overflow = true, want false (no new identity arrived)")
		}
	})
}

// mustParam builds a validated parameter or fails the test.
func mustParam(t *testing.T, name, location, value, source string, at time.Time) asset.Parameter {
	t.Helper()
	p, err := asset.NewParameter(name, location, value, source, at,
		asset.Provenance{Source: source, DiscoveredAt: at})
	if err != nil {
		t.Fatalf("NewParameter: %v", err)
	}
	return p
}

// TestAccumulatorConcurrentMerges pins the accumulator's thread safety and
// its deterministic report: many goroutines merging disjoint URL sets
// concurrently produce exactly the distinct-URL report, sorted, with every
// entry intact. Run under -race this also proves the mutex discipline.
func TestAccumulatorConcurrentMerges(t *testing.T) {
	const workers, perWorker = 8, 25
	acc := NewAccumulator()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				raw := fmt.Sprintf("http://example.com/p%d?q=%d", w*perWorker+i, i)
				e := entryFor(raw, "test-adapter", fixedTime)
				acc.merge(e)
				acc.merge(e) // duplicate: must deduplicate in place
			}
		}(w)
	}
	wg.Wait()

	rep := acc.Report()
	if len(rep.Entries) != workers*perWorker {
		t.Fatalf("entries = %d, want %d distinct URLs", len(rep.Entries), workers*perWorker)
	}
	prev := ""
	for _, e := range rep.Entries {
		if e.URL.String() <= prev {
			t.Fatalf("entries not strictly sorted at %q after %q", e.URL.String(), prev)
		}
		prev = e.URL.String()
		if e.Status != StatusCompleted || len(e.Sources) != 1 || len(e.Parameters) != 1 {
			t.Fatalf("entry %s = %+v", e.URL.String(), e)
		}
	}
}

// TestReportAccessors pins the report-level asset merges: URL/host/endpoint/
// parameter/relationship views deduplicated by Phase 2 identity and sorted.
func TestReportAccessors(t *testing.T) {
	acc := NewAccumulator()
	acc.merge(entryFor("http://example.com/a?q=1&x=2", "test-adapter", fixedTime))
	acc.merge(entryFor("http://example.com/b?q=3", "test-adapter", fixedTime.Add(time.Hour)))
	acc.merge(entryFor("http://192.0.2.1/c?q=4", "test-adapter", fixedTime.Add(2*time.Hour)))
	rep := acc.Report()

	urls := make([]string, 0, len(rep.AllURLs()))
	for _, u := range rep.AllURLs() {
		urls = append(urls, u.String())
	}
	requireEqualStrings(t, "AllURLs", urls, []string{
		"http://192.0.2.1/c?q=4",
		"http://example.com/a?q=1&x=2",
		"http://example.com/b?q=3",
	})

	hosts := make([]string, 0, len(rep.AllHosts()))
	for _, h := range rep.AllHosts() {
		hosts = append(hosts, h.String())
	}
	requireEqualStrings(t, "AllHosts", hosts, []string{"example.com"})

	if got := len(rep.AllEndpoints()); got != 3 {
		t.Fatalf("AllEndpoints = %d, want 3", got)
	}

	// Parameters merge across entries by identity: q observed in all three
	// URLs, x in one. The merge order follows the report's sorted entry
	// order (192.0.2.1, a, b).
	params := rep.AllParameters()
	got := map[string][]string{}
	for _, p := range params {
		got[p.Name] = p.ObservedValues
	}
	if len(params) != 2 {
		t.Fatalf("AllParameters = %d, want 2 (q, x)", len(params))
	}
	requireEqualStrings(t, "q values across entries", got["q"], []string{"4", "1", "3"})
	requireEqualStrings(t, "x values", got["x"], []string{"2"})

	// Relationships deduplicated by edge identity across entries.
	rels := rep.AllRelationships()
	seen := map[string]bool{}
	for _, r := range rels {
		if seen[r.ID()] {
			t.Fatalf("duplicate relationship %q", r.ID())
		}
		seen[r.ID()] = true
	}
	// Entry 1: 6 edges (host + endpoint + 2 params); entry 2: 4 (host +
	// endpoint + 1 param); entry 3 (IP literal): 3 (no host edge).
	if len(rels) != 13 {
		t.Fatalf("relationships = %d, want 13", len(rels))
	}
}

// TestReportDeterminism pins that merging the same observations in different
// orders produces identical reports (merge rules are order-stable for
// disjoint and duplicate observations).
func TestReportDeterminism(t *testing.T) {
	entries := []URLEntry{
		entryFor("http://example.com/a?q=1", "test-adapter", fixedTime),
		entryFor("http://example.com/b?q=2", "test-adapter", fixedTime),
		entryFor("http://example.com/c", "test-adapter", fixedTime),
	}

	forward, backward := NewAccumulator(), NewAccumulator()
	for _, e := range entries {
		forward.merge(e)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		backward.merge(entries[i])
	}
	if fp1, fp2 := reportFingerprint(forward.Report()), reportFingerprint(backward.Report()); fp1 != fp2 {
		t.Fatalf("merge order changed the report:\n%s\nvs\n%s", fp1, fp2)
	}
}

// TestAccumulatorMalformedCounting pins the malformed-line counter on the
// accumulator itself.
func TestAccumulatorMalformedCounting(t *testing.T) {
	acc := NewAccumulator()
	if acc.Malformed() != 0 {
		t.Fatalf("Malformed() = %d, want 0", acc.Malformed())
	}
	acc.addMalformed()
	acc.addMalformed()
	if acc.Malformed() != 2 {
		t.Fatalf("Malformed() = %d, want 2", acc.Malformed())
	}
	rep := acc.Report()
	if rep.Malformed != 2 || len(rep.Entries) != 0 {
		t.Fatalf("report = %+v", rep)
	}
}
