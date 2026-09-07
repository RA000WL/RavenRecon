package pipeline

import (
	"context"
	"sync"
	"time"
)

// LeveledStage is the optional execution-level contract: a Stage that
// declares it runs at a fixed level of the dependency DAG. Consecutive
// selection entries sharing a level form one group and run CONCURRENTLY;
// every other entry runs solo, in selection position. Groups execute in
// selection order, members merge in selection order — so the merged
// corpus, results, documents, and provenance are byte-identical to the
// sequential runner. Concurrency never changes WHAT a stage sees beyond
// the level contract: every member receives the merged state of all
// earlier groups (never a same-group member's additions).
//
// Levels encode producer/consumer independence along the production order
// (discover → dns → httpprobe → urlintel → crawl → techintel → jsintel →
// secrentel → urllive → priority → detect → report):
//
//   - 0: discover, ingest (corpus roots; ingest replaces discover)
//   - 1: dns (discover hosts only)
//   - 2: httpprobe, urlintel (dns outputs + declared target only: dns
//     Hosts/IPs/CNAMEs for the probe; Target/Domains for urlintel, which
//     reads no Results, Documents, or corpus beyond that — and emits no
//     Evidence, IPs, or CNAME shapes the probe reads)
//   - 3: crawl (probe + archive URLs)
//   - 4: techintel, jsintel (post-crawl corpus; techintel adds nothing
//     and reads TLS/relationship kinds jsintel never emits; jsintel reads
//     URLs only)
//   - 5: secrentel, urllive (jsintel Documents/URLs; neither emits the
//     other's input — secrentel adds nothing and no Documents, urllive
//     adds no Documents)
//   - 6: priority, 7: detect, 8: report (whole-corpus consumers, strictly
//     ordered)
//
// The grouping rule is deliberately structural, not value-based: groups
// NEVER reorder the selection. A same-level pair separated by another
// level runs solo in position; only ADJACENT same-level entries share a
// group. Custom selections therefore degrade to sequential exactly where
// the production adjacency breaks — never to a reordered run.
//
// A Stage that does not implement LeveledStage is a BARRIER: it always
// runs solo, in selection position. Test fakes and external stages stay
// sequential with zero changes; only stages with a verified independence
// argument opt into concurrency. Events still emit started/finished per
// stage in selection order (started for every group member, then
// finished for every member) — the alternation loosens to
// started*finished* within a group, never across groups.
type LeveledStage interface {
	Stage
	// Level is the execution level (see above). Values have no meaning
	// outside equality of adjacent entries.
	Level() int
}

// levelOf resolves one entry's level: the declared level for LeveledStage,
// or -1 (barrier: always solo, in position) otherwise.
func levelOf(s Stage) int {
	if ls, ok := s.(LeveledStage); ok {
		return ls.Level()
	}
	return -1
}

// stageGroup is one concurrently-executed run of consecutive selection
// indices, in selection order. A barrier entry forms a singleton group
// with level -1.
type stageGroup struct {
	level   int
	indices []int
}

// planGroups partitions selection levels into execution groups: maximal
// runs of adjacent equal non-negative levels form multi-member groups;
// every barrier entry (-1) forms a singleton group in position. The plan
// is a pure function of its input: identical levels produce identical
// groups, and output order always follows selection order.
func planGroups(levels []int) []stageGroup {
	var out []stageGroup
	for i := 0; i < len(levels); {
		j := i + 1
		for j < len(levels) && levels[j] >= 0 && levels[j] == levels[i] {
			j++
		}
		out = append(out, stageGroup{level: levels[i], indices: indices(i, j)})
		i = j
	}
	return out
}

// indices returns [start, end).
func indices(start, end int) []int {
	out := make([]int, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, i)
	}
	return out
}

// memberResult is one member's raw execution outcome, finalized by the
// caller in selection order (normalize → record → events → merge).
type memberResult struct {
	res StageResult
	err error
	dur time.Duration
}

// runGroup executes one group's member closures concurrently and returns
// their raw outcomes in slice order. A singleton group runs inline with
// no goroutine. Closures capture their own stage, timeout context, and
// input snapshot; results land on disjoint indices and each closure is
// panic-contained by runStage — the run is race-free by construction.
// Callers finalize outcomes in selection order after runGroup returns,
// so merges stay first-seen deterministic.
func runGroup(ctx context.Context, runs []func(context.Context) memberResult) []memberResult {
	out := make([]memberResult, len(runs))
	if len(runs) == 1 {
		out[0] = runs[0](ctx)
		return out
	}
	var wg sync.WaitGroup
	for i := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = runs[i](ctx)
		}()
	}
	wg.Wait()
	return out
}
