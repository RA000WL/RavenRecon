package tui

import "time"

// maxStageRecords bounds the retained stage list (finished entries kept in
// pipeline order). The real runner executes at most ten stages per run; the
// bound is a hostile-stream guard: entries beyond it are dropped from the
// list while the counters (started/completed) stay exact.
const maxStageRecords = 64

// stageRecord is one concluded stage entry, projected from a
// stage_finished event. Every field mirrors event.StageFinished, which
// mirrors the pipeline's StageRecord.
type stageRecord struct {
	name           string
	outcome        string
	truncated      bool
	itemsProcessed int
	itemsFailed    int
	duration       time.Duration
	err            string
}

// stageState is the live stage feed: the current stage (name + start
// time), exact started/completed counters, and the bounded ordered list of
// concluded entries. It is projected ONLY from KindStageStarted /
// KindStageFinished events; a stream that carries neither leaves it empty,
// and the renderer shows no stage feed at all rather than fabricating one.
//
// The stage total is deliberately not tracked: the event stream never
// declares how many stages a run will execute, so progress renders the
// completed count over an honest unknown total — a denominator is never
// fabricated.
type stageState struct {
	// current is the most recently started stage, startedAt its start
	// time. A stage_finished event does NOT clear them: the runner emits
	// started→finished pairs synchronously in stage order, and keeping
	// the last started name gives the final frame (rendered after the
	// stream ends, typically right after the last finished) a meaningful
	// phase instead of falling back to "—". The next started replaces it.
	current   string
	startedAt time.Time

	// startedCount counts stage_started events consumed, completedCount
	// counts stage_finished events consumed (exact counters,
	// hostile-stream safe: they only ever increment).
	startedCount   int
	completedCount int

	// records is the ordered list of concluded entries, bounded to the
	// first maxStageRecords (the run's beginning, in pipeline order);
	// overflow is dropped from the list only, never from the counters.
	records []stageRecord
}

// started records a stage_started: the named stage becomes current at at.
func (st *stageState) started(name string, at time.Time) {
	st.current = name
	st.startedAt = at
	st.startedCount++
}

// finished records a stage_finished entry: the counter advances and the
// entry joins the ordered list unless the list is at its bound.
func (st *stageState) finished(name, outcome string, truncated bool, itemsProcessed, itemsFailed int, duration time.Duration, errMsg string) {
	st.completedCount++
	if len(st.records) >= maxStageRecords {
		return
	}
	st.records = append(st.records, stageRecord{
		name:           name,
		outcome:        outcome,
		truncated:      truncated,
		itemsProcessed: itemsProcessed,
		itemsFailed:    itemsFailed,
		duration:       duration,
		err:            errMsg,
	})
}
