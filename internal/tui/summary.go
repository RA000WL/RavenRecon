package tui

import "time"

// Summary is the final run summary, derived ONLY from the consumed event
// stream (counters updated by State.Apply). Fields that the stream never
// established are honestly zero/empty; the renderer shows "—" for them.
type Summary struct {
	// StartedAt / EndedAt bound the run (ScanStarted / ScanStopped).
	StartedAt time.Time
	EndedAt   time.Time
	// Duration is EndedAt-StartedAt when both bounds exist; the renderer
	// shows "—" otherwise.
	Duration time.Duration
	// Outcome is the ScanStopped state ("completed"/"cancelled"), "" when
	// the run never concluded.
	Outcome string

	// Assets is every AssetDiscovered event; Hosts/URLs/Endpoints/
	// Technologies/Secrets/SourceMaps are the per-kind slices of it
	// (asset.Kind projections).
	Assets, Hosts, URLs, Endpoints, Technologies, Secrets, SourceMaps int
	// Findings counts FindingCreated events; Rules sums RuleExecuted
	// executions; Relationships counts RelationshipCreated events;
	// Requests counts RequestObserved events.
	Findings, Rules, Relationships, Requests int
	// CacheHits / CacheMisses count CacheAccess events by Hit.
	CacheHits, CacheMisses int
	// Warnings / Errors count KindWarning / KindError events.
	Warnings, Errors int

	// Target is RunMetadata.Target; OutputDir is RunMetadata.OutputDir
	// ("" = never declared; the renderer shows "—").
	Target    string
	OutputDir string

	// Stages is the ordered list of concluded stage entries (bounded:
	// the first maxStageRecords are retained; overflow is dropped from
	// the list while StagesCompleted stays exact). It is derived from
	// the pipeline's stage events and is empty for streams that carry
	// none.
	Stages []StageSummary
	// StagesStarted / StagesCompleted count stage_started /
	// stage_finished events consumed; CurrentStage names the stage in
	// flight (the last started one while started > completed), "" when
	// none is in flight.
	StagesStarted   int
	StagesCompleted int
	CurrentStage    string
}

// StageSummary is one concluded pipeline stage entry projected from a
// stage_finished event (fields mirror event.StageFinished, which mirrors
// pipeline.StageRecord).
type StageSummary struct {
	Name           string
	Outcome        string
	Truncated      bool
	ItemsProcessed int
	ItemsFailed    int
	Duration       time.Duration
	Err            string
}

// Summary computes the final run summary from the state.
func (s *State) Summary() Summary {
	sum := Summary{
		StartedAt:       s.progress.startedAt,
		EndedAt:         s.progress.endedAt,
		Outcome:         s.progress.outcome,
		Assets:          s.counts.assets,
		Hosts:           s.counts.byKind["host"],
		URLs:            s.counts.byKind["url"],
		Endpoints:       s.counts.byKind["endpoint"],
		Technologies:    s.counts.byKind["technology"],
		Secrets:         s.counts.byKind["secret_candidate"],
		SourceMaps:      s.counts.byKind["source_map"],
		Findings:        s.counts.findings,
		Rules:           s.counts.rules,
		Relationships:   s.counts.relationships,
		Requests:        s.counts.requests,
		CacheHits:       s.counts.cacheHits,
		CacheMisses:     s.counts.cacheMisses,
		Warnings:        s.counts.warnings,
		Errors:          s.counts.errors,
		Target:          s.progress.target,
		OutputDir:       s.progress.outputDir,
		StagesStarted:   s.stages.startedCount,
		StagesCompleted: s.stages.completedCount,
	}
	if s.stages.startedCount > s.stages.completedCount {
		sum.CurrentStage = s.stages.current
	}
	for _, r := range s.stages.records {
		sum.Stages = append(sum.Stages, StageSummary{
			Name:           r.name,
			Outcome:        r.outcome,
			Truncated:      r.truncated,
			ItemsProcessed: r.itemsProcessed,
			ItemsFailed:    r.itemsFailed,
			Duration:       r.duration,
			Err:            r.err,
		})
	}
	if !sum.StartedAt.IsZero() && !sum.EndedAt.IsZero() {
		sum.Duration = sum.EndedAt.Sub(sum.StartedAt)
		if sum.Duration < 0 {
			sum.Duration = 0
		}
	}
	return sum
}
