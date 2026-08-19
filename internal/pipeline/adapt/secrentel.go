package adapt

import (
	"context"
	"errors"
	"fmt"

	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/secrentel"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// secrentelTruncatedFlag and secrentelOverflowFlag are the sticky flags
// this adapter records when the engine report carries its truncation
// signals (secrentel.Report.Truncated / Report.Overflow). They are
// preserved end-to-end (result → RunReport → report), never swallowed
// (AGENTS §0.6 names secrentel's Truncated/Overflow signals explicitly —
// the §0.6 carve-out list). The names follow the package convention
// (adapt/doc.go): a sticky flag is <engine>_<what>_truncated — never a
// bare generic like "truncated".
const (
	secretIntelTruncatedFlag = "secrentel_truncated"
	secretIntelOverflowFlag  = "secrentel_overflow"
)

// secretIntelStage adapts internal/secrentel (secrentel.Ingest) into a
// pipeline.Stage.
//
// Construction is explicit — there is no registry: NewSecretIntelStage
// returns the stage and callers pass it to pipeline.Run as part of the
// stages slice.
type secretIntelStage struct {
	// db is the engine's pattern-database seam (secrentel.Config.DB). nil
	// means the engine's production default (patterns.Load, the
	// compile-once database), exactly as secrentel.Config.DB documents.
	// The adapter never substitutes a database of its own.
	db *patterns.DB
}

var _ pipeline.Stage = (*secretIntelStage)(nil)

// NewSecretIntelStage returns the secrentel pipeline stage wrapping
// internal/secrentel.
//
// db is the constructor test-seam hook (adapt/doc.go): pass nil for
// production (the engine loads the compiled-in pattern database via
// patterns.Load — the compile-once contract, mirroring the engine's own
// nil-DB semantics on secrentel.Config.DB), or a hermetic synthetic
// database compiled with patterns.CompileForTest in tests. It is never
// read from StageParams — params are operator configuration, not test
// plumbing.
func NewSecretIntelStage(db *patterns.DB) pipeline.Stage {
	return &secretIntelStage{db: db}
}

// Name implements pipeline.Stage.
func (s *secretIntelStage) Name() pipeline.StageName { return pipeline.StageSecretIntel }

// Run implements pipeline.Stage.
//
// Engine config is derived from StageInput only:
//
//	Concurrency ← in.Bounds.MaxConcurrency
//	QueueSize   ← in.Bounds.QueueSize
//	Timeout     ← in.Bounds.Timeout      (0 = engine: no per-job deadline)
//	Rate        ← in.Bounds.Rate         (<= 0 = engine: pacing disabled)
//	Burst       ← in.Bounds.Burst        (< 1 = engine: normalized to 1)
//	Clock       ← in.Clock               (nil = engine: wall clock)
//	Cache       ← in.Cache               (nil = engine: caching disabled)
//	DB          ← the constructor seam   (nil = engine: patterns.Load)
//
// The engine's per-document analysis caps (MaxCandidatesPerDocument,
// MaxEvidencePerCandidate) are deliberately NOT configurable here: they
// are engine defaults (64 / 8 — secrentel.DefaultConfig), and this
// milestone documents them as fixed for the pipeline. The stage leaves
// them at 0 so the engine's own validateAndDefault fills the documented
// defaults; there is no StageParams surface for them.
//
// Zero bounds are passed through verbatim and mean "engine default/disabled"
// per the ENGINE's documented semantics (adapt/doc.go), NOT pre-resolved
// pipeline defaults: the pipeline runner has already resolved 0 to the
// pipeline defaults (Concurrency/QueueSize/Burst are positive by then),
// while a direct caller may deliberately pass Timeout 0 / Rate 0 to
// disable the engine's per-job deadline and pacing. The engine requires a
// positive Concurrency and QueueSize; a direct caller passing 0 for either
// gets the engine's own config-validation error (mapped to Outcome failed
// below).
//
// StageParams: none. in.Config is never read — the stage has no documented
// parameter keys, and unknown keys are ignored by construction.
//
// Documents: the stage consumes in.Documents — the pipeline's
// pipeline-internal document channel — as its document source. Every
// pipeline document becomes exactly one secrentel.Document: Kind is always
// KindJS (the document channel's contract: bounded retained script bodies
// from the jsintel stage), Content and URL pass through, SourceAsset is the
// pipeline document's canonical Identity (the jsintel-stage asset identity
// — the engine then produces candidates whose Source is that identity, so
// the same value found by jsintel and secrentel deduplicates to ONE Phase 2
// candidate), and Source stays "" (the engine's default provenance name
// "secrentel" — the dedup key against jsintel candidates is SourceAsset,
// not the source name, per secrentel.Document.SourceAsset). ObservedAt
// stays zero: the engine defaults it to the run clock (in.Clock), which
// keeps the run deterministic. Documents with Truncated = true or Content
// == nil are SKIPPED — nothing honest to scan: a truncated document's
// retained prefix would be scanned as if complete, and a nil-content
// document is an empty scan; both would fabricate a completed scan out of
// data the channel explicitly says is incomplete (never silently
// completed). Skipped documents are not counted (they never reach the
// engine), mirroring the input-filtering conventions of the sibling
// adapters.
//
// Scope: NO additional filtering — the stage's inputs are the run's own
// documents, so its outputs are in-scope by construction. This contrasts
// with the corpus-filtering conventions of the other adapters (they
// consume corpus entries that earlier stages may have produced outside the
// declared scope — CNAME targets, tool line streams — and must gate them);
// the document channel is produced by the pipeline's own jsintel stage
// from in-scope assets, and the engine's cache key derives from the
// document's scan identity (content digest + source asset + ...), so the
// engine cannot produce an out-of-domain asset through this adapter. The
// stage consequently produces NO corpus additions — secrets, evidence, and
// relationships are results, propagated by the results channel. Additions
// stay empty by construction, and Documents stay empty too (the stage
// consumes the document channel, never produces it).
//
// Empty-input short-circuit: no scannable documents (empty input, or every
// document skipped by the truncation rule) + canonical target: the stage
// short-circuits with a vacuous completed result — the engine is never
// invoked (zero cache reads) and the counters are honest zeros. secrentel.
// Ingest treats an empty document source as VALID input (it returns an
// empty report without processing anything), so short-circuiting is
// observationally identical to calling the engine on every runner-reachable
// path (the engine's config validation and pattern-DB load cannot fail
// through the runner) — but only when the target is canonical: with a
// non-canonical target the stage falls through to the engine with an empty
// source and lets the engine produce its own honest vacuous completed (the
// canonicality gate kept for shape-consistency with the sibling adapters,
// so a future engine-side target validation would surface honestly instead
// of being masked by a completed short-circuit; the re-check goes through
// asset.NewDomain — the single normalization point).
//
// Outcome mapping (engine document statuses → pipeline outcome; the engine
// folds its per-document statuses into Report.Documents counts):
//
//	Report.Documents.Completed  -> a completed entry
//	Report.Documents.Incomplete -> an honest truncated scan: the scanned
//	                               prefix's candidates are reported, but the
//	                               document exceeded the engine's ingest
//	                               cap — the retained set is incomplete by
//	                               definition (partial)
//	Report.Documents.Cancelled  -> a cancelled entry (run teardown, or the
//	                               engine's per-job deadline fired)
//	Report.Documents.Failed     -> a failed entry (no usable document)
//	Report.Documents.Malformed  -> a rejected document: counted in
//	                               ItemsFailed, never folded into the outcome
//
// The stage fold over those counts is deterministic, in the unified adapter
// precedence (adapt/doc.go "Unified outcome mapping", MEDIUM-1 review
// unification): cancelled > failed&&!completed > completed > partial —
//
//  1. any cancelled entry                                -> cancelled
//  2. any failed entry and no completed entry            -> failed
//  3. no failed, cancelled, or incomplete entry          -> completed
//     (vacuously true for an empty report)
//  4. otherwise (incomplete documents, or completed
//     mixed with failed/incomplete entries)              -> partial
//
// Cancellation note: per-document cancellations with a still-live stage
// context mean the ENGINE's own teardown cut the entries (for example the
// engine's per-job deadline fired while the stage deadline is disabled), so
// the stage reports cancelled with a nil Err — the outcome, not the error
// field, carries cancellation. When the stage context fired instead, the
// context error is attached (see below).
//
// Engine error paths. Errors are wrapped with context ("stage %s: %w") and
// returned; a non-nil error return additionally forces Outcome failed or
// cancelled (never anything else), so the runner's normalizeResult contract
// is honored. When the engine returns an error while the stage context is
// also firing, cancellation is the dominant signal and the engine's
// shutdown detail is errors.Join-ed so nothing is lost. A clean engine
// drain followed by a fired stage context reports cancelled with the
// context error. A pre-cancelled context is handled honestly on every path
// (the engine itself returns an empty report with a nil error for a
// pre-cancelled context — the reader stops before submitting anything — so
// the stage's own context checks drive the cancelled outcome).
//
// Counters: ItemsProcessed is the engine report's Completed + Incomplete +
// Cancelled + Failed document count (every document the engine processed);
// ItemsFailed is Failed + Malformed (everything that could not be
// processed — engine-failed documents and rejected ones), mirroring the
// techintel adapter's counter convention exactly.
//
// Truncation (Report.Truncated / Report.Overflow): the flags map to
// Truncated=true and StickyFlags[secrentel_truncated] /
// StickyFlags[secrentel_overflow], never swallowed. The completed+flag
// carve-out (AGENTS §0.6) is legal because the secrentel engine's
// truncation chain is verified intact end-to-end: the engine writes both
// flags into its cache records (internal/secrentel/record.go encodeStoredScan
// — st.Truncated = entry.Truncated, st.Overflow = entry.Overflow), replays
// them from cache on hits (entryFromStored rebuilds Truncated/Overflow from
// the stored scan — a truncated document is never stored completed and a
// completed record claiming truncation is rejected, so only Overflow can
// replay through a completed hit; truncated documents honestly re-scan),
// merges them stickily (mergeEntries ORs them), and re-exposes them in the
// Report (buildReport ORs the entries' flags). Through this adapter
// Report.Truncated is unreachable by construction — pipeline documents are
// bounded to pipeline.MaxDocumentBytes (2 MiB, the engine's own ingest
// cap), truncated pipeline documents are skipped above, and the runner's
// merge re-binds hostile over-cap content — so the only signal that can
// genuinely fire is Overflow (a document with >= 64 candidates, the
// engine's fixed per-document cap); the Truncated mapping is kept anyway so
// no engine signal is ever swallowed. A flag-carrying report with an
// otherwise-clean fold stays completed: the flags, never the outcome alone,
// mark the retained set incomplete.
//
// Queue: the engine's offline verification queue (Report.Queue /
// Report.QueueOverflow) is never executed and never propagated — the
// pipeline's secrentel stage scans and reports candidates only; the queue
// is offline bookkeeping (nothing is ever verified online), and surfacing
// the queue count is T6 CLI work. Nothing in this stage ever contacts a
// service.
//
// Events: the stage emits NO events itself — the runner owns stage events
// (T3a: exactly one stage_started/stage_finished per entry). The engine's
// optional Config.Emit hook is deliberately ignored: the Report already
// carries every per-document entry, and wiring Emit would double-emit
// observations the stage is not entitled to produce (the bus is
// observer-only and the runner's stage events are the pipeline's one
// emission point).
func (s *secretIntelStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}
	// Document filtering (see Run): truncated and nil-content documents are
	// skipped — nothing honest to scan. No scope filtering: the document
	// channel is the pipeline's own, in-scope by construction.
	docs := filterDocuments(in.Documents)

	// Empty filtered input short-circuit. secrentel.Ingest treats an empty
	// document source as VALID input (it returns an empty report without
	// processing anything), so short-circuiting here is observationally
	// identical to calling the engine — but only when the engine would
	// actually accept the call: the secrentel engine never validates the
	// target (it consumes documents only), so a non-canonical target with
	// no scannable documents yields an empty report (vacuously completed),
	// never a fabricated error. The canonicality gate is kept for
	// shape-consistency with the sibling adapters and so that a future
	// engine-side target validation would surface honestly instead of being
	// masked by a completed short-circuit. The re-check goes through
	// asset.NewDomain — the single normalization point, exactly as the
	// sibling adapters do.
	if len(docs) == 0 {
		if !targetCanonical(in.Target) {
			return s.runIngest(ctx, in, nil)
		}
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, wrapped
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	return s.runIngest(ctx, in, docs)
}

// runIngest derives the engine config from the StageInput, calls
// secrentel.Ingest, and maps the engine's report and error onto the
// pipeline's StageResult shape. It is shared by the normal path and the
// non-canonical-target fall-through so both honor the identical error and
// cancellation mapping.
func (s *secretIntelStage) runIngest(ctx context.Context, in pipeline.StageInput, docs []pipeline.Document) (pipeline.StageResult, error) {
	cfg := secrentel.Config{
		// Bounds pass-through: 0 = engine default/disabled per the engine's
		// own documented semantics, never pre-resolved pipeline defaults
		// (adapt/doc.go). Concurrency/QueueSize are required positive by the
		// engine (the runner always resolves them to the defaults, so
		// through the runner they are never 0); Timeout 0 disables the
		// per-job deadline; Rate <= 0 disables pacing; Burst < 1 means 1.
		Concurrency: in.Bounds.MaxConcurrency,
		QueueSize:   in.Bounds.QueueSize,
		Timeout:     in.Bounds.Timeout,
		Rate:        in.Bounds.Rate,
		Burst:       in.Bounds.Burst,
		// Cache and Clock pass through: nil cache = caching disabled; nil
		// clock = the engine's wall clock. The runner guarantees a non-nil
		// clock; the engine tolerates nil either way.
		Clock: in.Clock,
		Cache: in.Cache,
		// Constructor test seam: nil = the engine's production database
		// (patterns.Load). The per-document analysis caps
		// (MaxCandidatesPerDocument / MaxEvidencePerCandidate) stay at 0 =
		// the engine's documented defaults (64 / 8) — fixed for this
		// milestone, deliberately NOT configurable (see Run).
		DB: s.db,
	}

	src := secrentel.SliceDocumentSource(toSecretDocuments(docs))
	rep, engineErr := secrentel.Ingest(ctx, cfg, &src)

	// Engine error while the stage context is also firing: cancellation is
	// the dominant, more honest signal (pipeline contract); the engine's
	// shutdown detail is joined so nothing is lost. The report's honest
	// per-document statuses are still reflected in the mapped result.
	if engineErr != nil && ctx.Err() != nil {
		joined := fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), engineErr))
		return s.buildSecretResult(rep, pipeline.OutcomeCancelled, joined), nil
	}
	if engineErr != nil {
		// Any other engine error (invalid config, pool failure, shutdown
		// failure): failed, wrapped with context. This is the only path that
		// can surface a failed outcome through this adapter — the engine's
		// cache key cannot fail on a canonical document
		// (internal/secrentel/record.go), so per-document StatusFailed is
		// effectively unreachable; the failed/partial folds are still pinned
		// by the foldSecretIntelOutcome table test below.
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), engineErr)
		return s.buildSecretResult(rep, pipeline.OutcomeFailed, wrapped), wrapped
	}
	if ctx.Err() != nil {
		// The engine drained cleanly but the run was cancelled in flight:
		// the report's per-document statuses are honest cancelled entries
		// and the stage outcome is cancelled, with the context error
		// attached.
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
		return s.buildSecretResult(rep, pipeline.OutcomeCancelled, wrapped), nil
	}

	// Per-document outcome fold over the engine's report counts (mapping
	// table documented on Run).
	res := s.buildSecretResult(rep, foldSecretIntelOutcome(rep.Documents), nil)
	if res.Outcome == pipeline.OutcomeCancelled && ctx.Err() != nil {
		// Per-document cancellations with a still-live stage context report
		// cancelled with a nil Err (documented on Run). If the stage context
		// fired in the window between the check above and the fold, attach it
		// so the cancellation is unambiguous.
		res.Err = fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())
	}
	return res, nil
}

// buildSecretResult maps one engine report onto the pipeline's StageResult
// shape: the honest counters, the results-channel additions (the engine's
// canonical assets, copied — never rebuilt — per the one-normalization-point
// rule), the truncation/overflow flags (never swallowed), and empty
// Additions/Documents (the secrentel stage consumes the document channel,
// never produces corpus or document entries).
func (s *secretIntelStage) buildSecretResult(rep secrentel.Report, outcome pipeline.Outcome, err error) pipeline.StageResult {
	res := pipeline.StageResult{
		Outcome:        outcome,
		Err:            err,
		ItemsProcessed: secretIntelProcessed(rep),
		ItemsFailed:    secretIntelFailed(rep),
	}
	// Results: the engine's report already carries the canonical Phase 2
	// assets (produced through the asset builders at scan time). The adapter
	// copies them into the results channel, never rebuilds them — the
	// one-normalization-point rule (AGENTS §0.5). Scope needs no additional
	// filtering (see Run): the stage's inputs are the run's own documents.
	for _, sr := range rep.Secrets {
		res.Results.Secrets = append(res.Results.Secrets, sr.Candidate)
	}
	res.Results.Evidence = rep.Evidence
	res.Results.Relationships = rep.Relationships
	// Truncation/overflow: every engine signal maps to Truncated + its
	// documented sticky flag, never swallowed (AGENTS §0.6; the
	// completed+flag carve-out is verified intact — see Run).
	if rep.Truncated || rep.Overflow {
		res.Truncated = true
		res.StickyFlags = map[string]bool{}
		if rep.Truncated {
			res.StickyFlags[secretIntelTruncatedFlag] = true
		}
		if rep.Overflow {
			res.StickyFlags[secretIntelOverflowFlag] = true
		}
	}
	return res
}

// foldSecretIntelOutcome reduces the engine report's document counts to one
// stage outcome (mapping table documented on secretIntelStage.Run).
// Malformed is a diagnostic, never folded (mirrors the techintel adapter's
// malformed observations). The default row is unreachable by construction —
// DocumentStats is a fixed struct — and folds to failed rather than ever
// masking an unrecognized state as completed (the sibling adapters'
// unknown→failed convention).
func foldSecretIntelOutcome(stats secrentel.DocumentStats) pipeline.Outcome {
	switch {
	case stats.Cancelled > 0:
		return pipeline.OutcomeCancelled
	case stats.Failed > 0 && stats.Completed == 0:
		return pipeline.OutcomeFailed
	case stats.Incomplete > 0 && stats.Completed == 0:
		return pipeline.OutcomePartial
	case stats.Failed == 0 && stats.Cancelled == 0 && stats.Incomplete == 0:
		// Every entry completed (vacuously true for an empty report).
		return pipeline.OutcomeCompleted
	case stats.Completed > 0:
		// Completed mixed with failed or incomplete entries.
		return pipeline.OutcomePartial
	default:
		// Unreachable (fixed struct); never mask as completed.
		return pipeline.OutcomeFailed
	}
}

// secretIntelProcessed returns the engine report's honest processed count:
// every document the engine processed, including incomplete, cancelled, and
// failed ones.
func secretIntelProcessed(rep secrentel.Report) int {
	s := rep.Documents
	return s.Completed + s.Incomplete + s.Cancelled + s.Failed
}

// secretIntelFailed returns the engine report's honest "could not be
// processed" count: engine-failed documents plus rejected (malformed)
// documents (the engine's document-level error path).
func secretIntelFailed(rep secrentel.Report) int {
	return rep.Documents.Failed + rep.Documents.Malformed
}

// filterDocuments drops the documents the stage cannot honestly scan:
// Truncated = true (the retained content is a truncated prefix — scanning
// it as if complete would fabricate a completed scan out of an incomplete
// set) and Content == nil (nothing to scan). The returned slice is fresh
// and never aliases the input; the input slice is never mutated (read-only
// StageInput contract).
func filterDocuments(docs []pipeline.Document) []pipeline.Document {
	out := make([]pipeline.Document, 0, len(docs))
	for _, d := range docs {
		if d.Truncated || d.Content == nil {
			continue
		}
		out = append(out, d)
	}
	return out
}

// toSecretDocuments maps the scannable pipeline documents onto the
// engine's document seam: Kind is always KindJS (the document channel's
// contract), Content and URL pass through, SourceAsset is the pipeline
// document's canonical Identity (the engine's jsintel dedup contract — see
// Run), and Source stays "" so the engine uses its documented default
// provenance name "secrentel". ObservedAt stays zero so the engine stamps
// the run clock (in.Clock) — deterministic through the injected clock.
func toSecretDocuments(docs []pipeline.Document) []secrentel.Document {
	out := make([]secrentel.Document, 0, len(docs))
	for _, d := range docs {
		out = append(out, secrentel.Document{
			Kind:        secrentel.KindJS,
			Content:     d.Content,
			URL:         d.URL,
			SourceAsset: &d.Identity,
			Source:      "",
		})
	}
	return out
}
