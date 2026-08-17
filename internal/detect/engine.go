package detect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Engine defaults and bounds (fixed constants).
const (
	// defaultEngineConcurrency is the default worker count.
	defaultEngineConcurrency = 8
	// defaultEngineQueueSize is the default bounded queue size.
	defaultEngineQueueSize = 256
	// maxEngineDiagnostics bounds the run-level diagnostics the engine
	// retains.
	maxEngineDiagnostics = 32
	// maxFindingsPerRule bounds one rule's validated output; a rule that
	// exceeds it has violated its contract and fails.
	maxFindingsPerRule = 256
	// maxFindingsPerRun bounds the report's retained findings; the cut is
	// surfaced through Report.FindingsTruncated, never silent.
	maxFindingsPerRun = 4096
)

// storeTimeout bounds a single cache write performed after the run context
// was already cancelled (persisting a completed execution). Mirrors the
// convention shared by the other cache-consuming stages.
const storeTimeout = 5 * time.Second

// shutdownGrace / shutdownForceBudget bound Shutdown's drain, mirroring the
// convention shared by the other runtime consumers.
const (
	shutdownGrace       = 15 * time.Second
	shutdownForceBudget = 30 * time.Second
)

// RuleStatus is the per-rule outcome of one engine run, in the house
// outcome vocabulary: a rule whose detector ran to completion (fresh or
// cache-served) is completed, a rule whose detector failed is failed (its
// structured error is attached), a rule whose work never executed is
// cancelled, and a rule the framework did not attempt is skipped with an
// honest reason (disabled, required asset kind absent, or a dependency that
// did not complete).
type RuleStatus string

const (
	RuleStatusCompleted RuleStatus = "completed"
	RuleStatusFailed    RuleStatus = "failed"
	RuleStatusCancelled RuleStatus = "cancelled"
	RuleStatusSkipped   RuleStatus = "skipped"
)

// Outcome is the aggregate outcome of one engine run, derived from the
// per-rule statuses in fixed priority order: any cancelled rule →
// cancelled; a run whose retained findings were cut at maxFindingsPerRun →
// incomplete (truncated results are never completed, even when every
// attempted rule completed); any failed rule alongside completed ones →
// incomplete (the successes are kept and reported, the run is not
// completed); every attempted rule failed → failed; otherwise completed.
// Skipped rules do not force a non-completed outcome: a rule skipped for an
// absent required asset kind is a normal empty-input observation, and a rule
// skipped for a failed dependency already implies a failed (or cancelled)
// rule in the report. An empty run is completed (zero rules, nothing
// attempted).
type Outcome string

const (
	OutcomeCompleted  Outcome = "completed"
	OutcomeIncomplete Outcome = "incomplete"
	OutcomeFailed     Outcome = "failed"
	OutcomeCancelled  Outcome = "cancelled"
)

// RuleResult is one rule's honest outcome.
type RuleResult struct {
	// RuleID is the canonical rule ID.
	RuleID string `json:"rule_id"`

	// RuleVersion is the rule's declared version.
	RuleVersion string `json:"rule_version"`

	// Status is the per-rule outcome.
	Status RuleStatus `json:"status"`

	// SkipReason explains a skipped rule (bounded; empty otherwise).
	SkipReason string `json:"skip_reason,omitempty"`

	// Cached reports that the result was served from a validated cache hit
	// (zero detector execution).
	Cached bool `json:"cached,omitempty"`

	// Findings counts the rule's validated findings.
	Findings int `json:"findings"`

	// Err carries the structured per-rule error for failed rules.
	Err error `json:"-"`
}

// Report is the deterministic result of one engine run: every rule's
// outcome sorted by rule ID, the merged findings sorted by finding
// identity, the counts, the aggregate outcome, and the bounded rule logs.
// Two identical runs under an identical injected Clock produce identical
// reports (pinned by test) — identical up to the findings cap: above
// maxFindingsPerRun the retained findings are the completion-order prefix,
// which is not deterministic across runs. Execution timings deliberately
// live in Metrics, never here.
type Report struct {
	// Outcome is the aggregate run outcome (see Outcome).
	Outcome Outcome `json:"outcome"`

	// Rules holds one result per registered rule, sorted by rule ID.
	Rules []RuleResult `json:"rules"`

	// Findings holds the run's validated findings, merged by identity and
	// sorted by finding identity.
	Findings []asset.Finding `json:"findings"`

	// FindingsTruncated reports that Findings was cut at
	// maxFindingsPerRun; a truncated run's aggregate outcome is incomplete.
	FindingsTruncated bool `json:"findings_truncated,omitempty"`

	// Completed, Failed, Cancelled, and Skipped count the per-rule
	// statuses.
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Cancelled int `json:"cancelled"`
	Skipped   int `json:"skipped"`

	// CacheHits counts validated cache hits served.
	CacheHits int `json:"cache_hits"`

	// Levels is the number of dependency levels in the executed schedule.
	Levels int `json:"levels"`

	// Logs holds the bounded rule log entries (sorted; empty when a caller
	// provided its own Logger).
	Logs []LogEntry `json:"logs,omitempty"`

	// LogsDropped counts log entries the bounded default logger dropped.
	LogsDropped int `json:"logs_dropped,omitempty"`
}

// EngineConfig configures one engine run. Numeric fields are validated;
// invalid values are rejected with an error rather than silently normalized
// (mirroring the other runtime consumers).
type EngineConfig struct {
	// Registry is the validated rule registry. Required.
	Registry *Registry

	// Concurrency is the exact worker count. Must be > 0; default 8.
	Concurrency int

	// QueueSize is the bounded submit→worker queue. Must be > 0; a full
	// queue blocks the submitter (backpressure, never unbounded memory).
	// Default 256.
	QueueSize int

	// Timeout is the pool-level default per-job deadline. Every job
	// overrides it with its rule's own declared Timeout, so this value only
	// covers jobs without a rule (none today); 0 disables the default.
	Timeout time.Duration

	// Rate is the optional per-job start rate limit (jobs/sec) honored
	// through the pool's central limiter; 0 disables.
	Rate float64

	// Burst is the rate limiter burst size; values below 1 normalize to 1.
	Burst int

	// Clock is the injectable time seam (execution timing and cache record
	// stamps); nil uses the wall clock.
	Clock runtime.Clock

	// Cache is the Phase 3 cache. When nil, cache-before-execute is
	// disabled and every rule executes fresh.
	Cache cache.Cache

	// Logger is the rule logging seam; nil installs the engine's bounded
	// default logger whose entries surface on the Report.
	Logger Logger

	// Config is the bounded configuration map delivered to rules through
	// the Context AND included in every rule result cache key.
	Config map[string]string

	// Emit, when non-nil, is called once per finding (fresh or
	// cache-served). Streaming order across parallel rules is completion
	// order; within one rule it is that rule's sorted finding order. Panics
	// inside Emit are contained and reported as run diagnostics.
	Emit func(context.Context, asset.Finding) error

	// Metrics, when non-nil, accumulates the run's work counters.
	Metrics *Metrics
}

// DefaultEngineConfig returns the documented default engine configuration.
func DefaultEngineConfig(registry *Registry) EngineConfig {
	return EngineConfig{
		Registry:    registry,
		Concurrency: defaultEngineConcurrency,
		QueueSize:   defaultEngineQueueSize,
	}
}

func (c EngineConfig) validateAndDefault() (*EngineConfig, error) {
	if c.Registry == nil {
		return nil, fmt.Errorf("detect: Registry must not be nil")
	}
	if c.Concurrency <= 0 {
		return nil, fmt.Errorf("detect: Concurrency must be > 0")
	}
	if c.QueueSize <= 0 {
		return nil, fmt.Errorf("detect: QueueSize must be > 0")
	}
	if c.Timeout < 0 {
		return nil, fmt.Errorf("detect: Timeout must be >= 0")
	}
	if err := validateConfig(c.Config); err != nil {
		return nil, err
	}
	d := c
	if d.Clock == nil {
		d.Clock = engineClock{}
	}
	cfg := make(map[string]string, len(d.Config))
	for k, v := range d.Config {
		cfg[k] = v
	}
	d.Config = cfg
	return &d, nil
}

// env is the immutable per-run environment shared by the level loop and
// every worker.
type env struct {
	dctx       *Context
	observed   map[asset.Identity]struct{}
	cache      cache.Cache
	clock      runtime.Clock
	metrics    *Metrics
	emit       func(context.Context, asset.Finding) error
	snapshotFP string
	config     map[string]string
	logger     *boundedLogger

	errMu  sync.Mutex
	diags  []error
	excess int
}

func (e *env) recordErr(err error) {
	if err == nil {
		return
	}
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if len(e.diags) < maxEngineDiagnostics {
		e.diags = append(e.diags, err)
	} else {
		e.excess++
	}
}

func (e *env) runError() error {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if len(e.diags) == 0 && e.excess == 0 {
		return nil
	}
	msgs := make([]string, 0, len(e.diags)+1)
	for _, d := range e.diags {
		msgs = append(msgs, d.Error())
	}
	if e.excess > 0 {
		msgs = append(msgs, fmt.Sprintf("... and %d more diagnostics suppressed", e.excess))
	}
	return errors.New("detect: " + joinStrings(msgs, "; "))
}

func joinStrings(msgs []string, sep string) string {
	out := ""
	for i, m := range msgs {
		if i > 0 {
			out += sep
		}
		out += m
	}
	return out
}

// resultAccumulator merges per-rule results keyed by rule ID and collects
// the run's findings under the run-level cap.
type resultAccumulator struct {
	mu        sync.Mutex
	results   map[string]*RuleResult
	findings  []asset.Finding
	truncated bool
}

func newResultAccumulator() *resultAccumulator {
	return &resultAccumulator{results: make(map[string]*RuleResult)}
}

// install stores a result only when no result exists yet (selection-time
// skipped results and cancelled placeholders).
func (a *resultAccumulator) install(r RuleResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.results[r.RuleID]; !ok {
		cp := r
		a.results[r.RuleID] = &cp
	}
}

// merge installs a real result: it replaces placeholders and loses only to
// an existing result that beats it under the deterministic total order.
func (a *resultAccumulator) merge(r RuleResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if prev, ok := a.results[r.RuleID]; ok && betterResult(*prev, r) {
		return
	}
	cp := r
	a.results[r.RuleID] = &cp
}

// get returns a copy of the rule's current result.
func (a *resultAccumulator) get(id string) (RuleResult, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.results[id]
	if !ok {
		return RuleResult{}, false
	}
	return *r, true
}

// addFindings appends validated findings under the run cap.
func (a *resultAccumulator) addFindings(fs []asset.Finding) {
	if len(fs) == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	room := maxFindingsPerRun - len(a.findings)
	if room <= 0 {
		a.truncated = true
		return
	}
	if len(fs) > room {
		fs = fs[:room]
		a.truncated = true
	}
	a.findings = append(a.findings, fs...)
}

func (a *resultAccumulator) snapshot() ([]RuleResult, []asset.Finding, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	results := make([]RuleResult, 0, len(a.results))
	for _, r := range a.results {
		results = append(results, *r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].RuleID < results[j].RuleID })
	findings := make([]asset.Finding, len(a.findings))
	copy(findings, a.findings)
	sortFindings(findings)
	return results, findings, a.truncated
}

// betterResult reports whether a strictly beats b under the deterministic
// merge order: completed > failed > cancelled > skipped — the winner never
// depends on processing order.
func betterResult(a, b RuleResult) bool {
	rank := func(s RuleStatus) int {
		switch s {
		case RuleStatusCompleted:
			return 3
		case RuleStatusFailed:
			return 2
		case RuleStatusCancelled:
			return 1
		}
		return 0
	}
	return rank(a.Status) > rank(b.Status)
}

// Run executes the registry's enabled rules against the snapshot:
// registry validation → snapshot normalization → rule selection (disabled
// and required-kind-absent rules are skipped with honest reasons) →
// dependency-level scheduling → one bounded pool job per rule (cache lookup
// → detector with the rule's own deadline and panic isolation → finding
// validation → cache store) → streaming emit → deterministic report.
//
// The engine is the cache-composing consumer stage per the architecture
// rule: the runtime pool stays cache-independent, and THIS stage performs
// the lookup → execute → store sequencing around pool jobs. Only completed
// executions are cached; partial executions never are.
//
// Cancellation is honest: rules whose work never executed report cancelled,
// the aggregate outcome reports cancelled, and no worker goroutine outlives
// the run (pinned by leak tests). The returned error joins the bounded run
// diagnostics; per-rule errors ride on their results.
func Run(ctx context.Context, cfg EngineConfig, snap Snapshot) (Report, error) {
	c, err := cfg.validateAndDefault()
	if err != nil {
		return Report{}, err
	}
	if ctx == nil {
		return Report{}, fmt.Errorf("detect: context must not be nil")
	}
	if err := c.Registry.Validate(); err != nil {
		return Report{}, err
	}
	corpus, err := normalizeSnapshot(snap)
	if err != nil {
		return Report{}, err
	}
	snapshotFP, err := fingerprintSnapshot(corpus)
	if err != nil {
		return Report{}, err
	}

	logger := newBoundedLogger()
	dctx := corpus.context
	dctx.Config = c.Config
	dctx.Logger = c.Logger
	if dctx.Logger == nil {
		dctx.Logger = logger
	}
	dctx.Clock = c.Clock

	internal := &Metrics{}
	e := &env{
		dctx:       &dctx,
		observed:   corpus.observed,
		cache:      c.Cache,
		clock:      c.Clock,
		metrics:    internal,
		emit:       c.Emit,
		snapshotFP: snapshotFP,
		config:     c.Config,
		logger:     logger,
	}

	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: c.Concurrency,
		QueueSize:   c.QueueSize,
		Timeout:     c.Timeout,
		Rate:        c.Rate,
		Burst:       c.Burst,
		Clock:       c.Clock,
	})
	if err != nil {
		return Report{}, fmt.Errorf("detect: pool: %w", err)
	}

	acc := newResultAccumulator()

	// Selection: every registered rule appears in the report. Disabled
	// rules and rules whose required asset kinds are absent from the
	// corpus are skipped up front with honest reasons.
	allRules := c.Registry.Rules()
	ruleByID := make(map[string]Rule, len(allRules))
	for _, r := range allRules {
		ruleByID[r.ID] = r
	}
	levels, err := scheduleLevels(ruleByID)
	if err != nil {
		return Report{}, err
	}
	for _, r := range allRules {
		if !r.Enabled {
			acc.install(RuleResult{RuleID: r.ID, RuleVersion: r.Version,
				Status: RuleStatusSkipped, SkipReason: "rule disabled"})
			delete(ruleByID, r.ID)
			continue
		}
		if missing := missingRequiredKind(r, corpus.kinds); missing != "" {
			acc.install(RuleResult{RuleID: r.ID, RuleVersion: r.Version,
				Status: RuleStatusSkipped, SkipReason: fmt.Sprintf("required asset kind %q absent from the corpus", missing)})
			delete(ruleByID, r.ID)
		}
	}
	levels = pruneLevels(levels, ruleByID)

levelsLoop:
	for _, level := range levels {
		if ctx.Err() != nil {
			break
		}
		resolved := make(chan struct{}, len(level))
		submitted := 0
		for _, id := range level {
			r := ruleByID[id]
			// Dependency gate: a rule runs only after every dependency
			// completed; anything else cascades an honest skip.
			if bad, status := incompleteDependency(r, acc); bad != "" {
				acc.install(RuleResult{RuleID: r.ID, RuleVersion: r.Version,
					Status:     RuleStatusSkipped,
					SkipReason: fmt.Sprintf("dependency %q did not complete (status %s)", bad, status)})
				continue
			}
			acc.install(RuleResult{RuleID: r.ID, RuleVersion: r.Version, Status: RuleStatusCancelled})
			if _, err := pool.Submit(ctx, runtime.Job{
				Timeout: r.Timeout,
				Func: func(jctx context.Context) (any, error) {
					defer func() { resolved <- struct{}{} }()
					res, fs := processRule(jctx, r, e)
					acc.merge(res)
					acc.addFindings(fs)
					return nil, nil
				},
			}); err != nil {
				if errors.Is(err, runtime.ErrPoolClosed) || ctx.Err() != nil {
					continue // placeholder covers it
				}
				e.recordErr(fmt.Errorf("detect: submit rule %q: %w", r.ID, err))
				continue
			}
			submitted++
		}
		for i := 0; i < submitted; i++ {
			select {
			case <-resolved:
			case <-ctx.Done():
				break levelsLoop
			}
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout(c.Timeout))
	err = pool.Shutdown(shutdownCtx)
	cancel()
	if err != nil {
		e.recordErr(fmt.Errorf("detect: shutdown: %w", err))
	}

	// Every registered rule appears in the report: a rule whose level was
	// never reached (or whose job was dropped by a forced shutdown) keeps
	// its honest cancelled placeholder. install fills only absent entries,
	// so late completions that merged during the drain are never clobbered.
	for _, level := range levels {
		for _, id := range level {
			acc.install(RuleResult{RuleID: id, RuleVersion: ruleByID[id].Version, Status: RuleStatusCancelled})
		}
	}

	if c.Metrics != nil {
		c.Metrics.fold(internal.Snapshot())
	}

	return buildReport(acc, e, len(levels)), e.runError()
}

// shutdownTimeout derives the bounded drain budget.
func shutdownTimeout(poolDefault time.Duration) time.Duration {
	if poolDefault <= 0 {
		return shutdownForceBudget
	}
	return poolDefault + shutdownGrace
}

// missingRequiredKind returns the first required asset kind absent from the
// corpus census, or "".
func missingRequiredKind(r Rule, kinds map[asset.Kind]int) string {
	for _, k := range r.RequiredAssetTypes {
		if kinds[k] == 0 {
			return string(k)
		}
	}
	return ""
}

// incompleteDependency returns the first dependency of r that has not
// completed, with its current status; or ("", "") when every dependency
// completed.
func incompleteDependency(r Rule, acc *resultAccumulator) (string, RuleStatus) {
	for _, dep := range r.Dependencies {
		res, ok := acc.get(dep)
		if !ok || res.Status != RuleStatusCompleted {
			status := RuleStatusCancelled
			if ok {
				status = res.Status
			}
			return dep, status
		}
	}
	return "", ""
}

// pruneLevels drops rules removed at selection (disabled or kind-absent)
// from the computed levels and removes emptied levels, preserving order.
func pruneLevels(levels [][]string, keep map[string]Rule) [][]string {
	out := make([][]string, 0, len(levels))
	for _, level := range levels {
		kept := make([]string, 0, len(level))
		for _, id := range level {
			if _, ok := keep[id]; ok {
				kept = append(kept, id)
			}
		}
		if len(kept) > 0 {
			out = append(out, kept)
		}
	}
	return out
}

// buildReport assembles the deterministic run report and derives the
// aggregate outcome in the fixed priority order: cancelled rules win, and a
// truncated findings list forces incomplete (the per-rule statuses may all
// be completed — the run itself is not, because its result was cut).
func buildReport(acc *resultAccumulator, e *env, levels int) Report {
	results, findings, truncated := acc.snapshot()
	rep := Report{Rules: results, Findings: findings, FindingsTruncated: truncated, Levels: levels}
	for _, r := range results {
		switch r.Status {
		case RuleStatusCompleted:
			rep.Completed++
		case RuleStatusFailed:
			rep.Failed++
		case RuleStatusCancelled:
			rep.Cancelled++
		case RuleStatusSkipped:
			rep.Skipped++
		}
	}
	m := e.metrics.Snapshot()
	rep.CacheHits = m.CacheHits
	logs, dropped := e.logger.snapshot()
	if len(logs) > 0 {
		rep.Logs = logs
	}
	rep.LogsDropped = dropped
	switch {
	case rep.Cancelled > 0:
		rep.Outcome = OutcomeCancelled
	case truncated:
		rep.Outcome = OutcomeIncomplete
	case rep.Failed > 0 && rep.Completed > 0:
		rep.Outcome = OutcomeIncomplete
	case rep.Failed > 0:
		rep.Outcome = OutcomeFailed
	default:
		rep.Outcome = OutcomeCompleted
	}
	return rep
}

// processRule runs one rule through cache-before-execute: a validated
// cache hit serves the stored findings with ZERO detector execution; a miss
// executes the detector under the rule's own deadline with panic isolation,
// validates every finding against the framework's output contract, and
// stores the completed record. A tampered or contradictory record is
// evicted and recomputed in the same run, never served.
func processRule(ctx context.Context, r Rule, e *env) (RuleResult, []asset.Finding) {
	if err := ctx.Err(); err != nil {
		return RuleResult{RuleID: r.ID, RuleVersion: r.Version, Status: RuleStatusCancelled}, nil
	}

	if e.cache != nil {
		key, err := ruleKey(r, e.snapshotFP, e.config)
		if err != nil {
			e.recordErr(fmt.Errorf("detect: cache key rule %q: %w", r.ID, err))
		} else if served, hit := lookupFindings(ctx, key, r, e); hit {
			res := RuleResult{RuleID: r.ID, RuleVersion: r.Version,
				Status: RuleStatusCompleted, Cached: true, Findings: len(served)}
			e.emitFindings(ctx, r, served)
			return res, served
		}
	}
	return executeRule(ctx, r, e)
}

// lookupFindings performs cache-before-execute for one rule. It returns the
// served findings and whether a validated hit occurred — a completed hit
// with zero findings is still a hit, so the flag (never the slice's
// nilness) decides. Any non-hit outcome falls through to a fresh execution;
// a completed hit is decoded with strict re-validation and a rejected
// record is deleted (evicted) and recomputed.
func lookupFindings(ctx context.Context, key cache.Key, r Rule, e *env) ([]asset.Finding, bool) {
	out := e.cache.Get(ctx, key)
	switch out.State {
	case cache.StateHit:
		findings, err := decodeStoredFindings(*out.Record, r, e.observed)
		if err != nil {
			e.recordErr(fmt.Errorf("detect: rule %q cache hit rejected: %w", r.ID, err))
			if derr := e.cache.Delete(ctx, key); derr != nil {
				e.recordErr(fmt.Errorf("detect: rule %q cache delete: %w", r.ID, derr))
			}
			e.metrics.recordCache(r.ID, false)
			return nil, false
		}
		e.metrics.recordCache(r.ID, true)
		return findings, true
	case cache.StateCorrupt, cache.StateSchemaIncompatible, cache.StateIncomplete:
		if out.Err != nil {
			e.recordErr(fmt.Errorf("detect: rule %q cache get: %w", r.ID, out.Err))
		}
	case cache.StateError:
		if out.Err != nil && ctx.Err() == nil {
			e.recordErr(fmt.Errorf("detect: rule %q cache get: %w", r.ID, out.Err))
		}
	case cache.StateMiss, cache.StateExpired:
	}
	e.metrics.recordCache(r.ID, false)
	return nil, false
}

// executeRule runs the detector under the rule's own deadline, validates
// and merges its findings, streams them through the emit hook, and stores
// the completed cache record.
func executeRule(ctx context.Context, r Rule, e *env) (RuleResult, []asset.Finding) {
	rctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	findings, d, err := e.runDetector(rctx, r)
	if err != nil {
		switch {
		case errors.Is(rctx.Err(), context.DeadlineExceeded):
			e.metrics.recordFailure(r.ID, "timeout")
			return failedResult(r, fmt.Errorf("rule %q timed out after %s: %w", r.ID, r.Timeout, err)), nil
		case rctx.Err() != nil || ctx.Err() != nil:
			return RuleResult{RuleID: r.ID, RuleVersion: r.Version, Status: RuleStatusCancelled}, nil
		case isPanicError(err):
			e.metrics.recordFailure(r.ID, "panic")
			return failedResult(r, err), nil
		default:
			e.metrics.recordFailure(r.ID, "error")
			return failedResult(r, fmt.Errorf("rule %q detector: %w", r.ID, err)), nil
		}
	}
	if len(findings) > maxFindingsPerRule {
		e.metrics.recordFailure(r.ID, "error")
		return failedResult(r, fmt.Errorf("rule %q returned %d findings over bound %d",
			r.ID, len(findings), maxFindingsPerRule)), nil
	}
	for i, f := range findings {
		if err := validateFinding(f, r, e.observed); err != nil {
			e.metrics.recordFailure(r.ID, "error")
			return failedResult(r, fmt.Errorf("rule %q finding %d violates the output contract: %w", r.ID, i, err)), nil
		}
	}
	merged, err := mergeFindings(findings)
	if err != nil {
		e.metrics.recordFailure(r.ID, "error")
		return failedResult(r, fmt.Errorf("rule %q: %w", r.ID, err)), nil
	}
	sortFindings(merged)
	e.metrics.recordExecution(r.ID, d, len(merged))

	if e.cache != nil {
		storeFindings(ctx, r, merged, e)
	}
	e.emitFindings(ctx, r, merged)
	return RuleResult{RuleID: r.ID, RuleVersion: r.Version,
		Status: RuleStatusCompleted, Findings: len(merged)}, merged
}

// runDetector invokes the rule's detector with panic isolation and returns
// the measured duration. A panicking detector never takes down the worker,
// the run, or sibling rules: the panic is recovered and surfaced as the
// rule's structured error.
func (e *env) runDetector(ctx context.Context, r Rule) (findings []asset.Finding, d time.Duration, err error) {
	started := e.clock.Now()
	defer func() {
		d = e.clock.Now().Sub(started)
		if p := recover(); p != nil {
			findings = nil
			err = fmt.Errorf("%w: rule %q: %v", errPanicked, r.ID, p)
		}
	}()
	findings, err = r.Detector(ctx, e.dctx)
	return findings, d, err
}

// isPanicError reports whether err was produced by runDetector's panic
// recovery (the sentinel prefix; panic values themselves are opaque).
func isPanicError(err error) bool {
	return errors.Is(err, errPanicked)
}

// errPanicked wraps every panic-recovery error so isPanicError is exact.
var errPanicked = errors.New("detector panicked")

// storeFindings persists one rule's completed, validated findings. When the
// run context was already cancelled, the write runs under a fresh short
// budget (a completed result deserves persistence even during teardown).
func storeFindings(ctx context.Context, r Rule, findings []asset.Finding, e *env) {
	storeCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		storeCtx, cancel = context.WithTimeout(context.Background(), storeTimeout)
		defer cancel()
	}
	rec, err := encodeStoredFindings(r.ID, findings, e.clock.Now())
	if err != nil {
		e.recordErr(fmt.Errorf("detect: rule %q encode: %w", r.ID, err))
		return
	}
	key, err := ruleKey(r, e.snapshotFP, e.config)
	if err != nil {
		e.recordErr(fmt.Errorf("detect: cache key rule %q: %w", r.ID, err))
		return
	}
	if err := e.cache.Put(storeCtx, key, rec); err != nil {
		e.recordErr(fmt.Errorf("detect: rule %q cache put: %w", r.ID, err))
	}
}

// emitFindings streams findings through the optional emit hook in the
// rule's deterministic order; hook errors and panics are contained as run
// diagnostics and never lose the findings themselves.
func (e *env) emitFindings(ctx context.Context, r Rule, findings []asset.Finding) {
	if e.emit == nil || len(findings) == 0 {
		return
	}
	for _, f := range findings {
		if err := callEmit(ctx, e.emit, f); err != nil {
			e.recordErr(fmt.Errorf("detect: rule %q emit: %w", r.ID, err))
		}
	}
}

// callEmit runs the emit hook, containing panics.
func callEmit(ctx context.Context, fn func(context.Context, asset.Finding) error, f asset.Finding) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("emit hook panicked: %v", r)
		}
	}()
	return fn(ctx, f)
}

func failedResult(r Rule, err error) RuleResult {
	return RuleResult{RuleID: r.ID, RuleVersion: r.Version, Status: RuleStatusFailed, Err: err}
}
