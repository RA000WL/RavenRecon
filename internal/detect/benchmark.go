package detect

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// maxBenchmarkIterations bounds one BenchmarkDetector run (fixed constant):
// a benchmark is caller-driven measurement, not an unbounded loop.
const maxBenchmarkIterations = 1_000_000

// BenchResult is the measurement of one detector benchmark: per-iteration
// durations with their deterministic summary statistics, the validated
// finding totals, and the failure counts. Durations of zero mean the
// injected clock did not advance (deterministic tests).
type BenchResult struct {
	// RuleID is the benchmarked rule's ID.
	RuleID string

	// Iterations is the number of detector executions performed.
	Iterations int

	// Errors and Panics count failed iterations (panics isolated exactly
	// as in the engine).
	Errors int
	Panics int

	// Findings is the total validated finding count across iterations.
	Findings int

	// Total, Min, Max, Mean, and Median summarize the per-iteration
	// durations (Median over the sorted durations).
	Total  time.Duration
	Min    time.Duration
	Max    time.Duration
	Mean   time.Duration
	Median time.Duration
}

// BenchmarkDetector measures one rule's detector against a snapshot: it
// executes the detector iterations times (each under the rule's own
// deadline, with the engine's panic isolation), validates every returned
// finding through the same output contract the engine enforces, and
// summarizes the durations. It performs no caching, no scheduling, and no
// side effects beyond the detector's own work; the snapshot is normalized
// exactly as Run normalizes it.
//
// The rule does not need to be registered. A rule whose every iteration
// failed returns the last error alongside the result (the counts are still
// reported).
func BenchmarkDetector(ctx context.Context, rule Rule, snap Snapshot, iterations int, clock runtime.Clock) (BenchResult, error) {
	if err := ValidateRule(rule); err != nil {
		return BenchResult{}, fmt.Errorf("detect: benchmark rule: %w", err)
	}
	if iterations <= 0 || iterations > maxBenchmarkIterations {
		return BenchResult{}, fmt.Errorf("detect: iterations must be in [1, %d], got %d", maxBenchmarkIterations, iterations)
	}
	if clock == nil {
		clock = engineClock{}
	}
	corpus, err := normalizeSnapshot(snap)
	if err != nil {
		return BenchResult{}, err
	}
	dctx := corpus.context
	dctx.Config = nil
	dctx.Logger = noopLogger{}
	dctx.Clock = clock

	res := BenchResult{RuleID: rule.ID, Iterations: iterations}
	durations := make([]time.Duration, 0, iterations)
	var lastErr error
	for i := 0; i < iterations; i++ {
		if err := ctx.Err(); err != nil {
			return res, fmt.Errorf("detect: benchmark cancelled after %d iterations: %w", i, err)
		}
		findings, d, err := benchOnce(ctx, rule, &dctx, clock)
		if err != nil {
			lastErr = err
			if isPanicError(err) {
				res.Panics++
			} else {
				res.Errors++
			}
			continue
		}
		for j, f := range findings {
			if verr := validateFinding(f, rule, corpus.observed); verr != nil {
				return res, fmt.Errorf("detect: benchmark finding %d violates the output contract: %w", j, verr)
			}
		}
		res.Findings += len(findings)
		durations = append(durations, d)
	}
	if len(durations) == 0 {
		return res, fmt.Errorf("detect: every iteration failed (last error: %v)", lastErr)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	res.Min, res.Max = durations[0], durations[len(durations)-1]
	for _, d := range durations {
		res.Total += d
	}
	res.Mean = res.Total / time.Duration(len(durations))
	res.Median = durations[len(durations)/2]
	if len(durations)%2 == 0 {
		res.Median = (durations[len(durations)/2-1] + durations[len(durations)/2]) / 2
	}
	return res, nil
}

// benchOnce runs one isolated detector execution.
func benchOnce(ctx context.Context, rule Rule, dctx *Context, clock runtime.Clock) ([]asset.Finding, time.Duration, error) {
	e := &env{clock: clock, dctx: dctx}
	rctx, cancel := context.WithTimeout(ctx, rule.Timeout)
	defer cancel()
	return e.runDetector(rctx, rule)
}

// noopLogger discards everything; detector benchmarks are measurement, not
// observation collection.
type noopLogger struct{}

func (noopLogger) Log(LogLevel, string, string) {}
