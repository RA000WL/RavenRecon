package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Operation is the stable cache operation name for passive discovery. It is
// part of the Phase 3 cache key payload; changing it invalidates every
// previously stored discovery record by construction.
const Operation = "passive-discovery"

// defaultDetectTimeout bounds each individual tool detection invocation.
const defaultDetectTimeout = 5 * time.Second

// storeTimeout bounds a single cache write performed after the run context was
// already cancelled (persisting a cancelled record). Cache writes are small
// atomic files; this budget only exists so a cancelled run cannot wedge
// shutdown on a pathological filesystem.
const storeTimeout = 5 * time.Second

// shutdownGrace is added to the pool timeout to bound Shutdown's drain: jobs
// already respect their per-job deadline, so a clean drain needs at most the
// timeout plus one grace period. When a job ignores cancellation, this budget
// force-cancels the remaining jobs and unwinds the pool.
const shutdownGrace = 15 * time.Second

// shutdownForceBudget bounds Shutdown's drain when the pool per-job timeout
// is disabled (0).
const shutdownForceBudget = 30 * time.Second

// Config configures one passive discovery run.
//
// Zero values are normalized where documented (MaxOutputSize, DetectTimeout,
// Sources). Concurrency and QueueSize must be positive; they are validated by
// the worker pool and its errors surface unchanged.
type Config struct {
	// Sources selects sources by name ("subfinder", "assetfinder", "amass").
	// Nil or empty means every built-in source. Unknown names are an error.
	Sources []string

	// Concurrency and QueueSize configure the single runtime pool that owns
	// all scheduling for this run: exactly one job per selected source is
	// submitted, and the pool owns concurrency, cancellation, deadlines, and
	// job-start rate limiting.
	Concurrency int
	QueueSize   int

	// Timeout is the per-job deadline at pool level; 0 disables it.
	Timeout time.Duration

	// Rate and Burst configure the pool's central token-bucket limiter, which
	// gates job STARTS only. It does not rate-limit network traffic inside an
	// external binary: subfinder and amass perform their own throttling, and
	// no per-request limits are faked for external processes. Rate <= 0
	// disables job-start rate limiting; Burst < 1 means 1.
	Rate  float64
	Burst int

	// Bin optionally overrides the executable path per source name. Empty
	// means PATH lookup of the tool's default name.
	Bin map[string]string

	// MaxOutputSize caps each captured stdout/stderr stream in bytes. Zero
	// means DefaultMaxOutput (4 MiB per stream). Output beyond the cap is
	// discarded and diagnosed (the run is stored incomplete), never buffered
	// without bound.
	MaxOutputSize int64

	// DetectTimeout bounds each tool detection invocation. Zero means
	// defaultDetectTimeout.
	DetectTimeout time.Duration

	// Cache, when non-nil, enables cache-before-execute: each job first
	// derives the Phase 3 key and returns the stored result on a usable hit;
	// on a miss it executes the adapter and stores a statused record. Nil
	// disables caching.
	Cache cache.Cache

	// Runner executes tool commands. Nil means ExecRunner (real execution);
	// tests inject fakes through this seam. Detection and discovery share it.
	Runner Runner

	// LookPath resolves tool executables. Nil means exec.LookPath; tests
	// inject fakes.
	LookPath LookupFunc

	// Now returns the timestamp used for provenance. Nil means time.Now.
	Now func() time.Time
}

// DefaultConfig returns a Config with documented defaults.
func DefaultConfig() Config {
	return Config{
		Concurrency:   2,
		QueueSize:     8,
		Timeout:       30 * time.Second,
		Rate:          2,
		Burst:         1,
		MaxOutputSize: DefaultMaxOutput,
		DetectTimeout: defaultDetectTimeout,
	}
}

// env builds the tool environment for one source from cfg.
func (cfg Config) env(name string) toolEnv {
	runner := cfg.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	lookup := cfg.LookPath
	if lookup == nil {
		lookup = exec.LookPath
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	dt := cfg.DetectTimeout
	if dt <= 0 {
		dt = defaultDetectTimeout
	}
	mo := cfg.MaxOutputSize
	if mo <= 0 {
		mo = DefaultMaxOutput
	}
	return toolEnv{
		name:          name,
		bin:           cfg.Bin[name],
		runner:        runner,
		lookup:        lookup,
		limits:        Limits{MaxOutput: mo},
		detectTimeout: dt,
		now:           now,
	}
}

// detectSafe runs a source's Detect with panic containment, matching the
// containment style used for pool jobs: a panicking detection becomes a WARN
// with a reason (never a MISSING and never a crash), so one broken adapter
// cannot take down the whole run — or, through DetectAll, the doctor command.
func detectSafe(ctx context.Context, src Source) (det Detection) {
	defer func() {
		if r := recover(); r != nil {
			det = Detection{
				Source: src.Name(),
				Status: StatusWarn,
				Reason: fmt.Sprintf("detection panicked: %v", r),
			}
		}
	}()
	return src.Detect(ctx)
}

// DetectAll runs detection for every built-in source in stable order against
// the real environment (exec.LookPath + ExecRunner). bins optionally
// overrides executable paths per source name. The doctor command and the
// discover command share this exactly with the pipeline's per-source
// detection — there is no second detection implementation.
func DetectAll(ctx context.Context, bins map[string]string, detectTimeout time.Duration) []Detection {
	cfg := DefaultConfig()
	cfg.Bin = bins
	cfg.DetectTimeout = detectTimeout
	names := builtInNames()
	dets := make([]Detection, 0, len(names))
	for _, n := range names {
		dets = append(dets, detectSafe(ctx, registry[n](cfg.env(n))))
	}
	return dets
}

// Out classifies one source's run outcome.
type Out int

const (
	// OutCompleted: a trustworthy complete result, produced by execution or
	// served from cache. An empty-but-successful run is still completed.
	OutCompleted Out = iota
	// OutPartial: partial data only (non-zero exit with usable output, or
	// stdout truncated at the capture cap). Stored as StatusIncomplete.
	OutPartial
	// OutFailed: no usable output (clean failure, missing executable, ...).
	// Stored as StatusFailed.
	OutFailed
	// OutCancelled: cancelled or timed out, or the job never started.
	// Stored as StatusCancelled.
	OutCancelled
	// OutSkipped: the source was not run (tool MISSING).
	OutSkipped
)

// String returns a stable human-readable label for the outcome.
func (o Out) String() string {
	switch o {
	case OutCompleted:
		return "completed"
	case OutPartial:
		return "partial"
	case OutFailed:
		return "failed"
	case OutCancelled:
		return "cancelled"
	case OutSkipped:
		return "skipped"
	default:
		return fmt.Sprintf("outcome(%d)", int(o))
	}
}

// SourceResult is the structured outcome of one source for one run.
type SourceResult struct {
	Source    string
	Detection Detection
	Status    Out
	Version   string
	Hosts     []asset.Host
	Malformed int
	Truncated bool
	Cached    bool
	Err       error
}

// Report is the complete outcome of a discovery run.
type Report struct {
	Target asset.Domain
	// Results holds one entry per selected source, in selection order. It is
	// safe to read after Run returns; Run's Shutdown is the join point.
	Results []SourceResult
}

// All merges every source's hosts across the report. Hosts sharing a Phase 2
// identity are merged with asset.MergeHosts semantics: the earliest
// observation's provenance wins (a tie resolves to the first-encountered
// source). The result is sorted by canonical name.
func (r Report) All() []asset.Host {
	byID := make(map[asset.Identity]int)
	var merged []asset.Host
	for _, res := range r.Results {
		for _, h := range res.Hosts {
			if idx, ok := byID[h.Identity()]; ok {
				if m, err := asset.MergeHosts(merged[idx], h); err == nil {
					merged[idx] = m
				}
				continue
			}
			byID[h.Identity()] = len(merged)
			merged = append(merged, h)
		}
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Name < merged[j].Name })
	return merged
}

// validateTarget re-validates the target at the pipeline boundary. Run
// receives an asset.Domain that is normally produced by asset.NewDomain, but
// a hand-built struct literal could bypass its normalization rules and reach
// argv construction; this check refuses such values up front. Defense-in-depth:
// the CLI already normalizes before calling Run.
func validateTarget(target asset.Domain) error {
	got, err := asset.NewDomain(target.Name, asset.Provenance{})
	if err != nil {
		return fmt.Errorf("discovery: invalid target %q: %w", target.Name, err)
	}
	if got.Name != target.Name {
		return fmt.Errorf("discovery: target %q is not in canonical form (normalized %q)", target.Name, got.Name)
	}
	return nil
}

// Run executes passive discovery for target. It returns a structured report
// and an error; when the run context is cancelled or the pool had to be
// forced down, the report still carries whatever each job observed (partial
// results are never lost).
func Run(ctx context.Context, target asset.Domain, cfg Config) (Report, error) {
	if ctx == nil {
		return Report{}, fmt.Errorf("discovery: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("discovery: %w", err)
	}
	if err := validateTarget(target); err != nil {
		return Report{}, err
	}
	names, err := resolveSourceNames(cfg.Sources)
	if err != nil {
		return Report{}, err
	}
	// Detect every selected source up front, sequentially, each bounded by
	// DetectTimeout. A MISSING source is skipped with a warning; a panicking
	// detection is contained as a WARN (detectSafe), so detection failures
	// never crash the run. Detection supplies the version used in cache keys.
	results := make([]SourceResult, len(names))
	sources := make([]Source, len(names))
	for i, n := range names {
		src := registry[n](cfg.env(n))
		sources[i] = src
		det := detectSafe(ctx, src)
		results[i] = SourceResult{Source: src.Name(), Detection: det, Version: det.Version, Status: OutCancelled}
		if det.Status == StatusMissing {
			results[i].Status = OutSkipped
		}
	}

	// One runtime pool owns every job of this run.
	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: cfg.Concurrency,
		QueueSize:   cfg.QueueSize,
		Timeout:     cfg.Timeout,
		Rate:        cfg.Rate,
		Burst:       cfg.Burst,
	})
	if err != nil {
		return Report{}, fmt.Errorf("discovery: create worker pool: %w", err)
	}

	// Submit one cache-before-execute job per runnable source. Each job
	// writes only its own slot, so the results slice is race-free.
	for i, s := range sources {
		if results[i].Status == OutSkipped {
			continue
		}
		s, i := s, i
		if _, err := pool.Submit(ctx, runtime.Job{Func: func(jctx context.Context) (any, error) {
			defer func() {
				if r := recover(); r != nil {
					// A panicking adapter must fail its source, never the
					// scan (the pool also contains the panic; this records
					// the outcome).
					results[i] = SourceResult{
						Source:    s.Name(),
						Detection: results[i].Detection,
						Status:    OutFailed,
						Err:       fmt.Errorf("discovery: %s panicked during execution", s.Name()),
					}
				}
			}()
			results[i] = runSource(jctx, target, s, results[i].Detection, cfg)
			return nil, nil
		}}); err != nil {
			results[i] = SourceResult{
				Source:    s.Name(),
				Detection: results[i].Detection,
				Status:    OutCancelled,
				Err:       fmt.Errorf("discovery: submit %s: %w", s.Name(), err),
			}
			// The run context is done or the pool is closing; the remaining
			// sources keep their initialized cancelled status.
			break
		}
	}

	// Shutdown is the join point: it drains every queued and in-flight job
	// before returning. The drain is bounded so a job that ignores
	// cancellation cannot wedge the run forever.
	budget := cfg.Timeout + shutdownGrace
	if cfg.Timeout <= 0 {
		budget = shutdownForceBudget
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), budget)
	shutdownErr := pool.Shutdown(shutCtx)
	cancel()

	report := Report{Target: target, Results: results}
	if shutdownErr != nil {
		return report, fmt.Errorf("discovery: pool shutdown: %w", shutdownErr)
	}
	return report, nil
}

// resolveSourceNames validates and deduplicates the source selection,
// preserving order. Nil or empty selects every built-in source.
func resolveSourceNames(sel []string) ([]string, error) {
	if len(sel) == 0 {
		return builtInNames(), nil
	}
	var out []string
	seen := make(map[string]bool)
	for _, n := range sel {
		n = strings.TrimSpace(n)
		if n == "" {
			return nil, fmt.Errorf("discovery: empty source name in %q", sel)
		}
		if _, ok := registry[n]; !ok {
			return nil, fmt.Errorf("discovery: unknown source %q (built-in sources: %s)", n, strings.Join(builtInNames(), ", "))
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

// runSource is one cache-before-execute job body: for known-version tools,
// derive the Phase 3 key, return the stored result on a usable hit, otherwise
// execute the adapter, classify, and store a statused record. A record that
// fails decodeStored is never served as a hit: it is deleted (best-effort)
// and the job falls through to a fresh execution, so the canonical result of
// this run replaces the stale record (self-healing). Tools with an unknown
// version (det.Version == "") are never cached at all — no key, no Get, no
// Put — and execute fresh on every run (see the policy note at the cache
// gate below).
func runSource(ctx context.Context, target asset.Domain, src Source, det Detection, cfg Config) SourceResult {
	res := SourceResult{Source: src.Name(), Detection: det, Version: det.Version, Status: OutCompleted}
	var key cache.Key
	haveKey := false
	if cfg.Cache != nil && det.Version != "" {
		// Cache policy: a tool whose version is unknown (det.Version == "")
		// is NON-CACHEABLE. An unknown version cannot be distinguished from
		// any other unknown version, so a ""-version key could serve one
		// unknown-version tool state's results for another — silently
		// returning stale results across an undetectable upgrade.
		// Unknown-version runs therefore bypass the cache entirely: no key,
		// no Get, no Put, and every run executes fresh. Versioned tools cache
		// on the detected version; a version change misses and re-executes.
		k, err := cacheKey(target, src, det)
		if err != nil {
			res.Status = OutFailed
			res.Err = fmt.Errorf("discovery: %s: build cache key: %w", src.Name(), err)
			return res
		}
		key, haveKey = k, true
		out := cfg.Cache.Get(ctx, key)
		// A non-hit Get that carries a diagnosis (StateError,
		// StateCorrupt, StateSchemaIncompatible — Miss/Expired/Incomplete
		// carry no Err) is a warning, never a failure: the run falls
		// through to a fresh execution below and the cause is joined into
		// res.Err so the renderer can surface it. No cache outcome can block
		// or fail the discovery layer indefinitely.
		if !out.IsHit() && out.Err != nil {
			res.Err = errors.Join(res.Err, fmt.Errorf("discovery: %s: cache get: %w", src.Name(), out.Err))
		}
		if out.IsHit() {
			// Only a completed, unexpired record for the exact key is a hit.
			// The cache never surfaces failed, cancelled, incomplete,
			// expired, corrupt, or schema-incompatible entries as valid
			// results (distinct miss states; the cache heals its own
			// corrupt entries on read). The record's own tool identity must
			// also match the query — a record found under this key with
			// different tool fields could only be tampered with — and the
			// payload is cross-checked by decodeStored (target, source, and
			// domain containment). A record that fails decodeStored is
			// deleted and recomputed in this same run (self-healing), so it
			// is never served as a hit and never wedges the source into
			// repeated failures until TTL expiry.
			if out.Record.Tool.Name != src.Name() || out.Record.Tool.Version != det.Version {
				res.Status = OutFailed
				res.Err = fmt.Errorf("discovery: %s: cached record tool identity %q/%q does not match %q/%q",
					src.Name(), out.Record.Tool.Name, out.Record.Tool.Version, src.Name(), det.Version)
				return res
			}
			sr, err := decodeStored(out.Record.Data, target, src.Name())
			if err != nil {
				// Self-healing: the record is unusable (tampered or
				// non-canonical) and must never be served as a hit or
				// emitted. Remove it best-effort — errors are surfaced per
				// the cache-convention of joining them into the result —
				// and FALL THROUGH to a fresh execution below, so the
				// canonical result of this run replaces the stale record.
				// If the delete fails, the store below still overwrites the
				// stale record; the delete additionally covers the case
				// where execution fails and nothing gets stored.
				if derr := cfg.Cache.Delete(ctx, key); derr != nil {
					res.Err = errors.Join(res.Err, fmt.Errorf("discovery: %s: delete unusable cached record: %w", src.Name(), derr))
				}
				res.Err = errors.Join(res.Err, fmt.Errorf("discovery: %s: discarded unusable cached result: %w", src.Name(), err))
			} else {
				res.Cached = true
				res.Hosts = sr.Hosts
				res.Malformed = sr.Malformed
				res.Truncated = sr.Truncated
				return res
			}
		}
	}

	dres, err := src.Discover(ctx, target)
	res.Hosts = dres.Hosts
	res.Malformed = dres.Malformed
	res.Truncated = dres.Truncated
	res.Status = classify(ctx, dres, err)
	if err != nil {
		res.Err = err
	}

	if haveKey {
		rec := cache.Record{
			Operation: Operation,
			Target:    target.Identity().String(),
			Tool:      cache.ToolInfo{Name: src.Name(), Version: det.Version},
			Status:    statusToCache(res.Status),
			Meta:      map[string]string{"source": src.Name()},
		}
		sr := storedResult{
			Source:    src.Name(),
			Version:   det.Version,
			Target:    target.Identity().String(),
			Hosts:     dres.Hosts,
			Malformed: dres.Malformed,
			Truncated: dres.Truncated,
		}
		if b, merr := json.Marshal(sr); merr == nil {
			rec.Data = b
		} else {
			res.Err = errors.Join(res.Err, fmt.Errorf("discovery: %s: encode result: %w", src.Name(), merr))
		}
		// A cancelled run still persists its terminal record: the store uses
		// a detached, bounded context so the write cannot wedge shutdown.
		storeCtx := ctx
		if ctx.Err() != nil {
			var scancel context.CancelFunc
			storeCtx, scancel = context.WithTimeout(context.Background(), storeTimeout)
			defer scancel()
		}
		if perr := cfg.Cache.Put(storeCtx, key, rec); perr != nil {
			res.Err = errors.Join(res.Err, fmt.Errorf("discovery: %s: cache put: %w", src.Name(), perr))
		}
	}
	return res
}

// classify maps an adapter outcome plus its context to a run outcome.
//
// Cancellation and deadline-exceeded are always OutCancelled (never failure
// and never success), matching the runtime's terminal classification.
// A non-zero exit or start failure with usable output is OutPartial (the
// partial data is kept and stored as incomplete); with no usable output it is
// OutFailed. Truncated stdout — even from a successful tool — is OutPartial:
// the captured set is incomplete by definition.
func classify(ctx context.Context, dres DiscoverResult, err error) Out {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return OutCancelled
	case err != nil:
		if len(dres.Hosts) > 0 {
			return OutPartial
		}
		return OutFailed
	case dres.Truncated:
		return OutPartial
	default:
		return OutCompleted
	}
}

// statusToCache maps a run outcome to the cache record status. Tool execution
// failures and cancellations are never stored as completed.
func statusToCache(o Out) cache.Status {
	switch o {
	case OutCompleted:
		return cache.StatusCompleted
	case OutPartial:
		return cache.StatusIncomplete
	case OutCancelled:
		return cache.StatusCancelled
	default:
		return cache.StatusFailed
	}
}
