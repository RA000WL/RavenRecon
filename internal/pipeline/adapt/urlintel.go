package adapt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/urlintel"
	urladapt "github.com/RA000WL/RavenRecon/internal/urlintel/adapt"
)

// urlintelParametersTruncated is the sticky-flag name this adapter sets when
// the urlintel engine reports an overflow: parameters were dropped because a
// URL's distinct-parameter set hit the engine's per-URL cap
// (urlintel maxParametersPerURL). It is the adapter's mapping of the engine's
// own truncation marker — URLEntry.Overflow (internal/urlintel/report.go),
// which the engine sets when extraction OR the merge-at-emit drops a new
// parameter identity past the cap — and is preserved end-to-end (written to
// the cache record, replayed from cache on hits, merged stickily, and exposed
// in the report; AGENTS §0.6 names "urlintel's Overflow" as a mandatory
// carve-out chain), never swallowed.
//
// Truncation-flag finding (documented per the T2c contract): urlintel's
// Report/URLEntry carry exactly ONE truncation/overflow signal — the
// per-entry Overflow field. There is no run-level Truncated marker on
// urlintel.Report. The flag name follows the package convention
// (adapt/doc.go): <engine>_<what>_truncated — the thing cut is the per-URL
// parameter set, so "urlintel_parameters_truncated", never a bare generic
// like "truncated" or "overflow" that could collide across engines.
const urlintelParametersTruncated = "urlintel_parameters_truncated"

// defaultTool is the StageParams["tool"] default: the first tool in
// urlintel/adapt's stable Builtins() order (gau, waybackurls, waymore).
// urlintel/adapt itself offers no single-tool default (its DefaultConfig
// selects every built-in tool); the pipeline adapter picks the first built-in
// and documents it here.
const defaultTool = "gau"

// urlintelStage adapts the URL-intelligence engine (internal/urlintel) and
// its historical-URL tool adapters (internal/urlintel/adapt) to the pipeline
// Stage contract (internal/pipeline/adapt/doc.go, T2c conventions).
//
// StageParams keys (all others are ignored — the adapter reads defensively):
//
//	"tool"              — the historical-URL source to query:
//	                      "gau" | "waybackurls" | "waymore" (urlintel/adapt's
//	                      built-in Tool descriptors). Absent, empty, or
//	                      all-whitespace selects the documented default
//	                      "gau" (defaultTool — the first built-in in
//	                      urlintel/adapt.Builtins() stable order). An unknown
//	                      name is a structured error (Outcome failed): there
//	                      is no engine-side validation to fall through to.
//	"parse_parameters"  — "true" (default) or "false" (case-insensitive,
//	                      surrounding whitespace trimmed). Controls the
//	                      engine's query-parameter extraction
//	                      (urlintel.Config.ParseParameters). It is
//	                      result-relevant and therefore enters the engine's
//	                      per-(URL, adapter) cache keys; the pipeline adapter
//	                      passes it through verbatim. Parameter extraction is
//	                      retained in the engine report only — corpus
//	                      propagation carries URLs only (adapt/doc.go). Any
//	                      other value is a structured error (Outcome failed).
//
// Config derivation (engine Config from StageInput only — no pre-resolved
// pipeline defaults):
//
//	Concurrency/QueueSize/Timeout/Rate/Burst ← in.Bounds verbatim.
//	  0 means "engine default/disabled" per the URLINTEL engine's own
//	  semantics (urlintel.validateAndDefault): Concurrency and QueueSize
//	  must be positive (the engine rejects 0 with its own pool-config error,
//	  mapped to Outcome failed — the pipeline runner resolves them to the
//	  defaults before invoking the stage, so through the runner they are
//	  never 0), Timeout 0 disables the per-job deadline, Rate <= 0 disables
//	  job-start pacing, Burst < 1 means 1. The adapter deliberately does not
//	  apply pipeline.WithDefaults.
//	Cache ← in.Cache (nil = the engine's caching-disabled).
//	Clock ← in.Clock (nil = the engine's wall clock).
//	Adapter ← the selected tool name (urlintel/adapt's adapter identity: it
//	  enters per-(URL, adapter) cache keys and the provenance of every
//	  asset; non-empty and <= 128 bytes — every built-in name qualifies).
//
// Input: the adapter queries in.Target plus every entry of in.Domains
// (deduplicated by asset.Identity, deterministic order: the declared target
// first, then in.Domains in corpus order). The domain list is not filtered:
// the tool queries each declared domain, and the output boundary protects the
// shared corpus (below). For each domain the adapter constructs the selected
// tool's LineSource and ingests it (bounded per-domain runs: each
// urlintel.IngestInto owns one bounded runtime.Pool configured from
// in.Bounds — no goroutine per URL and no adapter-owned concurrency at all;
// domains run sequentially).
//
// Source construction (the constructor test seam): urlintel/adapt exports no
// per-tool LineSource constructor — its toolSource is unexported and lives
// inside adapt.Run's per-slot execution. The adapter therefore constructs
// each domain's source itself, using exactly the hooks urlintel/adapt's own
// runOne uses (adapt source.go): resolve the tool's executable through the
// lookPath seam (nil = exec.LookPath, production), execute it through the
// runner seam (nil = discovery.ExecRunner, production) with the tool's typed
// argv (urladapt.Tool.Args — the canonical target always appears as its own
// single argv element, never shell-joined; exec.CommandContext semantics are
// the runner's contract), and wrap the runner's bounded stdout capture in the
// adapter's toolLineSource (the same trim/skip-blank stream semantics
// urlintel/adapt's toolSource documents — the adapter boundary is raw:
// canonical-boundary rejection is the engine's Malformed accounting, never
// the adapter's). When the source cannot be constructed for a domain — the
// executable is missing (lookup failure), the tool could not be executed
// (runner error), or the domain is not representable as a canonical host —
// the failure is recorded honestly as ItemsFailed, never as a silent skip.
//
// Output: Additions.URLs = the merged engine-report URLs, deduplicated by
// Phase 2 identity (the engine's shared accumulator merges every domain's
// observations at emit time — the engine's documented multi-run merge,
// mirroring corpus.go's dedup-by-Identity semantics — and Report sorts by
// canonical URL string) and boundary-filtered against in.Target through the
// package's filterURLs (the URL-aware equivalent of pipeline.FilterHosts, the
// same output-side boundary the httpprobe adapter applies): out-of-domain
// URL hosts and IP literals never reach the shared corpus. Domains and Hosts
// additions are always nil: urlintel consumes the declared target and
// produces URLs only. All other engine results — parameters, sources
// provenance, endpoints, relationships — stay inside the engine report; the
// pipeline corpus carries URLs only per the T2c conventions (adapt/doc.go).
//
// Outcome mapping (per the unified table, adapt/doc.go):
//
//	engine error + ctx fired     → cancelled, with
//	                              errors.Join(ctx.Err(), engineErr) attached
//	                              (the outcome, not the Go error, carries
//	                              cancellation — the joined context error is
//	                              what the runner's isContextError traverses)
//	engine error, ctx live       → failed (wrapped "stage %s: %w")
//	clean completion, per-domain → folded with the unified precedence
//	statuses                      (cancelled > failed&&!completed > completed
//	                              > partial): a domain is completed (tool
//	                              executed, capture streamed, ingest clean,
//	                              exit 0, capture within the cap), partial
//	                              (non-zero exit with usable output, or the
//	                              capture cut at the runner's capture cap —
//	                              the captured set is incomplete by
//	                              definition, mirroring urlintel/adapt's
//	                              ResultPartial), failed (source could not be
//	                              constructed, the tool produced no usable
//	                              output, or the ingest failed), or cancelled
//	                              (run teardown).
//
// A domain whose tool exited non-zero or whose capture was cut at the
// runner's capture cap folds partial — never completed, never silently
// truncated (AGENTS §0.6): the outcome itself marks the retained set
// incomplete, exactly as urlintel/adapt's own slot vocabulary classifies
// ResultPartial. The sticky truncation flag is reserved for the ENGINE's own
// report signal — URLEntry.Overflow (parameters dropped at the per-URL cap)
// sets Truncated=true plus the urlintelParametersTruncated sticky flag, never
// swallowed. An overflow entry is still engine-completed, so the outcome may
// stay completed with the flag set — the AGENTS §0.6 carve-out for
// "urlintel's Overflow", which is preserved end-to-end by the engine's own
// record/merge chain.
//
// Counters: ItemsProcessed is the engine report's honest processed count —
// one entry per distinct canonical URL consumed (including cancelled-status
// entries from a teardown, mirroring how the dns adapter counts cancelled
// hosts). ItemsFailed is the report's Malformed count (raw tool lines the
// engine rejected at the ingest boundary) plus the count of domains whose
// tool source could not be constructed or produced no usable output — the
// honest failed items, never a silent skip.
//
// Errors: every error is wrapped with context ("stage %s: %w") and returned;
// cancellation is reported through Outcome cancelled exactly as the pipeline
// contract documents. The engine report's honest retained observations are
// merged into Additions on EVERY path, including the engine-error branches —
// the runner merges a failed stage's additions (LOW-2 convention).
type urlintelStage struct {
	// runner is the tool-execution seam (nil = discovery.ExecRunner,
	// production).
	runner discovery.Runner
	// lookPath is the executable-resolution seam (nil = exec.LookPath,
	// production).
	lookPath discovery.LookupFunc
}

var _ pipeline.Stage = (*urlintelStage)(nil)

// NewURLIntelStage constructs the URL-intelligence pipeline stage. The hooks
// are constructor test seams only — nil means production behavior (the
// engine's execution defaults: discovery.ExecRunner and exec.LookPath, the
// same seams urlintel/adapt's env.sanitized applies). Tests inject hermetic
// fakes through these, never through StageParams (params are operator
// configuration, not test plumbing).
func NewURLIntelStage(runner discovery.Runner, lookPath discovery.LookupFunc) pipeline.Stage {
	return &urlintelStage{runner: runner, lookPath: lookPath}
}

// Name implements pipeline.Stage.
func (s *urlintelStage) Name() pipeline.StageName { return pipeline.StageURLIntel }

// Run implements pipeline.Stage.
func (s *urlintelStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}
	if !targetCanonical(in.Target) {
		// The pipeline runner validates the target before any stage runs, so
		// this guards direct callers only: a non-canonical target is rejected
		// through the single normalization point (asset.NewDomain) instead of
		// being silently queried in a non-canonical form (mirrors the dns
		// adapter's honesty about the engine's scope boundary).
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: target %q is not canonical (build it with asset.NewDomain — the single normalization point)", s.Name(), in.Target.Name)
	}
	tool, err := toolParam(in.Config)
	if err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: %w", s.Name(), err)
	}
	parseParams, err := parseParametersParam(in.Config)
	if err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: %w", s.Name(), err)
	}
	if err := ctx.Err(); err != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
		return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, wrapped
	}

	cfg := urlintel.Config{
		// Bounds pass-through, verbatim: 0 means engine default/disabled per
		// the URLINTEL engine's own documented semantics (adapt/doc.go), never
		// pre-resolved pipeline defaults. Through the runner Concurrency and
		// QueueSize are always positive; a direct caller passing 0 gets the
		// engine's own pool-config error (mapped to Outcome failed).
		Concurrency: in.Bounds.MaxConcurrency,
		QueueSize:   in.Bounds.QueueSize,
		Timeout:     in.Bounds.Timeout,
		Rate:        in.Bounds.Rate,
		Burst:       in.Bounds.Burst,
		// Adapter = the tool name: the engine's adapter identity, entering
		// per-(URL, adapter) cache keys and every asset's provenance
		// (mandatory non-empty, <= 128 bytes — all built-in names qualify).
		Adapter: tool.Name,
		// Result-relevant: enters the engine's cache keys (see urlKey).
		ParseParameters: parseParams,
		// Cache and Clock pass through: nil cache = caching disabled; nil
		// clock = the engine's wall clock.
		Cache: in.Cache,
		Clock: in.Clock,
	}

	// One shared accumulator merges every domain's observations at emit time:
	// one report entry per distinct canonical URL across the whole stage,
	// deterministically sorted — the engine's documented multi-run merge
	// (engine.go IngestInto), mirroring corpus.go's dedup-by-Identity
	// semantics.
	acc := urlintel.NewAccumulator()
	var anyCompleted, anyFailed, anyPartial, anyCancelled bool
	failedDomains := 0

	for _, d := range urlintelDomains(in) {
		status, engineErr := s.runDomain(ctx, tool, cfg, d, acc)
		if engineErr != nil {
			// Engine error paths (the unified outcome mapping table): the
			// engine report's honest retained observations still propagate as
			// Additions — the runner merges a failed stage's additions.
			report := acc.Report()
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), engineErr)
			switch {
			case isContextError(engineErr):
				// The engine's own error IS the context signal (a source
				// surfaced ctx.Err() mid-ingest): the outcome, not the Go
				// error, carries cancellation, with the context error
				// attached — the runner's isContextError traverses the wrap
				// and keeps the cancelled classification (mirrors the dns
				// adapter's mapping).
				return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped, Additions: urlintelAdditions(in, report)}, wrapped
			case ctx.Err() != nil:
				// The stage context fired while the engine errored (for
				// example teardown on forced pool shutdown): cancellation is
				// the dominant, more honest signal — the context's own error
				// attached, with the engine's error joined in so nothing is
				// lost (INFO-1 convention, mirroring the dns adapter).
				joined := fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), engineErr))
				return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: joined, Additions: urlintelAdditions(in, report)}, nil
			default:
				return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped, Additions: urlintelAdditions(in, report)}, wrapped
			}
		}
		switch status {
		case domainCompleted:
			anyCompleted = true
		case domainPartial:
			anyPartial = true
		case domainFailed:
			anyFailed = true
			failedDomains++
		case domainCancelled:
			anyCancelled = true
		}
	}
	if err := ctx.Err(); err != nil {
		// The run was cancelled while the engine drained cleanly (its
		// per-domain statuses already reflect the teardown): the outcome, not
		// the Go error, carries cancellation, with the context error
		// attached.
		report := acc.Report()
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
		return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped, Additions: urlintelAdditions(in, report)}, wrapped
	}

	report := acc.Report()
	res := pipeline.StageResult{
		Outcome:        foldDomainOutcomes(anyCompleted, anyFailed, anyPartial, anyCancelled),
		ItemsProcessed: len(report.Entries),
		ItemsFailed:    report.Malformed + failedDomains,
		Additions:      urlintelAdditions(in, report),
	}
	if urlintelTruncated(report) {
		// Any entry's Overflow (parameters dropped at the per-URL cap): the
		// engine's documented truncation marker, never swallowed — the entry
		// is still engine-completed, so the outcome may stay completed with
		// the flag set (the AGENTS §0.6 carve-out for urlintel's Overflow).
		res.Truncated = true
		res.StickyFlags = map[string]bool{urlintelParametersTruncated: true}
	}
	return res, nil
}

// domainStatus is one queried domain's honest outcome within the stage.
type domainStatus int

const (
	domainCompleted domainStatus = iota
	domainPartial
	domainFailed
	domainCancelled
)

// runDomain constructs the selected tool's LineSource for one domain and
// ingests it into the shared accumulator. It returns a domain status and,
// only for ENGINE errors (urlintel.IngestInto failures), a non-nil error for
// the run-level mapping. Tool-execution failures (lookup, runner) are domain
// statuses — never returned errors: the fold and ItemsFailed carry them
// honestly, and returning a Go error would force the runner's failed
// classification over the fold.
func (s *urlintelStage) runDomain(ctx context.Context, tool urladapt.Tool, cfg urlintel.Config, d asset.Domain, acc *urlintel.Accumulator) (domainStatus, error) {
	if err := ctx.Err(); err != nil {
		return domainCancelled, nil
	}
	// The tool argv is built from the canonical host form of the domain
	// (asset.NewHost through the single normalization point — never a second
	// normalizer). A domain that cannot be represented as a canonical host is
	// not applicable to the tool: recorded as failed, never silently skipped.
	host, err := asset.NewHost(d.Name, asset.Provenance{})
	if err != nil {
		return domainFailed, nil
	}

	// Source construction, exactly the hooks urlintel/adapt's runOne uses
	// (adapt/source.go): resolve the executable, execute the typed argv
	// through the runner, wrap the bounded stdout capture as the line source.
	lookPath := s.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	bin := tool.Bin
	if bin == "" {
		bin = tool.Name
	}
	path, err := lookPath(bin)
	if err != nil {
		return domainFailed, nil
	}
	runner := s.runner
	if runner == nil {
		runner = discovery.ExecRunner{}
	}
	rres, err := runner.Run(ctx, discovery.Cmd{Path: path, Args: tool.Args(host)}, discovery.Limits{MaxOutput: discovery.DefaultMaxOutput})
	if err != nil {
		if ctx.Err() != nil {
			// Run teardown (cancellation or the pipeline's per-stage
			// deadline): the stage reports cancelled; the tool's error detail
			// is not needed because the context error is the dominant signal.
			return domainCancelled, nil
		}
		return domainFailed, nil
	}

	// The bounded capture is a valid line stream regardless of the exit code
	// (mirroring urlintel/adapt's runOne): stream it through the engine, then
	// classify the domain.
	src := newToolLineSource(rres.Stdout)
	if ierr := urlintel.IngestInto(ctx, cfg, src, acc); ierr != nil {
		// An engine error: the run-level mapping decides failed vs cancelled.
		// The shared accumulator keeps every observation consumed so far.
		return domainFailed, ierr
	}

	switch {
	case rres.ExitCode != 0 && src.lineCount() == 0 && !rres.StdoutTruncated:
		// Clean failure with no usable output: nothing was ingested for this
		// domain.
		return domainFailed, nil
	case rres.ExitCode != 0 || rres.StdoutTruncated:
		// Non-zero exit with usable output, or the capture cut at the
		// runner's capture cap: the captured URL set is incomplete by
		// definition (mirroring urlintel/adapt's ResultPartial) — never
		// completed, never silently truncated (AGENTS §0.6).
		return domainPartial, nil
	default:
		return domainCompleted, nil
	}
}

// urlintelDomains is the stage's query set: the declared target plus every
// corpus domain, deduplicated by asset.Identity with the target first and
// in.Domains in corpus order (deterministic).
func urlintelDomains(in pipeline.StageInput) []asset.Domain {
	seen := make(map[asset.Identity]struct{}, 1+len(in.Domains))
	out := make([]asset.Domain, 0, 1+len(in.Domains))
	add := func(d asset.Domain) {
		id := d.Identity()
		if _, dup := seen[id]; dup {
			return
		}
		seen[id] = struct{}{}
		out = append(out, d)
	}
	add(in.Target)
	for _, d := range in.Domains {
		add(d)
	}
	return out
}

// urlintelAdditions builds the stage's Additions from the merged engine
// report: the report's URLs, deduplicated by Phase 2 identity and sorted by
// the engine, re-filtered through the package's filterURLs — the URL-aware
// equivalent of pipeline.FilterHosts, the same output-side boundary the
// httpprobe adapter applies — so an out-of-domain URL host or an IP literal
// never reaches the shared corpus. Domains and Hosts are always nil: urlintel
// consumes domains and produces URLs only. It is used on every path: the
// success path and both engine-error branches (the runner merges a failed
// stage's additions).
func urlintelAdditions(in pipeline.StageInput, report urlintel.Report) pipeline.StageAdditions {
	return pipeline.StageAdditions{
		URLs: filterURLs(in.Target, report.AllURLs()),
	}
}

// foldDomainOutcomes reduces the per-domain statuses to one stage outcome
// with exactly the unified adapter precedence (adapt/doc.go): cancelled >
// failed&&!completed > completed > partial.
func foldDomainOutcomes(anyCompleted, anyFailed, anyPartial, anyCancelled bool) pipeline.Outcome {
	switch {
	case anyCancelled:
		return pipeline.OutcomeCancelled
	case anyFailed && !anyCompleted:
		return pipeline.OutcomeFailed
	case !anyFailed && !anyPartial && !anyCancelled:
		// Every domain completed (vacuously true for an empty query set).
		return pipeline.OutcomeCompleted
	default:
		// Completed domains mixed with failed ones, or any partial domain.
		return pipeline.OutcomePartial
	}
}

// urlintelTruncated reports whether any report entry carries the engine's
// truncation marker (URLEntry.Overflow — parameters dropped at the per-URL
// parameter cap). The marker is never swallowed: the caller sets Truncated
// and the urlintelParametersTruncated sticky flag from it.
func urlintelTruncated(report urlintel.Report) bool {
	for _, e := range report.Entries {
		if e.Overflow {
			return true
		}
	}
	return false
}

// toolParam reads the "tool" StageParams key defensively: absent, empty, or
// all-whitespace values select the documented default (defaultTool); the
// value is trimmed and resolved through urlintel/adapt's built-in tool
// lookup. An unknown tool name is a structured error (the caller maps it to
// Outcome failed).
func toolParam(params map[string]string) (urladapt.Tool, error) {
	name, ok := params["tool"]
	if !ok || strings.TrimSpace(name) == "" {
		name = defaultTool
	}
	name = strings.TrimSpace(name)
	t, found := urladapt.LookupTool(name)
	if !found {
		return urladapt.Tool{}, fmt.Errorf("unknown tool %q (built-ins: gau, waybackurls, waymore)", name)
	}
	return t, nil
}

// parseParametersParam reads the "parse_parameters" StageParams key
// defensively: absent selects the documented default (true — the engine's own
// DefaultConfig default). Values are trimmed and case-insensitively matched
// against "true"/"false"; anything else is a structured error (the caller
// maps it to Outcome failed).
func parseParametersParam(params map[string]string) (bool, error) {
	v, ok := params["parse_parameters"]
	if !ok {
		return true, nil
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid parse_parameters value %q (want \"true\" or \"false\")", v)
	}
}

// toolLineSource is the adapter's urlintel.LineSource over one tool's bounded
// stdout capture. The adapter stream is raw — lines are trimmed (CRLF and
// surrounding whitespace stripped), blank lines are skipped, and EVERYTHING
// else passes through unchanged — exactly the boundary semantics
// urlintel/adapt's toolSource documents (adapt/doc.go "Adapter boundary"):
// canonical-boundary rejection (non-URLs, oversized lines, control-character
// garbage) is the ENGINE's Malformed accounting, never the adapter's, so
// garbage from a noisy tool is counted, never fatal and never silently
// dropped. The underlying capture is already bounded by the runner
// (Limits.MaxOutput), so the stream is bounded by construction. Not safe for
// concurrent use: the engine reads a source sequentially by design.
type toolLineSource struct {
	data  []byte
	pos   int
	lines int
}

// newToolLineSource wraps a bounded stdout capture.
func newToolLineSource(stdout []byte) *toolLineSource {
	return &toolLineSource{data: stdout}
}

// Next implements urlintel.LineSource. It returns io.EOF at end of stream
// and honors ctx cancellation (returning ctx.Err()).
func (s *toolLineSource) Next(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	for s.pos < len(s.data) {
		start := s.pos
		if nl := bytes.IndexByte(s.data[start:], '\n'); nl >= 0 {
			s.pos = start + nl + 1
		} else {
			s.pos = len(s.data)
		}
		line := strings.TrimSpace(string(s.data[start:s.pos]))
		if line == "" {
			continue
		}
		s.lines++
		return line, nil
	}
	return "", io.EOF
}

// lineCount reports how many non-blank lines were streamed. It is final once
// the source is exhausted.
func (s *toolLineSource) lineCount() int {
	return s.lines
}
