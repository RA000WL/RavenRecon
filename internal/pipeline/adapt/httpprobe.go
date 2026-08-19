package adapt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// HTTPProbeStickyFlag is the sticky-flag name the httpprobe adapter records
// in StageResult.StickyFlags when any probe of the run hit a hard cap
// (redirects, headers, or body). It names the engine's truncation marker —
// ProbeStatus "truncated-incomplete" / ProbeResult.Truncated (internal/
// httpprobe/observe.go) — and is preserved end-to-end (result → RunReport →
// report), never swallowed (AGENTS §0.6).
const HTTPProbeStickyFlag = "probe_truncated"

// HTTPProbeStage adapts the httpprobe engine to the pipeline.Stage contract
// (internal/pipeline/adapt/doc.go).
//
// StageParams keys (all others are ignored — the adapter reads defensively):
//
//	"request_timeout" — a Go duration string (time.ParseDuration) naming the
//	per-request deadline the engine applies around every outbound request
//	(slowloris protection; httpprobe.Config.RequestTimeout). Absent,
//	unparseable, zero, or negative values resolve to 0, which the engine
//	treats as its 10 s default. Negative values are clamped to 0 (the
//	default) rather than passed through: a negative per-request deadline
//	would otherwise silently disable the engine's slowloris protection, and
//	the pipeline itself rejects inverted time bounds.
//
// Outcome mapping (engine host status → pipeline outcome; internal/
// httpprobe/observe.go "classifyHost"):
//
//	StatusCompleted  -> completed
//	StatusIncomplete -> partial   (the engine's own definition: "partial
//	                               results only; the successful parts are
//	                               retained")
//	StatusFailed     -> failed
//	StatusCancelled  -> cancelled
//
// The stage fold over the report's host results is deterministic, in this
// precedence: (1) any cancelled host, or a cancelled run context, folds to
// cancelled; (2) every host failed with no completed host folds to failed;
// (3) every host completed folds to completed; (4) otherwise (any mix of
// completed/failed/incomplete) folds to partial. This is exactly the unified
// adapter shape (adapt/doc.go "Unified outcome mapping", MEDIUM-1 review
// unification): cancelled > failed&&!completed > completed > partial — the
// same precedence the dns adapter and the pipeline runner's foldOutcome use
// (with the runner's incomplete bucket reserved for discovery's OutSkipped
// and the truncation downgrade). A run whose hosts are all truncated-incomplete
// folds to partial with the truncation flag set — partial + a named sticky
// flag is the AGENTS §0.6-legal combination for a retained set cut at a cap;
// the flag, never the outcome alone, marks the set incomplete.
//
// Truncation (engine probe status "truncated-incomplete" / ProbeResult.
// Truncated — a redirect, header, or body cap): sets Truncated=true and
// StickyFlags[HTTPProbeStickyFlag]=true. The adapter never produces
// completed+Truncated (a truncated probe forces the engine's host status to
// StatusIncomplete, which folds to partial), so the runner's completed+
// Truncated+empty-flags downgrade never triggers on this adapter.
//
// Counters: ItemsProcessed is the number of host results in the engine report
// (one per input host); ItemsFailed is the number of hosts whose overall
// status is StatusFailed (incomplete hosts are partial, not failed).
//
// Boundary (mandatory, both sides): input hosts are pre-filtered with
// pipeline.FilterHosts before Probe is called, because the engine validates
// the whole host list against the target and rejects the entire call on any
// out-of-domain host. The engine's reported hosts and URLs are filtered again
// before they become Additions: hosts through pipeline.FilterHosts, URLs by
// the canonical host extracted from the URL asset (out-of-domain hosts and IP
// literals are dropped — IPs are never in scope and are not yet in the
// corpus). The engine's probe targets are always built from the filtered
// in-domain input, so the output filter is a defensive boundary that never
// drops anything through normal operation; it is pinned by unit tests.
//
// An empty filtered host list short-circuits to completed with zero additions
// and zero counters without calling the engine — but ONLY when the target is
// canonical (targetCanonical, the same boundary check the engine applies in
// validateScope). The engine itself tolerates an empty list (Probe returns an
// empty report without starting a pool), so the short-circuit is a pure
// optimization, not a correctness requirement — but it keeps the stage
// trivial. For a non-canonical target the adapter falls through to the
// engine so its honest scope error is not masked by a completed outcome
// (mirroring the dns adapter). Cancellation is still honored on that path: a
// cancelled context reports cancelled, mirroring the engine, which checks
// ctx.Err() before its empty-list check.
//
// v1.3 note (adapt/doc.go): IP assets are not yet part of the pipeline
// corpus, so the adapter passes a nil ips map to Probe; the ip->port edges
// the engine derives from caller-provided addresses are deferred until the
// corpus carries IPs.
type HTTPProbeStage struct {
	// transport is the constructor test seam: nil means the engine's bounded
	// production transport; tests inject hermetic loopback transports.
	transport http.RoundTripper
}

// NewHTTPProbeStage constructs the httpprobe stage. A nil transport selects
// the engine's bounded production transport (a clone of http.DefaultTransport
// with a response-header byte cap, a response-header timeout, and proxy
// support disabled). Tests inject a hermetic transport — never through
// StageParams (params are operator configuration, not test plumbing).
func NewHTTPProbeStage(transport http.RoundTripper) pipeline.Stage {
	return &HTTPProbeStage{transport: transport}
}

// Name implements pipeline.Stage.
func (s *HTTPProbeStage) Name() pipeline.StageName { return pipeline.StageHTTPProbe }

// Run implements pipeline.Stage.
func (s *HTTPProbeStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}

	// Boundary, input side: the engine validates the whole host list against
	// the target and rejects the entire call on any out-of-domain host, so
	// every out-of-domain corpus host is filtered out before the engine sees
	// the list (canonical names only — the single normalization point stays
	// in internal/asset).
	hosts := pipeline.FilterHosts(in.Target, in.Hosts)

	// Empty filtered list: short-circuit with completed and zero additions —
	// but only for a canonical target. The engine tolerates an empty list
	// (empty report, no pool), so this is a pure optimization; a non-canonical
	// target falls through so the engine's own scope-validation error is not
	// masked (LOW-1 review finding, mirroring the dns adapter). The context
	// is still honored first, exactly as the engine checks ctx.Err() before
	// its own empty-list branch.
	if len(hosts) == 0 && targetCanonical(in.Target) {
		if ctx.Err() != nil {
			return pipeline.StageResult{
				Outcome: pipeline.OutcomeCancelled,
				Err:     fmt.Errorf("stage %s: %w", s.Name(), ctx.Err()),
			}, nil
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	cfg := httpprobe.Config{
		// Bounds pass-through: 0 = engine default/disabled per the engine's
		// own documented semantics, never pre-resolved pipeline defaults
		// (adapt/doc.go). Concurrency/QueueSize are required positive by the
		// engine (the runner always resolves them to the defaults, so through
		// the runner they are never 0); Timeout 0 disables the per-job
		// deadline; Rate <= 0 disables pacing; Burst < 1 means 1.
		Concurrency: in.Bounds.MaxConcurrency,
		QueueSize:   in.Bounds.QueueSize,
		Timeout:     in.Bounds.Timeout,
		Rate:        in.Bounds.Rate,
		Burst:       in.Bounds.Burst,
		// The single StageParam (documented on the type): invalid or absent
		// resolves to 0 = the engine's 10 s per-request default.
		RequestTimeout: requestTimeoutFromParams(in.Config),
		// Cache and Clock pass through: nil cache = caching disabled; nil
		// clock = the engine's wall clock. The runner guarantees a non-nil
		// clock; the engine tolerates nil either way.
		Cache: in.Cache,
		Clock: in.Clock,
		// Constructor test seam: nil = the engine's bounded production
		// transport.
		Transport: s.transport,
	}

	// v1.3 note: IP assets are not yet part of the pipeline corpus, so the
	// ips map is nil (adapt/doc.go); the ip->port edges the engine derives
	// from caller-provided addresses are deferred until the corpus carries
	// IPs.
	report, err := httpprobe.Probe(ctx, in.Target, hosts, nil, cfg)

	if err != nil && ctx.Err() != nil {
		// The run was cancelled: the outcome, not the error field, carries
		// cancellation (pipeline contract). The wrapped context error is
		// attached so the runner keeps the cancelled classification even when
		// the engine also surfaced a shutdown error; the engine error is
		// joined so nothing is lost.
		return buildResult(in.Target, report, pipeline.OutcomeCancelled,
			fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), err))), nil
	}
	if err != nil {
		// Any other engine error (invalid config, pool failure, shutdown
		// failure): failed, wrapped with context. The report's honest
		// observations are still returned as Additions — the runner merges
		// them even from a failed stage.
		werr := fmt.Errorf("stage %s: %w", s.Name(), err)
		return buildResult(in.Target, report, pipeline.OutcomeFailed, werr), werr
	}
	if ctx.Err() != nil {
		// The engine drained cleanly but the run was cancelled in flight: the
		// per-host statuses are cancelled and the stage outcome is cancelled,
		// with the context error attached.
		return buildResult(in.Target, report, pipeline.OutcomeCancelled,
			fmt.Errorf("stage %s: %w", s.Name(), ctx.Err())), nil
	}

	// Outcome fold over the engine's per-host statuses (mapping table
	// documented on the type).
	return buildResult(in.Target, report, foldHostOutcomes(report), nil), nil
}

// buildResult maps one engine report onto the pipeline's StageResult shape:
// the honest counters, the truncation flag (never swallowed), and the
// boundary-filtered Additions (the output-side mandatory filter: out-of-domain
// hosts and URL hosts are dropped before propagation).
func buildResult(declared asset.Domain, report httpprobe.Report, outcome pipeline.Outcome, err error) pipeline.StageResult {
	res := pipeline.StageResult{
		Outcome:        outcome,
		ItemsProcessed: len(report.Results),
		ItemsFailed:    failedHostCount(report),
		Err:            err,
	}
	if probeTruncated(report) {
		res.Truncated = true
		res.StickyFlags = map[string]bool{HTTPProbeStickyFlag: true}
	}
	res.Additions = pipeline.StageAdditions{
		Hosts: pipeline.FilterHosts(declared, report.AllHosts()),
		URLs:  filterURLs(declared, report.AllURLs()),
	}
	return res
}

// foldHostOutcomes reduces the engine report's per-host statuses to one stage
// outcome (mapping table documented on HTTPProbeStage).
func foldHostOutcomes(report httpprobe.Report) pipeline.Outcome {
	if len(report.Results) == 0 {
		// Defensive: the engine returns exactly one result per input host and
		// the adapter short-circuits empty inputs, so this cannot occur
		// through normal operation; a vacuous empty report folds to completed,
		// mirroring the engine's own empty-list behavior.
		return pipeline.OutcomeCompleted
	}
	anyCompleted, anyFailed, anyCancelled := false, false, false
	allCompleted := true
	for _, hr := range report.Results {
		switch hr.Status {
		case httpprobe.StatusCompleted:
			anyCompleted = true
		case httpprobe.StatusFailed:
			anyFailed = true
			allCompleted = false
		case httpprobe.StatusCancelled:
			anyCancelled = true
			allCompleted = false
		case httpprobe.StatusIncomplete:
			// Engine-incomplete (partial results retained): not completed,
			// and it folds into the partial bucket below — the adapters
			// themselves never emit OutcomeIncomplete.
			allCompleted = false
		}
	}
	switch {
	case anyCancelled:
		return pipeline.OutcomeCancelled
	case anyFailed && !anyCompleted:
		return pipeline.OutcomeFailed
	case allCompleted:
		return pipeline.OutcomeCompleted
	default:
		return pipeline.OutcomePartial
	}
}

// failedHostCount returns the number of host results whose overall status is
// StatusFailed — the engine report's honest failed count. Incomplete hosts
// (partial results retained) are not failures.
func failedHostCount(report httpprobe.Report) int {
	n := 0
	for _, hr := range report.Results {
		if hr.Status == httpprobe.StatusFailed {
			n++
		}
	}
	return n
}

// probeTruncated reports whether any probe of the report hit a hard cap (the
// engine's ProbeTruncated status / truncated-incomplete marker, or its
// Truncated flag). The marker is never swallowed: the caller sets Truncated
// and the sticky flag from it.
func probeTruncated(report httpprobe.Report) bool {
	for _, hr := range report.Results {
		for _, pr := range hr.Probes {
			if pr.Status == httpprobe.ProbeTruncated || pr.Truncated {
				return true
			}
		}
	}
	return false
}

// filterURLs drops every URL whose canonical host is out-of-domain, an IP
// literal, or not representable as a canonical asset.Host. The engine's probe
// targets are always built from the filtered in-domain input hosts, so this
// never drops anything through normal operation — it is the mandatory
// output-side boundary against out-of-domain assets the engine could produce
// (adapt/doc.go) and is pinned by unit tests.
func filterURLs(declared asset.Domain, urls []asset.URL) []asset.URL {
	out := make([]asset.URL, 0, len(urls))
	for _, u := range urls {
		h, ok := urlHost(u)
		if !ok {
			continue // IP literal or unparseable host: never in-domain
		}
		if pipeline.InDomain(declared, h) {
			out = append(out, u)
		}
	}
	return out
}

// urlHost extracts the canonical hostname of a URL asset as an asset.Host.
// The canonical HostPort may carry a non-default port ("host:8080" or a
// bracketed IPv6 literal), which is stripped; IP literals are rejected — a
// Host is a hostname, not an address, and IP assets are not yet in the corpus.
func urlHost(u asset.URL) (asset.Host, bool) {
	hp := u.HostPort
	if host, _, err := net.SplitHostPort(hp); err == nil {
		hp = host
	}
	hp = strings.TrimPrefix(hp, "[")
	hp = strings.TrimSuffix(hp, "]")
	if _, err := netip.ParseAddr(hp); err == nil {
		return asset.Host{}, false // IP literal: never in-domain
	}
	h, err := asset.NewHost(hp, asset.Provenance{})
	if err != nil {
		return asset.Host{}, false
	}
	return h, true
}

// requestTimeoutFromParams reads the adapter's single StageParam key,
// "request_timeout", as a Go duration string. Absent, unparseable, zero, and
// negative values resolve to 0, which the engine treats as its 10 s default.
// Unknown params are ignored.
func requestTimeoutFromParams(params map[string]string) time.Duration {
	v, ok := params["request_timeout"]
	if !ok {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}
