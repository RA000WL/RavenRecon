package adapt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
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

// HTTPProbeTLSDNSNamesStickyFlag is the sticky flag this adapter records
// when any TLS certificate it returns carries the asset model's
// DNSNamesTruncated marker (asset.TLSCertificate.DNSNamesTruncated — a
// MergeTLSCertificates union was cut at maxTLSCertificateDNSNames, dropping
// SAN names from the retained set). It is preserved end-to-end (result →
// RunReport → report), never swallowed (AGENTS §0.6).
//
// The name follows the package convention (adapt/doc.go): a sticky flag is
// <engine>_<what>_truncated. "probe" is this engine's token
// (HTTPProbeStickyFlag); "tls_dns_names" names exactly what was cut — kept
// distinct from the runner's channel-level tls_certificates_truncated flag
// (a results-channel MaxOutput cut) and from HTTPProbeStickyFlag (the
// per-probe redirect/header/body caps), which can fire alongside it.
const HTTPProbeTLSDNSNamesStickyFlag = "probe_tls_dns_names_truncated"

// httpprobeSANTargetsTruncatedFlag marks a run whose SAN-derived probe
// host set exceeded the engine's per-run cap (NEW-136): only the sorted
// head was probed. It follows the package convention (a sticky flag is
// <engine>_<what>_truncated) and accumulates with the sibling cut flags.
const httpprobeSANTargetsTruncatedFlag = "httpprobe_san_targets_truncated"

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
//	"tls_san_expansion" — TLS SAN host expansion (default ON): after probing,
//	every DNS name on a returned TLS certificate (the SANs of certificates
//	the probes already captured — passive observation, zero extra network
//	cost) that parses as a canonical in-domain Host asset AND is not already
//	in the corpus becomes an additional Host addition, so later stages — and
//	subsequent runs over the merged corpus — discover hosts from certificate
//	data. The exact value "false" (case/space-insensitive) disables it.
//	Wildcards ("*.example.com"), IP literals, and out-of-domain names are not
//	Host assets / not in scope: they are dropped at asset.NewHost /
//	pipeline.FilterHosts (the single normalization point). Expansion output is
//	deduplicated against the input corpus and the report's own hosts, sorted,
//	and appended after them; provenance Source "tls-san". A certificate whose
//	SAN union was CUT at the model's cap carries DNSNamesTruncated — expansion
//	operates on the retained names only; the existing
//	probe_tls_dns_names_truncated flag already marks that cut end-to-end, so
//	no additional marker is raised here.
//
//	"port_discovery" — optional naabu port discovery (default OFF; see
//	ports.go for the full contract). Truthy values ("true"/"1"/"yes"/"on",
//	case-insensitive — the dnsx_brute spelling convention) enable it: BEFORE
//	probing begins (i.e. after the dns stage has resolved addresses into
//	StageInput.Results.IPs), naabu runs over those addresses with -top-ports
//	100 -silent -rate 300 -c 25, and every open ip:port pair is emitted as a
//	results-channel addition: an asset.Port (tcp) plus an
//	asset.RelationshipIPToPort edge from the resolved address to the port.
//	The feature is inert without resolved IPs (honest zero cost, no flag) and
//	honestly marked when it cannot honor the request: ports_naabu_missing
//	(binary absent — decided ONLY by exec.LookPath, never by a failed version
//	probe), ports_naabu_failed (execution failure; pairs parsed before the
//	failure still merge), ports_output_truncated (+ Truncated: the captured
//	stdout hit the stream cap, so the retained pair set is incomplete).
//	Discovered ports propagate through the results channel;
//	results-channel caps stay runner-side per MaxOutput. Cache op
//	"ports.discover", keyed on the scope hash of the input IPs, the
//	result-affecting flags, and the tool version (§11).
//
//	"probe_ports" — optional probing of discovered ports (default OFF;
//	NEW-121). Truthy values (same spellings) build scheme://host:port/
//	engine targets from the discovery output: each in-scope host's ports
//	are resolved through the dns stage's host→IP edges (plus one CNAME
//	hop) joined with naabu's ip→port edges, capped at 16 ports per host
//	(sorted head; the cut sets httpprobe_port_targets_truncated +
//	Truncated). Targets probe through the standard engine path
//	(cache-before-execute under their own URL identities, redirect
//	scope, asset/edge derivation), so port surfaces join the corpus and
//	flow downstream like root targets. Without probe_ports, discovery
//	output is inventory only (the historical behavior, byte-identical).
//	probe_ports without discovery results is an inert no-op (no ports,
//	no flag).
//
//	"probe_san" — optional probing of TLS SAN hosts (default OFF;
//	NEW-136). Truthy values (same spellings) feed the SAN DNS names of
//	the certificates the first probe pass captured back as probe targets:
//	every synthesized host (see httpprobe.SynthesizeSANProbeTargets —
//	wildcards skipped-and-counted, never expanded; out-of-scope names
//	dropped, never probed; deduped against the corpus; capped at 16 per
//	run with an honest cut flag) is probed through a second engine call
//	with the IDENTICAL config (same pool shape, same per-request budgets,
//	same HostPorts synthesis map, same mistake-path surface, same session
//	headers), so SAN targets ride the standard engine path
//	(cache-before-execute under their own URL identities, redirect
//	scope, asset/edge derivation) and cert-only hosts join the corpus
//	and flow downstream like root targets. The two engine reports merge
//	deterministically (sorted by host) and the outcome refolds over the
//	union. A dedicated knob — not folded into "tls_san_expansion" —
//	because passive corpus enrichment (zero extra traffic) and active
//	probing (up to 32 root requests, plus up to 38 mistake-path requests
//	per SAN host when mistake_paths is also enabled) are different budgets:
//	cheap enrichment defaults ON, traffic-multiplying features default OFF
//	(the probe_ports knob philosophy). Without probe_san, SAN names are
//	inventory only (the historical behavior, byte-identical).
//	probe_san with no captured certificates is an inert no-op (no SAN
//	hosts, no flag). Exactly one feedback round runs: certificates the
//	SAN pass itself captures are observed (and passively expanded) but
//	never re-fed, so the phase cannot chain. The cut sets
//	httpprobe_san_targets_truncated + Truncated; a failed or cancelled SAN pass folds like any engine
//	error (failed/cancelled with the retained observations merged).
//	SAN-feedback hosts skip takeover confirmation and port-target synthesis (both derive from the first-pass corpus only).
//
//	"takeover_confirm" — optional HTTP confirmation of dangling CNAME
//	hosts (default ON; NEW-122). The exact value "false"
//	(case/space-insensitive) disables it. When on, hosts with a CNAME
//	edge whose target has no addresses (dangling shape — computed from
//	the dns stage's host→IP/host→CNAME edges, no provider lists) get
//	bounded root fetches matched against a curated provider table
//	(github-pages/heroku/aws-s3); matches become takeover evidence.
//	Capped at 64 hosts per run (sorted head; the cut sets
//	httpprobe_takeover_overflow + Truncated), body-cap hits and hard
//	errors set httpprobe_takeover_truncated + Truncated. The fetch is
//	deliberately uncached (freshness-critical claims); confirmed matches
//	flow downstream as evidence, coherent through the snapshot
//	fingerprint like every other evidence record. Hosts synthesized by
//	SAN feedback are never takeover candidates (selection runs on the first-pass corpus only).
//
//	"mistake_paths" — developer-mistake path probing (default OFF).
//	Truthy values ("true"/"1"/"yes"/"on", case-insensitive — the
//	dnsx_brute spelling convention, mirroring "probe_ports") fetch the
//	curated well-known set (defaultMistakePaths: robots/sitemaps,
//	version control, env files, actuator/health/metrics/debug endpoints,
//	API docs, GraphQL playgrounds, backups, manifests, legacy handlers)
//	on every probed host. The engine gates paths per host — only a root
//	that proved an HTTP server enables them, on the responding scheme —
//	so dead hosts cost zero extra requests; every path enjoys
//	cache-before-execute under its own URL identity with the standard
//	redirect/header/body bounds, and the observations join the corpus
//	(URLs, GET endpoints, host→url edges) for techintel, jsintel, and
//	the detect packs. Default OFF like "probe_ports": 38 extra targets
//	per host is a traffic decision the operator makes explicitly, never
//	a silent multiplication of the scan profile. No trim, no flag: the
//	curated set sits below the engine bound by construction (pinned).
//	Tuning requirement: the engine probes one host's whole surface
//	sequentially in one job (2 roots + port pairs + one request per
//	path, at most 1 in flight), so the run Timeout must cover all 38
//	extra requests — a Timeout sized for roots alone expires
//	mid-surface and the host folds to Cancelled by the cancelled-first
//	vocabulary. That outcome is contractual, not surprising (pinned by
//	the engine's short-Timeout contract test). Enablement is
//	programmatic-only in this milestone: this stage parameter — no
//	scan CLI flag or global config key exists for it.
//	"session_headers" — optional operator session file (default absent =
//	anonymous; NEW-125). The value is a filesystem path to "Name: value"
//	headers (see ReadSessionFile); the file is read at stage start and
//	a broken file fails the stage (fail-closed). Headers ride in-scope
//	requests (cross-host redirect hops never inherit them) and bind
//	cache keys by digest — values never enter logs, errors, reports,
//	or cache records.
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
// completed+Truncated from THAT signal (a truncated probe forces the
// engine's host status to StatusIncomplete, which folds to partial). A
// second, asset-level signal exists: a returned certificate carrying
// TLSCertificate.DNSNamesTruncated (a MergeTLSCertificates union cut at the
// model's 32-name cap) sets Truncated=true and
// StickyFlags[HTTPProbeTLSDNSNamesStickyFlag]=true while the host outcome
// stays whatever the probes earned — completed + flag is the legal §0.6
// carve-out for a retained set cut at a cap, because the flag is recomputed
// from the returned/replayed certificates on every path (success AND cache
// replay). Both signals can fire together; their flags accumulate.
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

	// ports is the optional port-discovery seam (see ports.go): nil selects
	// the production naabuPortSource (which itself resolves its runner and
	// LookPath seams lazily). Tests inject a fake portDiscoverer — or a
	// naabuPortSource built over fake seams — never through StageParams.
	ports portDiscoverer
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

// Level implements pipeline.LeveledStage: probing needs dns-resolved hosts.
func (s *HTTPProbeStage) Level() int { return 2 }

// Run implements pipeline.Stage.
func (s *HTTPProbeStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}

	// Optional port discovery (opt-in via StageParams["port_discovery"]):
	// runs BEFORE probing — i.e. after the dns stage resolved addresses into
	// in.Results.IPs — and rides every outcome path below through opts.
	pd := s.runPortDiscovery(ctx, in)

	// Boundary, input side: the engine validates the whole host list against
	// the target and rejects the entire call on any out-of-domain host, so
	// every out-of-domain corpus host is filtered out before the engine sees
	// the list (canonical names only — the single normalization point stays
	// in internal/asset).
	hosts := pipeline.FilterHosts(in.Target, in.Hosts)
	// Port-target synthesis (NEW-121): when the operator opted into BOTH
	// discovery and probing, each in-scope host's naabu ports become
	// scheme://host:port/ engine targets. Either knob off means root-only
	// probing — byte-identical to the pre-synthesis behavior.
	var portTargets map[string][]int
	portsTruncated := false
	if portProbeEnabled(in.Config) {
		portTargets, portsTruncated = synthesizePortTargets(hosts, in.Results.Relationships, pd)
	}
	// Mistake-path surface: the curated set when the operator opted in
	// (nil = root-only probing, byte-identical to the historical
	// behavior).
	var mistakePaths []string
	if mistakePathsEnabled(in.Config) {
		mistakePaths = defaultMistakePaths
	}
	// Takeover candidate selection is input-determined (no network): the
	// cut flag rides every outcome path below through opts, exactly like
	// the port-synthesis cut.
	var takeoverHosts []asset.Host
	takeoverCut := false
	if takeoverConfirmEnabled(in.Config) {
		takeoverHosts, takeoverCut = selectTakeoverHosts(hosts, in.Results.Relationships)
	}
	opts := probeResultOptions{
		sanExpansion: tlsSANExpansionEnabled(in.Config),
		corpusHosts:  hosts,
		ports:        pd,
		portsCut:     portsTruncated,
		takeoverCut:  takeoverCut,
	}
	// Operator session headers (NEW-125): resolved before the
	// short-circuit below so a broken session file fails the stage even
	// on an empty corpus — fail-closed, never scan anonymously when
	// authentication was asked for.
	sessionHeaders, err := sessionHeadersFromParams(in.Config)
	if err != nil {
		wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed, Err: wrapped}, wrapped
	}

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
		return buildResult(in.Target, httpprobe.Report{}, pipeline.OutcomeCompleted, nil, opts), nil
	}

	// Operator session headers (NEW-125): resolved above (fail-closed).
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
		// Operator session headers (nil = anonymous probing).
		RequestHeaders: sessionHeaders,
		// Cache and Clock pass through: nil cache = caching disabled; nil
		// clock = the engine's wall clock. The runner guarantees a non-nil
		// clock; the engine tolerates nil either way.
		Cache: in.Cache,
		Clock: in.Clock,
		// Constructor test seam: nil = the engine's bounded production
		// transport.
		Transport: s.transport,
		// Synthesized port targets (nil = root-only probing).
		HostPorts: portTargets,
		// Mistake-path targets (nil = root-only probing).
		WellKnownPaths: mistakePaths,
		// Forward the run observer into the engine pool; nil disables events.
		Observer: in.Observer,
	}

	// The ips map stays nil: IP assets are not part of the pipeline corpus
	// (the results channel carries them — see buildResult — but the corpus
	// merge does not), so the ip→port edges the engine derives from
	// caller-provided addresses remain deferred (adapt/doc.go). The engine
	// report's own resolved addresses, ports, services, TLS certificates,
	// endpoints, and relationships flow through the results channel.
	report, err := httpprobe.Probe(ctx, in.Target, hosts, nil, cfg)

	if err != nil && ctx.Err() != nil { // The run was cancelled: the outcome, not the error field, carries
		// cancellation (pipeline contract). The wrapped context error is
		// attached so the runner keeps the cancelled classification even when
		// the engine also surfaced a shutdown error; the engine error is
		// joined so nothing is lost.
		return buildResult(in.Target, report, pipeline.OutcomeCancelled,
			fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), err)), opts), nil
	}
	if err != nil {
		// Any other engine error (invalid config, pool failure, shutdown
		// failure): failed, wrapped with context. The report's honest
		// observations are still returned as Additions — the runner merges
		// them even from a failed stage.
		werr := fmt.Errorf("stage %s: %w", s.Name(), err)
		return buildResult(in.Target, report, pipeline.OutcomeFailed, werr, opts), werr
	}
	if ctx.Err() != nil {
		// The engine drained cleanly but the run was cancelled in flight: the
		// per-host statuses are cancelled and the stage outcome is cancelled,
		// with the context error attached.
		return buildResult(in.Target, report, pipeline.OutcomeCancelled,
			fmt.Errorf("stage %s: %w", s.Name(), ctx.Err()), opts), nil
	}

	// SAN→target feedback (NEW-136): the certificates the first pass
	// captured may name hosts the corpus never listed. When the operator
	// opted in, those names become probe targets through a second engine
	// call with the IDENTICAL cfg — the same pool shape, per-request
	// budgets, HostPorts synthesis, mistake-path surface, and session
	// headers — so SAN targets ride the standard engine path
	// (cache-before-execute under their own URL identities with the
	// session digest bound, redirect scope, asset/edge derivation). The
	// reports merge deterministically and the outcome refolds over the
	// union; the synthesis cut flag rides every path below through opts.
	// Engine-error paths above skip this phase (existing behavior
	// preserved); a failed or cancelled SAN pass folds like any engine
	// error, with the retained observations merged.
	if probeSANEnabled(in.Config) {
		sanOut := httpprobe.SynthesizeSANProbeTargets(in.Target, report.AllTLSCertificates(), hosts)
		opts.sanCut = sanOut.Truncated
		if len(sanOut.Hosts) > 0 {
			if ctx.Err() != nil {
				return buildResult(in.Target, report, pipeline.OutcomeCancelled,
					fmt.Errorf("stage %s: %w", s.Name(), ctx.Err()), opts), nil
			}
			sanReport, sanErr := httpprobe.Probe(ctx, in.Target, sanOut.Hosts, nil, cfg)
			report = mergeProbeReports(report, sanReport)
			if sanErr != nil && ctx.Err() != nil {
				return buildResult(in.Target, report, pipeline.OutcomeCancelled,
					fmt.Errorf("stage %s: %w", s.Name(), errors.Join(ctx.Err(), sanErr)), opts), nil
			}
			if sanErr != nil {
				werr := fmt.Errorf("stage %s: %w", s.Name(), sanErr)
				return buildResult(in.Target, report, pipeline.OutcomeFailed, werr, opts), werr
			}
			if ctx.Err() != nil {
				return buildResult(in.Target, report, pipeline.OutcomeCancelled,
					fmt.Errorf("stage %s: %w", s.Name(), ctx.Err()), opts), nil
			}
		}
	}

	// Outcome fold over the engine's per-host statuses (mapping table
	// documented on the type).
	outcome := foldHostOutcomes(report)
	// Takeover confirmation (NEW-122): additive evidence over completed
	// or partial liveness — a failed or cancelled run leaves no corpus
	// worth confirming. It never changes a failed/cancelled outcome and
	// only ever downgrades completed to partial (never the reverse).
	if takeoverConfirmEnabled(in.Config) && (outcome == pipeline.OutcomeCompleted || outcome == pipeline.OutcomePartial) {
		evs, trunc, cerr := s.confirmTakeover(ctx, in, takeoverHosts, cfg)
		opts.takeoverEvidence = evs
		if trunc {
			opts.takeoverTruncated = true
		}
		if cerr != nil {
			// Hard-error cut-short: the liveness result stands,
			// downgraded to partial when it was completed, with the
			// truncation flag marking the evidence set incomplete. The
			// detail rides res.Err with a NIL Go return — a non-nil
			// return would force Outcome failed and corrupt the honest
			// partial (runner normalizeResult contract).
			opts.takeoverTruncated = true
			if outcome == pipeline.OutcomeCompleted {
				outcome = pipeline.OutcomePartial
			}
			return buildResult(in.Target, report, outcome,
				fmt.Errorf("stage %s: takeover confirmation: %w", s.Name(), cerr), opts), nil
		}
	}
	return buildResult(in.Target, report, outcome, nil, opts), nil
}

// probeResultOptions carries the Run-scoped inputs buildResult needs beyond
// the engine report: the SAN-expansion gate and its known-corpus seed, the
// optional port-discovery output to merge into the results channel, the
// port-target synthesis cut flag, and the takeover-confirmation output.
type probeResultOptions struct {
	// sanExpansion enables TLS SAN host expansion (StageParams
	// "tls_san_expansion" != "false").
	sanExpansion bool
	// corpusHosts is the filtered input host list — the corpus this stage
	// received — used to avoid re-emitting known names from SANs.
	corpusHosts []asset.Host
	// ports is the optional port-discovery output; nil = disabled or inert.
	ports *portDiscoveryOutput
	// portsCut reports that port-target synthesis cut a host's port list
	// at maxProbePortsPerHost (NEW-121).
	portsCut bool
	// takeoverEvidence carries confirmed-takeover evidence (NEW-122);
	// nil when confirmation was disabled, inapplicable, or silent.
	takeoverEvidence []asset.Evidence
	// takeoverCut reports that the takeover candidate set exceeded
	// maxTakeoverConfirmHosts (NEW-122).
	takeoverCut bool
	// sanCut reports that SAN→target synthesis cut the host list at the
	// engine's per-run cap (NEW-136).
	sanCut bool
	// takeoverTruncated reports an incomplete confirmation set: body-cap
	// hits or a hard-error cut-short (NEW-122).
	takeoverTruncated bool
}

// buildResult maps one engine report onto the pipeline's StageResult shape:
// the honest counters, the truncation flag (never swallowed), the
// boundary-filtered Additions (the output-side mandatory filter: out-of-domain
// hosts and URL hosts are dropped before propagation), and the results-channel
// additions (the engine report's canonical assets, copied — never rebuilt —
// per the one-normalization-point rule). opts carries the Run-scoped extras:
// TLS SAN host expansion (Additions.Hosts) and the optional port-discovery
// merge (Results.Ports / Results.Relationships + its sticky flags).
func buildResult(declared asset.Domain, report httpprobe.Report, outcome pipeline.Outcome, err error, opts probeResultOptions) pipeline.StageResult {
	res := pipeline.StageResult{
		Outcome:        outcome,
		ItemsProcessed: len(report.Results),
		ItemsFailed:    failedHostCount(report),
		Err:            err,
	}
	// Truncation markers are never swallowed (AGENTS §0.6): the per-probe
	// caps (probeTruncated) and the asset-level SAN-name merge cut on the
	// returned certificates each set Truncated and their own named sticky
	// flag. Both flags are computed from the returned/replayed report on
	// EVERY path — success, engine error, and cache replay alike — because
	// the engine replays stored certificates as decoded assets on a cache
	// hit: the marker rides the record and the flag is recomputed from
	// whatever the stage returns, so the §0.6 chain holds trivially.
	certs := report.AllTLSCertificates()
	flags := map[string]bool{}
	if probeTruncated(report) {
		res.Truncated = true
		flags[HTTPProbeStickyFlag] = true
	}
	if tlsDNSNamesTruncated(certs) {
		res.Truncated = true
		flags[HTTPProbeTLSDNSNamesStickyFlag] = true
	}
	if opts.portsCut {
		res.Truncated = true
		flags[httpprobePortTargetsTruncatedFlag] = true
	}
	if opts.sanCut {
		res.Truncated = true
		flags[httpprobeSANTargetsTruncatedFlag] = true
	}
	if opts.takeoverCut {
		res.Truncated = true
		flags[httpprobeTakeoverOverflowFlag] = true
	}
	if opts.takeoverTruncated {
		res.Truncated = true
		flags[httpprobeTakeoverTruncatedFlag] = true
	}
	if len(flags) > 0 {
		res.StickyFlags = flags
	}
	res.Additions = pipeline.StageAdditions{
		Hosts: pipeline.FilterHosts(declared, report.AllHosts()),
		URLs:  filterURLs(declared, report.AllURLs()),
	}
	// TLS SAN host expansion (default ON): certificate DNS names that are
	// valid canonical in-domain hosts not already in the corpus become
	// additional Host additions (see the StageParams documentation).
	if opts.sanExpansion {
		res.Additions.Hosts = expandTLSSANHosts(declared, certs, res.Additions.Hosts, opts.corpusHosts)
	}
	// Results: IPs, ports, services, TLS certificates, endpoints, and
	// relationships are not corpus values — the results channel carries
	// them. IPs/ports/services/TLS certificates need no scope filter: they
	// are observations of the in-scope hosts this stage probed (an address
	// or port is not "in-domain"; the engine derives them from the probed
	// hosts' own targets). Endpoints and relationships are copied whole:
	// they are derived from the in-scope URLs the engine observed, and
	// relationship edges cannot be meaningfully scope-filtered without
	// corrupting the graph (adapt/doc.go T3d).
	res.Results = pipeline.Results{
		IPs:             report.AllIPs(),
		Ports:           report.AllPorts(),
		Services:        report.AllServices(),
		Endpoints:       report.AllEndpoints(),
		TLSCertificates: certs,
		Relationships:   report.AllRelationships(),
		Evidence:        opts.takeoverEvidence,
	}
	// Optional port discovery (opt-in): naabu's open ports and ip→port
	// edges merge into the results channel on EVERY path above (success,
	// engine error, cancellation-with-report), mirroring the corpus/results
	// merge-even-from-failed semantics; its honesty markers ride the same
	// StickyFlags/Truncated surface.
	mergePortDiscovery(&res, opts.ports)
	return res
}

// expandTLSSANHosts extracts Host additions from the returned certificates'
// SAN DNS names: a name qualifies when it parses as a canonical Host asset
// (wildcards, IP literals, and non-hostname strings do not), is in-domain
// (mandatory output-side boundary via pipeline.FilterHosts), and is not
// already known — neither in the corpus this stage received nor among the
// report's own host additions. The appended names are deduplicated against
// each other, sorted by canonical name for determinism, and placed after the
// report's hosts. The input slices are read-only; the result aliases nothing.
func expandTLSSANHosts(declared asset.Domain, certs []asset.TLSCertificate, additions, corpus []asset.Host) []asset.Host {
	if len(certs) == 0 {
		return additions
	}
	known := make(map[string]bool, len(additions)+len(corpus))
	for _, h := range corpus {
		known[h.Name] = true
	}
	for _, h := range additions {
		known[h.Name] = true
	}
	var found []asset.Host
	for _, c := range certs {
		for _, n := range c.DNSNames {
			// Provenance is the engine's single shared literal
			// (httpprobe.SANProvenance): the passive expansion here and
			// the engine's SAN-target synthesis never disagree on origin.
			h, err := asset.NewHost(n, asset.Provenance{Source: httpprobe.SANProvenance})
			if err != nil {
				continue // wildcards, IP literals, invalid names: not Host assets
			}
			if known[h.Name] {
				continue // already in the corpus or already reported
			}
			known[h.Name] = true
			found = append(found, h)
		}
	}
	if len(found) == 0 {
		return additions
	}
	found = pipeline.FilterHosts(declared, found)
	if len(found) == 0 {
		return additions
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return append(additions, found...)
}

// mergePortDiscovery folds the optional port-discovery output into the stage
// result: ports and relationships are deduplicated (by identity / edge ID)
// against what probing itself observed, deterministically sorted, and
// appended; the feature's sticky flags merge into the stage's set; a
// truncated capture sets Truncated (never swallowed — completed + the
// ports_output_truncated flag is the §0.6 carve-out). A nil pd is a no-op.
func mergePortDiscovery(res *pipeline.StageResult, pd *portDiscoveryOutput) {
	if pd == nil || (len(pd.Ports) == 0 && len(pd.Relationships) == 0 && !pd.Truncated && !pd.MissingTool && !pd.Failed) {
		return
	}
	if len(pd.Ports) > 0 {
		res.Results.Ports = mergePortAssets(res.Results.Ports, pd.Ports)
	}
	if len(pd.Relationships) > 0 {
		res.Results.Relationships = mergeRelationshipAssets(res.Results.Relationships, pd.Relationships)
	}
	extra := pd.flags()
	if len(extra) == 0 {
		return
	}
	if res.StickyFlags == nil {
		res.StickyFlags = make(map[string]bool, len(extra))
	}
	for k, v := range extra {
		res.StickyFlags[k] = v
	}
	if pd.Truncated {
		res.Truncated = true
	}
}

// mergePortAssets unions two port lists, first-seen dedup by identity,
// sorted ascending — deterministic regardless of argument order beyond
// first-seen provenance retention.
func mergePortAssets(base, add []asset.Port) []asset.Port {
	seen := make(map[asset.Identity]bool, len(base)+len(add))
	out := make([]asset.Port, 0, len(base)+len(add))
	for _, p := range append(append([]asset.Port{}, base...), add...) {
		if seen[p.Identity()] {
			continue
		}
		seen[p.Identity()] = true
		out = append(out, p)
	}
	sortPorts(out)
	return out
}

// Takeover-confirmation bounds and flags (NEW-122).
const (
	// maxTakeoverConfirmHosts caps confirmed hosts per run: worst case
	// twice that many confirmation GETs, inside pool/queue budgets, with
	// the per-request deadline bounding slow ones honestly. Dangling
	// hosts are rare; the cap is a backstop, and cuts set
	// httpprobeTakeoverOverflowFlag — never silent.
	maxTakeoverConfirmHosts = 64
	// httpprobeTakeoverOverflowFlag marks a run whose dangling candidate
	// set exceeded maxTakeoverConfirmHosts: only the sorted head was
	// confirmed.
	httpprobeTakeoverOverflowFlag = "httpprobe_takeover_overflow"
	// httpprobeTakeoverTruncatedFlag marks an incomplete confirmation
	// set: body-cap hits or a hard-error cut-short.
	httpprobeTakeoverTruncatedFlag = "httpprobe_takeover_truncated"
)

// takeoverConfirmEnabled reports whether takeover confirmation runs: ON
// unless StageParams carries an explicit "false"
// (case/space-insensitive). Confirmation traffic is tiny (dangling hosts
// only — usually zero), so operators opt OUT rather than in; liveness
// probing itself is unaffected either way.
func takeoverConfirmEnabled(params map[string]string) bool {
	if params == nil {
		return true
	}
	v, ok := params["takeover_confirm"]
	if !ok {
		return true
	}
	return strings.TrimSpace(strings.ToLower(v)) != "false"
}

// selectTakeoverHosts resolves the confirmation candidates (NEW-122):
// in-scope hosts with a host→CNAME edge whose target carries no
// host→IP edge (dangling shape). No provider lists are consulted here —
// candidacy is pure DNS shape, so the stage never branches on pack
// content; the takeover pack's suffix lists decide relevance
// downstream. Output is sorted by hostname; beyond
// maxTakeoverConfirmHosts the head is kept and the cut reported.
func selectTakeoverHosts(hosts []asset.Host, rels []asset.Relationship) ([]asset.Host, bool) {
	inScope := make(map[string]asset.Host, len(hosts))
	for _, h := range hosts {
		inScope[h.Identity().String()] = h
	}
	hasIP := make(map[string]bool)
	var cnames [][2]string
	for _, r := range rels {
		switch r.Kind {
		case asset.RelationshipHostToIP:
			hasIP[r.From.String()] = true
		case asset.RelationshipHostToCNAME:
			cnames = append(cnames, [2]string{r.From.String(), r.To.String()})
		}
	}
	var cands []asset.Host
	seen := make(map[string]bool)
	for _, c := range cnames {
		src, tgt := c[0], c[1]
		h, ok := inScope[src]
		if !ok || seen[src] {
			continue
		}
		if hasIP[tgt] {
			continue
		}
		seen[src] = true
		cands = append(cands, h)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].Name < cands[j].Name })
	if len(cands) > maxTakeoverConfirmHosts {
		cands = cands[:maxTakeoverConfirmHosts]
		return cands, true
	}
	return cands, false
}

// confirmTakeover runs provider confirmation over the candidate hosts
// and maps confirmed verdicts to evidence. Unconfirmed verdicts
// (clean pages, errors, truncations) yield no evidence — the pack
// treats missing evidence as "unconfirmed" (fail-open). It returns the
// sorted evidence, whether the confirmation set is incomplete (any
// body-cap hit OR any per-host error — an unreachable host contributes
// no verdict), and the hard error (nil unless the confirmation run
// itself failed).
func (s *HTTPProbeStage) confirmTakeover(ctx context.Context, in pipeline.StageInput, hosts []asset.Host, cfg httpprobe.Config) ([]asset.Evidence, bool, error) {
	if len(hosts) == 0 {
		return nil, false, nil
	}
	// Takeover evidence is always anonymous (NEW-125): confirmation
	// probes assert what a stranger on the internet sees (a dangling
	// CNAME serving attacker-chosen content), so session credentials
	// never ride them even in authed runs.
	anon := cfg
	anon.RequestHeaders = nil
	rep, err := httpprobe.ConfirmTakeoverHosts(ctx, in.Target, hosts, anon)
	if err != nil {
		return nil, true, err
	}
	var evs []asset.Evidence
	truncated := false
	for _, v := range rep.Results {
		if v.Truncated || v.Err != nil {
			// A body-cap hit OR a per-host transport/cancel/submit
			// failure: no verdict was reachable, so the confirmation
			// set is incomplete — flagged, never silent (review wave
			// 2026-09-03).
			truncated = true
		}
		if !v.Confirmed {
			continue
		}
		ev, everr := httpprobe.TakeoverEvidence(v.Host.Identity(), v.Provider, v.Fingerprint)
		if everr != nil {
			continue
		}
		evs = append(evs, ev)
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].ID() < evs[j].ID() })
	return evs, truncated, nil
}

// mergeRelationshipAssets unions two relationship lists, first-seen dedup by
// edge ID, sorted deterministically.
func mergeRelationshipAssets(base, add []asset.Relationship) []asset.Relationship {
	seen := make(map[string]bool, len(base)+len(add))
	out := make([]asset.Relationship, 0, len(base)+len(add))
	for _, r := range append(append([]asset.Relationship{}, base...), add...) {
		id := r.ID()
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
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

// tlsDNSNamesTruncated reports whether any returned certificate carries the
// asset model's DNSNamesTruncated marker (a MergeTLSCertificates union was
// cut at maxTLSCertificateDNSNames, dropping SAN names). The marker is never
// swallowed: the caller sets Truncated and the sticky flag from it. It is
// computed from the returned/replayed certificates on EVERY path — success
// and cache replay alike — so a marker stored in a cache record still fires
// on a warm run.
func tlsDNSNamesTruncated(certs []asset.TLSCertificate) bool {
	for _, c := range certs {
		if c.DNSNamesTruncated {
			return true
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

// runPortDiscovery executes the opt-in port-discovery path (ports.go): gated
// on StageParams["port_discovery"], a non-empty resolved-address list (the
// dns stage's results channel — without resolved IPs the feature is an honest
// zero-cost no-op), and a canonical target. The returned output rides every
// outcome path through buildResult; its flags()/Truncated carry the honesty
// markers. Cancellation during discovery is NOT flagged: the stage outcome
// carries it (the engine call that follows sees the same fired context).
func (s *HTTPProbeStage) runPortDiscovery(ctx context.Context, in pipeline.StageInput) *portDiscoveryOutput {
	if !portDiscoveryEnabled(in.Config) || len(in.Results.IPs) == 0 || !targetCanonical(in.Target) {
		return nil
	}
	src := s.ports
	if src == nil {
		src = newNaabuPortSource(nil, nil)
	}
	out, err := src.DiscoverPorts(ctx, in.Target, in.Results.IPs,
		portDiscoveryConfig{Cache: in.Cache})
	if err != nil {
		if isContextError(err) || ctx.Err() != nil {
			return nil // cancellation: the outcome carries it, never a flag
		}
		out.Failed = true // execution failure with any retained pairs kept
	}
	return &out
}

// tlsSANExpansionEnabled reports whether TLS SAN host expansion runs. It is
// ON by default (passive observation of certificates already captured); the
// exact value "false" (case/space-insensitive) disables it. Every other
// value — including absent — leaves it enabled.
func tlsSANExpansionEnabled(params map[string]string) bool {
	if params == nil {
		return true
	}
	v, ok := params["tls_san_expansion"]
	if !ok {
		return true
	}
	return strings.TrimSpace(strings.ToLower(v)) != "false"
}

// portDiscoveryEnabled reports whether optional naabu port discovery was
// requested via StageParams["port_discovery"]. OFF by default; truthy values
// follow the dnsx_brute spelling convention ("true"/"1"/"yes"/"on",
// case-insensitive).
func portDiscoveryEnabled(params map[string]string) bool {
	if params == nil {
		return false
	}
	v, ok := params["port_discovery"]
	if !ok {
		return false
	}
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// mistakePathsEnabled reports whether mistake-path probing runs. OFF by
// default (38 extra targets per host is an explicit traffic decision);
// truthy values ("true"/"1"/"yes"/"on", case-insensitive — the
// dnsx_brute spelling convention, mirroring portDiscoveryEnabled) enable
// it. Every other value — including absent — leaves it disabled.
func mistakePathsEnabled(params map[string]string) bool {
	if params == nil {
		return false
	}
	switch strings.TrimSpace(strings.ToLower(params["mistake_paths"])) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// probeSANEnabled reports whether captured TLS SAN hosts are additionally
// probed as targets (NEW-136), via StageParams["probe_san"]. OFF by
// default; truthy values follow the probe_ports spelling convention
// ("true"/"1"/"yes"/"on", case-insensitive). It is a SEPARATE knob from
// tls_san_expansion on purpose: passive corpus enrichment costs zero
// extra traffic (default ON), while SAN feedback probing multiplies it
// (default OFF) — operators opt into budgets, never out of surprises.
func probeSANEnabled(params map[string]string) bool {
	if params == nil {
		return false
	}
	v, ok := params["probe_san"]
	if !ok {
		return false
	}
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// mergeProbeReports unions two engine reports from one stage run (the root
// pass and the SAN feedback pass, NEW-136): results concatenate and sort
// by canonical host name for determinism. Both reports share the declared
// target; the first report's target wins (they are always equal — both
// calls probe under the same declared domain).
//
// Disjoint-precondition: the two result sets must name disjoint hosts —
// the merge concatenates without dedup. It holds by construction for the
// NEW-136 call site (SynthesizeSANProbeTargets seeds its seen set from the
// corpus the first pass probed and dedups synthesized names against each
// other, and the SAN pass probes only those synthesized hosts), so every
// host appears exactly once. Future callers must preserve that
// disjointness or add dedup first: overlapping inputs would double-count
// hosts in ItemsProcessed.
func mergeProbeReports(first, second httpprobe.Report) httpprobe.Report {
	if len(second.Results) == 0 {
		return first
	}
	merged := make([]httpprobe.HostResult, 0, len(first.Results)+len(second.Results))
	merged = append(merged, first.Results...)
	merged = append(merged, second.Results...)
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].Host.Name < merged[j].Host.Name })
	return httpprobe.Report{Target: first.Target, Results: merged}
}

// defaultMistakePaths is the curated well-known set fetched per live host:
// robots/sitemaps, version control, env files, actuator/health/metrics/
// debug endpoints, API docs, GraphQL playgrounds, backups, manifests, and
// legacy handlers. It must stay below the engine's maxWellKnownPaths bound
// (pinned by TestDefaultMistakePathsBounded) — no trim, no flag.
var defaultMistakePaths = []string{
	"/.DS_Store",
	"/.env",
	"/.env.bak",
	"/.git/HEAD",
	"/.git/config",
	"/.hg/hgrc",
	"/.svn/entries",
	"/.well-known/change-password",
	"/.well-known/security.txt",
	"/actuator",
	"/actuator/health",
	"/api-docs",
	"/api/docs",
	"/backup.zip",
	"/clientaccesspolicy.xml",
	"/composer.json",
	"/crossdomain.xml",
	"/db.sqlite",
	"/debug/pprof/",
	"/elmah.axd",
	"/favicon.ico",
	"/graphiql",
	"/graphql",
	"/health",
	"/healthz",
	"/info.php",
	"/metrics",
	"/openapi.json",
	"/package.json",
	"/phpinfo.php",
	"/playground",
	"/robots.txt",
	"/server-status",
	"/sitemap.xml",
	"/sitemap_index.xml",
	"/swagger.json",
	"/swagger.yaml",
	"/wp-json/",
}
