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
//	Discovered ports propagate through the results channel rather than
//	mutating the probe-target list (targets are hostname-built URL forms);
//	results-channel caps stay runner-side per MaxOutput. Cache op
//	"ports.discover", keyed on the scope hash of the input IPs, the
//	result-affecting flags, and the tool version (§11).
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
	opts := probeResultOptions{
		sanExpansion: tlsSANExpansionEnabled(in.Config),
		corpusHosts:  hosts,
		ports:        pd,
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

	// The ips map stays nil: IP assets are not part of the pipeline corpus
	// (the results channel carries them — see buildResult — but the corpus
	// merge does not), so the ip→port edges the engine derives from
	// caller-provided addresses remain deferred (adapt/doc.go). The engine
	// report's own resolved addresses, ports, services, TLS certificates,
	// endpoints, and relationships flow through the results channel.
	report, err := httpprobe.Probe(ctx, in.Target, hosts, nil, cfg)

	if err != nil && ctx.Err() != nil {
		// The run was cancelled: the outcome, not the error field, carries
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

	// Outcome fold over the engine's per-host statuses (mapping table
	// documented on the type).
	return buildResult(in.Target, report, foldHostOutcomes(report), nil, opts), nil
}

// probeResultOptions carries the Run-scoped inputs buildResult needs beyond
// the engine report: the SAN-expansion gate and its known-corpus seed, and
// the optional port-discovery output to merge into the results channel.
type probeResultOptions struct {
	// sanExpansion enables TLS SAN host expansion (StageParams
	// "tls_san_expansion" != "false").
	sanExpansion bool
	// corpusHosts is the filtered input host list — the corpus this stage
	// received — used to avoid re-emitting known names from SANs.
	corpusHosts []asset.Host
	// ports is the optional port-discovery output; nil = disabled or inert.
	ports *portDiscoveryOutput
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
			h, err := asset.NewHost(n, asset.Provenance{Source: tlsSANProvenance})
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

// tlsSANProvenance marks hosts discovered from certificate SAN names.
const tlsSANProvenance = "tls-san"

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
