package httpprobe

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// ProbeStatus classifies one probe target's outcome. The labels follow the
// Phase 4 / Phase 3 conventions, with one probe-specific extension:
// "truncated-incomplete" marks an outcome that hit a hard cap (redirects,
// headers, or body) and is therefore incomplete by definition — it is stored
// incomplete and never served from cache as a complete result.
type ProbeStatus string

const (
	// ProbeCompleted: the probe produced a trustworthy result. This
	// includes HTTP responses of any status code AND the two legitimate
	// negative observations — connection refused ("service absent") and a
	// TLS handshake failure ("https not served") — which are completed
	// probes with no HTTP response (FailureReason conn_refused / tls).
	ProbeCompleted ProbeStatus = "completed"
	// ProbeFailed: the probe failed (timeout, DNS failure, or any other
	// failure). No usable observation.
	ProbeFailed ProbeStatus = "failed"
	// ProbeCancelled: the probe was cancelled (context cancellation)
	// before or while it was in flight. Whatever was observed is retained.
	ProbeCancelled ProbeStatus = "cancelled"
	// ProbeTruncated: the probe hit a hard cap — more redirects than
	// MaxRedirects, more response headers than MaxHeaderBytes/MaxHeaders,
	// or a body larger than MaxBodyBytes. The captured observation is
	// incomplete by definition and is stored incomplete, never served as a
	// hit.
	ProbeTruncated ProbeStatus = "truncated-incomplete"
)

// String returns the stable status label.
func (s ProbeStatus) String() string { return string(s) }

// FailureReason is the typed cause of a failed probe, or of a completed probe
// that received no HTTP response. It lets callers react per kind without
// parsing error messages.
type FailureReason string

const (
	// ReasonNone: no failure (completed with an HTTP response, or
	// cap-truncated without a specific reason).
	ReasonNone FailureReason = ""
	// ReasonConnRefused: the TCP connection was refused. A legitimate
	// completed observation: the service is absent on this port.
	ReasonConnRefused FailureReason = "conn_refused"
	// ReasonTimeout: the request timed out (client request timeout, pool
	// deadline, or a net-level timeout, including DNS timeouts).
	ReasonTimeout FailureReason = "timeout"
	// ReasonDNS: the dial failed to resolve the hostname (non-timeout DNS
	// failure). Matching the DNS pipeline's convention, a resolver failure
	// at probe time is a failed probe, never a completed one.
	ReasonDNS FailureReason = "dns"
	// ReasonTLS: the TLS handshake failed (certificate verification
	// failure, protocol mismatch, or a non-TLS server on the https port). A
	// legitimate completed observation: https is not served on this
	// endpoint from RavenRecon's trust perspective (certificate metadata
	// extraction is the TLS milestone, 5C).
	ReasonTLS FailureReason = "tls"
	// ReasonTooManyRedirects: the redirect chain exceeded MaxRedirects. The
	// outcome is truncated-incomplete.
	ReasonTooManyRedirects FailureReason = "too_many_redirects"
	// ReasonOther: any other failure.
	ReasonOther FailureReason = "other"
)

// String returns the stable reason label.
func (r FailureReason) String() string { return string(r) }

// validFailureReason reports whether r is a known reason label (used to
// re-validate stored records).
func validFailureReason(r FailureReason) bool {
	switch r {
	case ReasonNone, ReasonConnRefused, ReasonTimeout, ReasonDNS, ReasonTLS, ReasonTooManyRedirects, ReasonOther:
		return true
	}
	return false
}

// HeaderEntry is one response header of the final response, with its key
// canonicalized via http.CanonicalHeaderKey. Entries are sorted by key and
// bounded: at most MaxHeaders entries, with the whole header block bounded by
// the transport's MaxHeaderBytes cap.
type HeaderEntry struct {
	Key    string   `json:"key"`
	Values []string `json:"values,omitempty"`
}

// boundedHeaders copies the final response's headers into a bounded, ordered
// entry list. Over MaxHeaders entries the copy is capped at MaxHeaders and
// truncated is set: the observation is incomplete by definition (the caller
// stores it incomplete, never as a completed hit). Keys are re-canonicalized
// defensively.
func boundedHeaders(h http.Header) ([]HeaderEntry, bool) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, http.CanonicalHeaderKey(k))
	}
	sort.Strings(keys)
	truncated := len(keys) > MaxHeaders
	if truncated {
		keys = keys[:MaxHeaders]
	}
	entries := make([]HeaderEntry, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, HeaderEntry{Key: k, Values: h[k]})
	}
	return entries, truncated
}

// ProbeResult is the typed observation of one probe target: GET <url>.
// Infrastructure is never represented as ad-hoc strings: the URL, the final
// URL, and the in-scope redirect chain targets are Phase 2 URL assets, and
// the derived ports/services/endpoints/relationships live on the enclosing
// HostResult.
type ProbeResult struct {
	// Host is the canonical input host the probe belongs to.
	Host asset.Host

	// URL is the probe target: the canonical Phase 2 URL asset
	// (http://host/ or https://host/ — default port removed). This is the
	// identity of the probe and the cache key target; it is never a dial
	// address.
	URL asset.URL

	// Scheme is the probe scheme, "http" or "https".
	Scheme string

	// Status classifies the probe outcome (see ProbeStatus).
	Status ProbeStatus

	// Cached reports that the result was served from a completed cache
	// record without issuing any network request.
	Cached bool

	// Executed reports that the probe job actually ran. It is false only
	// for probe targets that were never submitted (run teardown before the
	// job started). Only executed probes contribute typed assets and
	// relationships to the report.
	Executed bool

	// StatusCode is the status code of the last response actually received
	// (the original request's response when no redirect was followed, or
	// the final followed hop's response). Zero when no HTTP response was
	// received (conn_refused, tls, timeout, dns, cancellation). For a
	// redirect-capped probe it is the status of the last followed response.
	StatusCode int

	// FinalURL is the last URL actually requested: the probe target when
	// no in-scope redirect was followed, otherwise the last followed
	// in-scope hop's URL. Always a canonical Phase 2 URL asset.
	FinalURL asset.URL

	// RedirectChain records every observed Location target in order,
	// bounded at MaxRedirects+1 entries. In-scope hops carry typed URL
	// assets; out-of-scope hops carry canonicalized strings and were NEVER
	// requested.
	RedirectChain []RedirectHop

	// Headers are the final response's headers, bounded and sorted by
	// canonical key (see boundedHeaders).
	Headers []HeaderEntry

	// ResponseSize is the number of body bytes actually read from the
	// final response, capped at MaxBodyBytes. Body content is never
	// retained — bytes are counted only.
	ResponseSize int64

	// TLS reports that the https probe completed a TLS handshake. Always
	// false for http probes.
	TLS bool

	// TLSMeta is the typed TLS observation of a completed https probe (the
	// 5C metadata shape): the leaf certificate as a Phase 2 asset and the
	// techintel.TLSInfo-shaped fields (ALPN / Issuer / Subject / DNSNames
	// map field-for-field onto techintel.TLSInfo; see tls.go). It is nil
	// when the probe completed no TLS handshake (http probes,
	// conn_refused, tls-failure, timeouts, cancellation), and also nil when
	// a completed handshake produced no captureable peer certificate (a
	// defensive transport path; TLS remains true then). A truncated probe
	// (redirect, header, or body cap) retains the terminal handshake's
	// metadata here in the observation, but contributes no certificate
	// asset or edges (see assemble) — its record is stored incomplete and
	// never served from cache.
	TLSMeta *TLSMetadata

	// Truncated reports that the probe hit a hard cap (redirects, headers,
	// or body). The observation is incomplete by definition and was stored
	// incomplete — it can never be served from cache as a completed result.
	Truncated bool

	// FailureReason is the typed cause for failed probes and for completed
	// probes without an HTTP response (see FailureReason).
	FailureReason FailureReason

	// Err carries the classification cause for failed and cancelled
	// probes, plus non-fatal diagnostics (for example cache read warnings)
	// joined for other outcomes.
	Err error
}

// Status classifies one host's overall probing outcome, mirroring the DNS
// pipeline's host-level convention (completed / incomplete / failed /
// cancelled).
type Status string

const (
	// StatusCompleted: every probe of the host finished with a trustworthy
	// result (HTTP responses of any code, and the legitimate negative
	// observations conn_refused / tls-failure).
	StatusCompleted Status = "completed"
	// StatusIncomplete: partial results only — at least one probe completed
	// while another failed or hit a cap. The successful parts are retained.
	StatusIncomplete Status = "incomplete"
	// StatusFailed: no usable observations (every probe failed).
	StatusFailed Status = "failed"
	// StatusCancelled: the run was cancelled before probing finished.
	// Whatever was observed is retained.
	StatusCancelled Status = "cancelled"
)

// String returns the stable status label.
func (s Status) String() string { return string(s) }

// HostResult is the full outcome of probing one input host: the typed
// observations of its two probe targets (http and https), the derived Phase 2
// assets, and the typed relationships.
type HostResult struct {
	// Host is the canonical input host.
	Host asset.Host

	// Status classifies the overall host outcome (see Status).
	Status Status

	// Probes holds the per-target observations in stable order: the http
	// probe, then the https probe. It is safe to read after Probe returns.
	Probes []ProbeResult

	// URLs are the probe target URL assets (http://host/ and https://host/),
	// deduplicated by Phase 2 identity, sorted by canonical URL.
	URLs []asset.URL

	// Ports are the ports observed open on the host (80/tcp for a served or
	// TLS-failed http/https probe, 443/tcp likewise), deduplicated by
	// identity, sorted. Ports that were refused, timed out, or never probed
	// are not included.
	Ports []asset.Port

	// Services are the services confirmed on the host (http on 80, https on
	// 443 — only when a probe completed with an HTTP response),
	// deduplicated by identity, sorted.
	Services []asset.Service

	// TLSCertificates are the leaf TLS certificates observed serving the
	// host: one per https probe that completed a handshake whose leaf was
	// representable in the Phase 2 model (the 5C observation),
	// deduplicated by fingerprint, sorted by fingerprint.
	TLSCertificates []asset.TLSCertificate

	// Endpoints are the probe endpoints (GET on each probe target),
	// deduplicated by identity, sorted. Endpoints describe the probed
	// request shapes of executed jobs and exist regardless of outcome.
	Endpoints []asset.Endpoint

	// IPs are the caller-provided resolved addresses (DNS-pipeline
	// observations) that probing dialed and attached edges to, when any
	// were provided. Probing itself observes no addresses.
	IPs []asset.IP

	// Relationships are the typed edges derived from the observations:
	// host->url for served URLs, ip->port for open ports (requires a
	// caller-provided resolved address), port->service for confirmed
	// services, and url->endpoint for the probe shapes. Edges are
	// deduplicated by relationship identity and sorted deterministically.
	Relationships []asset.Relationship

	// Err carries the cause for hosts whose jobs were never submitted (run
	// cancellation or pool errors). It is nil for hosts whose jobs executed.
	Err error
}

// Report is the complete outcome of one probing run.
type Report struct {
	// Target is the declared scope domain.
	Target asset.Domain

	// Results holds one entry per input host, sorted by canonical name. It
	// is safe to read after Probe returns; Probe's pool shutdown is the
	// join point.
	Results []HostResult
}

// AllHosts merges every host asset across the report (the input hosts).
// Hosts sharing a Phase 2 identity are merged with asset.MergeHosts
// semantics (earliest provenance wins). The result is sorted by canonical
// name.
func (r Report) AllHosts() []asset.Host {
	hosts := make([]asset.Host, 0, len(r.Results))
	for _, hr := range r.Results {
		hosts = append(hosts, hr.Host)
	}
	return mergeHosts(hosts)
}

// AllURLs merges every probe target URL asset across the report.
func (r Report) AllURLs() []asset.URL {
	var urls []asset.URL
	for _, hr := range r.Results {
		urls = append(urls, hr.URLs...)
	}
	return mergeURLs(urls)
}

// AllPorts merges every open-port asset across the report.
func (r Report) AllPorts() []asset.Port {
	var ports []asset.Port
	for _, hr := range r.Results {
		ports = append(ports, hr.Ports...)
	}
	return mergePorts(ports)
}

// AllServices merges every confirmed-service asset across the report.
func (r Report) AllServices() []asset.Service {
	var services []asset.Service
	for _, hr := range r.Results {
		services = append(services, hr.Services...)
	}
	return mergeServices(services)
}

// AllEndpoints merges every probe endpoint asset across the report.
func (r Report) AllEndpoints() []asset.Endpoint {
	var endpoints []asset.Endpoint
	for _, hr := range r.Results {
		endpoints = append(endpoints, hr.Endpoints...)
	}
	return mergeEndpoints(endpoints)
}

// AllTLSCertificates merges every leaf TLS certificate asset observed
// serving a host across the report (the 5C observations).
func (r Report) AllTLSCertificates() []asset.TLSCertificate {
	var certs []asset.TLSCertificate
	for _, hr := range r.Results {
		certs = append(certs, hr.TLSCertificates...)
	}
	return mergeTLSCertificates(certs)
}

// AllIPs merges every caller-provided resolved address asset across the
// report.
func (r Report) AllIPs() []asset.IP {
	var ips []asset.IP
	for _, hr := range r.Results {
		ips = append(ips, hr.IPs...)
	}
	return mergeIPs(ips)
}

// AllRelationships merges every relationship across the report,
// deduplicated by edge identity and sorted deterministically.
func (r Report) AllRelationships() []asset.Relationship {
	var rels []asset.Relationship
	for _, hr := range r.Results {
		rels = append(rels, hr.Relationships...)
	}
	return sortRelationships(rels)
}

// mergeHosts deduplicates hosts by Phase 2 identity using asset.MergeHosts.
func mergeHosts(hosts []asset.Host) []asset.Host {
	byID := make(map[asset.Identity]int)
	var out []asset.Host
	for _, h := range hosts {
		if idx, ok := byID[h.Identity()]; ok {
			if m, err := asset.MergeHosts(out[idx], h); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[h.Identity()] = len(out)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// mergeIPs deduplicates addresses by Phase 2 identity using asset.MergeIPs.
func mergeIPs(ips []asset.IP) []asset.IP {
	byID := make(map[asset.Identity]int)
	var out []asset.IP
	for _, ip := range ips {
		if idx, ok := byID[ip.Identity()]; ok {
			if m, err := asset.MergeIPs(out[idx], ip); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[ip.Identity()] = len(out)
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.String() < out[j].Addr.String() })
	return out
}

// mergeURLs deduplicates URLs by Phase 2 identity using asset.MergeURLs.
func mergeURLs(urls []asset.URL) []asset.URL {
	byID := make(map[asset.Identity]int)
	var out []asset.URL
	for _, u := range urls {
		if idx, ok := byID[u.Identity()]; ok {
			if m, err := asset.MergeURLs(out[idx], u); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[u.Identity()] = len(out)
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// mergePorts deduplicates ports by Phase 2 identity using asset.MergePorts.
func mergePorts(ports []asset.Port) []asset.Port {
	byID := make(map[asset.Identity]int)
	var out []asset.Port
	for _, p := range ports {
		if idx, ok := byID[p.Identity()]; ok {
			if m, err := asset.MergePorts(out[idx], p); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[p.Identity()] = len(out)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// mergeServices deduplicates services by Phase 2 identity using
// asset.MergeServices.
func mergeServices(services []asset.Service) []asset.Service {
	byID := make(map[asset.Identity]int)
	var out []asset.Service
	for _, s := range services {
		if idx, ok := byID[s.Identity()]; ok {
			if m, err := asset.MergeServices(out[idx], s); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[s.Identity()] = len(out)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity().String() < out[j].Identity().String() })
	return out
}

// mergeEndpoints deduplicates endpoints by Phase 2 identity using
// asset.MergeEndpoints.
func mergeEndpoints(endpoints []asset.Endpoint) []asset.Endpoint {
	byID := make(map[asset.Identity]int)
	var out []asset.Endpoint
	for _, ep := range endpoints {
		if idx, ok := byID[ep.Identity()]; ok {
			if m, err := asset.MergeEndpoints(out[idx], ep); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[ep.Identity()] = len(out)
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity().String() < out[j].Identity().String() })
	return out
}

// mergeTLSCertificates deduplicates TLS certificate assets by Phase 2
// identity (the fingerprint) using asset.MergeTLSCertificates; merge errors
// are impossible for identity-equal observations and are skipped
// defensively, keeping the first observation. The result is sorted by
// identity, so it is deterministic.
func mergeTLSCertificates(certs []asset.TLSCertificate) []asset.TLSCertificate {
	byID := make(map[asset.Identity]int)
	var out []asset.TLSCertificate
	for _, c := range certs {
		if idx, ok := byID[c.Identity()]; ok {
			if m, err := asset.MergeTLSCertificates(out[idx], c); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[c.Identity()] = len(out)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity().String() < out[j].Identity().String() })
	return out
}

// sortRelationships orders relationships deterministically by identity.
func sortRelationships(rs []asset.Relationship) []asset.Relationship {
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID() < rs[j].ID() })
	return rs
}

// classifyHost maps a host's per-probe outcomes to its overall status,
// deterministically, in priority order (mirroring the DNS pipeline):
//
//   - any cancelled probe -> cancelled (run teardown; never success)
//   - any truncated probe -> incomplete (the captured observation is
//     incomplete by definition)
//   - failed with at least one completed probe -> incomplete (partial; the
//     completed probes are retained)
//   - every probe failed -> failed
//   - otherwise (all probes completed, including the legitimate negative
//     observations conn_refused / tls) -> completed
func classifyHost(probes []ProbeResult) Status {
	var completed, failed, cancelled, truncated bool
	for _, pr := range probes {
		switch pr.Status {
		case ProbeCompleted:
			completed = true
		case ProbeFailed:
			failed = true
		case ProbeCancelled:
			cancelled = true
		case ProbeTruncated:
			truncated = true
		}
	}
	switch {
	case cancelled:
		return StatusCancelled
	case truncated:
		return StatusIncomplete
	case failed && completed:
		return StatusIncomplete
	case failed:
		return StatusFailed
	default:
		return StatusCompleted
	}
}

// portForScheme returns the TCP port asset for a probe scheme, or nil for an
// unknown scheme.
func portForScheme(scheme string) *asset.Port {
	switch scheme {
	case "http":
		p, err := asset.NewPort(80, "tcp", asset.Provenance{})
		if err != nil {
			return nil
		}
		return &p
	case "https":
		p, err := asset.NewPort(443, "tcp", asset.Provenance{})
		if err != nil {
			return nil
		}
		return &p
	}
	return nil
}

// assemble derives the typed assets and relationships of one host from its
// probe observations:
//
//   - the probe target URLs are host assets of the report (they are the
//     probed surface, regardless of outcome)
//   - url->endpoint(GET) edges for every probe target of an executed job:
//     the endpoint describes the probed request shape; it exists regardless
//     of the outcome, and cached hits reproduce it from the stored
//     observation
//   - host->url edges only for served URLs (a probe completed with an HTTP
//     response)
//   - ip->port edges for open ports (served, or a TLS handshake failure
//     proving a listener) — only when the caller provided a resolved address
//     for the host (DNS-pipeline observation)
//   - port->service edges only for confirmed services (a probe completed
//     with an HTTP response); a TLS failure proves a listener but not a
//     service
//   - host->tls_certificate and port->tls_certificate edges for every leaf
//     certificate captured from a completed https handshake (the 5C
//     observation); the certificate asset is collected on the host result
//     alongside them
//
// Redirect-hop and final URLs are recorded in the observations only; the
// graph stays about the probed surface (see the package documentation,
// "Relationship mapping").
func assemble(host asset.Host, probes []ProbeResult, e *env) HostResult {
	hr := HostResult{Host: host, Probes: probes}
	prov := asset.Provenance{Source: "http-probe", DiscoveredAt: e.clock.Now().UTC()}

	var urls []asset.URL
	var ports []asset.Port
	var services []asset.Service
	var endpoints []asset.Endpoint
	var certs []asset.TLSCertificate
	var rels []asset.Relationship
	relSet := make(map[string]bool)
	addRel := func(from asset.Identity, kind asset.RelationshipKind, to asset.Identity) {
		r, err := asset.NewRelationship(from, kind, to)
		if err != nil {
			return // cannot happen with validated identities; skip defensively
		}
		if relSet[r.ID()] {
			return
		}
		relSet[r.ID()] = true
		rels = append(rels, r)
	}

	for _, pr := range probes {
		urls = append(urls, pr.URL)
		if !pr.Executed {
			// The job never ran (never submitted): no assets beyond the
			// probe target itself.
			continue
		}
		ep, err := asset.NewEndpoint("GET", pr.URL.String(), prov)
		if err == nil {
			endpoints = append(endpoints, ep)
			addRel(pr.URL.Identity(), asset.RelationshipURLToEndpoint, ep.Identity())
		}
		if pr.Status != ProbeCompleted {
			continue
		}
		served := pr.StatusCode != 0
		open := served || pr.FailureReason == ReasonTLS
		if served {
			addRel(host.Identity(), asset.RelationshipHostToURL, pr.URL.Identity())
		}
		if pr.TLSMeta != nil && !pr.TLSMeta.Certificate.Identity().IsZero() {
			// The 5C certificate asset: every leaf certificate of a
			// completed https handshake representable in the Phase 2 model
			// becomes a host-level asset with host->tls_certificate and
			// port->tls_certificate edges. A completed handshake exists
			// only on an https probe (validateStoredTLS enforces the same
			// rule for stored records), so the port is the https probe's
			// own port and is always among the open ports above. A
			// metadata-only capture (chain deeper than the model cap)
			// contributes no asset and no edges.
			c := pr.TLSMeta.Certificate
			certs = append(certs, c)
			addRel(host.Identity(), asset.RelationshipHostToTLSCertificate, c.Identity())
			if p := portForScheme(pr.Scheme); p != nil {
				addRel(p.Identity(), asset.RelationshipPortToTLSCertificate, c.Identity())
			}
		}
		if open {
			if p := portForScheme(pr.Scheme); p != nil {
				ports = append(ports, *p)
				if ip, ok := e.ips[host.Name]; ok {
					addRel(ip.Identity(), asset.RelationshipIPToPort, p.Identity())
				}
				if served {
					if svc, err := asset.NewService(pr.Scheme, *p, prov); err == nil {
						services = append(services, svc)
						addRel(p.Identity(), asset.RelationshipPortToService, svc.Identity())
					}
				}
			}
		}
	}

	if ip, ok := e.ips[host.Name]; ok {
		hr.IPs = append(hr.IPs, ip)
	}
	hr.URLs = mergeURLs(urls)
	hr.Ports = mergePorts(ports)
	hr.Services = mergeServices(services)
	hr.Endpoints = mergeEndpoints(endpoints)
	hr.TLSCertificates = mergeTLSCertificates(certs)
	hr.IPs = mergeIPs(hr.IPs)
	hr.Relationships = sortRelationships(rels)
	hr.Status = classifyHost(probes)
	return hr
}

// fmtHostResult is a small identity helper used in error messages.
func fmtHostResult(hr HostResult) string {
	return fmt.Sprintf("host %s (%s)", hr.Host.Name, hr.Status)
}
