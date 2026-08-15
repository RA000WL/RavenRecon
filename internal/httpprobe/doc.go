// Package httpprobe implements the HTTP probing pipeline (roadmap v0.6,
// sub-milestone 5B of Active Infrastructure): probing discovered host assets
// and attaching typed HTTP observations to the Phase 2 asset model. It is a
// library-level stage with no CLI command yet; the full design, limits,
// cancellation semantics, and security considerations live in
// ARCHITECTURE.md ("HTTP probing").
//
// # Scope
//
// Probe accepts an explicit host list (for example the output of passive
// discovery or the DNS pipeline) plus the run's declared target domain.
// Every input hostname is re-validated canonically through the Phase 2 asset
// model and must be the target domain itself or a subdomain of it; anything
// non-canonical or out-of-domain is rejected before a single request is
// issued. Redirects are followed ONLY into the target domain: an in-scope
// Location is normalized through asset.ParseURL and may be followed (up to
// MaxRedirects hops), while an out-of-scope Location — including any IP
// literal, which is never in scope — is recorded as a canonicalized display
// string and NEVER requested. The package is a boundary, not an
// arbitrary-scanning feature, and redirect handling cannot be abused to
// chase probing outside the declared domain or to rebind to arbitrary
// addresses.
//
// # Observations and relationships
//
// Every host is probed at exactly two targets — http://host/ and
// https://host/ — with a GET request. Each probe records the final response
// status code, the final URL, the bounded redirect chain, the bounded final
// response headers, the counted (never retained) body size, whether an https
// probe completed its TLS handshake, and a typed outcome. Infrastructure is
// never represented as ad-hoc strings: probe targets, final URLs, and
// in-scope redirect hops are Phase 2 URL assets. Each host result carries
// typed asset.Relationship edges — host->url for served URLs,
// url->endpoint(GET) for the probe shapes, ip->port for open ports (only
// with a caller-provided resolved address), and port->service for confirmed
// services (see observe.go, "assemble").
//
// Two legitimate negative observations count as COMPLETED probes with no
// HTTP response: a connection refusal proves the service is absent on that
// port (ReasonConnRefused), and a TLS handshake failure — certificate
// verification failure, protocol mismatch, or a non-TLS server on the https
// port — proves https is not served on that endpoint from RavenRecon's
// trust perspective (ReasonTLS). On a completed https handshake the probe
// also captures typed TLS metadata — the leaf certificate as a Phase 2
// asset plus the ALPN protocol, issuer DN, subject CN, and SAN DNS names
// (sub-milestone 5C; see tls.go).
//
// # Concurrency and rate limiting
//
// Probing runs on a single bounded runtime.Pool with one job per host. Each
// job performs its two bounded probes sequentially, honors the per-job
// deadline and cancellation, and — on a cache miss — waits on one shared
// central token-bucket limiter (the runtime engine's Limiter) before every
// outbound request, INCLUDING each followed redirect hop, so the aggregate
// request dispatch rate is bounded regardless of concurrency. The pool's
// job-start rate limiting is deliberately disabled; the central limiter
// subsumes it.
//
// # Cancellation
//
// Cancellation is classified per probe: a probe cancelled before dispatch
// and a probe cancelled while in flight are both recorded cancelled, a host
// whose job never started keeps its initialized cancelled status, and once
// the job context is done no further request is issued. In-flight requests
// are cancelled promptly by the stdlib transport when their context is
// cancelled, and the pool shutdown budgets bound the overall drain.
//
// # Caching
//
// Each probe target is cached under its own Phase 3 key composed of exactly
// the operation ("http.probe") and the canonical Phase 2 URL identity (see
// cache.go) — nothing else: the request shape is fixed, the caps are fixed
// constants, and timings, rate limits, and the transport never enter a key.
// HTTP responses of any code and the legitimate negative observations are
// stored completed; truncated probes are stored incomplete and never served;
// failed and cancelled probes are stored failed/cancelled and can never be
// served as success. A cache hit performs zero network requests, and TTL
// semantics are the Phase 3 cache's own.
//
// # Resource limits
//
// Per probe: at most MaxRedirects (10) in-scope redirect hops are followed
// (the observed chain is recorded at most MaxRedirects+1 entries); the final
// response's header block is byte-capped at MaxHeaderBytes (64 KiB, enforced
// by the production transport) and its retention is entry-capped at
// MaxHeaders (128); the body is counted only, capped at MaxBodyBytes (1 MiB).
// Any cap hit marks the probe truncated-incomplete by definition: the
// observation is stored incomplete and never served from cache as a
// completed result. Per-request deadlines default to 10 s
// (Config.RequestTimeout; the spec-mandated slowloris budget), per-job
// deadlines default to 30 s (the request ⊆ job ⊆ shutdown budget chain is
// invariant), and pool bounds default to 8 workers and a queue of 256. At
// most MaxConcurrentPerHost (2) requests may ever be in flight for one host;
// the current single-job-per-host design stays below the cap (one request at
// a time per host). Body content is never retained.
//
// # Known limitations
//
// The caller-provided resolved-address map attaches at most one address per
// host (for example the first A record of a DNS observation); the DNS
// pipeline's multi-address closure is not yet wired to probing, and probing
// always dials through the configured transport's own resolution, never an
// address directly. Out-of-scope redirect targets are recorded as display
// strings that are never re-parsed into the asset model. Response-body read
// failures after a response was received are diagnostics, never probe
// failures. All tests are hermetic: no unit test touches the public
// Internet.
package httpprobe
