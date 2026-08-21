// Package dns implements the DNS pipeline (roadmap v0.6, sub-milestone 5A of
// Active Infrastructure): resolving discovered host assets and attaching
// typed DNS observations to the Phase 2 asset model. It is a library-level
// stage with no CLI command yet; the full design, limits, cancellation
// semantics, and security considerations live in ARCHITECTURE.md
// ("DNS pipeline").
//
// # Scope
//
// Resolve accepts an explicit host list (for example the output of passive
// discovery) plus the run's declared target domain. Every input hostname is
// re-validated canonically through the Phase 2 asset model and must be the
// target domain itself or a subdomain of it; anything non-canonical or
// out-of-domain is rejected before a single query is issued. A queried host's
// CNAME target is a DNS observation and may legitimately point outside the
// target domain; its addresses are resolved at depth exactly 1 (see
// "Records and relationships") and never deeper. The package is a boundary,
// not an arbitrary-scanning feature.
//
// # Records and relationships
//
// A, AAAA, and CNAME records are supported. Every observation is normalized
// into a Phase 2 asset (asset.IP for addresses, asset.Host for CNAME targets)
// — infrastructure is never represented as ad-hoc strings — and every host
// result carries typed asset.Relationship edges (host->address via
// RelationshipHostToIP, host->CNAME-target via RelationshipHostToCNAME).
// CNAME queries use the stdlib's LookupCNAME, which follows the chain to the
// final canonical target (multi-hop chains are flattened; see "Known
// limitations"). When a host's CNAME query completes with a target, the
// direct target's A and AAAA records are additionally resolved at depth
// exactly 1 so the canonical target becomes a first-class host asset with its
// own address relationships; no deeper recursion ever happens, so CNAME loops
// are impossible by construction.
//
// # Concurrency and rate limiting
//
// Resolution runs on a single bounded runtime.Pool with one job per host.
// Each job performs its bounded per-type queries sequentially, honors the
// per-job deadline and cancellation, and — on a cache miss — waits on one
// shared central token-bucket limiter (the runtime engine's Limiter) before
// every outbound query, so the aggregate query dispatch rate is bounded
// regardless of concurrency. The limiter controls only RavenRecon's own query
// dispatch pacing: the system resolver performs its own server selection and
// retries per /etc/resolv.conf, and RavenRecon neither controls nor claims to
// control that.
//
// Scope of the limiter promise: it covers the queries Resolve itself
// dispatches through its pool jobs. The standalone wildcard probe
// (IsWildcard, brute.go) is a single pre-brute query issued by the caller
// OUTSIDE Resolve's pool/env — it does not wait on the shared limiter. Its
// cost is bounded by shape (one query per domain, only when opt-in brute is
// enabled) and by the caller's context, not by pacing; routing it through a
// separately constructed limiter would share no bucket state with Resolve's
// env and would pace nothing.
//
// # Cancellation
//
// Cancellation is classified per type: a query cancelled before dispatch and
// a query cancelled while in flight are both recorded cancelled, and a host
// whose job never started keeps its initialized cancelled status. One honest
// stdlib limitation: the pure-Go resolver does not abort an in-flight UDP
// query when its context is cancelled — the query returns at the resolver's
// own per-attempt deadline, and the surfaced *net.DNSError may then carry
// IsTimeout|IsTemporary with no reachable context error (classified
// ErrTimeout). RavenRecon issues no further queries once its context is done,
// and the pool shutdown budgets bound the overall drain; in-flight
// cancellation is therefore bounded, not prompt.
//
// # Caching
//
// Each (host, record type) pair is cached under its own Phase 3 key composed
// of the operation, the canonical host identity, and the record type only
// (see cache.go). Positive answers, legitimate empty answers (NODATA-style),
// and NXDOMAIN observations are stored completed; truncated answer sets are
// stored incomplete and never served; failed, timed-out, and cancelled types
// are stored failed/cancelled and can never be served as success. A cache hit
// performs zero DNS requests, and TTL semantics are the Phase 3 cache's own.
//
// # Resource limits
//
// Per-query answers are deduplicated by Phase 2 identity, sorted, and capped
// at MaxAnswersPerType (a fixed constant, never configuration); oversized
// answer sets are retained truncated and reported (and stored) as incomplete,
// never as complete. CNAME depth is ≤ 1 by construction, per-job deadlines
// default to 30 s, and answer content is retained only as normalized
// netip.Addr/string values with bounded counts.
//
// # Known limitations
//
// Multi-hop CNAME chains are flattened to their final canonical target
// (intermediate hops are not observed); in-flight query cancellation is
// bounded but not prompt (see "Cancellation"); the system resolver's own
// retries are not subject to RavenRecon's limiter; and answers carry the OS
// resolver's trust model (no DNSSEC validation). All tests are hermetic: no
// unit test touches the public Internet.
package dns
