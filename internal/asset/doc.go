// Package asset defines RavenRecon's normalized asset model.
//
// It provides typed, canonical representations of reconnaissance data —
// domains, hosts, IPs, ports, services, URLs, endpoints, and JavaScript
// resources — together with deterministic identity, provenance, merge, and
// serialization primitives.
//
// The package is intentionally independent of external reconnaissance tools.
// Provenance sources are generic capability names ("passive-discovery",
// "http-probe") rather than specific binaries.
//
// Future stages (discovery, DNS, HTTP, TLS, URL, JS, scoring) consume these
// types. A persistent store, correlation engine, and asset graph are NOT part
// of this phase.
package asset
