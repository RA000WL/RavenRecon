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
//
// Hostname label policy: per RFC 8552 service labels a label may start with a
// leading underscore '_' (e.g. "_dmarc", "_acme-challenge",
// "s1._domainkey") followed by one or more [a-z0-9-] characters; the remainder
// after the underscore is subject to the same hyphen rules as ordinary labels
// (must not start or end with '-'). Mid-label underscores remain rejected per
// RFC 952/1123 — only '_' at label[0] is permitted. Bare "_" and "__*"
// labels are invalid.
package asset
