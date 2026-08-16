// Package priority is the Attack Surface Intelligence Engine (Phase 9,
// Round 1): it consumes canonical Phase 2 assets, relationships, and
// evidence — already normalized by the earlier phases — and produces
// explainable, deterministic priorities for which surfaces deserve a
// researcher's attention first.
//
// The engine is a PRIORITY engine, nothing more. It is explicitly NOT a
// vulnerability detector: it never claims a weakness, never assigns
// severity, never names CVEs or misconfigurations, and never tests
// anything. Its only output is a ranked, fully explained interestingness
// judgment — "this surface combines an administrative path with an
// authenticated technology and a high-value secret candidate" — that a
// human researcher (or a later reporting phase) consumes. Every factor
// cites the canonical asset identity it was derived from, so every score
// can be audited back to observations.
//
// Round 1 landed the canonical model types, the two data-driven catalogs
// (interestingness and risk indicators), and the pure scoring engine with
// tests and benchmarks. Round 2 landed the intelligence layer
// (deterministic Correlate grouping, evidence-tied attack-path
// hypotheses, and recommendations rendered onto every indicator factor)
// and the engine stage: bounded workers on the runtime pool with
// cache-before-execute composed around pool jobs (operation
// "priority.score"), catalog-digest cache keys, and strict decode
// re-validation with eviction. CLI wiring and the reporting phase that
// consumes groups, paths, and recommendations remain future work.
//
// Design mirrors:
//
//   - internal/secrentel/patterns — the compile-once, validated,
//     data-only catalog discipline (unique IDs, strict validation, schema
//     version for future cache keys, no mutation after Load);
//   - internal/secrentel/confidence.go — the factor combination math
//     (1 − ∏(1 − w)), fixed thresholds, caps, and level gates;
//   - determinism everywhere: no map-iteration-order dependence, no
//     randomness, no clock reads (timestamps are explicit inputs), and
//     identical signals produce bit-for-bit identical results.
//
// Catalog entries reference ONLY data the earlier phases actually emit
// (endpoint/URL paths, JavaScript asset sizes, source-map assets,
// technology names/categories/confidences, secret candidate
// types/confidences, parameter names, ports, service names, host labels,
// and httpprobe's bounded final-response headers). Where the spec's
// indicator families need data no phase produces, the family is omitted
// and the reason documented in the table source.
package priority
