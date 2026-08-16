// Package secrentel is the Phase 8 Evidence & Secret Intelligence Engine: a
// library-level engine (no CLI command) that scans bounded documents
// (JavaScript, source maps, HTML, JSON, environment files, configuration,
// YAML, XML, GraphQL, OpenAPI, and raw HTTP responses) for secret candidates
// and classifies them into a structured, evidence-driven model.
//
// The engine is deliberately NOT a "secret scanner": it is an evidence
// engine. Every emitted candidate carries its canonical Phase 2
// asset.SecretCandidate identity, the pattern fingerprints that matched, an
// entropy assessment, extracted context (variable names, JSON keys, comments,
// nearby provider indicators), multi-evidence correlation (provider
// endpoints, sibling candidates, technologies), and a confidence score
// composed from all of those signals. No anonymous strings are ever
// returned.
//
// Phase boundaries, by design:
//
//   - Candidates are detected, NEVER verified: no network call, no cloud API
//     validation, no AWS/GitHub/Stripe validation, no exploitation. The
//     offline verification QUEUE records which candidates a future
//     verification module should consume; it executes nothing and is never
//     cached.
//   - False-positive reduction is a first-class stage: documented example
//     values, placeholders, dummy values, and lorem-ipsum material are
//     suppressed (counted, never emitted), and documentation/test/sample
//     contexts cap confidence at Low.
//   - Entropy alone NEVER classifies a secret: entropy only qualifies
//     pattern-gated candidates and contributes one confidence factor among
//     several.
//
// The pipeline mirrors techintel: a Document source seam feeds one bounded
// runtime.Pool; each document runs cache-before-execute (operation
// "secret.scan") → scan → correlate → score → merge-at-emit; the report is
// deterministic and the verification queue is derived at report build.
package secrentel
