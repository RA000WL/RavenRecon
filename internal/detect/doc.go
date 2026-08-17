// Package detect is RavenRecon's Detection Framework & Rule Engine
// (phase 10): the execution engine that runs reusable detection rules
// against the canonical knowledge graph.
//
// The framework itself detects nothing. It provides rule registration,
// validation, dependency-ordered scheduling on the shared runtime pool,
// per-rule timeouts with panic isolation, a rule result cache, execution
// metrics, and the canonical finding pipeline. Vulnerability-specific rules
// are future phases; none ship here.
//
// A rule is an immutable descriptor plus a Detector function. Detectors
// receive a fixed, immutable Context — the structured corpus of everything
// the earlier phases observed (assets, relationships, evidence,
// technologies, secret candidates, JavaScript, endpoints), a bounded
// configuration map, a bounded Logger, the cancellation context, and the
// injected Clock — and nothing else. They operate only on those structured
// assets: no raw HTTP parsing, no JS parsing, no URL parsing (those phases
// are complete). Detectors return canonical asset.Finding values; the engine
// validates every finding against the rule's own metadata (a rule can never
// forge another rule's findings), the asset model's bounds, and the observed
// corpus (a finding can never cite an asset that was not observed).
//
// Layering mirrors the other consumer stages: internal/runtime never imports
// internal/cache, and THIS stage composes cache-before-execute (lookup →
// execute → store) around pool jobs. One pool job per rule per run;
// dependency levels execute in order, rules within a level execute in
// parallel. Findings stream through an optional Emit hook and land in a
// deterministic Report.
package detect
