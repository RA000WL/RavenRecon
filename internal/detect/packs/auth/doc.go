// Package auth is the minimal SDK v2 demonstration pack for RavenRecon's
// detection framework. It proves the SDK v2 reopening (APIMajor 1→2) with a
// single stateless rule that is inexpressible on SDK v1:
//
//   - auth.jwt.none-alg reads Context.PriorFindings (findings from completed
//     dependency levels, deterministically sorted) and Context.GraphView
//     (read-only Neighbors/Path over Snapshot.Relationships+Assets).
//
// On SDK v1 the Context had no PriorFindings/GraphView fields, so the detector
// would not compile — the concrete failing need that justified the SDK v2
// 4-step gate (see internal/detect/api.go). The rule is stateless, hermetic,
// bounded (≤256 findings, <100 lines), and informational-only per §0.1 (it
// reports a shape indicator over the observed corpus, never claims
// exploitability, and never performs live verification).
//
// The pack follows the exact registration pattern the other packs proved:
// Rules() → CheckAPIVersion(2,0) → ValidateRule → Registry.Register →
// Validate → Seal, so loading is confined to startup and the compiler
// enforces that the pack uses only what internal/detect exports (pinned by
// TestPackUsesOnlyExportedSurface in the sibling packs).
package auth
