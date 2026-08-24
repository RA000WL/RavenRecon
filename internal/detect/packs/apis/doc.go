// Package apis is RavenRecon's API security detection pack (v2.0 Batch 4).
// It proves the pack loader story established in Batch 1 (OPT-P1-2) and
// extended in Batch 2 (Web) / Batch 3 (JS): packs are in-repo Go packages
// sibling to internal/detect/examples, exporting Rules() ([]Rule,error)
// starting with CheckAPIVersion(1,0), registered through ValidateRule →
// Registry.Register (deep copy) → Validate graph → Seal (startup confinement),
// never auto-discovered.
//
// Research order is Web → JS → APIs → Cloud; APIs third proves endpoint/URL
// reuse: it reuses the existing Context domains (Endpoints, Evidence,
// Technologies — no new asset kinds, no Snapshot field bloat, no APIMajor
// bump) to inspect the observed endpoint corpus for API surface signals —
// OpenAPI/Swagger docs, REST IDOR indicators, and GraphQL introspection —
// with stdlib-only, per-endpoint, context-honoring, bounded (256) findings.
//
// Rules (3, each <100 lines, deterministic fixtures):
//
//	api.openapi.exposed      — information — endpoints+evidence+technology — per-endpoint/tech OpenAPI/Swagger doc present
//	api.rest.idor-indicator  — information — endpoints — per-endpoint REST IDOR indicator (numeric/UUID segment)
//	api.graphql.introspection — api — endpoints+evidence+technology — per-endpoint GraphQL introspection surface
//
// Each rule honors context.Context, uses Detector
// func(context.Context,*Context)([]asset.Finding,error), builds findings
// via asset.NewFinding, respects RequiredAssetTypes (endpoint) for census
// skip, handles Config deterministically (sorted keys, explicit lookups),
// and respects the per-rule finding bound via deterministic truncation.
//
// Loading sketch (SDK-only, no core edits):
//
//	rules, err := apis.Rules() // CheckAPIVersion(1,0) first
//	if err != nil { return err }
//	reg := detect.NewRegistry()
//	for _, r := range rules {
//	    if err := reg.Register(r); err != nil { return err } // ValidateRule → deep copy
//	}
//	if err := reg.Validate(); err != nil { return err } // graph
//	reg.Seal() // startup confinement
//	cfg := detect.DefaultEngineConfig(reg)
//	rep, err := detect.Run(ctx, cfg, snap) // per-rule Context clone already proven
package apis
