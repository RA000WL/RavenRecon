// Package web is RavenRecon's web security detection pack (v2.0 Batch 2).
// It proves the pack loader story established in Batch 1 (OPT-P1-2): packs
// are in-repo Go packages sibling to internal/detect/examples, exporting
// Rules() ([]Rule,error) starting with CheckAPIVersion(1,0), registered
// through ValidateRule → Registry.Register (deep copy) → Validate graph →
// Seal (startup confinement), never auto-discovered.
//
// Research order is Web → JS → APIs → Cloud; Web first proves the pack
// story with all 7 Context domains already present (assets, relationships,
// evidence, technologies, secrets, JavaScript, endpoints). No new asset
// kinds or Snapshot fields are introduced — headers are bounded as
// Evidence, URL/tech/JS signals reuse existing domains, so no APIMajor
// bump is required.
//
// Rules (5, each <100 lines, deterministic fixtures):
//
//	web.csp.missing        — information — assets+evidence+technology — per-host CSP absence
//	web.hsts.missing       — information — assets+evidence — per-host HSTS absence
//	web.cors.wildcard      — misconfiguration — evidence — Access-Control-Allow-Origin == "*"
//	web.robots.exposed     — information — endpoints+evidence+technology — /robots.txt present
//	web.sourcemap.exposed  — information — javascript+evidence — source map exposed
//
// Each rule honors context.Context, uses Detector
// func(context.Context,*Context)([]asset.Finding,error), builds findings
// via asset.NewFinding, respects RequiredAssetTypes for census skip,
// handles Config deterministically (sorted keys, explicit lookups), and
// respects the per-rule finding bound via deterministic truncation.
//
// Loading sketch (SDK-only, no core edits):
//
//	rules, err := web.Rules() // CheckAPIVersion(1,0) first
//	if err != nil { return err }
//	reg := detect.NewRegistry()
//	for _, r := range rules {
//	    if err := reg.Register(r); err != nil { return err } // ValidateRule → deep copy
//	}
//	if err := reg.Validate(); err != nil { return err } // graph
//	reg.Seal() // startup confinement
//	cfg := detect.DefaultEngineConfig(reg)
//	rep, err := detect.Run(ctx, cfg, snap) // per-rule Context clone already proven
package web
