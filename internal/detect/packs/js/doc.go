// Package js is RavenRecon's JavaScript security detection pack (v2.0 Batch 3).
// It proves the parser-reuse story established in Batch 1 (OPT-P1-2) and
// extended in Batch 2 (Web): packs are in-repo Go packages sibling to
// internal/detect/examples, exporting Rules() ([]Rule,error) starting with
// CheckAPIVersion(1,0), registered through ValidateRule → Registry.Register
// (deep copy) → Validate graph → Seal (startup confinement), never
// auto-discovered.
//
// Research order is Web → JS → APIs → Cloud; JS second proves parser reuse:
// it reuses the stdlib-only jsintel parser seam (internal/jsintel.Parser,
// bounded 2 MiB JS / 1 MiB HTML, 1k scripts) to inspect synthetic script
// content derived deterministically from each observed JavaScript asset —
// no raw HTTP parsing, no new asset kinds, and no DSL/json rule files.
// The Snapshot already carries JavaScript assets; JS content for the
// synthetic fixtures is derived from the asset's canonical URL so tests
// remain hermetic and deterministic.
//
// Rules (3, each <100 lines, deterministic fixtures):
//
//	js.dom.xss                 — injection — javascript — per-script DOM XSS sink (innerHTML/outerHTML/document.write) — Parse invoked for bounding/validation (maxParseInputBytes 8MiB); sink detection is currently string-contains on the synthetic source after successful Parse — future work may inspect Parsed.Strings for token-aware filtering
//	js.postmessage.no-origin-check — misconfiguration — javascript — per-script postMessage without origin check — Parse invoked for bounding/validation (maxParseInputBytes 8MiB); sink detection is currently string-contains on the synthetic source after successful Parse — future work may inspect Parsed.Strings for token-aware filtering
//	js.prototype.pollution     — information — javascript — per-script prototype pollution assignment — Parse invoked for bounding/validation (maxParseInputBytes 8MiB); sink detection is currently string-contains on the synthetic source after successful Parse — future work may inspect Parsed.Strings for token-aware filtering
//
// Each rule honors context.Context, uses Detector
// func(context.Context,*Context)([]asset.Finding,error), builds findings
// via asset.NewFinding, respects RequiredAssetTypes (javascript) for census
// skip, handles Config deterministically (sorted keys, explicit lookups),
// and respects the per-rule finding bound via deterministic truncation.
//
// Loading sketch (SDK-only, no core edits):
//
//	rules, err := js.Rules() // CheckAPIVersion(1,0) first
//	if err != nil { return err }
//	reg := detect.NewRegistry()
//	for _, r := range rules {
//	    if err := reg.Register(r); err != nil { return err } // ValidateRule → deep copy
//	}
//	if err := reg.Validate(); err != nil { return err } // graph
//	reg.Seal() // startup confinement
//	cfg := detect.DefaultEngineConfig(reg)
//	rep, err := detect.Run(ctx, cfg, snap) // per-rule Context clone already proven
package js
