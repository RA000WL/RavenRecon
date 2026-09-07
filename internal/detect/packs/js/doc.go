// Package js is RavenRecon's JavaScript security detection pack (v2.1 Batch 3).
// It follows the in-repo pack pattern established in Batch 1 (OPT-P1-2) and
// extended in Batch 2 (Web): packs are in-repo Go packages sibling to
// internal/detect/examples, exporting Rules() ([]Rule,error) starting with
// CheckAPIVersion(2,1), registered through ValidateRule → Registry.Register
// (deep copy) → Validate graph → Seal (startup confinement), never
// auto-discovered.
//
// Research order is Web → JS → APIs → Cloud; JS second inspects retained
// script bodies: it reads the SDK v2.1 retained-script-body channel
// (Context.JavaScriptContent, one entry per retained file body or chunk
// window) through a minimal single-pass code tokenizer (tokenize.go:
// code-vs-comment/string/template distinction with sink-LHS and
// handler-scope structural checks) —
// no new asset kinds, and no DSL/json rule files.
// The Snapshot already carries JavaScript assets; detectors iterate the
// retained bodies directly (file bodies and chunk windows alike) and
// normalize every finding subject to the FILE identity with
// file-relative offsets, so tests remain hermetic and
// deterministic. Scripts without a retained body are silent by construction,
// so the pack refuses to load on a pre-2.1 surface rather than run blind.
//
// Rules (3, each <100 lines, deterministic fixtures):
//
//	js.dom.xss                 — information — javascript — per-script DOM XSS sink in code (innerHTML/outerHTML dotted writes, document.write calls) — token-aware structural scan (comments/strings/template text quiet); scripts without a retained body are silent
//	js.postmessage.no-origin-check — information — javascript — per-script postMessage without origin check in code (static "message" handler arg, no code .origin read — file-global scope, see hasCodeOrigin) — token-aware structural scan; scripts without a retained body are silent
//	js.prototype.pollution     — information — javascript — per-script prototype pollution write in code (dotted __proto__/constructor.prototype with assignment) — token-aware structural scan; scripts without a retained body are silent
//
// Each rule honors context.Context, uses Detector
// func(context.Context,*Context)([]asset.Finding,error), builds findings
// via asset.NewFinding, respects RequiredAssetTypes (javascript) for census
// skip, handles Config deterministically (sorted keys, explicit lookups),
// and respects the per-rule finding bound via deterministic truncation.
//
// Loading sketch (SDK-only, no core edits):
//
//	rules, err := js.Rules() // CheckAPIVersion(2,1) first
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
