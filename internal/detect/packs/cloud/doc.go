// Package cloud is RavenRecon's cloud-surface detection pack (v2.0 Batch 5).
// It follows the pack loader story established in Batch 1 (OPT-P1-2) and
// extended in Batches 2-4 (Web / JS / APIs): packs are in-repo Go packages
// sibling to internal/detect/examples, exporting Rules() ([]Rule,error)
// starting with CheckAPIVersion(1,0), registered through ValidateRule →
// Registry.Register (deep copy) → Validate graph → Seal (startup confinement),
// never auto-discovered.
//
// Research order is Web → JS → APIs → Cloud; Cloud fourth (research Q5):
// CLOUD RULES ARE INFORMATIONAL INDICATORS ONLY. Bucket existence, IAM
// posture, and credential validity require live confirmation that is outside
// the recon-only charter (AGENTS §0.1), so every rule emits PriorityInfo /
// StatusOpen / CategoryCloud observations about what the corpus literally
// contains — never exploitability, reachability, or validity claims. False-
// positive risk is higher than Web/JS, so heuristics are deliberately
// conservative: exact provider-host shapes for storage endpoints, whole-token
// AWS access-key shapes with the providers' documented EXAMPLE convention
// suppressed, and specific Firebase hosts/config markers.
//
// Rules (3, each <100 lines, deterministic fixtures):
//
//	cloud.aws.key-indicator  — information — secrets+evidence — per-subject AWS credential indicator observed
//	cloud.bucket.url         — information — endpoints    — per-endpoint cloud storage endpoint observed
//	cloud.firebase.indicator — information — evidence+tech+endpoints — per-subject Firebase service indicator
//
// Each rule honors context.Context, builds findings via asset.NewFinding
// with subjects drawn from the observed corpus only, respects
// RequiredAssetTypes (single primary kind — see rules.go for the per-rule
// choice under the census gate's AND semantics), handles Config
// deterministically (sorted keys, explicit lookups), and caps emission at
// 256 deterministically. Secret candidate VALUES are never copied into
// findings, metadata, logs, or errors (AGENTS §0.8/§15).
//
// Loading sketch (SDK-only, no core edits):
//
//	rules, err := cloud.Rules() // CheckAPIVersion(1,0) first
//	if err != nil { return err }
//	reg := detect.NewRegistry()
//	for _, r := range rules {
//	    if err := reg.Register(r); err != nil { return err } // ValidateRule → deep copy
//	}
//	if err := reg.Validate(); err != nil { return err } // graph
//	reg.Seal() // startup confinement
package cloud
