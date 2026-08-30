// Package takeover is RavenRecon's subdomain takeover detection pack
// (v2.1 Batch 1, high-value recon win).
//
// It follows the pack loader story established in Batch 1 (OPT-P1-2) and
// extended in Batches 2-6 (Web/JS/APIs/Cloud/Triage): packs are in-repo Go
// packages sibling to internal/detect/examples, exporting Rules()
// ([]Rule,error) starting with CheckAPIVersion(1,0), registered through
// ValidateRule → Registry.Register (deep copy) → Validate graph → Seal
// (startup confinement), never auto-discovered.
//
// Research rationale (NEW-95 v2.1, ARCHITECTURE.md:752): DNS already emits
// host→CNAME at depth 1 (CNAME chain followed once, target's A/AAAA at
// depth 1) and httpprobe already emits conn_refused/tls observations, but no
// pack correlates them. Takeover detection is a high-value recon win that
// reuses those already-emitted relationships + evidence without new I/O,
// new asset kinds, or SDK surface changes.
//
// Rules (3, each <100 lines, deterministic fixtures, informational per §0.1):
//
//	takeover.cname.unclaimed — information — relationships+assets — per-host dangling CNAME to unclaimed provider fingerprint (github.io, herokuapp.com, amazonaws.com, azurewebsites.net, cloudfront.net, etc) with no A/AAAA for the CNAME target — informational, never claims exploitability
//	takeover.cname.dangling   — information — relationships+assets — per-host dangling CNAME (any target with no A/AAAA) excluding provider-matched hosts — informational orphan signal
//	takeover.s3.bucket        — information — endpoints — per-endpoint S3 bucket endpoint observed (host shape .s3.amazonaws.com) — informational indicator via techintel endpoint shape
//
// Each rule honors context.Context, uses Detector
// func(context.Context,*Context)([]asset.Finding,error), builds findings
// via asset.NewFinding (CategoryInformation, PriorityInfo, MethodDetection
// evidence, observed subjects), respects RequiredAssetTypes (single primary
// kind — see rules.go for census-gate tradeoff), handles Config
// deterministically (sorted keys, explicit disabled lookups), and caps
// emission at 256 deterministically with truncated metadata.
//
// This pack produces RECON OBSERVATIONS, not vulnerability claims: every
// finding is CategoryInformation / PriorityInfo, StatusOpen, Confidence 0.6
// (heuristic), with metadata naming the signal and never claiming
// exploitability, reachability, or validity (AGENTS §0.1).
//
// Loading sketch (SDK-only, no core edits):
//
//	rules, err := takeover.Rules() // CheckAPIVersion(1,0) first
//	if err != nil { return err }
//	reg := detect.NewRegistry()
//	for _, r := range rules {
//	    if err := reg.Register(r); err != nil { return err } // ValidateRule → deep copy
//	}
//	if err := reg.Validate(); err != nil { return err } // graph
//	reg.Seal() // startup confinement
//	cfg := detect.DefaultEngineConfig(reg)
//	rep, err := detect.Run(ctx, cfg, snap) // per-rule Context clone already proven
package takeover
