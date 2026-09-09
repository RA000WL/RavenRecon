// Package authz is RavenRecon's authorization-signal detection pack
// (NEW-142 Task 1, first honest SDK v2 consumer beyond the auth demo probe).
//
// It follows the pack loader story established in Batch 1 (OPT-P1-2) and
// extended in Batches 2-6 plus v2.1 Batch 1 (Web/JS/APIs/Cloud/Triage/
// Takeover): packs are in-repo Go packages sibling to
// internal/detect/examples, exporting Rules() ([]Rule,error) starting with
// CheckAPIVersion(2,0), registered through ValidateRule → Registry.Register
// (deep copy) → Validate graph → Seal (startup confinement), never
// auto-discovered.
//
// Research rationale (NEW-142): triage.idor already flags IDOR-shaped query
// params per endpoint, and techintel already observes authentication
// technologies and session cookie/header indicators — but no pack correlates
// them. This pack reads both through the SDK v2 read-only views
// (Context.PriorFindings for the triage signals, Context.GraphView for the
// host→technology attribution) without new I/O, new asset kinds, or SDK
// surface changes.
//
// Rules (2):
//
//	authz.idor.insecure-direct-object — authorization — per-endpoint IDOR candidate surface on cross-host same-domain auth divergence
//	authz.idor.path-object — authorization — per-endpoint path-object IDOR candidate surface on cross-host same-domain auth divergence
//
// The rule emits ONLY on cross-host, same-domain endpoint pairs that share
// a triage-flagged IDOR param where exactly one side carries an observed
// auth signal: the subject is the UNAUTHENTICATED endpoint, the peer is
// cited in metadata. Priority is medium (confidence 0.7) when live
// reflection evidence backs a flagged param, else info (confidence 0.5) —
// never high, never an exploitability claim. The path-object rule emits
// ONLY on cross-host, same-domain endpoint pairs that share a qualifying
// numeric/UUID path segment value (api.rest.idor-indicator signal with the
// year/pagination exclusions, confirmed present in each side's own path —
// endpoint URLs are never mined beyond that confirmation) where exactly
// one side carries an observed auth signal: fixed info (confidence 0.5),
// never medium — the apis signal carries no reflection marker to split on.
//
// Each rule honors context.Context, uses Detector
// func(context.Context,*Context)([]asset.Finding,error), builds findings
// via asset.NewFinding (CategoryAuthorization, observed endpoint subjects
// only — parameter identities ride metadata strings, never Subject), respects
// RequiredAssetTypes (single primary kind KindEndpoint — the NEW-108
// census-gate precedent), handles Config deterministically (sorted keys,
// explicit disabled lookup), and caps emission at 256 deterministically with
// subjects_dropped + truncated metadata and a LevelWarn log (NEW-135).
//
// This pack produces RECON SIGNALS, not vulnerability claims: every finding
// carries verdict=candidate-surface, wording that names a researcher-review
// candidate, never proof of unauthorized access (AGENTS §0.1).
//
// Loading sketch (SDK-only, no core edits):
//
//	rules, err := authz.Rules() // CheckAPIVersion(2,0) first
//	if err != nil { return err }
//	reg := detect.NewRegistry()
//	for _, r := range rules {
//	    if err := reg.Register(r); err != nil { return err } // ValidateRule → deep copy
//	}
//	if err := reg.Validate(); err != nil { return err } // graph: fails without triage.idor
//	reg.Seal() // startup confinement
//	cfg := detect.DefaultEngineConfig(reg)
//	rep, err := detect.Run(ctx, cfg, snap) // triage.idor completes at level 0, authz reads priors at level 1
package authz
