// Package bizlogic is RavenRecon's business-logic-signal detection pack
// (NEW-144 Rule 1, an honest SDK v2 consumer alongside the authz pack).
//
// It follows the pack loader story established in Batch 1 (OPT-P1-2) and
// extended in Batches 2-6 plus v2.1 Batch 1 and NEW-142 (Web/JS/APIs/Cloud/
// Triage/Takeover/AuthZ): packs are in-repo Go packages sibling to
// internal/detect/examples, exporting Rules() ([]Rule,error) starting with
// CheckAPIVersion(2,0), registered through ValidateRule → Registry.Register
// (deep copy) → Validate graph → Seal (startup confinement), never
// auto-discovered.
//
// Research rationale (NEW-144): triage.idor already flags IDOR-shaped query
// params per endpoint, authz.idor already correlates cross-host auth
// divergence, and the snapshot graph already links hosts to their endpoints
// — but no pack asks whether same-host endpoints sharing one IDOR-shaped
// token form a candidate multi-step workflow (a state-transition shape: the
// same identifier carried across distinct steps of one host). This pack
// reads all three through the SDK v2 read-only views
// (Context.PriorFindings for the triage token signals and the authz member
// signal, Context.GraphView.Path for host⇝step co-reachability)
// without new I/O, new asset kinds, or SDK surface changes.
//
// Rules (1; Rule 2 / cross-host / POST-body correlation is a deferred
// slice, never a placeholder here):
//
//	bizlogic.workflow.state-transition — business_logic — candidate multi-step workflow on one host
//
// The rule emits at most one candidate-flow finding per (host, shared
// token) step set: every step carries the same triage-flagged IDOR token
// (confirmed present in its own query string — endpoint URLs are never
// mined), every step sits on the same host, every step is co-reachable
// from the host through the observed graph (a directed host⇝step path for
// every step — Path-only co-reachability; JavaScript-hub correlation needs
// an SDK reverse lookup, step → referencing scripts, which is a deferred
// follow-up needing sign-off, never improvised here), at least one step
// carries an authz.idor candidate (the auth-divergent member), and the
// steps are dissimilar (distinct identities over distinct method+path
// pairs — GET+POST on one path still counts as two steps, while
// pagination twins collapse and stay quiet). The subject is the
// identity-smallest step; peers ride metadata strings only.
// Priority is always info — confidence 0.5 for 2-step flows, 0.6 for 3+
// steps — never medium or higher, never an exploitability claim.
//
// Each rule honors context.Context, uses Detector
// func(context.Context,*Context)([]asset.Finding,error), builds findings
// via asset.NewFinding (CategoryBusinessLogic, observed endpoint subjects
// only — parameter identities ride metadata strings, never Subject), respects
// RequiredAssetTypes (single primary kind KindEndpoint — the NEW-108
// census-gate precedent), handles Config deterministically (sorted keys,
// explicit disabled lookup), and caps emission at 256 deterministically with
// subjects_dropped + truncated metadata and a LevelWarn log (NEW-135).
// Flows that cannot fit the finding bounds (more than maxFlowSteps steps,
// or a flow_steps citation over 256 bytes) are SKIPPED with a LevelInfo
// count — a long flow is never truncated into a shorter one.
//
// This pack produces RECON SIGNALS, not vulnerability claims: every finding
// carries verdict=candidate-flow with edge_basis=correlated-not-traversed
// wording that names a researcher-review candidate workflow, never a
// confirmed transition and never proof of anything beyond the observed
// correlation (AGENTS §0.1).
//
// Loading sketch (SDK-only, no core edits):
//
//	rules, err := bizlogic.Rules() // CheckAPIVersion(2,0) first
//	if err != nil { return err }
//	reg := detect.NewRegistry()
//	for _, r := range rules {
//	    if err := reg.Register(r); err != nil { return err } // ValidateRule → deep copy
//	}
//	if err := reg.Validate(); err != nil { return err } // graph: fails without authz.idor
//	reg.Seal() // startup confinement
//	cfg := detect.DefaultEngineConfig(reg)
//	rep, err := detect.Run(ctx, cfg, snap) // triage L0, authz L1, bizlogic reads priors at L2
package bizlogic
