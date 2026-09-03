// The detection SDK is versioned in three independent layers:
//
//   - SchemaVersion (record.go) versions the CACHE RECORD LAYOUT: a schema
//     bump invalidates stored rule results; it never changes the SDK
//     contract.
//   - APIMajor/APIMinor (below) version the frozen SDK SURFACE (Level 1,
//     the "SDK v1 (Core)" freeze of milestone v1.2.5): the rule-author
//     contract — Rule, Detector, Context, Snapshot, Registry (including
//     Seal), Run, the vocabularies and parsers, and the exported bounds
//     constants. A major bump means packs must be recompiled against a new
//     contract; a minor bump is backward compatible (this build
//     understands every pack compiled against its own minor or lower).
//   - Rule.Version versions rule CONTENT: the detector's logic and
//     metadata. A content bump changes the rule's cache key (the documented
//     bump contract); it never affects SDK compatibility.
//
// Level 1 stability policy: the surface above is frozen for the lifetime of
// API (APIMajor, APIMinor). Any change that would break a pack compiled
// against it must be a deliberate, documented reopening decision that bumps
// APIMajor — never a silent alteration of the contract.
//
// SDK v2 reopening (APIMajor 1→2, SchemaVersion 2→3, 2026-08-30 — 4-step gate):
//
//  1. Concrete failing need — AuthZ/Business-logic families (e.g.
//     authz.idor.insecure-direct-object) inexpressible on SDK v1:
//     dependencies order execution but never flow data (detect.go:187-188,
//     ARCHITECTURE.md:2369); a rule cannot see findings from its
//     dependencies nor traverse the asset graph — the gate that blocked
//     auth.jwt.none-alg and similar cross-rule reasoning since v0.2.
//  2. Proposal — add Context.PriorFindings []asset.Finding (findings from
//     completed levels only, deterministically sorted by finding identity)
//     and Context.GraphView GraphQuerier (Neighbors(Identity)
//     []Relationship; Path(Identity, Identity) []Identity) as read-only
//     views over Snapshot.Relationships+Assets; engine level barrier
//     collects findings, GraphView wraps snapshot relationships with a map
//     index built once per Run; fingerprintSnapshot gains graph_digest and
//     ruleKey gains graph_digest; SchemaVersion 2→3 invalidates old
//     detect.rule records by construction.
//  3. Maintainer approval — documented here as the deliberate reopening
//     decision that bumps APIMajor (this file) — never a silent alteration.
//  4. Golden regeneration in the SAME change — testdata/api_v1.golden →
//     testdata/api_v2.golden via `go test -update` (same commit as this
//     bump), plus CheckAPIVersion(2,0) gate; AllStages stays 12, AllPacks
//     grows only when packs opt into SDK v2.
//
// Dependencies order execution; they do not flow data — now
// PriorFindings/GraphView are the ONLY read-only inter-rule dataflow
// (SDK v2). See Context.PriorFindings and Context.GraphView for the
// contract.
package detect

import "fmt"

// APIMajor and APIMinor identify the frozen SDK surface version (Level 1).
// They are independent of SchemaVersion (cache record layout) and
// Rule.Version (rule content): a pack compiled against this build's SDK
// surface carries the API level it was built against and verifies it
// through CheckAPIVersion before loading.
//
// SDK v2 is APIMajor 2, APIMinor 0 — the first breaking reopening since
// the v1.2.5 freeze. Packs compiled against v1 (CheckAPIVersion(1,0))
// must be recompiled against v2.
const (
	APIMajor = 2
	APIMinor = 0
)

// CheckAPIVersion reports whether a pack compiled against version
// (requiredMajor, requiredMinor) of the SDK is compatible with this build:
// same major, and this build's minor >= the required minor. A
// major mismatch means the pack must be recompiled; a too-new required
// minor means this build predates the pack. The error names the SDK and
// both versions. Pack loaders call this before loading any rule.
func CheckAPIVersion(requiredMajor, requiredMinor int) error {
	if requiredMajor != APIMajor {
		return fmt.Errorf("detect SDK: pack requires API %d.%d, this build provides %d.%d (major version mismatch: the pack must be recompiled against the current SDK)",
			requiredMajor, requiredMinor, APIMajor, APIMinor)
	}
	if requiredMinor > APIMinor {
		return fmt.Errorf("detect SDK: pack requires API %d.%d, this build provides %d.%d (this build predates the pack's required minor)",
			requiredMajor, requiredMinor, APIMajor, APIMinor)
	}
	return nil
}
