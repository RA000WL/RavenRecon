package priority

import (
	"fmt"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Attack-path bounds (fixed constants).
const (
	// maxStepsPerPath bounds the steps of one attack path (the correlation
	// root step plus contributing members).
	maxStepsPerPath = 8
	// maxPathsPerRun bounds the number of attack paths one run emits.
	maxPathsPerRun = 32
)

// PathStep is one step of an attack path. Every step is EVIDENCE-TIED: it
// carries the identity it stopped at, the exact factor that put the step
// on the path, and that factor's evidence references. The correlation root
// step (FactorName empty) cites the member identities it was derived from.
// No step is ever invented: intermediate surfaces without factors do not
// contribute steps.
type PathStep struct {
	// Identity is the canonical identity at this step (the group anchor for
	// the root step, a member surface identity otherwise).
	Identity asset.Identity `json:"identity"`

	// Kind is the identity's asset kind (mirrored for convenience).
	Kind asset.Kind `json:"kind"`

	// FactorName is the name of the factor this step cites; empty for the
	// correlation root step, which cites the grouping derivation instead.
	FactorName string `json:"factor_name,omitempty"`

	// Reason is the exact reason text of the cited factor — the same bytes
	// the scored surface emitted, never rephrased. For the root step it is
	// the correlation derivation statement.
	Reason string `json:"reason"`

	// Evidence is a deep copy of the cited factor's evidence references
	// (the identities the factor was derived from), capped at
	// maxEvidencePerFactor — the step never aliases the member factor's
	// backing array. For the root step it is the member identities the
	// anchor was derived from.
	Evidence []string `json:"evidence"`
}

// AttackPath is one ordered RECONNAISSANCE HYPOTHESIS: a walk from a
// correlation root through correlated hosts and URLs to the final
// evidence attachment. It is a reading order for a human researcher —
// which observed surfaces and which recorded evidence belong to one story
// on the attack surface.
//
// An AttackPath is NOT an exploitation chain: it names no vulnerability,
// claims no weakness, and implies nothing is exploitable. Every step cites
// recorded evidence only; nothing about the path has been tested.
type AttackPath struct {
	// Root is the correlation root the path starts from (the group's
	// anchor identity).
	Root asset.Identity `json:"root"`

	// Steps are the ordered steps (root step first), bounded at
	// maxStepsPerPath.
	Steps []PathStep `json:"steps"`

	// Score is the originating group's aggregate score (the ranking key).
	Score float64 `json:"score"`

	// Level is the originating group's level.
	Level PriorityLevel `json:"level"`

	// Truncated reports that contributing members were dropped by the
	// step bound.
	Truncated bool `json:"truncated,omitempty"`
}

// AttackPaths derives deterministic attack-path hypotheses from correlated
// groups.
//
// For each group with at least one contributing member (a member surface
// carrying at least one factor), the path walks:
//
//	step 1  the correlation root — the group anchor, citing the member
//	        identities it groups (the derivation evidence);
//	steps   one step per contributing member, ordered container-first
//	        (domain, then host, then URL/endpoint/JavaScript/source-map,
//	        then other kinds; within a rank score desc, identity asc),
//	        each citing the member's highest-weight factor (ties by factor
//	        name): its exact reason and its evidence references. The LAST
//	        contributing member's step is the path's final evidence
//	        attachment.
//
// Bounds: at most maxStepsPerPath steps per path (Truncated reports the
// cut) and maxPathsPerRun paths per run, kept highest group score first
// (ties by root identity asc) — both total orders, so identical group
// input produces bit-for-bit identical output. Groups without contributing
// members produce no path; empty input produces no paths; nothing panics.
//
// Reminder of scope (see AttackPath): these are recon hypotheses for a
// researcher's reading order — never exploitation chains, never
// vulnerability claims, never tested statements.
func AttackPaths(groups []Group) []AttackPath {
	var paths []AttackPath
	for _, g := range groups {
		contributing := contributingMembers(g.Members)
		if len(contributing) == 0 {
			continue
		}

		var steps []PathStep
		steps = append(steps, PathStep{
			Identity: g.Anchor,
			Kind:     g.Anchor.Kind,
			Reason: fmt.Sprintf("correlation root: %d scored surface(s) group under this anchor",
				len(g.Members)),
			Evidence: memberEvidence(g.Members),
		})
		for _, m := range contributing {
			if len(steps) == maxStepsPerPath {
				break
			}
			f := topFactor(m)
			steps = append(steps, PathStep{
				Identity:   m.Identity,
				Kind:       m.Kind,
				FactorName: f.Name,
				Reason:     f.Reason,
				Evidence:   copyEvidence(f.Evidence),
			})
		}
		truncated := len(contributing)+1 > len(steps)

		paths = append(paths, AttackPath{
			Root:      g.Anchor,
			Steps:     steps,
			Score:     g.Score,
			Level:     g.Level,
			Truncated: truncated,
		})
	}

	// Rank first, truncate second: the emitted set is the top
	// maxPathsPerRun by (score desc, root asc) regardless of the order the
	// groups arrived in.
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].Score != paths[j].Score {
			return paths[i].Score > paths[j].Score
		}
		return paths[i].Root.String() < paths[j].Root.String()
	})
	if len(paths) > maxPathsPerRun {
		paths = paths[:maxPathsPerRun]
	}
	return paths
}

// contributingMembers returns the members carrying at least one factor,
// ordered container-first and then (score desc, identity asc).
func contributingMembers(members []SurfaceAsset) []SurfaceAsset {
	out := make([]SurfaceAsset, 0, len(members))
	for _, m := range members {
		if len(m.Factors) > 0 {
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := kindRank(out[i].Kind), kindRank(out[j].Kind)
		if ri != rj {
			return ri < rj
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Identity.String() < out[j].Identity.String()
	})
	return out
}

// kindRank orders container kinds before content kinds: domain < host <
// URL/endpoint/JavaScript/source map < everything else.
func kindRank(k asset.Kind) int {
	switch k {
	case asset.KindDomain:
		return 0
	case asset.KindHost:
		return 1
	case asset.KindURL, asset.KindEndpoint, asset.KindJavaScript, asset.KindSourceMap:
		return 2
	}
	return 3
}

// topFactor returns a member's highest-weight factor, ties by name asc —
// the factor the member's path step cites.
func topFactor(m SurfaceAsset) Factor {
	best := m.Factors[0]
	for _, f := range m.Factors[1:] {
		if f.Weight > best.Weight || (f.Weight == best.Weight && f.Name < best.Name) {
			best = f
		}
	}
	return best
}

// copyEvidence deep-copies a factor's evidence references into a PathStep
// (≤ maxEvidencePerFactor refs, trivial cost): steps are independent value
// records and must never alias the member factor's backing array.
func copyEvidence(ev []string) []string {
	out := make([]string, len(ev))
	copy(out, ev)
	return out
}

// memberEvidence cites the member identities a root step groups, capped at
// maxEvidencePerFactor (the same evidence bound factors obey).
func memberEvidence(members []SurfaceAsset) []string {
	n := len(members)
	if n > maxEvidencePerFactor {
		n = maxEvidencePerFactor
	}
	out := make([]string, 0, n)
	for _, m := range members[:n] {
		out = append(out, m.Identity.String())
	}
	return out
}
