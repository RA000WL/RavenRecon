package priority

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// pathFixture builds the canonical path story: an internal host plus a
// source map URL observed on it, correlated under the parent domain.
func pathFixture(t *testing.T) []Group {
	t.Helper()
	ic, rc := mustCatalogs(t)
	groups, _ := Correlate([]SurfaceAsset{
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindHost, Value: "internal.example.com"},
			Kind:     asset.KindHost, Hostname: "internal.example.com",
		}),
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindSourceMap, Value: "https://internal.example.com/static/app.js.map"},
			Kind:     asset.KindSourceMap, Path: "/static/app.js.map",
		}),
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindURL, Value: "https://internal.example.com/admin"},
			Kind:     asset.KindURL, Path: "/admin",
		}),
	})
	return groups
}

// TestAttackPathsEvidenceContract pins the evidence contract: every step
// carries the identity it stopped at, and every non-root step cites the
// EXACT reason and evidence of a real factor of a real member — no
// invented intermediate steps. The root step cites the member identities
// it was derived from.
func TestAttackPathsEvidenceContract(t *testing.T) {
	groups := pathFixture(t)
	paths := AttackPaths(groups)
	if len(paths) != 1 {
		t.Fatalf("paths = %d, want 1", len(paths))
	}
	p := paths[0]
	if p.Root.String() != "domain:example.com" {
		t.Errorf("root = %s, want domain:example.com", p.Root)
	}
	if len(p.Steps) != 4 { // root + host + sourcemap + url
		t.Fatalf("steps = %d, want 4: %+v", len(p.Steps), p.Steps)
	}

	// Member ordering is container-first: host before URL kinds.
	if p.Steps[1].Kind != asset.KindHost {
		t.Errorf("step 1 kind = %s, want host first", p.Steps[1].Kind)
	}

	// The root step cites the grouping derivation and its members.
	root := p.Steps[0]
	if root.FactorName != "" {
		t.Errorf("root step must not cite a factor, got %q", root.FactorName)
	}
	if len(root.Evidence) == 0 || len(root.Evidence) > maxEvidencePerFactor {
		t.Errorf("root evidence = %v", root.Evidence)
	}
	memberIDs := map[string]bool{}
	for _, g := range groups {
		for _, m := range g.Members {
			memberIDs[m.Identity.String()] = true
		}
	}
	for _, ev := range root.Evidence {
		if !memberIDs[ev] {
			t.Errorf("root evidence %q is not a member identity", ev)
		}
	}

	// Every non-root step cites a factor of a member EXACTLY (name, reason,
	// evidence bytes) — and carries a DEEP COPY of that factor's evidence:
	// the step's slice must not alias the member factor's backing array.
	byMember := map[asset.Identity]SurfaceAsset{}
	for _, g := range groups {
		for _, m := range g.Members {
			byMember[m.Identity] = m
		}
	}
	for i, s := range p.Steps[1:] {
		m, ok := byMember[s.Identity]
		if !ok {
			t.Fatalf("step %d identity %v is not a member of the group", i+1, s.Identity)
		}
		cited := false
		for _, f := range m.Factors {
			if f.Name == s.FactorName && f.Reason == s.Reason {
				if len(s.Evidence) == 0 && len(f.Evidence) != 0 {
					continue
				}
				if len(s.Evidence) > 0 && len(f.Evidence) > 0 &&
					&s.Evidence[0] == &f.Evidence[0] {
					t.Errorf("step %d evidence aliases the member factor's backing array", i+1)
				}
				cited = true
				break
			}
		}
		if !cited {
			t.Errorf("step %d (%v) does not cite an exact (name, reason) of member %v's factors: %+v",
				i+1, s.Identity, s.Identity, s)
		}
		if len(s.Evidence) == 0 {
			t.Errorf("step %d carries no evidence", i+1)
		}
	}
}

// TestAttackPathsBounds pins the step and path bounds: at most
// maxStepsPerPath steps (Truncated reports the cut) and maxPathsPerRun
// paths, kept highest score first.
func TestAttackPathsBounds(t *testing.T) {
	ic, rc := testCatalogs(t, corrIndicators()...)

	// Step bound: one group with more contributing members than the step
	// bound.
	var members []SurfaceAsset
	for i := 0; i < maxStepsPerPath+4; i++ {
		members = append(members, scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindURL, Value: fmt.Sprintf("https://api.example.com/a%02d", i)},
			Kind:     asset.KindURL, Path: "/a",
		}))
	}
	groups, _ := Correlate(members)
	paths := AttackPaths(groups)
	if len(paths) != 1 {
		t.Fatalf("paths = %d, want 1", len(paths))
	}
	if len(paths[0].Steps) != maxStepsPerPath {
		t.Errorf("steps = %d, want the cap %d", len(paths[0].Steps), maxStepsPerPath)
	}
	if !paths[0].Truncated {
		t.Error("Truncated must report the step cut")
	}

	// Path bound: more contributing groups than the path bound.
	var manyGroups []Group
	for i := 0; i < maxPathsPerRun+10; i++ {
		groups, _ := Correlate([]SurfaceAsset{
			scored(t, ic, rc, Signal{
				Identity: asset.Identity{Kind: asset.KindURL, Value: fmt.Sprintf("https://branch%02d.example.com/a", i)},
				Kind:     asset.KindURL, Path: "/a",
			}),
		})
		manyGroups = append(manyGroups, groups...)
	}
	capped := AttackPaths(manyGroups)
	if len(capped) != maxPathsPerRun {
		t.Errorf("paths = %d, want the cap %d", len(capped), maxPathsPerRun)
	}
	for i := 1; i < len(capped); i++ {
		if capped[i-1].Score < capped[i].Score {
			t.Errorf("paths not ranked by score desc: %v then %v", capped[i-1].Score, capped[i].Score)
		}
	}
}

// TestAttackPathsSkipsFactorlessGroups: a group whose members carry no
// factors produces no path (there is no evidence to tie steps to); empty
// input produces no paths.
func TestAttackPathsSkipsFactorlessGroups(t *testing.T) {
	ic, rc := testCatalogs(t, corrIndicators()...)
	quiet, _ := Correlate([]SurfaceAsset{
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindURL, Value: "https://quiet.example.com/home"},
			Kind:     asset.KindURL, Path: "/home",
		}),
	})
	if len(quiet) != 1 {
		t.Fatalf("groups = %d", len(quiet))
	}
	if paths := AttackPaths(quiet); len(paths) != 0 {
		t.Errorf("factorless group must yield no path, got %d", len(paths))
	}
	if paths := AttackPaths(nil); paths != nil {
		t.Errorf("nil groups must yield no paths, got %v", paths)
	}
}

// TestAttackPathsDeterministic pins bit-for-bit determinism.
func TestAttackPathsDeterministic(t *testing.T) {
	a, err := json.Marshal(AttackPaths(pathFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(AttackPaths(pathFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("identical group inputs must produce identical path output bytes")
	}
}
