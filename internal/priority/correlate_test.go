package priority

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// testCatalogs builds one interestingness catalog with the given entries
// and an empty risk catalog, for correlation tests with exactly known
// weights.
func testCatalogs(t *testing.T, entries ...Indicator) (*Catalog, *Catalog) {
	t.Helper()
	ic, err := CompileForTest("interestingness", entries)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := CompileForTest("risk", nil)
	if err != nil {
		t.Fatal(err)
	}
	return ic, rc
}

func corrIndicators() []Indicator {
	return []Indicator{
		{ID: "alpha", Category: "alpha", Weight: 0.5, Field: FieldPath, Terms: []string{"/a"}, Reason: "alpha path %s", Recommendation: "review the path %s"},
		{ID: "beta", Category: "beta", Weight: 0.3, Field: FieldPath, Terms: []string{"/b"}, Reason: "beta path %s", Recommendation: "review the path %s"},
	}
}

func scored(t *testing.T, ic, rc *Catalog, sig Signal) SurfaceAsset {
	t.Helper()
	sig.FirstSeen = fixedTime(1)
	sig.ScoredAt = fixedTime(2)
	out, err := ScoreSurface(sig, ic, rc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCorrelateGroupsByParentDomain pins the grouping rule: URL, endpoint,
// host, and domain surfaces of one branch land in ONE group anchored at
// the first-label-dropped parent domain; a distinct branch anchors
// elsewhere; ports in URL hosts and IP-literal hosts are handled through
// the asset normalizers.
func TestCorrelateGroupsByParentDomain(t *testing.T) {
	ic, rc := testCatalogs(t, corrIndicators()...)
	surfaces := []SurfaceAsset{
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindURL, Value: "https://api.example.com/a"},
			Kind:     asset.KindURL, Path: "/a", Hostname: "api.example.com",
		}),
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindHost, Value: "api.example.com"},
			Kind:     asset.KindHost, Hostname: "api.example.com",
		}),
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindEndpoint, Value: "GET https://api.example.com:8443/b"},
			Kind:     asset.KindEndpoint, Path: "/b", Hostname: "api.example.com", Port: 8443,
		}),
		// A deeper branch anchors one label down, not at the same parent.
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindURL, Value: "https://x.internal.example.com/a"},
			Kind:     asset.KindURL, Path: "/a", Hostname: "x.internal.example.com",
		}),
	}
	groups, truncated := Correlate(surfaces)
	if truncated {
		t.Error("two anchors are under the group cap; Truncated must be false")
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2 (api branch + deeper branch): %+v", len(groups), groups)
	}
	var api, deeper *Group
	for i := range groups {
		switch groups[i].Anchor.String() {
		case "domain:example.com":
			api = &groups[i]
		case "domain:internal.example.com":
			deeper = &groups[i]
		}
	}
	if api == nil || deeper == nil {
		t.Fatalf("anchors = %v", groups)
	}
	if len(api.Members) != 3 {
		t.Errorf("api branch members = %d, want 3 (url, host, endpoint)", len(api.Members))
	}
	if len(deeper.Members) != 1 {
		t.Errorf("deeper branch members = %d, want 1", len(deeper.Members))
	}

	// IP-literal hosts anchor at the IP identity through asset.NewIP, and
	// an ip asset groups with URLs on that address (bracketed IPv6
	// included).
	ipSurfaces := []SurfaceAsset{
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindURL, Value: "http://192.0.2.10/a"},
			Kind:     asset.KindURL, Path: "/a", Hostname: "192.0.2.10",
		}),
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindURL, Value: "https://[2001:db8::1]/a"},
			Kind:     asset.KindURL, Path: "/a", Hostname: "2001:db8::1",
		}),
	}
	ipGroups, _ := Correlate(ipSurfaces)
	if len(ipGroups) != 2 {
		t.Fatalf("ip groups = %d, want 2", len(ipGroups))
	}
	anchors := map[string]bool{ipGroups[0].Anchor.String(): true, ipGroups[1].Anchor.String(): true}
	if !anchors["ip:192.0.2.10"] || !anchors["ip:2001:db8::1"] {
		t.Errorf("ip anchors = %v", anchors)
	}
}

// TestCorrelateSingletonFallback pins the honest fallback: a surface whose
// anchor cannot be derived (unknown kind, identity that does not re-parse)
// groups at its own identity, alone — never a panic, never a shared
// "invalid" bucket.
func TestCorrelateSingletonFallback(t *testing.T) {
	ic, rc := mustCatalogs(t)
	surfaces := []SurfaceAsset{
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindTechnology, Value: "framework/django"},
			Kind:     asset.KindTechnology,
			Technologies: []TechSignal{
				{Name: "django", Category: "framework", Confidence: 0.9, Identity: "framework/django"},
			},
		}),
		// A url identity whose value does not re-parse canonically.
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindURL, Value: "not a url"},
			Kind:     asset.KindURL,
		}),
		scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindPort, Value: "tcp/8080"},
			Kind:     asset.KindPort, Port: 8080,
		}),
	}
	groups, _ := Correlate(surfaces)
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3 singletons: %+v", len(groups), groups)
	}
	seen := map[string]int{}
	for _, g := range groups {
		if len(g.Members) != 1 {
			t.Errorf("group %s has %d members, want a singleton", g.Anchor, len(g.Members))
		}
		seen[g.Anchor.String()]++
	}
	for _, want := range []string{
		"technology:framework/django", "url:not a url", "port:tcp/8080",
	} {
		if seen[want] != 1 {
			t.Errorf("anchor %s seen %d times, want 1 (anchors %v)", want, seen[want], seen)
		}
	}
}

// TestCorrelateAggregateFormulaPinned pins the documented aggregate
// formula: the group score is compose() over the UNION of the retained
// members' factors — the same group/cap/combine math as single-surface
// scoring — with hand-computed expectations, recomposition equality, and
// the repeat-amplification cap.
func TestCorrelateAggregateFormulaPinned(t *testing.T) {
	ic, rc := testCatalogs(t, corrIndicators()...)
	urlA := func(v string) asset.Identity { return asset.Identity{Kind: asset.KindURL, Value: v} }

	// Two members, one factor each, distinct categories:
	// score = 1 − (1−0.5)(1−0.3) = 0.65, two indicator categories → medium.
	groups, _ := Correlate([]SurfaceAsset{
		scored(t, ic, rc, Signal{Identity: urlA("https://api.example.com/a"), Kind: asset.KindURL, Path: "/a"}),
		scored(t, ic, rc, Signal{Identity: urlA("https://api.example.com/b"), Kind: asset.KindURL, Path: "/b"}),
	})
	if len(groups) != 1 {
		t.Fatalf("groups = %d", len(groups))
	}
	g := groups[0]
	if want := round4(1 - (1-0.5)*(1-0.3)); g.Score != want {
		t.Errorf("aggregate score = %v, want hand-computed %v", g.Score, want)
	}
	if g.Level != LevelMedium {
		t.Errorf("aggregate level = %s, want medium (score 0.65, two categories)", g.Level)
	}

	// Recomposition equality: the group score is exactly compose over the
	// union of the retained members' factor lists.
	var union []Factor
	for _, m := range g.Members {
		union = append(union, m.Factors...)
	}
	score, _, confidence, categories := compose(union)
	if g.Score != score || g.Confidence != confidence {
		t.Errorf("aggregate (%v,%v) != compose(union) (%v,%v)", g.Score, g.Confidence, score, confidence)
	}
	if lv := levelFor(score, categories); g.Level != lv {
		t.Errorf("aggregate level %s != recomputed %s", g.Level, lv)
	}

	// Shared indicators: the intersection of factor names across members.
	if len(g.SharedIndicators) != 0 {
		t.Errorf("distinct-category members share no indicators, got %v", g.SharedIndicators)
	}

	// Repeat amplification stays under the per-category cap: two members
	// carrying the SAME alpha factor combine to 1−0.5² = 0.75 inside the
	// category, capped at perCategoryCap for the group score.
	repeat, _ := Correlate([]SurfaceAsset{
		scored(t, ic, rc, Signal{Identity: urlA("https://api.example.com/a"), Kind: asset.KindURL, Path: "/a"}),
		scored(t, ic, rc, Signal{Identity: urlA("https://api.example.com/a2"), Kind: asset.KindURL, Path: "/a"}),
	})
	if len(repeat) != 1 {
		t.Fatalf("repeat groups = %d", len(repeat))
	}
	if want := round4(perCategoryCap); repeat[0].Score != want {
		t.Errorf("repeat-amplified score = %v, want the category cap %v", repeat[0].Score, want)
	}
	if !reflect.DeepEqual(repeat[0].SharedIndicators, []string{"interestingness:alpha"}) {
		t.Errorf("shared indicators = %v, want [interestingness:alpha]", repeat[0].SharedIndicators)
	}
}

// TestCorrelateBounds pins the output bounds: at most
// maxCorrelationGroups groups (the run-level Truncated return flag reports
// that cut; exactly-at-cap input reports false), at most
// maxMembersPerGroup members per group, with deterministic retention
// (highest score first, ties by identity) and an honest per-group
// Truncated flag.
func TestCorrelateBounds(t *testing.T) {
	ic, rc := testCatalogs(t, corrIndicators()...)

	// Member cap: one anchor, maxMembersPerGroup + 5 members. The kept set
	// is the highest-scoring members, tie-broken by identity.
	var members []SurfaceAsset
	for i := 0; i < maxMembersPerGroup+5; i++ {
		path := "/neutral"
		if i < 3 {
			path = "/a" // the three highest scorers
		}
		members = append(members, scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindURL, Value: fmt.Sprintf("https://api.example.com/n%03d", i)},
			Kind:     asset.KindURL, Path: path,
		}))
	}
	groups, groupTruncated := Correlate(members)
	if groupTruncated {
		t.Error("one anchor is under the group cap; the run-level Truncated flag must be false")
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	g := groups[0]
	if len(g.Members) != maxMembersPerGroup {
		t.Errorf("members = %d, want the cap %d", len(g.Members), maxMembersPerGroup)
	}
	if !g.Truncated {
		t.Error("Truncated must report the member cut")
	}
	withFactor := 0
	for _, m := range g.Members {
		if len(m.Factors) > 0 {
			withFactor++
		}
	}
	if withFactor != 3 {
		t.Errorf("kept members include %d factor-carrying (highest-scoring) surfaces, want all 3", withFactor)
	}

	// Group cap: maxCorrelationGroups + 40 singleton anchors — the run-level
	// Truncated flag must report the group cut.
	var many []SurfaceAsset
	for i := 0; i < maxCorrelationGroups+40; i++ {
		many = append(many, scored(t, ic, rc, Signal{
			Identity: asset.Identity{Kind: asset.KindTechnology, Value: fmt.Sprintf("framework/lib-%04d", i)},
			Kind:     asset.KindTechnology,
		}))
	}
	capped, groupTruncated := Correlate(many)
	if len(capped) != maxCorrelationGroups {
		t.Errorf("groups = %d, want the cap %d", len(capped), maxCorrelationGroups)
	}
	if !groupTruncated {
		t.Error("the run-level Truncated flag must report the group cut beyond the cap")
	}
	for i := 1; i < len(capped); i++ {
		if capped[i-1].Score < capped[i].Score {
			t.Errorf("groups not sorted by score desc: %v then %v", capped[i-1].Score, capped[i].Score)
		}
	}

	// Exactly at the cap: nothing dropped, no truncation signal.
	atCap, groupTruncated := Correlate(many[:maxCorrelationGroups])
	if len(atCap) != maxCorrelationGroups {
		t.Errorf("groups = %d, want exactly the cap %d", len(atCap), maxCorrelationGroups)
	}
	if groupTruncated {
		t.Error("exactly maxCorrelationGroups anchors are within the cap; the run-level Truncated flag must be false")
	}
}

// TestCorrelateDeterministic pins bit-for-bit determinism: two identical
// runs produce identical JSON bytes.
func TestCorrelateDeterministic(t *testing.T) {
	ic, rc := mustCatalogs(t)
	build := func() []SurfaceAsset {
		return []SurfaceAsset{
			scored(t, ic, rc, Signal{Identity: asset.Identity{Kind: asset.KindURL, Value: "https://www.example.com/admin"}, Kind: asset.KindURL, Path: "/admin", Hostname: "www.example.com"}),
			scored(t, ic, rc, Signal{Identity: asset.Identity{Kind: asset.KindHost, Value: "internal.example.com"}, Kind: asset.KindHost, Hostname: "internal.example.com"}),
			scored(t, ic, rc, Signal{Identity: asset.Identity{Kind: asset.KindURL, Value: "https://internal.example.com/static/app.js.map"}, Kind: asset.KindURL, Path: "/static/app.js.map"}),
		}
	}
	corr := func() []Group {
		groups, _ := Correlate(build())
		return groups
	}
	a, err := json.Marshal(corr())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(corr())
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("identical inputs must produce identical output bytes")
	}
}

// TestCorrelateEmptyInput pins the trivial-input contract: empty (and nil)
// input yields empty output and no truncation signal, no panic.
func TestCorrelateEmptyInput(t *testing.T) {
	if got, truncated := Correlate(nil); got != nil || truncated {
		t.Errorf("Correlate(nil) = %v, %v; want nil, false", got, truncated)
	}
	if got, truncated := Correlate([]SurfaceAsset{}); got != nil || truncated {
		t.Errorf("Correlate(empty) = %v, %v; want nil, false", got, truncated)
	}
}

// TestCorrelateMemberOrderTotalOrder pins the member tie-break's total
// order: two surfaces with the SAME identity and score but different
// bodies sort by their byte-wise serialized surface, so the member order is
// identical regardless of input order. Unreachable through the engine
// (identities are deduped before Correlate), but Correlate is an exported
// function and must be deterministic for every input.
func TestCorrelateMemberOrderTotalOrder(t *testing.T) {
	id := asset.Identity{Kind: asset.KindURL, Value: "https://api.example.com/a"}
	light := SurfaceAsset{
		Identity: id, Kind: asset.KindURL, Score: 0.5,
		Factors: []Factor{{
			Name: "interestingness:probe", Weight: 0.5,
			Evidence: []string{id.String()}, Reason: "probe factor",
		}},
	}
	heavy := light
	heavy.Factors = append(append([]Factor{}, light.Factors...), Factor{
		Name: "confidence:technology", Weight: 0.4,
		Evidence: []string{id.String()}, Reason: "second probe factor",
	})
	if marshalSurface(&light) == marshalSurface(&heavy) {
		t.Fatal("test construction error: the two surfaces must serialize differently")
	}
	wantFirst := marshalSurface(&light)
	if alt := marshalSurface(&heavy); alt < wantFirst {
		wantFirst = alt
	}

	run := func(order []SurfaceAsset) []SurfaceAsset {
		groups, truncated := Correlate(order)
		if truncated || len(groups) != 1 || len(groups[0].Members) != 2 {
			t.Fatalf("groups = %+v (truncated %v)", groups, truncated)
		}
		return groups[0].Members
	}
	for _, order := range [][]SurfaceAsset{{light, heavy}, {heavy, light}} {
		members := run(order)
		if got := marshalSurface(&members[0]); got != wantFirst {
			t.Errorf("member order is not the serialized-bytes total order: first = %s, want %s", got, wantFirst)
		}
	}
}

// TestCorrelateScoresAreFinite is a smoke invariant: every emitted score
// and confidence is finite and within [0,1].
func TestCorrelateScoresAreFinite(t *testing.T) {
	ic, rc := mustCatalogs(t)
	groups, _ := Correlate([]SurfaceAsset{
		scored(t, ic, rc, Signal{Identity: asset.Identity{Kind: asset.KindURL, Value: "https://www.example.com/api/v2/admin"}, Kind: asset.KindURL, Path: "/api/v2/admin", Hostname: "www.example.com"}),
	})
	for _, g := range groups {
		if math.IsNaN(g.Score) || g.Score < 0 || g.Score > 1 {
			t.Errorf("group score %v out of [0,1]", g.Score)
		}
		if math.IsNaN(g.Confidence) || g.Confidence < 0 || g.Confidence > 1 {
			t.Errorf("group confidence %v out of [0,1]", g.Confidence)
		}
	}
}
