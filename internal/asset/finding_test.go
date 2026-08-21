package asset

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func findingFixture(t *testing.T) Finding {
	t.Helper()
	subject := Identity{Kind: KindURL, Value: "https://example.com/admin"}
	ev, err := NewEvidence(MethodDetection, "demo.rule", "administrative interface exposed", subject, Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	created := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	f, err := NewFinding(Finding{
		RuleID:     "demo.rule",
		RuleName:   "Demo rule",
		Category:   "information",
		Subject:    subject,
		Confidence: 0.9,
		Evidence:   []Evidence{ev},
		Priority:   "medium",
		Status:     "open",
		Created:    created,
		Metadata:   map[string]string{"note": "synthetic"},
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

func TestNewFindingValid(t *testing.T) {
	f := findingFixture(t)
	if f.Identity().Kind != KindFinding {
		t.Fatalf("identity kind %q != %q", f.Identity().Kind, KindFinding)
	}
	want := percentEncode("demo.rule") + "@" + percentEncode(f.Subject.String())
	if f.Identity().Value != want {
		t.Fatalf("identity value %q != %q", f.Identity().Value, want)
	}
	if !f.Updated.Equal(f.Created) {
		t.Fatalf("Updated not defaulted to Created: %v != %v", f.Updated, f.Created)
	}
}

func TestNewFindingRejections(t *testing.T) {
	base := findingFixture(t)
	subject := base.Subject
	ev := base.Evidence[0]
	created := base.Created

	cases := []struct {
		name string
		mut  func(f *Finding)
	}{
		{"empty rule id", func(f *Finding) { f.RuleID = "" }},
		{"empty rule name", func(f *Finding) { f.RuleName = "" }},
		{"empty category", func(f *Finding) { f.Category = "" }},
		{"empty priority", func(f *Finding) { f.Priority = "" }},
		{"empty status", func(f *Finding) { f.Status = "" }},
		{"non-printable label", func(f *Finding) { f.Priority = "high\x01" }},
		{"oversized rule id", func(f *Finding) { f.RuleID = strings.Repeat("a", maxFindingRuleIDBytes+1) }},
		{"zero subject", func(f *Finding) { f.Subject = Identity{} }},
		{"confidence over 1", func(f *Finding) { f.Confidence = 1.5 }},
		{"negative confidence", func(f *Finding) { f.Confidence = -0.1 }},
		{"no evidence", func(f *Finding) { f.Evidence = nil }},
		{"oversized metadata value", func(f *Finding) {
			f.Metadata = map[string]string{"k": strings.Repeat("v", maxFindingMetadataValueBytes+1)}
		}},
		{"too many metadata entries", func(f *Finding) {
			m := map[string]string{}
			for i := 0; i < maxFindingMetadataEntries+1; i++ {
				m[string(rune('a'+i%26))+string(rune('0'+i/26))] = "v"
			}
			f.Metadata = m
		}},
		{"zero related asset", func(f *Finding) { f.RelatedAssets = []Identity{{}} }},
		{"zero created", func(f *Finding) { f.Created = time.Time{} }},
		{"updated before created", func(f *Finding) { f.Updated = created.Add(-time.Hour) }},
		{"non-canonical evidence", func(f *Finding) {
			bad := ev
			bad.Method = "no-such-method"
			f.Evidence = []Evidence{bad}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Finding{
				RuleID:     base.RuleID,
				RuleName:   base.RuleName,
				Category:   base.Category,
				Subject:    subject,
				Confidence: base.Confidence,
				Evidence:   []Evidence{ev},
				Priority:   base.Priority,
				Status:     base.Status,
				Created:    created,
			}
			tc.mut(&f)
			if _, err := NewFinding(f); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func TestNewFindingDedupesAndSorts(t *testing.T) {
	base := findingFixture(t)
	subject := base.Subject
	evA, err := NewEvidence(MethodDetection, "demo.rule", "signal a", subject, Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	evB, err := NewEvidence(MethodHeader, "server", "nginx", subject, Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	rel, err := NewRelationship(subject, RelationshipURLToEndpoint,
		Identity{Kind: KindEndpoint, Value: "GET https://example.com/admin"})
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	f, err := NewFinding(Finding{
		RuleID:   base.RuleID,
		RuleName: base.RuleName,
		Category: base.Category,
		Subject:  subject,
		Evidence: []Evidence{evA, evB, evA},
		RelatedAssets: []Identity{
			subject,
			{Kind: KindHost, Value: "example.com"},
			{Kind: KindHost, Value: "example.com"},
		},
		Relationships: []Relationship{rel, rel},
		Priority:      base.Priority,
		Status:        base.Status,
		Created:       base.Created,
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if len(f.Evidence) != 2 {
		t.Fatalf("evidence not deduplicated: %d", len(f.Evidence))
	}
	if f.Evidence[0].Identity().Value > f.Evidence[1].Identity().Value {
		t.Fatalf("evidence not sorted")
	}
	if len(f.RelatedAssets) != 2 {
		t.Fatalf("related assets not deduplicated: %d", len(f.RelatedAssets))
	}
	if len(f.Relationships) != 1 {
		t.Fatalf("relationships not deduplicated: %d", len(f.Relationships))
	}
}

// TestFindingEmptySetsAreNil is the T4 cache-parity regression pin: an
// absent RelatedAssets/Relationships set must normalize to nil, never an
// empty-but-non-nil slice. The canonical empty-set representation must
// match what a JSON round-trip produces (omitempty drops empty slices), or
// a cache-hit replay of a stored finding (decoded, never re-normalized)
// would differ from a freshly normalized one under DeepEqual — the exact
// cache-hit vs execute parity break the T4 full-run test caught.
func TestFindingEmptySetsAreNil(t *testing.T) {
	base := findingFixture(t)
	subject := base.Subject
	ev, err := NewEvidence(MethodDetection, "demo.rule", "signal a", subject, Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	f, err := NewFinding(Finding{
		RuleID:   base.RuleID,
		RuleName: base.RuleName,
		Category: base.Category,
		Subject:  subject,
		Evidence: []Evidence{ev},
		Priority: base.Priority,
		Status:   base.Status,
		Created:  base.Created,
		Metadata: map[string]string{"note": "synthetic"},
		// RelatedAssets and Relationships deliberately absent.
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if f.RelatedAssets != nil {
		t.Errorf("RelatedAssets = %#v, want nil (empty sets normalize to the JSON round-trip representation)", f.RelatedAssets)
	}
	if f.Relationships != nil {
		t.Errorf("Relationships = %#v, want nil (empty sets normalize to the JSON round-trip representation)", f.Relationships)
	}
	// The JSON round-trip of the normalized finding must be byte-identical
	// to itself — the storage/replay contract the detect engine's cache
	// hits rely on.
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var back Finding
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(f, back) {
		t.Errorf("JSON round-trip of a normalized finding is not DeepEqual to itself:\noriginal: %+v\nreplayed: %+v", f, back)
	}
	// MergeFindings (the other normalization point) must keep the same
	// representation for findings whose related sets are empty.
	m, err := MergeFindings(f, f)
	if err != nil {
		t.Fatalf("MergeFindings: %v", err)
	}
	if m.RelatedAssets != nil {
		t.Errorf("merged RelatedAssets = %#v, want nil", m.RelatedAssets)
	}
	if m.Relationships != nil {
		t.Errorf("merged Relationships = %#v, want nil", m.Relationships)
	}
}

func TestMergeFindingsDeterministic(t *testing.T) {
	base := findingFixture(t)
	subject := base.Subject
	evA, err := NewEvidence(MethodDetection, "demo.rule", "signal a", subject, Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	evB, err := NewEvidence(MethodDetection, "demo.rule", "signal b", subject, Provenance{})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	later := base.Created.Add(time.Hour)
	a, err := NewFinding(Finding{
		RuleID: base.RuleID, RuleName: base.RuleName, Category: base.Category,
		Subject: subject, Confidence: 0.5, Evidence: []Evidence{evA},
		Priority: "low", Status: "open", Created: base.Created, Updated: later,
	})
	if err != nil {
		t.Fatalf("NewFinding a: %v", err)
	}
	b, err := NewFinding(Finding{
		RuleID: base.RuleID, RuleName: base.RuleName + " v2", Category: base.Category,
		Subject: subject, Confidence: 0.9, Evidence: []Evidence{evB},
		Priority: "high", Status: "open", Created: later, Updated: later,
	})
	if err != nil {
		t.Fatalf("NewFinding b: %v", err)
	}

	ab, err := MergeFindings(a, b)
	if err != nil {
		t.Fatalf("MergeFindings a,b: %v", err)
	}
	ba, err := MergeFindings(b, a)
	if err != nil {
		t.Fatalf("MergeFindings b,a: %v", err)
	}
	if marshalFinding(t, ab) != marshalFinding(t, ba) {
		t.Fatalf("merge is order-dependent")
	}
	if ab.Confidence != 0.9 {
		t.Fatalf("confidence %v != max", ab.Confidence)
	}
	if ab.Priority != "high" || ab.RuleName != b.RuleName {
		t.Fatalf("denormalized fields not taken from the higher-confidence side")
	}
	if !ab.Created.Equal(base.Created) || !ab.Updated.Equal(later) {
		t.Fatalf("timestamps not composed honestly")
	}
	if len(ab.Evidence) != 2 {
		t.Fatalf("evidence not unioned: %d", len(ab.Evidence))
	}

	if _, err := MergeFindings(a, Finding{
		RuleID: "other.rule", RuleName: "Other", Category: "exposure",
		Subject: subject, Confidence: 1, Evidence: []Evidence{evA},
		Priority: "low", Status: "open", Created: base.Created,
	}); err == nil {
		t.Fatalf("expected mismatch rejection")
	}
}

func TestMergeFindingsEvidenceBound(t *testing.T) {
	base := findingFixture(t)
	subject := base.Subject
	mk := func(from, to int) Finding {
		evs := make([]Evidence, 0, to-from)
		for i := from; i < to; i++ {
			ev, err := NewEvidence(MethodDetection, "demo.rule",
				fmt.Sprintf("signal %02d", i), subject, Provenance{})
			if err != nil {
				t.Fatalf("NewEvidence: %v", err)
			}
			evs = append(evs, ev)
		}
		f, err := NewFinding(Finding{
			RuleID: base.RuleID, RuleName: base.RuleName, Category: base.Category,
			Subject: subject, Confidence: 0.5, Evidence: evs,
			Priority: "low", Status: "open", Created: base.Created,
		})
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		return f
	}
	// Two maximal findings: 16 + 16 distinct evidence records.
	a, b := mk(0, maxFindingEvidence), mk(maxFindingEvidence, 2*maxFindingEvidence)
	ab, err := MergeFindings(a, b)
	if err != nil {
		t.Fatalf("MergeFindings a,b: %v", err)
	}
	ba, err := MergeFindings(b, a)
	if err != nil {
		t.Fatalf("MergeFindings b,a: %v", err)
	}
	if len(ab.Evidence) != maxFindingEvidence {
		t.Fatalf("merged evidence %d records, want the %d bound", len(ab.Evidence), maxFindingEvidence)
	}
	if marshalFinding(t, ab) != marshalFinding(t, ba) {
		t.Fatalf("the evidence cut must be deterministic (merge-order independent)")
	}
	// The kept records are the identity-sorted prefix of the 32-record union.
	union := make([]string, 0, 2*maxFindingEvidence)
	for _, ev := range append(append([]Evidence{}, a.Evidence...), b.Evidence...) {
		union = append(union, ev.Identity().Value)
	}
	sort.Strings(union)
	for i, ev := range ab.Evidence {
		if ev.Identity().Value != union[i] {
			t.Fatalf("merged evidence is not the identity-sorted prefix at %d", i)
		}
	}
}

func TestFindingJSONRoundTrip(t *testing.T) {
	f := findingFixture(t)
	buf, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Finding
	if err := json.Unmarshal(buf, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	again, err := NewFinding(back)
	if err != nil {
		t.Fatalf("NewFinding on decoded finding: %v", err)
	}
	if marshalFinding(t, again) != marshalFinding(t, f) {
		t.Fatalf("JSON round trip changed the finding")
	}
}

func marshalFinding(t *testing.T, f Finding) string {
	t.Helper()
	buf, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	return string(buf)
}

func TestKindFindingVocabulary(t *testing.T) {
	if !KindFinding.Valid() {
		t.Fatalf("KindFinding must be valid")
	}
	kinds := KnownKinds()
	seen := map[Kind]bool{}
	for _, k := range kinds {
		if seen[k] {
			t.Fatalf("duplicate kind %q", k)
		}
		seen[k] = true
		if !k.Valid() {
			t.Fatalf("kind %q in KnownKinds is not Valid", k)
		}
	}
	if !seen[KindFinding] {
		t.Fatalf("KindFinding missing from KnownKinds")
	}
	if (Kind("bogus")).Valid() {
		t.Fatalf("unknown kind reported valid")
	}
	// sorted order
	for i := 1; i < len(kinds); i++ {
		if kinds[i-1] >= kinds[i] {
			t.Fatalf("KnownKinds not sorted at %d", i)
		}
	}
}

func TestMethodDetectionInVocabulary(t *testing.T) {
	if !MethodDetection.Valid() {
		t.Fatalf("MethodDetection must be valid")
	}
	methods := KnownMethods()
	found := false
	for _, m := range methods {
		if m == MethodDetection {
			found = true
		}
		if !m.Valid() {
			t.Fatalf("method %q in KnownMethods is not Valid", m)
		}
	}
	if !found {
		t.Fatalf("MethodDetection missing from KnownMethods")
	}
	for i := 1; i < len(methods); i++ {
		if methods[i-1] >= methods[i] {
			t.Fatalf("KnownMethods not sorted at %d", i)
		}
	}
}

// TestMergeFindingsTruncatedFlag pins the OPT-P1-4 contract for findings:
// every genuinely-silent over-cap DROP in MergeFindings (evidence at
// maxFindingEvidence, related assets at maxFindingRelated, relationships at
// maxFindingRelationships, metadata at maxFindingMetadataEntries) sets
// Truncated on the merged result; an exactly-at-cap union leaves it false
// (no false positives); normalization never sets it (NewFinding rejects
// over-cap input outright); and the marker is sticky across chained merges.
// Pre-fix, these cuts were silent (no field existed): the assertions on
// Truncated fail to compile against pre-fix code by construction, and the
// retained-set rows document exactly what used to be lost without a signal.
func TestMergeFindingsTruncatedFlag(t *testing.T) {
	base := findingFixture(t)
	subject := base.Subject

	mkEvidence := func(from, to int) []Evidence {
		evs := make([]Evidence, 0, to-from)
		for i := from; i < to; i++ {
			ev, err := NewEvidence(MethodDetection, "demo.rule",
				fmt.Sprintf("signal %02d", i), subject, Provenance{})
			if err != nil {
				t.Fatalf("NewEvidence: %v", err)
			}
			evs = append(evs, ev)
		}
		return evs
	}
	mkRelated := func(from, to int) []Identity {
		ids := make([]Identity, 0, to-from)
		for i := from; i < to; i++ {
			ids = append(ids, Identity{Kind: KindHost, Value: fmt.Sprintf("host-%02d.example.com", i)})
		}
		return ids
	}
	mkRelationships := func(from, to int) []Relationship {
		rels := make([]Relationship, 0, to-from)
		for i := from; i < to; i++ {
			rel, err := NewRelationship(subject, RelationshipKind("observed-on"),
				Identity{Kind: KindHost, Value: fmt.Sprintf("edge-%02d.example.com", i)})
			if err != nil {
				t.Fatalf("NewRelationship: %v", err)
			}
			rels = append(rels, rel)
		}
		return rels
	}
	mkMetadata := func(from, to int) map[string]string {
		m := make(map[string]string, to-from)
		for i := from; i < to; i++ {
			m[fmt.Sprintf("key-%02d", i)] = "synthetic"
		}
		return m
	}
	mkFinding := func(evidence []Evidence, related []Identity, rels []Relationship, meta map[string]string) Finding {
		f, err := NewFinding(Finding{
			RuleID: base.RuleID, RuleName: base.RuleName, Category: base.Category,
			Subject: subject, Confidence: 0.5,
			Evidence: evidence, RelatedAssets: related, Relationships: rels,
			Priority: "low", Status: "open", Created: base.Created, Metadata: meta,
		})
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		return f
	}
	merge := func(a, b Finding) Finding {
		m, err := MergeFindings(a, b)
		if err != nil {
			t.Fatalf("MergeFindings: %v", err)
		}
		return m
	}

	t.Run("evidence cut sets the flag", func(t *testing.T) {
		a := mkFinding(mkEvidence(0, maxFindingEvidence), nil, nil, nil)
		b := mkFinding(mkEvidence(maxFindingEvidence, 2*maxFindingEvidence), nil, nil, nil)
		m := merge(a, b)
		if len(m.Evidence) != maxFindingEvidence {
			t.Fatalf("retained %d evidence records, want the %d bound", len(m.Evidence), maxFindingEvidence)
		}
		if !m.Truncated {
			t.Fatal("Truncated = false after an evidence union was cut, want true (the pre-fix silent drop)")
		}
	})
	t.Run("evidence exactly at cap stays false", func(t *testing.T) {
		a := mkFinding(mkEvidence(0, maxFindingEvidence/2), nil, nil, nil)
		b := mkFinding(mkEvidence(maxFindingEvidence/2, maxFindingEvidence), nil, nil, nil)
		m := merge(a, b)
		if len(m.Evidence) != maxFindingEvidence {
			t.Fatalf("exactly-at-cap union retained %d records, want %d", len(m.Evidence), maxFindingEvidence)
		}
		if m.Truncated {
			t.Error("Truncated = true for an exactly-at-cap evidence union with nothing dropped, want false")
		}
	})
	t.Run("related assets cut sets the flag", func(t *testing.T) {
		a := mkFinding(mkEvidence(0, 1), mkRelated(0, 20), nil, nil)
		b := mkFinding(mkEvidence(1, 2), mkRelated(20, 40), nil, nil)
		m := merge(a, b)
		if len(m.RelatedAssets) != maxFindingRelated {
			t.Fatalf("retained %d related assets, want the %d bound", len(m.RelatedAssets), maxFindingRelated)
		}
		if !m.Truncated {
			t.Fatal("Truncated = false after a related-asset union was cut, want true")
		}
	})
	t.Run("related assets exactly at cap stay false", func(t *testing.T) {
		a := mkFinding(mkEvidence(0, 1), mkRelated(0, 16), nil, nil)
		b := mkFinding(mkEvidence(1, 2), mkRelated(16, 32), nil, nil)
		m := merge(a, b)
		if len(m.RelatedAssets) != maxFindingRelated {
			t.Fatalf("exactly-at-cap union retained %d identities, want %d", len(m.RelatedAssets), maxFindingRelated)
		}
		if m.Truncated {
			t.Error("Truncated = true for an exactly-at-cap related-asset union, want false")
		}
	})
	t.Run("relationships cut sets the flag", func(t *testing.T) {
		a := mkFinding(mkEvidence(0, 1), nil, mkRelationships(0, 20), nil)
		b := mkFinding(mkEvidence(1, 2), nil, mkRelationships(20, 40), nil)
		m := merge(a, b)
		if len(m.Relationships) != maxFindingRelationships {
			t.Fatalf("retained %d relationships, want the %d bound", len(m.Relationships), maxFindingRelationships)
		}
		if !m.Truncated {
			t.Fatal("Truncated = false after a relationship union was cut, want true")
		}
	})
	t.Run("relationships exactly at cap stay false", func(t *testing.T) {
		a := mkFinding(mkEvidence(0, 1), nil, mkRelationships(0, 16), nil)
		b := mkFinding(mkEvidence(1, 2), nil, mkRelationships(16, 32), nil)
		m := merge(a, b)
		if len(m.Relationships) != maxFindingRelationships {
			t.Fatalf("exactly-at-cap union retained %d edges, want %d", len(m.Relationships), maxFindingRelationships)
		}
		if m.Truncated {
			t.Error("Truncated = true for an exactly-at-cap relationship union, want false")
		}
	})
	t.Run("metadata cut sets the flag", func(t *testing.T) {
		a := mkFinding(mkEvidence(0, 1), nil, nil, mkMetadata(0, 10))
		b := mkFinding(mkEvidence(1, 2), nil, nil, mkMetadata(10, 20))
		m := merge(a, b)
		if len(m.Metadata) != maxFindingMetadataEntries {
			t.Fatalf("retained %d metadata entries, want the %d bound", len(m.Metadata), maxFindingMetadataEntries)
		}
		if !m.Truncated {
			t.Fatal("Truncated = false after a metadata union was cut, want true")
		}
	})
	t.Run("metadata exactly at cap stays false", func(t *testing.T) {
		a := mkFinding(mkEvidence(0, 1), nil, nil, mkMetadata(0, 8))
		b := mkFinding(mkEvidence(1, 2), nil, nil, mkMetadata(8, 16))
		m := merge(a, b)
		if len(m.Metadata) != maxFindingMetadataEntries {
			t.Fatalf("exactly-at-cap union retained %d entries, want %d", len(m.Metadata), maxFindingMetadataEntries)
		}
		if m.Truncated {
			t.Error("Truncated = true for an exactly-at-cap metadata union, want false")
		}
	})
	t.Run("sticky across chained merges", func(t *testing.T) {
		cut := merge(
			mkFinding(mkEvidence(0, maxFindingEvidence), nil, nil, nil),
			mkFinding(mkEvidence(maxFindingEvidence, 2*maxFindingEvidence), nil, nil, nil),
		)
		if !cut.Truncated {
			t.Fatal("precondition failed: the cut finding is not flagged")
		}
		chained := merge(cut, mkFinding(mkEvidence(100, 101), nil, nil, nil))
		if !chained.Truncated {
			t.Error("Truncated = false after re-merging a flagged finding with no new cut, want true (sticky)")
		}
		// Either input carrying the flag marks the result.
		flagged := base
		flagged.Truncated = true
		fromInput := merge(flagged, mkFinding(mkEvidence(200, 201), nil, nil, nil))
		if !fromInput.Truncated {
			t.Error("Truncated = false when one input carried the flag, want true (sticky)")
		}
	})
	t.Run("normalization never sets the flag", func(t *testing.T) {
		if base.Truncated {
			t.Error("NewFinding set Truncated on an ordinary in-bounds finding, want false")
		}
		maxed := mkFinding(mkEvidence(0, maxFindingEvidence),
			mkRelated(0, maxFindingRelated), mkRelationships(0, maxFindingRelationships),
			mkMetadata(0, maxFindingMetadataEntries))
		if maxed.Truncated {
			t.Error("NewFinding set Truncated on an exactly-at-cap finding, want false (normalization rejects, never truncates)")
		}
		// Over-cap input is REJECTED, not truncated — the honest path.
		if _, err := NewFinding(Finding{
			RuleID: base.RuleID, RuleName: base.RuleName, Category: base.Category,
			Subject: subject, Confidence: 0.5,
			Evidence: mkEvidence(0, maxFindingEvidence+1),
			Priority: "low", Status: "open", Created: base.Created,
		}); err == nil {
			t.Error("NewFinding accepted over-bound evidence, want an error (never a silent truncate)")
		}
	})
}

// TestFindingTruncatedJSON pins the wire compatibility of the marker: it
// round-trips through JSON, and records written before the field existed
// decode with it false.
func TestFindingTruncatedJSON(t *testing.T) {
	f := findingFixture(t)
	f.Truncated = true
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back Finding
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Truncated {
		t.Error("Truncated did not survive a JSON round trip")
	}
	if !strings.Contains(string(data), `"truncated":true`) {
		t.Errorf("marshaled form lacks the truncated key: %s", data)
	}
	// Old record (no marker key): decodes false.
	var legacy Finding
	if err := json.Unmarshal([]byte(`{"rule_id":"r","subject":{"kind":"url","value":"https://example.com/"}}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Truncated {
		t.Error("legacy record without the marker key decoded Truncated=true, want false")
	}
}
