package asset

import (
	"encoding/json"
	"fmt"
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
