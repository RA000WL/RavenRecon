package asset

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestNewParameter(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "url-intel", DiscoveredAt: at, Confidence: 0.9}

	prm, err := NewParameter("q", "query", "42", "url-intel", at, p)
	if err != nil {
		t.Fatalf("NewParameter: %v", err)
	}
	if prm.Name != "q" || prm.Location != "query" {
		t.Errorf("Name/Location = %q/%q", prm.Name, prm.Location)
	}
	if !reflect.DeepEqual(prm.ObservedValues, []string{"42"}) {
		t.Errorf("ObservedValues = %v", prm.ObservedValues)
	}
	if prm.FirstSeen != at || prm.LastSeen != at {
		t.Errorf("FirstSeen/LastSeen = %v/%v, want %v", prm.FirstSeen, prm.LastSeen, at)
	}
	if !reflect.DeepEqual(prm.Sources, []string{"url-intel"}) {
		t.Errorf("Sources = %v", prm.Sources)
	}
	if prm.Truncated {
		t.Error("Truncated should be false on construction")
	}
	if prm.Prov != p {
		t.Errorf("Prov = %v, want %v", prm.Prov, p)
	}
	if prm.ID() != "parameter:query:q" {
		t.Errorf("ID = %q, want parameter:query:q", prm.ID())
	}
	if prm.String() != "query:q" {
		t.Errorf("String = %q, want query:q", prm.String())
	}
}

func TestNewParameterValidation(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}

	// Reserved locations are allowlisted and construct successfully.
	for _, loc := range []string{"path", "body"} {
		if _, err := NewParameter("q", loc, "v", "s", at, p); err != nil {
			t.Errorf("reserved location %q must construct: %v", loc, err)
		}
	}

	cases := []struct {
		name    string
		prm     func() (Parameter, error)
		wantSub string
	}{
		{"empty name", func() (Parameter, error) { return NewParameter("", "query", "v", "s", at, p) }, "must not be empty"},
		{"oversized name", func() (Parameter, error) { return NewParameter(strings.Repeat("a", 513), "query", "v", "s", at, p) }, "longer than 512"},
		{"NUL in name", func() (Parameter, error) { return NewParameter("a\x00b", "query", "v", "s", at, p) }, "control character"},
		{"tab in name", func() (Parameter, error) { return NewParameter("a\tb", "query", "v", "s", at, p) }, "control character"},
		{"DEL in name", func() (Parameter, error) { return NewParameter("a\x7fb", "query", "v", "s", at, p) }, "control character"},
		{"bad location", func() (Parameter, error) { return NewParameter("q", "cookie", "v", "s", at, p) }, "unsupported parameter location"},
		{"uppercase location", func() (Parameter, error) { return NewParameter("q", "QUERY", "v", "s", at, p) }, "unsupported parameter location"},
		{"empty location", func() (Parameter, error) { return NewParameter("q", "", "v", "s", at, p) }, "unsupported parameter location"},
		{"empty value", func() (Parameter, error) { return NewParameter("q", "query", "", "s", at, p) }, "must not be empty"},
		{"oversized value", func() (Parameter, error) { return NewParameter("q", "query", strings.Repeat("v", 8193), "s", at, p) }, "longer than 8192"},
		{"empty source", func() (Parameter, error) { return NewParameter("q", "query", "v", "", at, p) }, "must not be empty"},
		{"oversized source", func() (Parameter, error) { return NewParameter("q", "query", "v", strings.Repeat("s", 129), at, p) }, "longer than 128"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			prm, err := tt.prm()
			if err == nil {
				t.Fatalf("expected error, got %v", prm)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err, tt.wantSub)
			}
		})
	}
}

func TestParameterIdentity(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}

	// The core of the model: identity is name+location; values are
	// observations, not identity.
	a, err := NewParameter("q", "query", "one", "s1", at, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewParameter("q", "query", "two", "s1", at, p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Identity() != b.Identity() {
		t.Fatal("same name+location must share an identity regardless of value")
	}
	if a.ID() != "parameter:query:q" {
		t.Errorf("ID = %q, want parameter:query:q", a.ID())
	}
	if a.Identity().Kind != KindParameter {
		t.Errorf("kind = %q, want %q", a.Identity().Kind, KindParameter)
	}

	// Location namespaces the name: query/a, path/a, and body/a are
	// different parameters.
	ids := map[string]string{}
	for _, loc := range []string{"query", "path", "body"} {
		prm, err := NewParameter("a", loc, "v", "s", at, p)
		if err != nil {
			t.Fatal(err)
		}
		ids[loc] = prm.ID()
	}
	if ids["query"] != "parameter:query:a" || ids["path"] != "parameter:path:a" || ids["body"] != "parameter:body:a" {
		t.Errorf("location-prefixed IDs = %v", ids)
	}
	if ids["query"] == ids["path"] || ids["query"] == ids["body"] || ids["path"] == ids["body"] {
		t.Error("different locations must namespace distinct identities")
	}

	// Distinct raw spellings of a name stay distinct (value-preserving).
	raw, _ := NewParameter("a b", "query", "v", "s", at, p)
	esc, _ := NewParameter("a%20b", "query", "v", "s", at, p)
	if raw.ID() == esc.ID() {
		t.Error("distinct raw names must not share an identity")
	}
	if raw.ID() != "parameter:query:a%20b" {
		t.Errorf("raw space name ID = %q, want parameter:query:a%%20b", raw.ID())
	}
	if esc.ID() != "parameter:query:a%2520b" {
		t.Errorf("escaped-looking name ID = %q, want parameter:query:a%%2520b", esc.ID())
	}

	// A name containing the separator colon cannot blur the boundary.
	colon, _ := NewParameter("path:x", "query", "v", "s", at, p)
	if colon.ID() != "parameter:query:path%3Ax" {
		t.Errorf("colon name ID = %q, want parameter:query:path%%3Ax", colon.ID())
	}
}

func TestParameterWithValue(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}
	prm, err := NewParameter("q", "query", "a", "s1", at, p)
	if err != nil {
		t.Fatal(err)
	}

	// Appending a new value records the observation.
	got, err := WithValue(prm, "b", "s2", fixedTime(12))
	if err != nil {
		t.Fatalf("WithValue: %v", err)
	}
	if !reflect.DeepEqual(got.ObservedValues, []string{"a", "b"}) {
		t.Errorf("ObservedValues = %v", got.ObservedValues)
	}
	if got.FirstSeen != at || got.LastSeen != fixedTime(12) {
		t.Errorf("FirstSeen/LastSeen = %v/%v", got.FirstSeen, got.LastSeen)
	}
	if !reflect.DeepEqual(got.Sources, []string{"s1", "s2"}) {
		t.Errorf("Sources = %v", got.Sources)
	}
	if got.Prov != p {
		t.Errorf("Prov must be preserved: %v", got.Prov)
	}

	// Purity: the input parameter is unchanged.
	if !reflect.DeepEqual(prm.ObservedValues, []string{"a"}) {
		t.Error("WithValue must not mutate its input")
	}

	// Dedup: a duplicate value is not appended, but the observation is
	// still recorded (LastSeen advances, source added once).
	dup, err := WithValue(got, "a", "s3", fixedTime(14))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dup.ObservedValues, []string{"a", "b"}) {
		t.Errorf("duplicate value appended: %v", dup.ObservedValues)
	}
	if dup.LastSeen != fixedTime(14) {
		t.Errorf("LastSeen = %v, want the observation time recorded", dup.LastSeen)
	}
	if !reflect.DeepEqual(dup.Sources, []string{"s1", "s2", "s3"}) {
		t.Errorf("Sources = %v", dup.Sources)
	}

	// A source is appended once no matter how many observations carry it.
	again, err := WithValue(dup, "c", "s3", fixedTime(15))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again.Sources, []string{"s1", "s2", "s3"}) {
		t.Errorf("Sources = %v, want s3 appended once", again.Sources)
	}

	// An earlier observation never moves LastSeen backwards.
	early, err := WithValue(again, "d", "s4", fixedTime(1))
	if err != nil {
		t.Fatal(err)
	}
	if early.LastSeen != fixedTime(15) {
		t.Errorf("LastSeen moved backwards: %v", early.LastSeen)
	}

	// Validation failures return errors.
	if _, err := WithValue(prm, "", "s", fixedTime(11)); err == nil {
		t.Error("empty value must error")
	}
	if _, err := WithValue(prm, "v", "", fixedTime(11)); err == nil {
		t.Error("empty source must error")
	}
	if _, err := WithValue(prm, strings.Repeat("v", 8193), "s", fixedTime(11)); err == nil {
		t.Error("oversized value must error")
	}
	if _, err := WithValue(prm, "v", strings.Repeat("s", 129), fixedTime(11)); err == nil {
		t.Error("oversized source must error")
	}
}

func TestParameterValueCap(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}
	prm, err := NewParameter("q", "query", "v0", "s", at, p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < maxParameterValues; i++ {
		prm, err = WithValue(prm, "v"+strconv.Itoa(i), "s", at)
		if err != nil {
			t.Fatalf("WithValue(%d): %v", i, err)
		}
	}
	if len(prm.ObservedValues) != maxParameterValues || prm.Truncated {
		t.Fatalf("at cap: len=%d truncated=%v", len(prm.ObservedValues), prm.Truncated)
	}

	// One more NEW value is dropped; existing values are never evicted.
	prm, err = WithValue(prm, "overflow", "s2", fixedTime(11))
	if err != nil {
		t.Fatal(err)
	}
	if !prm.Truncated {
		t.Error("Truncated must be set when a new value is dropped")
	}
	if len(prm.ObservedValues) != maxParameterValues {
		t.Errorf("len = %d, want %d (no eviction)", len(prm.ObservedValues), maxParameterValues)
	}
	if containsString(prm.ObservedValues, "overflow") {
		t.Error("new value beyond the cap must be dropped")
	}
	if prm.ObservedValues[0] != "v0" || prm.ObservedValues[maxParameterValues-1] != "v"+strconv.Itoa(maxParameterValues-1) {
		t.Error("existing values must survive in order")
	}
	// The dropped-value observation is still recorded in time and sources.
	if prm.LastSeen != fixedTime(11) || !containsString(prm.Sources, "s2") {
		t.Error("dropped-value observations still record time and source")
	}

	// Duplicate values at the cap change nothing but LastSeen.
	prm, err = WithValue(prm, "v0", "s", fixedTime(12))
	if err != nil {
		t.Fatal(err)
	}
	if len(prm.ObservedValues) != maxParameterValues {
		t.Errorf("duplicate at cap changed length: %d", len(prm.ObservedValues))
	}
	if prm.LastSeen != fixedTime(12) {
		t.Errorf("duplicate observation must advance LastSeen: %v", prm.LastSeen)
	}
}

func TestMergeParameters(t *testing.T) {
	t1 := fixedTime(10)
	t2 := fixedTime(12)
	p1 := Provenance{Source: "s1", DiscoveredAt: t1}
	p2 := Provenance{Source: "s2", DiscoveredAt: t2}

	a, err := NewParameter("q", "query", "a", "s1", t1, p1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewParameter("q", "query", "b", "s2", t2, p2)
	if err != nil {
		t.Fatal(err)
	}

	m, err := MergeParameters(a, b)
	if err != nil {
		t.Fatalf("MergeParameters: %v", err)
	}
	if m.ID() != "parameter:query:q" {
		t.Errorf("ID = %q", m.ID())
	}
	if !reflect.DeepEqual(m.ObservedValues, []string{"a", "b"}) {
		t.Errorf("ObservedValues = %v", m.ObservedValues)
	}
	if m.FirstSeen != t1 || m.LastSeen != t2 {
		t.Errorf("FirstSeen/LastSeen = %v/%v", m.FirstSeen, m.LastSeen)
	}
	if !reflect.DeepEqual(m.Sources, []string{"s1", "s2"}) {
		t.Errorf("Sources = %v", m.Sources)
	}
	if m.Prov != p1 {
		t.Errorf("Prov = %v, want the earliest %v", m.Prov, p1)
	}
	if m.Truncated {
		t.Error("Truncated must be false")
	}

	// Union order: a's values first, then b's new values in first-seen order.
	b2, err := NewParameter("q", "query", "a", "s3", t2, p2)
	if err != nil {
		t.Fatal(err)
	}
	b2, err = WithValue(b2, "c", "s3", t2)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := MergeParameters(a, b2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m2.ObservedValues, []string{"a", "c"}) {
		t.Errorf("union = %v, want [a c]", m2.ObservedValues)
	}
	if !reflect.DeepEqual(m2.Sources, []string{"s1", "s3"}) {
		t.Errorf("Sources = %v", m2.Sources)
	}

	// Identity mismatches refuse to merge.
	other, err := NewParameter("other", "query", "a", "s1", t1, p1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeParameters(a, other); err == nil {
		t.Error("different names must refuse to merge")
	}
	pathQ, err := NewParameter("q", "path", "a", "s1", t1, p1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeParameters(a, pathQ); err == nil {
		t.Error("different locations must refuse to merge")
	}
}

func TestMergeParametersCap(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "s1", DiscoveredAt: at}

	full, err := NewParameter("q", "query", "v0", "s1", at, p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < maxParameterValues; i++ {
		full, err = WithValue(full, "v"+strconv.Itoa(i), "s1", at)
		if err != nil {
			t.Fatal(err)
		}
	}
	extra, err := NewParameter("q", "query", "extra", "s2", fixedTime(12), p)
	if err != nil {
		t.Fatal(err)
	}

	// A union beyond the cap keeps a's values and drops b's new ones.
	m, err := MergeParameters(full, extra)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Truncated {
		t.Error("union beyond the cap must set Truncated")
	}
	if len(m.ObservedValues) != maxParameterValues {
		t.Errorf("len = %d, want %d", len(m.ObservedValues), maxParameterValues)
	}
	if containsString(m.ObservedValues, "extra") {
		t.Error("b's value beyond the cap must be dropped")
	}
	if m.ObservedValues[0] != "v0" || m.ObservedValues[maxParameterValues-1] != "v"+strconv.Itoa(maxParameterValues-1) {
		t.Error("a's values must be preserved in order")
	}
	if m.LastSeen != fixedTime(12) || !containsString(m.Sources, "s2") {
		t.Error("merge must still record b's observation time and source")
	}

	// Truncated ORs: a parameter truncated earlier stays truncated after a
	// merge that drops nothing new, in both argument orders.
	dupOfFull, err := NewParameter("q", "query", "v0", "s9", fixedTime(13), p)
	if err != nil {
		t.Fatal(err)
	}
	m3, err := MergeParameters(m, dupOfFull)
	if err != nil {
		t.Fatal(err)
	}
	if !m3.Truncated {
		t.Error("Truncated must OR across merges (a truncated)")
	}
	m4, err := MergeParameters(dupOfFull, m)
	if err != nil {
		t.Fatal(err)
	}
	if !m4.Truncated {
		t.Error("Truncated must OR across merges (b truncated)")
	}
}

func TestParameterRelationships(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at}
	u, err := ParseURL("https://example.com/p?q=1", p)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEndpoint("GET", "https://example.com/p?q=1", p)
	if err != nil {
		t.Fatal(err)
	}
	prm, err := NewParameter("q", "query", "1", "manual", at, p)
	if err != nil {
		t.Fatal(err)
	}

	urlToPrm, err := NewRelationship(u.Identity(), RelationshipURLToParameter, prm.Identity())
	if err != nil {
		t.Fatalf("url->parameter relationship: %v", err)
	}
	want := "url:https://example.com/p?q=1" + "url_to_parameter\x00" + "parameter:query:q"
	if urlToPrm.ID() != want {
		t.Errorf("ID = %q, want %q", urlToPrm.ID(), want)
	}

	endpointToPrm, err := NewRelationship(e.Identity(), RelationshipEndpointToParameter, prm.Identity())
	if err != nil {
		t.Fatalf("endpoint->parameter relationship: %v", err)
	}
	if endpointToPrm.ID() == urlToPrm.ID() {
		t.Error("different kinds must not share an identity")
	}

	// Identical edges deduplicate.
	again, err := NewRelationship(u.Identity(), RelationshipURLToParameter, prm.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if again.ID() != urlToPrm.ID() {
		t.Error("identical edges must deduplicate")
	}

	// NewRelationship validation behaves as it exists: non-zero endpoints
	// and a non-empty kind (kinds are not allowlisted).
	if _, err := NewRelationship(Identity{}, RelationshipURLToParameter, prm.Identity()); err == nil {
		t.Error("zero from must error")
	}
	if _, err := NewRelationship(u.Identity(), RelationshipURLToParameter, Identity{}); err == nil {
		t.Error("zero to must error")
	}
	if _, err := NewRelationship(u.Identity(), RelationshipKind(""), prm.Identity()); err == nil {
		t.Error("empty kind must error")
	}
}

func TestParameterSerializationRoundTrip(t *testing.T) {
	at := fixedTime(10)
	p := Provenance{Source: "manual", DiscoveredAt: at, Reference: "ref-1", Confidence: 0.9}
	prm, err := NewParameter("q", "query", "1", "manual", at, p)
	if err != nil {
		t.Fatal(err)
	}
	prm, err = WithValue(prm, "2", "other", fixedTime(12))
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(prm)
	if err != nil {
		t.Fatal(err)
	}
	var back Parameter
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, prm) {
		t.Errorf("round trip mismatch:\n got %#v\nwant %#v\njson: %s", back, prm, data)
	}
	if back.ID() != prm.ID() {
		t.Errorf("identity changed after serialization: %q != %q", back.ID(), prm.ID())
	}
}
