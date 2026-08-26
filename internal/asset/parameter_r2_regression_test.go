package asset

import (
	"reflect"
	"testing"
)

// TestWithValueBackDatesFirstSeen is the R2-M9 regression: WithValue must
// advance FirstSeen to the earliest observation (the minimum of existing
// and new), matching the field contract ("time of the earliest
// observation") and MergeParameters' min behavior. Before the fix an
// out-of-order observation left FirstSeen at the later construction time.
func TestWithValueBackDatesFirstSeen(t *testing.T) {
	t1 := fixedTime(10)
	t2 := fixedTime(12)
	if !t1.Before(t2) {
		t.Fatalf("test setup: %v must precede %v", t1, t2)
	}
	p := Provenance{Source: "url-intel", DiscoveredAt: t2}

	prm, err := NewParameter("q", "query", "later-value", "src-a", t2, p)
	if err != nil {
		t.Fatalf("NewParameter: %v", err)
	}

	got, err := WithValue(prm, "earlier-value", "src-b", t1)
	if err != nil {
		t.Fatalf("WithValue: %v", err)
	}
	if !got.FirstSeen.Equal(t1) {
		t.Errorf("FirstSeen = %v, want back-dated to the earliest observation %v", got.FirstSeen, t1)
	}
	if !got.LastSeen.Equal(t2) {
		t.Errorf("LastSeen = %v, want %v (latest observation unchanged)", got.LastSeen, t2)
	}
	if !reflect.DeepEqual(got.ObservedValues, []string{"later-value", "earlier-value"}) {
		t.Errorf("ObservedValues = %v, want both observations retained", got.ObservedValues)
	}
}
