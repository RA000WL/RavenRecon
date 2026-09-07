package triage

import "testing"

// TestTriageRuleVersions pins the content-bump contract: the reflection
// gate (NEW-120) changes findings, so all eight rules sit at 1.1.0 — old
// cached findings never replay.
func TestTriageRuleVersions(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	want := map[string]string{
		ruleRedirect:     "1.1.0",
		ruleIDOR:         "1.1.0",
		ruleSQLi:         "1.1.0",
		ruleLFI:          "1.1.0",
		ruleSSRF:         "1.1.0",
		ruleCMDi:         "1.1.0",
		ruleSSTI:         "1.1.0",
		ruleXSSReflected: "1.1.0",
	}
	if len(rules) != len(want) {
		t.Fatalf("pack carries %d rules, want %d", len(rules), len(want))
	}
	for _, r := range rules {
		if want[r.ID] != r.Version {
			t.Errorf("rule %q version %q, want %q", r.ID, r.Version, want[r.ID])
		}
	}
}
