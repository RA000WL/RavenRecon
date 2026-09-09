package triage

import "testing"

// TestTriageRuleVersions pins the content-bump contract: the pre-cap
// reflection-backed scoring (NEW-135 — backed subjects at 0.8 outrank
// name-only matches at 0.6 before the 256-cap) changes the retained set,
// so all eight rules sit at 1.2.0 — old cached findings never replay.
func TestTriageRuleVersions(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	want := map[string]string{
		ruleRedirect:     "1.2.0",
		ruleIDOR:         "1.2.0",
		ruleSQLi:         "1.2.0",
		ruleLFI:          "1.2.0",
		ruleSSRF:         "1.2.0",
		ruleCMDi:         "1.2.0",
		ruleSSTI:         "1.2.0",
		ruleXSSReflected: "1.2.0",
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
