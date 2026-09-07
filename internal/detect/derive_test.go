package detect

import (
	"math"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// deriveTestFinding builds one canonical finding about subjectURL with
// the given priority/confidence through the Phase 2 builders (synthetic
// values only — derivation tests never touch the network).
func deriveTestFinding(t *testing.T, subjectURL, ruleID, priority string, confidence float64) asset.Finding {
	t.Helper()
	subj, err := asset.ParseURL(subjectURL, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", subjectURL, err)
	}
	ev, err := asset.NewEvidence(asset.MethodDetection, "derive.test", "signal", subj.Identity(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	f, err := asset.NewFinding(asset.Finding{
		RuleID: ruleID, RuleName: "Derive Test", Category: "information",
		Subject: subj.Identity(), Confidence: confidence, Evidence: []asset.Evidence{ev},
		Priority: priority, Status: "open",
		Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

func deriveTestEvent() event.Event {
	return event.New(event.KindTaskCompleted, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		event.NewTaskCompleted(event.NewTaskTerminal(1, 0, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "", ""), nil))
}

func TestDeriveShapes(t *testing.T) {
	ev := deriveTestEvent()
	f := deriveTestFinding(t, "https://a.example.com/", "derive.x", "high", 0.8)

	// Value and pointer results derive identically.
	gotVal := Deriver{}.Derive(ev, ruleJobResult{Findings: []asset.Finding{f}})
	gotPtr := Deriver{}.Derive(ev, &ruleJobResult{Findings: []asset.Finding{f}})
	if len(gotVal) != 1 || len(gotPtr) != 1 {
		t.Fatalf("value=%d pointer=%d, want one derived event each", len(gotVal), len(gotPtr))
	}

	// Nil, unknown, and empty results derive nothing (a nil Observer
	// stays the off switch upstream; Derive itself stays total).
	for name, res := range map[string]any{
		"nil result":       nil,
		"nil pointer":      (*ruleJobResult)(nil),
		"unknown type":     "host:example.com",
		"unknown int":      42,
		"empty findings":   ruleJobResult{},
		"empty ptr":        &ruleJobResult{},
		"nil findings":     ruleJobResult{Findings: nil},
		"foreign findings": ruleJobResult{Findings: []asset.Finding{{}}},
	} {
		if got := (Deriver{}).Derive(ev, res); len(got) != 0 {
			t.Errorf("%s: derived %d events, want none", name, len(got))
		}
	}
}

func TestDeriveFieldMapping(t *testing.T) {
	ev := deriveTestEvent()
	f := deriveTestFinding(t, "https://a.example.com/", "derive.map", "medium", 0.6)
	got := Deriver{}.Derive(ev, ruleJobResult{Findings: []asset.Finding{f}})
	if len(got) != 1 {
		t.Fatalf("derived %d events, want 1", len(got))
	}
	d := got[0]
	if d.Kind != event.KindFindingCreated {
		t.Fatalf("kind = %s, want %s", d.Kind, event.KindFindingCreated)
	}
	if !d.At.Equal(ev.At) {
		t.Errorf("derived timestamp = %v, want the job event's %v", d.At, ev.At)
	}
	p, ok := d.Payload.(event.FindingCreated)
	if !ok {
		t.Fatalf("payload = %T, want FindingCreated", d.Payload)
	}
	// Golden field mapping: every event field cites the finding verbatim
	// (confidence clamped — 0.6 is in range, so identical).
	if p.Identity != f.ID() || p.RuleID != "derive.map" ||
		p.Subject != f.Subject.String() || p.Priority != "medium" ||
		p.Category != f.Category || p.Confidence != 0.6 {
		t.Errorf("field mapping wrong: %+v (finding %+v)", p, f)
	}
}

func TestDeriveClampsConfidence(t *testing.T) {
	ev := deriveTestEvent()
	subj, err := asset.ParseURL("https://a.example.com/", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		in   float64
		want float64
	}{
		{"zero stays", 0, 0},
		{"one stays", 1, 1},
		{"mid stays", 0.42, 0.42},
		{"negative clamps", -0.5, 0},
		{"above one clamps", 1.5, 0},
		{"NaN clamps", math.NaN(), 0},
		{"+Inf clamps", math.Inf(1), 0},
		{"-Inf clamps", math.Inf(-1), 0},
	} {
		// Hand-rolled (never NewFinding-validated: the builders reject
		// out-of-range confidence, which is exactly why the Deriver
		// clamps foreign inputs instead of trusting them).
		f := asset.Finding{
			RuleID: "derive.clamp", RuleName: "Derive Test", Category: "information",
			Subject: subj.Identity(), Confidence: tc.in,
			Priority: "low", Status: "open",
		}
		got := (Deriver{}).Derive(ev, ruleJobResult{Findings: []asset.Finding{f}})
		if len(got) != 1 {
			t.Fatalf("%s: derived %d events, want 1", tc.name, len(got))
		}
		p := got[0].Payload.(event.FindingCreated)
		if p.Confidence != tc.want || math.IsNaN(p.Confidence) {
			t.Errorf("%s: confidence = %v, want %v", tc.name, p.Confidence, tc.want)
		}
	}
}

func TestDeriveSkipsZeroIdentities(t *testing.T) {
	ev := deriveTestEvent()
	good := deriveTestFinding(t, "https://a.example.com/", "derive.skip", "low", 0.5)
	mixed := ruleJobResult{Findings: []asset.Finding{
		{},                      // zero subject (identity "finding:@")
		{RuleID: "derive.skip"}, // zero subject with a rule ID
		good,
	}}
	got := (Deriver{}).Derive(ev, mixed)
	if len(got) != 1 {
		t.Fatalf("derived %d events, want only the valid finding", len(got))
	}
	if p := got[0].Payload.(event.FindingCreated); p.RuleID != "derive.skip" {
		t.Errorf("surviving event wrong: %+v", p)
	}
}

func TestDerivedCapExceedsEngineBound(t *testing.T) {
	// Unreachability proof, pinned: the engine rejects any rule output
	// over maxFindingsPerRule (256) before it becomes a pool-job result,
	// so the Deriver's 512 cut can only bite foreign inputs.
	if maxDerivedPerJob <= maxFindingsPerRule {
		t.Fatalf("maxDerivedPerJob = %d must exceed maxFindingsPerRule = %d (defense-in-depth ordering)", maxDerivedPerJob, maxFindingsPerRule)
	}
	// And the cut itself is live for foreign oversized inputs: 513 valid
	// findings derive exactly 512.
	ev := deriveTestEvent()
	fs := make([]asset.Finding, 0, maxDerivedPerJob+1)
	for i := 0; i < maxDerivedPerJob+1; i++ {
		fs = append(fs, deriveTestFinding(t, "https://a.example.com/", "derive.cap", "low", 0.5))
	}
	if got := (Deriver{}).Derive(ev, ruleJobResult{Findings: fs}); len(got) != maxDerivedPerJob {
		t.Fatalf("oversized foreign result derived %d events, want the %d cap", len(got), maxDerivedPerJob)
	}
}
