package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestRunOverCapScoreOrderShuffledInput pins the NEW-135 run-cap contract
// end to end: an over-cap run keeps the deterministic top by finding rank
// (score descending, then rule ID, then subject identity), reports the cut
// honestly (FindingsTruncated + incomplete outcome, per-rule completed
// statuses untouched), and produces byte-identical reports across runs and
// across input orders (reversed asset order AND reversed rule registration
// order — completion order never decides the retained set).
func TestRunOverCapScoreOrderShuffledInput(t *testing.T) {
	const perRule = maxFindingsPerRule                     // 256; each rule stays within its own bound.
	const rules = maxFindingsPerRun/maxFindingsPerRule + 1 // 17 rules x 256 = 4352 > 4096.
	subs := make([]asset.Identity, 0, perRule)
	assets := make([]asset.Identity, 0, perRule)
	for i := 0; i < perRule; i++ {
		u, err := asset.ParseURL(fmt.Sprintf("https://example.com/p/%03d", i), asset.Provenance{Source: "test"})
		if err != nil {
			t.Fatalf("ParseURL: %v", err)
		}
		subs = append(subs, u.Identity())
		assets = append(assets, u.Identity())
	}
	// Two confidence tiers: rules cap.000-cap.007 emit 0.9, rules
	// cap.008-cap.016 emit 0.1. The 256 dropped findings must be exactly
	// rule cap.016's output — the rule-ID tie-break pin inside the 0.1
	// tier (category and priority are identical across rules, so only
	// rule ID decides there).
	mkRule := func(i int) Rule {
		id := fmt.Sprintf("cap.%03d", i)
		conf := 0.1
		if i < 8 {
			conf = 0.9
		}
		return makeRule(t, id, &ruleOptions{detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
			out := make([]asset.Finding, 0, len(subs))
			for j, subj := range subs {
				f, err := subjectFinding(dctx, id, "Rule "+id, CategoryInformation, subj, j)
				if err != nil {
					return nil, err
				}
				f.Confidence = conf
				out = append(out, f)
			}
			return out, nil
		}})
	}
	clock := fixedClock{at: time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)}
	run := func(reverse bool) Report {
		list := make([]Rule, 0, rules)
		for i := 0; i < rules; i++ {
			list = append(list, mkRule(i))
		}
		snapAssets := append([]asset.Identity(nil), assets...)
		if reverse {
			for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
				list[i], list[j] = list[j], list[i]
			}
			for i, j := 0, len(snapAssets)-1; i < j; i, j = i+1, j-1 {
				snapAssets[i], snapAssets[j] = snapAssets[j], snapAssets[i]
			}
		}
		cfg := DefaultEngineConfig(newTestRegistry(t, list...))
		cfg.Clock = clock
		rep, err := Run(context.Background(), cfg, Snapshot{Assets: snapAssets})
		if err != nil {
			t.Fatalf("Run(reverse=%v): %v", reverse, err)
		}
		return rep
	}
	rep1, rep2 := run(false), run(true)

	// Honesty: the cut is flagged and the run is incomplete, while every
	// per-rule status stays completed.
	for k, rep := range []Report{rep1, rep2} {
		if rep.Outcome != OutcomeIncomplete || !rep.FindingsTruncated {
			t.Fatalf("run %d: outcome %s truncated %v, want incomplete + truncated", k, rep.Outcome, rep.FindingsTruncated)
		}
		if len(rep.Findings) != maxFindingsPerRun {
			t.Fatalf("run %d kept %d findings, want the %d cap", k, len(rep.Findings), maxFindingsPerRun)
		}
		if rep.Completed != rules || rep.Failed != 0 {
			t.Fatalf("run %d per-rule statuses must all stay completed: %+v", k, rep)
		}
	}

	// Ordering: every 0.9 finding survives; inside the 0.1 tier the
	// lowest rule IDs survive and cap.016 is cut entirely.
	kept := make(map[string]bool, len(rep1.Findings))
	for _, f := range rep1.Findings {
		kept[f.RuleID+"\x00"+f.Subject.String()] = true
	}
	for i := 0; i < rules; i++ {
		id := fmt.Sprintf("cap.%03d", i)
		for _, subj := range subs {
			got := kept[id+"\x00"+subj.String()]
			if i < rules-1 && !got {
				t.Fatalf("finding %s on %s dropped over cap, want the score-top retained", id, subj)
			}
			if i == rules-1 && got {
				t.Fatalf("finding %s on %s kept over cap, want the rule-ID tail cut", id, subj)
			}
		}
	}

	// Determinism: byte-identical reports across runs and input orders.
	b1, err := json.Marshal(rep1)
	if err != nil {
		t.Fatalf("marshal rep1: %v", err)
	}
	b2, err := json.Marshal(rep2)
	if err != nil {
		t.Fatalf("marshal rep2: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("over-cap runs with reversed input order diverged (completion order leaked into retention)")
	}
}
