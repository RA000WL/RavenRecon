package triage

import (
	"context"
	"sort"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
)

// TestTriageVersionBumpEvictsStaleOverCapRecord pins the NEW-140
// content-bump: the pre-cap reflection-backed scoring (NEW-135) changes the
// retained set, so the 1.1.0 → 1.2.0 bump must evict stale records. A 1.1.0
// pack cold-run stores an over-cap (300 subjects, 100 reflection-backed at
// 0.8, 200 name-only at 0.6) mixed-backing record under cache; the 1.2.0
// pack over the identical snapshot must miss every rule and recompute (the
// version enters the rule fingerprint and key — the stale record is never
// served), and a second 1.2.0 run must hit (the fresh record stores under
// the new key).
func TestTriageVersionBumpEvictsStaleOverCapRecord(t *testing.T) {
	const total = 300
	var eps []asset.Endpoint
	for i := 0; i < total; i++ {
		eps = append(eps, mustEndpoint(t, "GET", "https://www.example.com/search"+itoa(i)+"?q="+itoa(i)))
	}
	// Rank endpoints by subject identity; back the highest 100, exactly as
	// TestTriageCapKeepsBackedFirst does. The fixture proves the version
	// enters the key (stale records never serve).
	ordered := append([]asset.Endpoint(nil), eps...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Identity().String() < ordered[j].Identity().String()
	})
	var evs []asset.Evidence
	for _, ep := range ordered[total-100:] {
		evs = append(evs, mustReflectEvidence(t, ep, "q", httpprobe.ReflectUnencoded))
	}
	snap := detect.Snapshot{Endpoints: eps, Evidence: evs}

	fresh, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	stale := make([]detect.Rule, 0, len(fresh))
	for _, r := range fresh {
		r.Version = "1.1.0"
		stale = append(stale, r)
	}

	fs, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	run := func(rules []detect.Rule) detect.Report {
		reg := detect.NewRegistry()
		for _, r := range rules {
			if err := reg.Register(r); err != nil {
				t.Fatalf("Register(%q): %v", r.ID, err)
			}
		}
		if err := reg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		reg.Seal()
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Cache = fs
		rep, err := detect.Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}
	ruleResult := func(rep detect.Report, id string) detect.RuleResult {
		t.Helper()
		for _, r := range rep.Rules {
			if r.RuleID == id {
				return r
			}
		}
		t.Fatalf("rule %q missing from report", id)
		return detect.RuleResult{}
	}

	// Cold 1.1.0 run: nothing cached; the over-cap mixed-backing record is
	// stored (xss keeps the 256-cap with every backed finding retained).
	cold := run(stale)
	if cold.CacheHits != 0 {
		t.Fatalf("stale cold run served %d cache hits, want 0", cold.CacheHits)
	}
	if got := ruleResult(cold, ruleXSSReflected).Findings; got != 256 {
		t.Fatalf("stale cold run xss findings = %d, want the 256-cap stored", got)
	}

	// Bumped 1.2.0 run over the identical snapshot: the stale record must
	// NOT serve — every rule misses and recomputes.
	bumped := run(fresh)
	if bumped.CacheHits != 0 {
		t.Fatalf("bumped run served %d cache hits, want 0 (stale 1.1.0 records must never replay)", bumped.CacheHits)
	}
	if r := ruleResult(bumped, ruleXSSReflected); r.Cached {
		t.Fatalf("bumped xss result served cached, want fresh recompute: %+v", r)
	}
	if got := ruleResult(bumped, ruleXSSReflected).Findings; got != 256 {
		t.Fatalf("bumped run xss findings = %d, want the 256-cap recomputed", got)
	}

	// Second 1.2.0 run: the fresh record stores under the new key, so every
	// rule hits.
	warm := run(fresh)
	if warm.CacheHits != len(fresh) {
		t.Fatalf("warm bumped run served %d cache hits, want %d (fresh 1.2.0 records must store)", warm.CacheHits, len(fresh))
	}
	for _, r := range warm.Rules {
		if !r.Cached {
			t.Errorf("warm bumped rule %q not served from cache: %+v", r.RuleID, r)
		}
	}
}

// itoa formats a small non-negative integer without importing strconv at
// test scope (fmt is already imported by the package's other tests, but a
// two-line helper keeps this file self-contained).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
