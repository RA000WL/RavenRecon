package takeover

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// enrichLogger is a concurrent-safe recording Logger for direct-detector
// tests (mirrors the authz pack's recLogger; stdlib only).
type enrichLogger struct {
	mu      sync.Mutex
	entries []detect.LogEntry
}

func (l *enrichLogger) Log(level detect.LogLevel, ruleID, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, detect.LogEntry{Level: level, Rule: ruleID, Message: message})
}

func (l *enrichLogger) has(ruleID string, level detect.LogLevel, substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if e.Rule == ruleID && e.Level == level && strings.Contains(e.Message, substr) {
			return true
		}
	}
	return false
}

// enrichStubGraph is a hand-built GraphQuerier for direct-detector tests:
// Neighbors only (the enrichment never touches Path — the SDK allows
// Neighbors + Path, and the narrower surface keeps the detector honest).
type enrichStubGraph struct {
	adj map[asset.Identity][]asset.Relationship
}

func (s enrichStubGraph) Neighbors(id asset.Identity) []asset.Relationship {
	out := append([]asset.Relationship(nil), s.adj[id]...)
	return out
}

func (s enrichStubGraph) Path(from, to asset.Identity) []asset.Identity { return nil }

// mustUnclaimedPrior builds one synthetic sibling unclaimed finding for
// direct-detector tests (synthetic values only, fixed clock).
func mustUnclaimedPrior(t testing.TB, subject asset.Identity, target, provider string, confirmed bool) asset.Finding {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleCNAMEUnclaimed,
		"takeover pack signal: "+ruleCNAMEUnclaimed, subject, asset.Provenance{Source: "takeover-test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	meta := map[string]string{
		"signal":       "takeover_cname_unclaimed",
		"cname_target": target,
		"provider":     provider,
		"category":     "unclaimed_provider",
	}
	if confirmed {
		meta["confirmed"] = "true"
		meta["confirmed_provider"] = "github-pages"
	}
	f, err := asset.NewFinding(asset.Finding{
		RuleID:     ruleCNAMEUnclaimed,
		RuleName:   "Takeover CNAME Unclaimed",
		Category:   detect.CategoryInformation.String(),
		Subject:    subject,
		Confidence: 0.6,
		Evidence:   []asset.Evidence{ev},
		Metadata:   meta,
		Priority:   detect.PriorityInfo.String(),
		Status:     detect.StatusOpen.String(),
		Created:    testClock.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

// enrichDirectCtx builds a hand-rolled Context for direct-detector tests.
func enrichDirectCtx(priors []asset.Finding, gv detect.GraphQuerier) *detect.Context {
	return &detect.Context{
		Config:        map[string]string{},
		Logger:        &enrichLogger{},
		Clock:         testClock,
		PriorFindings: priors,
		GraphView:     gv,
	}
}

// TestTakeoverEnrichmentFiresViaEngine pins the acceptance wiring: an
// unclaimed snapshot through the full engine yields BOTH the sibling
// unclaimed finding and the provider-confirmed enrichment (distinct
// identity, provider corroboration meta), informational throughout.
func TestTakeoverEnrichmentFiresViaEngine(t *testing.T) {
	reg := registerTakeoverPack(t)
	snap := buildUnclaimedSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var unclaimed, enriched []asset.Finding
	for _, f := range rep.Findings {
		switch f.RuleID {
		case ruleCNAMEUnclaimed:
			unclaimed = append(unclaimed, f)
		case ruleCNAMEProviderConfirmed:
			enriched = append(enriched, f)
		}
	}
	if len(unclaimed) != 1 {
		t.Fatalf("unclaimed findings %d, want 1", len(unclaimed))
	}
	if len(enriched) != 1 {
		t.Fatalf("provider-confirmed findings %d, want 1", len(enriched))
	}
	got := enriched[0]
	if got.Identity() == unclaimed[0].Identity() {
		t.Fatalf("enrichment identity %s collides with the sibling unclaimed identity", got.Identity())
	}
	if got.Subject != unclaimed[0].Subject {
		t.Fatalf("enrichment subject %s, want sibling subject %s", got.Subject, unclaimed[0].Subject)
	}
	if got.Category != detect.CategoryInformation.String() || got.Priority != detect.PriorityInfo.String() {
		t.Fatalf("category/priority %s/%s, want information/info (recon-only)", got.Category, got.Priority)
	}
	if got.Metadata["signal"] != "takeover_cname_provider_confirmed" {
		t.Fatalf("signal %q", got.Metadata["signal"])
	}
	if got.Metadata["provider"] != "github.io" || got.Metadata["cname_target"] != "unclaimed.github.io" {
		t.Fatalf("provider corroboration meta = %v, want provider=github.io + cname_target=unclaimed.github.io", got.Metadata)
	}
	if got.Metadata["unclaimed_rule"] != ruleCNAMEUnclaimed {
		t.Fatalf("unclaimed_rule %q, want the sibling rule linkage", got.Metadata["unclaimed_rule"])
	}
	if got.Confidence != 0.6 {
		t.Fatalf("confidence %v, want 0.6 (heuristic, never a claim)", got.Confidence)
	}
	// The enrichment rule completed (not skipped) at its level.
	for _, r := range rep.Rules {
		if r.RuleID == ruleCNAMEProviderConfirmed && r.Status != detect.RuleStatusCompleted {
			t.Fatalf("enrichment status %s, want completed", r.Status)
		}
	}
}

// TestTakeoverEnrichmentSilentMatrix pins fail-open across the
// priors/graph matrix: every cell without BOTH a sibling unclaimed prior
// and a CNAME→provider graph edge stays silent (nil findings, nil
// error — never a guess, never an error).
func TestTakeoverEnrichmentSilentMatrix(t *testing.T) {
	src := mustHost(t, "sub.example.com")
	tgt := mustHost(t, "unclaimed.github.io")
	cname := mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())
	graph := enrichStubGraph{adj: map[asset.Identity][]asset.Relationship{src.Identity(): {cname}}}
	foreignPrior := mustUnclaimedPrior(t, src.Identity(), "unclaimed.github.io", "github.io", false)
	foreignPrior.RuleID = "takeover.cname.dangling"

	t.Run("nil graph", func(t *testing.T) {
		got, err := providerConfirmedDetector(context.Background(),
			enrichDirectCtx([]asset.Finding{mustUnclaimedPrior(t, src.Identity(), "unclaimed.github.io", "github.io", false)}, nil))
		if err != nil {
			t.Fatalf("nil graph err = %v, want nil (fail-open)", err)
		}
		if len(got) != 0 {
			t.Fatalf("nil graph findings %d, want 0 (silent)", len(got))
		}
	})
	t.Run("empty priors", func(t *testing.T) {
		got, err := providerConfirmedDetector(context.Background(), enrichDirectCtx(nil, graph))
		if err != nil {
			t.Fatalf("empty priors err = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Fatalf("empty priors findings %d, want 0", len(got))
		}
	})
	t.Run("non-unclaimed priors only", func(t *testing.T) {
		got, err := providerConfirmedDetector(context.Background(), enrichDirectCtx([]asset.Finding{foreignPrior}, graph))
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Fatalf("non-unclaimed priors findings %d, want 0 (sibling linkage required)", len(got))
		}
	})
	t.Run("sibling prior without CNAME edge", func(t *testing.T) {
		priors := []asset.Finding{mustUnclaimedPrior(t, src.Identity(), "unclaimed.github.io", "github.io", false)}
		got, err := providerConfirmedDetector(context.Background(),
			enrichDirectCtx(priors, enrichStubGraph{adj: map[asset.Identity][]asset.Relationship{}}))
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Fatalf("edgeless findings %d, want 0 (graph corroboration required)", len(got))
		}
	})
	t.Run("sibling prior with non-provider CNAME edge", func(t *testing.T) {
		other := mustHost(t, "old-service.example.net")
		rel := mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, other.Identity())
		g := enrichStubGraph{adj: map[asset.Identity][]asset.Relationship{src.Identity(): {rel}}}
		priors := []asset.Finding{mustUnclaimedPrior(t, src.Identity(), "old-service.example.net", "github.io", false)}
		got, err := providerConfirmedDetector(context.Background(), enrichDirectCtx(priors, g))
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Fatalf("non-provider edge findings %d, want 0 (suffix match required)", len(got))
		}
	})
	t.Run("engine dangling-only snapshot", func(t *testing.T) {
		reg := registerTakeoverPack(t)
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		rep, err := detect.Run(context.Background(), cfg, buildDanglingSnapshot(t))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		for _, f := range rep.Findings {
			if f.RuleID == ruleCNAMEProviderConfirmed {
				t.Fatalf("dangling-only corpus must not enrich (no unclaimed sibling): %+v", f)
			}
		}
	})
	t.Run("engine safe snapshot", func(t *testing.T) {
		reg := registerTakeoverPack(t)
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		rep, err := detect.Run(context.Background(), cfg, buildSafeSnapshot(t))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		for _, f := range rep.Findings {
			if f.RuleID == ruleCNAMEProviderConfirmed {
				t.Fatalf("safe corpus must not enrich: %+v", f)
			}
		}
	})
	t.Run("engine unclaimed disabled at detector level", func(t *testing.T) {
		reg := registerTakeoverPack(t)
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Config = map[string]string{ruleCNAMEUnclaimed + ".disabled": "true"}
		rep, err := detect.Run(context.Background(), cfg, buildUnclaimedSnapshot(t))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		for _, f := range rep.Findings {
			if f.RuleID == ruleCNAMEProviderConfirmed {
				t.Fatalf("level-0 drop must stay silent (empty priors): %+v", f)
			}
		}
		for _, r := range rep.Rules {
			if r.RuleID == ruleCNAMEProviderConfirmed && r.Status != detect.RuleStatusCompleted {
				t.Fatalf("enrichment status %s, want completed-silent (dep completed empty, never dep-skip)", r.Status)
			}
		}
	})
}

// TestTakeoverEnrichmentConfirmationCarryOver pins that the corroboration
// inherits the sibling's HTTP-confirmation citation when present — and
// stays confirmation-free otherwise (fail-open preserved).
func TestTakeoverEnrichmentConfirmationCarryOver(t *testing.T) {
	src := mustHost(t, "sub.example.com")
	tgt := mustHost(t, "unclaimed.github.io")
	cname := mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())
	graph := enrichStubGraph{adj: map[asset.Identity][]asset.Relationship{src.Identity(): {cname}}}

	confirmed := []asset.Finding{mustUnclaimedPrior(t, src.Identity(), "unclaimed.github.io", "github.io", true)}
	got, err := providerConfirmedDetector(context.Background(), enrichDirectCtx(confirmed, graph))
	if err != nil {
		t.Fatalf("Run confirmed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("confirmed findings %d, want 1", len(got))
	}
	if got[0].Metadata["confirmed"] != "true" || got[0].Metadata["confirmed_provider"] != "github-pages" {
		t.Fatalf("meta = %v, want inherited confirmed=true + confirmed_provider=github-pages", got[0].Metadata)
	}

	plain := []asset.Finding{mustUnclaimedPrior(t, src.Identity(), "unclaimed.github.io", "github.io", false)}
	got, err = providerConfirmedDetector(context.Background(), enrichDirectCtx(plain, graph))
	if err != nil {
		t.Fatalf("Run plain: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("plain findings %d, want 1 (fail-open preserved)", len(got))
	}
	if _, ok := got[0].Metadata["confirmed"]; ok {
		t.Fatalf("unconfirmed enrichment carries confirmed meta: %v", got[0].Metadata)
	}
}

// TestTakeoverEnrichmentPerHostNotTargetEquality pins the documented
// per-host semantic: the enrichment corroborates provider presence for
// the host from the live graph edge and never cross-checks the sibling
// unclaimed finding's cname_target metadata, so a stale or divergent
// sibling target does not block the finding (fail-open).
func TestTakeoverEnrichmentPerHostNotTargetEquality(t *testing.T) {
	src := mustHost(t, "sub.example.com")
	tgt := mustHost(t, "unclaimed.github.io")
	cname := mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())
	graph := enrichStubGraph{adj: map[asset.Identity][]asset.Relationship{src.Identity(): {cname}}}
	// Sibling names a DIFFERENT target than the live graph edge.
	priors := []asset.Finding{mustUnclaimedPrior(t, src.Identity(), "stale-target.example.net", "github.io", false)}
	got, err := providerConfirmedDetector(context.Background(), enrichDirectCtx(priors, graph))
	if err != nil {
		t.Fatalf("err = %v, want nil (fail-open)", err)
	}
	if len(got) != 1 {
		t.Fatalf("findings %d, want 1 (per-host corroboration, not target equality)", len(got))
	}
	if got[0].Metadata["cname_target"] != "unclaimed.github.io" {
		t.Fatalf("cname_target %q, want the live graph edge target", got[0].Metadata["cname_target"])
	}
}

// TestTakeoverEnrichmentLeavesUnclaimedUntouched pins the acceptance
// identity contract: the sibling unclaimed finding is byte-identical
// with and without the enrichment loaded (the enrichment is a second
// finding, never a mutation).
func TestTakeoverEnrichmentLeavesUnclaimedUntouched(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	legacy := detect.NewRegistry()
	for _, r := range rules {
		if r.ID == ruleCNAMEProviderConfirmed {
			continue
		}
		if err := legacy.Register(r); err != nil {
			t.Fatalf("legacy Register(%q): %v", r.ID, err)
		}
	}
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy Validate: %v", err)
	}
	legacy.Seal()
	full := registerTakeoverPack(t)

	snap := buildUnclaimedSnapshot(t)
	run := func(reg *detect.Registry) []asset.Finding {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		rep, err := detect.Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		var out []asset.Finding
		for _, f := range rep.Findings {
			if f.RuleID == ruleCNAMEUnclaimed {
				out = append(out, f)
			}
		}
		return out
	}
	before, after := run(legacy), run(full)
	b1, _ := json.Marshal(before)
	b2, _ := json.Marshal(after)
	if string(b1) != string(b2) {
		t.Fatalf("unclaimed findings drifted with enrichment loaded:\nbefore %s\nafter  %s", b1, b2)
	}
}

// TestTakeoverEnrichmentDepSkip pins the engine dependency gate: when
// the unclaimed rule does not complete (disabled at registry level),
// the enrichment dep-skips with an honest dependency reason and emits
// nothing — it never executes blind.
func TestTakeoverEnrichmentDepSkip(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	reg := detect.NewRegistry()
	for _, r := range rules {
		if r.ID == ruleCNAMEUnclaimed {
			r.Enabled = false
		}
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
	rep, err := detect.Run(context.Background(), cfg, buildUnclaimedSnapshot(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, r := range rep.Rules {
		if r.RuleID != ruleCNAMEProviderConfirmed {
			continue
		}
		if r.Status != detect.RuleStatusSkipped {
			t.Fatalf("enrichment status %s, want skipped (dep did not complete)", r.Status)
		}
		if !strings.Contains(r.SkipReason, `dependency "takeover.cname.unclaimed" did not complete`) {
			t.Fatalf("enrichment skip reason %q, want dependency reason", r.SkipReason)
		}
	}
	for _, f := range rep.Findings {
		if f.RuleID == ruleCNAMEProviderConfirmed {
			t.Fatalf("dep-skip run must emit no enrichment: %+v", f)
		}
	}
}

// TestTakeoverEnrichmentBoundedAt256 pins the NEW-135 cap contract on
// the enrichment: 300 corroborated subjects keep the 256 lowest
// identities with subjects_dropped + truncated meta on every retained
// finding and a LevelWarn log — never silent.
//
// Note the harness shape: the 300 priors + 300 CNAME edges enter through
// a direct detector call, because through the engine the sibling
// unclaimed rule's own 256-cap bounds PriorFindings first (the
// enrichment then sees at most 256 subjects and has nothing to drop —
// pinned implicitly by TestTakeoverPackBoundedAt256's sibling counts).
func TestTakeoverEnrichmentBoundedAt256(t *testing.T) {
	var priors []asset.Finding
	adj := make(map[asset.Identity][]asset.Relationship, 300)
	for i := 0; i < 300; i++ {
		src := mustHost(t, fmt.Sprintf("sub%d.example.com", i))
		tgt := mustHost(t, fmt.Sprintf("unclaimed%d.github.io", i))
		priors = append(priors, mustUnclaimedPrior(t, src.Identity(), tgt.Name, "github.io", false))
		adj[src.Identity()] = []asset.Relationship{mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())}
	}
	logger := &enrichLogger{}
	dctx := &detect.Context{
		Config:        map[string]string{},
		Logger:        logger,
		Clock:         testClock,
		PriorFindings: priors,
		GraphView:     enrichStubGraph{adj: adj},
	}
	got, err := providerConfirmedDetector(context.Background(), dctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got) != 256 {
		t.Fatalf("enrichment findings %d, want 256 capped", len(got))
	}
	for _, f := range got {
		if f.Metadata["truncated"] != "true" || f.Metadata["subjects_dropped"] != "44" {
			t.Fatalf("capped enrichment missing truncation meta (want 44 dropped): %+v", f.Metadata)
		}
	}
	// Identity-ordered head: the retained set is the 256 lowest subjects.
	prev := ""
	for _, f := range got {
		if s := f.Subject.String(); s <= prev {
			t.Fatalf("enrichment findings not identity-ordered: %q after %q", s, prev)
		} else {
			prev = s
		}
	}
	if !logger.has(ruleCNAMEProviderConfirmed, detect.LevelWarn, "truncated 44 subjects over bound 256") {
		t.Fatalf("no LevelWarn truncation log for %q", ruleCNAMEProviderConfirmed)
	}
}

// TestTakeoverEnrichmentDeterminism pins sorted, stable emission: two
// identical runs marshal byte-identical, and multi-host findings arrive
// in subject-identity order.
func TestTakeoverEnrichmentDeterminism(t *testing.T) {
	reg := registerTakeoverPack(t)
	snap := buildMixedSnapshot(t)
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		rep, err := detect.Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}
	rep1, rep2 := run(), run()
	b1, _ := json.Marshal(rep1)
	b2, _ := json.Marshal(rep2)
	if string(b1) != string(b2) {
		t.Fatalf("determinism: two identical runs diverged")
	}
	var subjects []string
	for _, f := range rep1.Findings {
		if f.RuleID == ruleCNAMEProviderConfirmed {
			subjects = append(subjects, f.Subject.String())
		}
	}
	for i := 1; i < len(subjects); i++ {
		if subjects[i-1] > subjects[i] {
			t.Fatalf("enrichment subjects not identity-sorted: %v", subjects)
		}
	}
}

// TestTakeoverEnrichmentCacheColdWarmParity pins cache honesty for the
// dependent rule: the warm run replays the cold findings byte-identical
// (the graph_digest covers the prior set, so cross-rule reasoning stays
// coherent across the cache).
func TestTakeoverEnrichmentCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerTakeoverPack(t)
	snap := buildMixedSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Cache = fs
	cfg.Clock = testClock
	cold, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("cold Run: %v", err)
	}
	if cold.CacheHits != 0 {
		t.Fatalf("cold hits %d, want 0", cold.CacheHits)
	}
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Cache = fs
	cfg2.Clock = testClock
	warm, err := detect.Run(context.Background(), cfg2, snap)
	if err != nil {
		t.Fatalf("warm Run: %v", err)
	}
	if warm.CacheHits != len(cold.Rules)-cold.Skipped {
		t.Fatalf("warm hits %d, want %d (all attempted rules)", warm.CacheHits, len(cold.Rules)-cold.Skipped)
	}
	var coldEn, warmEn []asset.Finding
	for _, f := range cold.Findings {
		if f.RuleID == ruleCNAMEProviderConfirmed {
			coldEn = append(coldEn, f)
		}
	}
	for _, f := range warm.Findings {
		if f.RuleID == ruleCNAMEProviderConfirmed {
			warmEn = append(warmEn, f)
		}
	}
	b1, _ := json.Marshal(coldEn)
	b2, _ := json.Marshal(warmEn)
	if string(b1) != string(b2) {
		t.Fatalf("enrichment cold/warm drift:\ncold %s\nwarm %s", b1, b2)
	}
}

// TestTakeoverEnrichmentHonorsContext pins cancellation propagation:
// a cancelled context surfaces the error, never a partial finding set.
func TestTakeoverEnrichmentHonorsContext(t *testing.T) {
	src := mustHost(t, "sub.example.com")
	tgt := mustHost(t, "unclaimed.github.io")
	cname := mustRelationship(t, src.Identity(), asset.RelationshipHostToCNAME, tgt.Identity())
	graph := enrichStubGraph{adj: map[asset.Identity][]asset.Relationship{src.Identity(): {cname}}}
	priors := []asset.Finding{mustUnclaimedPrior(t, src.Identity(), "unclaimed.github.io", "github.io", false)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := providerConfirmedDetector(ctx, enrichDirectCtx(priors, graph)); err == nil {
		t.Fatalf("cancelled detector err = nil, want context error")
	}
}
