package dnsrec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/golden"
)

// fixedClock pins Now to a constant for deterministic reports.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time                         { return c.at }
func (c fixedClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

var testClock = fixedClock{at: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)}

func mustHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "dnsrec-test"})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

func mustRelationship(t testing.TB, from asset.Identity, kind asset.RelationshipKind, to asset.Identity) asset.Relationship {
	t.Helper()
	rel, err := asset.NewRelationship(from, kind, to)
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	return rel
}

func mustTXTEvidence(t testing.TB, source asset.Identity, value string) asset.Evidence {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodDNS, dnsTXTIndicator, value, source, asset.Provenance{Source: "dns"})
	if err != nil {
		t.Fatalf("NewEvidence txt: %v", err)
	}
	if ev.Method != asset.MethodDNS || ev.Indicator != dnsTXTIndicator {
		t.Fatalf("evidence = %+v, want MethodDNS/dns:txt", ev)
	}
	return ev
}

func mustSRVEvidence(t testing.TB, source asset.Identity, value string) asset.Evidence {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodDNS, dnsSRVIndicator, value, source, asset.Provenance{Source: "dns"})
	if err != nil {
		t.Fatalf("NewEvidence srv: %v", err)
	}
	return ev
}

func mustIP(t testing.TB, addr string) asset.IP {
	t.Helper()
	ip, err := asset.NewIP(addr, asset.Provenance{Source: "dnsrec-test"})
	if err != nil {
		t.Fatalf("NewIP: %v", err)
	}
	return ip
}

// buildNSDanglingSnapshot returns a host with an NS edge and no IP for the target.
func buildNSDanglingSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	src := mustHost(t, "example.com")
	tgt := mustHost(t, "ns1.example.net")
	rel := mustRelationship(t, src.Identity(), asset.RelationshipHostToNS, tgt.Identity())
	return detect.Snapshot{
		Assets:        []asset.Identity{src.Identity(), tgt.Identity()},
		Relationships: []asset.Relationship{rel},
	}
}

// buildNSWithIPSnapshot returns an NS edge whose target has an IP (not dangling).
func buildNSWithIPSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	src := mustHost(t, "example.com")
	tgt := mustHost(t, "ns1.example.net")
	rel := mustRelationship(t, src.Identity(), asset.RelationshipHostToNS, tgt.Identity())
	ip := mustIP(t, "192.0.2.53")
	ipRel := mustRelationship(t, tgt.Identity(), asset.RelationshipHostToIP, ip.Identity())
	return detect.Snapshot{
		Assets:        []asset.Identity{src.Identity(), tgt.Identity(), ip.Identity()},
		Relationships: []asset.Relationship{rel, ipRel},
	}
}

// buildMXDanglingSnapshot returns a host with an MX edge and no IP for the target.
func buildMXDanglingSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	src := mustHost(t, "shop.example.com")
	tgt := mustHost(t, "mail.example.net")
	rel := mustRelationship(t, src.Identity(), asset.RelationshipHostToMX, tgt.Identity())
	return detect.Snapshot{
		Assets:        []asset.Identity{src.Identity(), tgt.Identity()},
		Relationships: []asset.Relationship{rel},
	}
}

// buildMXWithIPSnapshot returns an MX edge whose target has an IP.
func buildMXWithIPSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	src := mustHost(t, "shop.example.com")
	tgt := mustHost(t, "mail.example.net")
	rel := mustRelationship(t, src.Identity(), asset.RelationshipHostToMX, tgt.Identity())
	ip := mustIP(t, "192.0.2.25")
	ipRel := mustRelationship(t, tgt.Identity(), asset.RelationshipHostToIP, ip.Identity())
	return detect.Snapshot{
		Assets:        []asset.Identity{src.Identity(), tgt.Identity(), ip.Identity()},
		Relationships: []asset.Relationship{rel, ipRel},
	}
}

// buildSPFWeakSnapshot returns a host with a complete weak SPF record.
func buildSPFWeakSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	h := mustHost(t, "example.com")
	ev := mustTXTEvidence(t, h.Identity(), "v=spf1 include:_spf.example.net ?all")
	return detect.Snapshot{
		Assets:   []asset.Identity{h.Identity()},
		Evidence: []asset.Evidence{ev},
	}
}

// buildMixedSnapshot triggers all five dnsrec rules deterministically.
func buildMixedSnapshot(t testing.TB) detect.Snapshot {
	t.Helper()
	// NS dangling.
	nsSrc := mustHost(t, "example.com")
	nsTgt := mustHost(t, "ns1.example.net")
	nsRel := mustRelationship(t, nsSrc.Identity(), asset.RelationshipHostToNS, nsTgt.Identity())
	// MX dangling.
	mxSrc := mustHost(t, "shop.example.com")
	mxTgt := mustHost(t, "mail.example.net")
	mxRel := mustRelationship(t, mxSrc.Identity(), asset.RelationshipHostToMX, mxTgt.Identity())
	// SPF weak host (also DMARC-missing: its TXT set is complete and has no DMARC).
	spfH := mustHost(t, "weak.example.com")
	spfEv := mustTXTEvidence(t, spfH.Identity(), "v=spf1 include:_spf.example.net ?all")
	// DMARC-missing host (complete non-DMARC TXT, no SPF).
	dmarcH := mustHost(t, "nodmarc.example.com")
	dmarcEv := mustTXTEvidence(t, dmarcH.Identity(), "some-verification=abc123")
	// SRV exposure host.
	srvH := mustHost(t, "sip.example.com")
	srvEv := mustSRVEvidence(t, srvH.Identity(), "sip-target.example.net:5060")
	return detect.Snapshot{
		Assets: []asset.Identity{
			nsSrc.Identity(), nsTgt.Identity(),
			mxSrc.Identity(), mxTgt.Identity(),
			spfH.Identity(), dmarcH.Identity(), srvH.Identity(),
		},
		Relationships: []asset.Relationship{nsRel, mxRel},
		Evidence:      []asset.Evidence{spfEv, dmarcEv, srvEv},
	}
}

func registerDNSRecPack(t testing.TB) *detect.Registry {
	t.Helper()
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
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
	return reg
}

func findingsForRule(t testing.TB, snap detect.Snapshot, ruleID string) []asset.Finding {
	t.Helper()
	reg := registerDNSRecPack(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var out []asset.Finding
	for _, f := range rep.Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func TestDNSRecPackCheckAPIVersion(t *testing.T) {
	if err := detect.CheckAPIVersion(2, 0); err != nil {
		t.Fatalf("CheckAPIVersion(2,0): %v", err)
	}
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 5 {
		t.Fatalf("pack carries %d rules, want 5", len(rules))
	}
}

func TestDNSRecPackLoadsThroughSDK(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	reg := detect.NewRegistry()
	for _, r := range rules {
		if err := detect.ValidateRule(r); err != nil {
			t.Fatalf("ValidateRule(%q): %v", r.ID, err)
		}
		if err := reg.Register(r); err != nil {
			t.Fatalf("Register(%q): %v", r.ID, err)
		}
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("Validate graph: %v", err)
	}
	orig := rules[0]
	orig.Inputs[0] = detect.RuleInput("bogus")
	got, ok := reg.Get(orig.ID)
	if !ok {
		t.Fatalf("Get %q missing", orig.ID)
	}
	if got.Inputs[0] == detect.RuleInput("bogus") {
		t.Fatalf("deep copy broken: registered rule mutated through caller alias")
	}
	if len(got.RequiredAssetTypes) != 1 || got.RequiredAssetTypes[0] != asset.KindHost {
		t.Fatalf("deep copy broken: RequiredAssetTypes aliasing, got %v", got.RequiredAssetTypes)
	}
	reg.Seal()
	if err := reg.Register(rules[0]); err == nil || err.Error() != "detect: registry is sealed" {
		t.Fatalf("seal not enforced: %v", err)
	}
}

func TestDNSRecPackMetadataDepsCompat(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	wantVersions := map[string]string{
		ruleNSDangling:   "1.0.0",
		ruleMXDangling:   "1.0.0",
		ruleSPFWeak:      "1.0.0",
		ruleDMARCMissing: "1.0.0",
		ruleSRVExposure:  "1.0.0",
	}
	if len(rules) != len(wantVersions) {
		t.Fatalf("pack carries %d rules, want %d", len(rules), len(wantVersions))
	}
	for _, r := range rules {
		if wantVersions[r.ID] != r.Version {
			t.Errorf("rule %q version %q, want %q", r.ID, r.Version, wantVersions[r.ID])
		}
		if _, _, _, err := detect.ParseRuleVersion(r.Version); err != nil {
			t.Fatalf("rule %q version %q invalid: %v", r.ID, r.Version, err)
		}
		if !r.Category.Valid() || r.Category != detect.CategoryInformation {
			t.Fatalf("rule %q category %q invalid or not information", r.ID, r.Category)
		}
		if len(r.Inputs) == 0 || len(r.Outputs) == 0 {
			t.Fatalf("rule %q inputs/outputs empty", r.ID)
		}
		for _, in := range r.Inputs {
			if !in.Valid() {
				t.Fatalf("rule %q input %q invalid", r.ID, in)
			}
		}
		if !r.EstimatedCost.Valid() {
			t.Fatalf("rule %q cost %q invalid", r.ID, r.EstimatedCost)
		}
		if r.Timeout <= 0 {
			t.Fatalf("rule %q timeout invalid", r.ID)
		}
		if r.Author == "" {
			t.Fatalf("rule %q author empty", r.ID)
		}
		if r.Detector == nil {
			t.Fatalf("rule %q detector nil", r.ID)
		}
		if !strings.HasPrefix(r.ID, "dnsrec.") {
			t.Fatalf("rule %q ID policy violation", r.ID)
		}
		if len(r.Dependencies) > 0 {
			t.Fatalf("dnsrec pack should have no dependencies for now (found on %q)", r.ID)
		}
		if len(r.RequiredAssetTypes) != 1 || r.RequiredAssetTypes[0] != asset.KindHost {
			t.Fatalf("rule %q required kinds %v, want [host]", r.ID, r.RequiredAssetTypes)
		}
		// Recon-only: every description frames the rule as an informational
		// observation and disclaims exploitability (takeover-pack precedent:
		// "never claims exploitability" is the required disclaimer, not a
		// claim — so we assert its presence, not the word's absence).
		lower := strings.ToLower(r.Description)
		if !strings.Contains(lower, "informational") {
			t.Fatalf("rule %q description missing informational framing: %q", r.ID, r.Description)
		}
		if !strings.Contains(lower, "never claims") {
			t.Fatalf("rule %q description missing never-claims disclaimer: %q", r.ID, r.Description)
		}
	}
}

func TestDNSRecPackRequiredAssetTypesSkipHonestly(t *testing.T) {
	reg := registerDNSRecPack(t)
	empty := detect.Snapshot{}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, empty)
	if err != nil {
		t.Fatalf("Run empty: %v", err)
	}
	if rep.Skipped != 5 {
		t.Fatalf("empty corpus: skipped %d, want 5", rep.Skipped)
	}
	if rep.Completed != 0 || rep.Failed != 0 {
		t.Fatalf("empty corpus: completed %d failed %d", rep.Completed, rep.Failed)
	}
	for _, r := range rep.Rules {
		if r.Status != detect.RuleStatusSkipped {
			t.Fatalf("rule %q status %s, want skipped", r.RuleID, r.Status)
		}
		if r.SkipReason == "" || !strings.Contains(r.SkipReason, "required asset kind") {
			t.Fatalf("rule %q skip reason %q", r.RuleID, r.SkipReason)
		}
	}
	// Host-only snapshot with no edges/evidence: all rules complete with zero findings (fail-open).
	host := mustHost(t, "www.example.com")
	snap := detect.Snapshot{Assets: []asset.Identity{host.Identity()}}
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	rep2, err := detect.Run(context.Background(), cfg2, snap)
	if err != nil {
		t.Fatalf("Run host: %v", err)
	}
	if rep2.Skipped != 0 {
		t.Fatalf("host-only: skipped %d, want 0 (host satisfies every gate)", rep2.Skipped)
	}
	if len(rep2.Findings) != 0 {
		t.Fatalf("host-only findings %d, want 0 (fail-open: no edges/evidence → silent)", len(rep2.Findings))
	}
	for _, r := range rep2.Rules {
		if r.Status != detect.RuleStatusCompleted {
			t.Fatalf("rule %q status %s, want completed", r.RuleID, r.Status)
		}
	}
}

func TestDNSRecPackDetectorsHonorContext(t *testing.T) {
	reg := registerDNSRecPack(t)
	snap := buildNSDanglingSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := detect.Run(ctx, cfg, snap)
	if err != nil {
		t.Fatalf("Run cancelled: %v", err)
	}
	if rep.Outcome != detect.OutcomeCancelled {
		t.Fatalf("cancelled run outcome %s, want cancelled", rep.Outcome)
	}
}

func TestDNSRecNSDanglingEmits(t *testing.T) {
	got := findingsForRule(t, buildNSDanglingSnapshot(t), ruleNSDangling)
	if len(got) != 1 {
		t.Fatalf("ns findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Category != detect.CategoryInformation.String() {
		t.Fatalf("category %s, want information", f.Category)
	}
	if f.Priority != detect.PriorityInfo.String() || f.Status != detect.StatusOpen.String() {
		t.Fatalf("priority/status %s/%s", f.Priority, f.Status)
	}
	if f.Confidence != 0.6 {
		t.Fatalf("confidence %v, want 0.6", f.Confidence)
	}
	if f.Subject.Kind != asset.KindHost || f.Subject.Value != "example.com" {
		t.Fatalf("subject %+v, want host:example.com", f.Subject)
	}
	if len(f.Evidence) == 0 || f.Evidence[0].Method != asset.MethodDetection {
		t.Fatalf("evidence method wrong")
	}
	if f.Metadata["signal"] != "dnsrec_ns_dangling_delegation" {
		t.Fatalf("signal %q", f.Metadata["signal"])
	}
	if f.Metadata["ns_target"] != "ns1.example.net" {
		t.Fatalf("ns_target %q", f.Metadata["ns_target"])
	}
}

func TestDNSRecNSHasIPExcluded(t *testing.T) {
	got := findingsForRule(t, buildNSWithIPSnapshot(t), ruleNSDangling)
	if len(got) != 0 {
		t.Fatalf("ns findings = %d, want 0 (target has IP)", len(got))
	}
}

func TestDNSRecMXDanglingEmits(t *testing.T) {
	got := findingsForRule(t, buildMXDanglingSnapshot(t), ruleMXDangling)
	if len(got) != 1 {
		t.Fatalf("mx findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Category != detect.CategoryInformation.String() {
		t.Fatalf("category %s, want information", f.Category)
	}
	if f.Confidence != 0.6 {
		t.Fatalf("confidence %v, want 0.6", f.Confidence)
	}
	if f.Metadata["signal"] != "dnsrec_mx_dangling" {
		t.Fatalf("signal %q", f.Metadata["signal"])
	}
	if f.Metadata["mx_target"] != "mail.example.net" {
		t.Fatalf("mx_target %q", f.Metadata["mx_target"])
	}
}

func TestDNSRecMXHasIPExcluded(t *testing.T) {
	got := findingsForRule(t, buildMXWithIPSnapshot(t), ruleMXDangling)
	if len(got) != 0 {
		t.Fatalf("mx findings = %d, want 0 (target has IP)", len(got))
	}
}

func TestDNSRecSPFWeakEmits(t *testing.T) {
	got := findingsForRule(t, buildSPFWeakSnapshot(t), ruleSPFWeak)
	if len(got) != 1 {
		t.Fatalf("spf findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Category != detect.CategoryInformation.String() || f.Confidence != 0.6 {
		t.Fatalf("category/confidence %+v", f)
	}
	if f.Metadata["signal"] != "dnsrec_spf_weak" {
		t.Fatalf("signal %q", f.Metadata["signal"])
	}
	if !strings.HasPrefix(f.Metadata["spf"], "v=spf1") {
		t.Fatalf("spf meta %q", f.Metadata["spf"])
	}
}

func TestDNSRecSPFStrongSilent(t *testing.T) {
	for _, strong := range []string{
		"v=spf1 include:_spf.example.net -all",
		"v=spf1 include:_spf.example.net ~all",
	} {
		h := mustHost(t, "example.com")
		snap := detect.Snapshot{
			Assets:   []asset.Identity{h.Identity()},
			Evidence: []asset.Evidence{mustTXTEvidence(t, h.Identity(), strong)},
		}
		got := findingsForRule(t, snap, ruleSPFWeak)
		if len(got) != 0 {
			t.Fatalf("spf %q: findings = %d, want 0 (hard/soft fail is not weak)", strong, len(got))
		}
	}
}

func TestDNSRecSPFPlusAllEmits(t *testing.T) {
	// Positive claim on COMPLETE input is fine: +all lacks -all/~all, so weak.
	h := mustHost(t, "example.com")
	snap := detect.Snapshot{
		Assets:   []asset.Identity{h.Identity()},
		Evidence: []asset.Evidence{mustTXTEvidence(t, h.Identity(), "v=spf1 +all")},
	}
	got := findingsForRule(t, snap, ruleSPFWeak)
	if len(got) != 1 {
		t.Fatalf("spf +all: findings = %d, want 1 (complete positive claim)", len(got))
	}
}

func TestDNSRecSPFClippedSilence(t *testing.T) {
	// A weak-looking clipped prefix must stay silent: the clipped tail may
	// hide -all/~all, so absence-of-directive is underivable (fail open).
	h := mustHost(t, "example.com")
	clipped := "v=spf1 include:_spf.example.net ?all " + strings.Repeat("a", 180) + "…"
	if !strings.HasSuffix(clipped, "…") {
		t.Fatalf("test clipped value missing marker")
	}
	snap := detect.Snapshot{
		Assets:   []asset.Identity{h.Identity()},
		Evidence: []asset.Evidence{mustTXTEvidence(t, h.Identity(), clipped)},
	}
	got := findingsForRule(t, snap, ruleSPFWeak)
	if len(got) != 0 {
		t.Fatalf("spf clipped: findings = %d, want 0 (clipped-silence guard)", len(got))
	}
	// Mixed: one complete weak + one clipped still fires on the complete
	// record (only all-clipped stays silent).
	snap2 := detect.Snapshot{
		Assets: []asset.Identity{h.Identity()},
		Evidence: []asset.Evidence{
			mustTXTEvidence(t, h.Identity(), "v=spf1 include:_spf.example.net ?all"),
			mustTXTEvidence(t, h.Identity(), clipped),
		},
	}
	got2 := findingsForRule(t, snap2, ruleSPFWeak)
	if len(got2) != 1 {
		t.Fatalf("spf mixed: findings = %d, want 1 (complete weak survives clipped sibling)", len(got2))
	}
}

func TestDNSRecDMARCMissingEmits(t *testing.T) {
	h := mustHost(t, "example.com")
	snap := detect.Snapshot{
		Assets:   []asset.Identity{h.Identity()},
		Evidence: []asset.Evidence{mustTXTEvidence(t, h.Identity(), "v=spf1 -all")},
	}
	got := findingsForRule(t, snap, ruleDMARCMissing)
	if len(got) != 1 {
		t.Fatalf("dmarc findings = %d, want 1 (complete TXT set, no DMARC)", len(got))
	}
	if got[0].Metadata["signal"] != "dnsrec_dmarc_missing" {
		t.Fatalf("signal %q", got[0].Metadata["signal"])
	}
}

func TestDNSRecDMARCPresentSilent(t *testing.T) {
	h := mustHost(t, "example.com")
	snap := detect.Snapshot{
		Assets: []asset.Identity{h.Identity()},
		Evidence: []asset.Evidence{
			mustTXTEvidence(t, h.Identity(), "v=spf1 -all"),
			mustTXTEvidence(t, h.Identity(), "v=DMARC1; p=none; rua=mailto:dmarc@example.com"),
		},
	}
	got := findingsForRule(t, snap, ruleDMARCMissing)
	if len(got) != 0 {
		t.Fatalf("dmarc findings = %d, want 0 (DMARC present)", len(got))
	}
}

func TestDNSRecDMARCClippedSilence(t *testing.T) {
	h := mustHost(t, "example.com")
	clipped := "some-long-verification=" + strings.Repeat("b", 180) + "…"
	snap := detect.Snapshot{
		Assets: []asset.Identity{h.Identity()},
		Evidence: []asset.Evidence{
			mustTXTEvidence(t, h.Identity(), "v=spf1 -all"),
			mustTXTEvidence(t, h.Identity(), clipped),
		},
	}
	got := findingsForRule(t, snap, ruleDMARCMissing)
	if len(got) != 0 {
		t.Fatalf("dmarc findings = %d, want 0 (any clipped TXT → incomplete set → silent)", len(got))
	}
	// Empty TXT set stays silent (no evidence is not evidence of absence).
	empty := detect.Snapshot{Assets: []asset.Identity{h.Identity()}}
	got2 := findingsForRule(t, empty, ruleDMARCMissing)
	if len(got2) != 0 {
		t.Fatalf("dmarc empty: findings = %d, want 0 (fail-open)", len(got2))
	}
}

func TestDNSRecSRVExposureEmits(t *testing.T) {
	h := mustHost(t, "example.com")
	snap := detect.Snapshot{
		Assets: []asset.Identity{h.Identity()},
		Evidence: []asset.Evidence{
			mustSRVEvidence(t, h.Identity(), "sip.example.net:5060"),
			mustSRVEvidence(t, h.Identity(), "sip.example.net:5070"),
		},
	}
	got := findingsForRule(t, snap, ruleSRVExposure)
	if len(got) != 1 {
		t.Fatalf("srv findings = %d, want 1 (per-host)", len(got))
	}
	f := got[0]
	if f.Metadata["signal"] != "dnsrec_srv_exposure" {
		t.Fatalf("signal %q", f.Metadata["signal"])
	}
	if !strings.Contains(f.Metadata["services"], "sip.example.net:5060") {
		t.Fatalf("services %q missing target:port", f.Metadata["services"])
	}
	if f.Metadata["service_count"] != "2" {
		t.Fatalf("service_count %q, want 2", f.Metadata["service_count"])
	}
}

func TestDNSRecSRVClippedSilence(t *testing.T) {
	h := mustHost(t, "example.com")
	clipped := "sip.example.net:506" + strings.Repeat("0", 200) + "…"
	snap := detect.Snapshot{
		Assets:   []asset.Identity{h.Identity()},
		Evidence: []asset.Evidence{mustSRVEvidence(t, h.Identity(), clipped)},
	}
	got := findingsForRule(t, snap, ruleSRVExposure)
	if len(got) != 0 {
		t.Fatalf("srv clipped: findings = %d, want 0 (only-clipped stays silent)", len(got))
	}
}

func TestDNSRecMixedPerRule(t *testing.T) {
	reg := registerDNSRecPack(t)
	snap := buildMixedSnapshot(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	counts := map[string]int{}
	for _, f := range rep.Findings {
		counts[f.RuleID]++
	}
	if counts[ruleNSDangling] != 1 {
		t.Fatalf("ns %d, want 1", counts[ruleNSDangling])
	}
	if counts[ruleMXDangling] != 1 {
		t.Fatalf("mx %d, want 1", counts[ruleMXDangling])
	}
	if counts[ruleSPFWeak] != 1 {
		t.Fatalf("spf %d, want 1", counts[ruleSPFWeak])
	}
	// Both SPF-weak and DMARC-missing fire on the weak host (complete TXT
	// without DMARC), plus DMARC-missing fires on the nodmarc host.
	if counts[ruleDMARCMissing] != 2 {
		t.Fatalf("dmarc %d, want 2 (weak + nodmarc hosts)", counts[ruleDMARCMissing])
	}
	if counts[ruleSRVExposure] != 1 {
		t.Fatalf("srv %d, want 1", counts[ruleSRVExposure])
	}
}

func TestDNSRecConfigDeterministic(t *testing.T) {
	reg := registerDNSRecPack(t)
	snap := buildNSDanglingSnapshot(t)
	cfgMap1 := map[string]string{ruleNSDangling + ".disabled": "false", "a": "1", "z": "2"}
	cfgMap2 := map[string]string{"z": "2", ruleNSDangling + ".disabled": "false", "a": "1"}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	cfg.Config = cfgMap1
	rep1, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run1: %v", err)
	}
	cfg2 := detect.DefaultEngineConfig(reg)
	cfg2.Clock = testClock
	cfg2.Config = cfgMap2
	rep2, err := detect.Run(context.Background(), cfg2, snap)
	if err != nil {
		t.Fatalf("Run2: %v", err)
	}
	b1, _ := json.Marshal(rep1)
	b2, _ := json.Marshal(rep2)
	if string(b1) != string(b2) {
		t.Fatalf("config map order affected report determinism")
	}
}

func TestDNSRecBoundedAt256(t *testing.T) {
	reg := registerDNSRecPack(t)
	var rels []asset.Relationship
	var assets []asset.Identity
	for i := 0; i < 300; i++ {
		src := mustHost(t, fmt.Sprintf("sub%d.example.com", i))
		tgt := mustHost(t, fmt.Sprintf("ns%d.example.net", i))
		assets = append(assets, src.Identity(), tgt.Identity())
		rels = append(rels, mustRelationship(t, src.Identity(), asset.RelationshipHostToNS, tgt.Identity()))
	}
	snap := detect.Snapshot{Assets: assets, Relationships: rels}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, r := range rep.Rules {
		if r.RuleID == ruleNSDangling {
			if r.Findings != 256 {
				t.Fatalf("ns findings %d, want 256 capped", r.Findings)
			}
		}
	}
	foundTrunc := false
	for _, f := range rep.Findings {
		if f.RuleID == ruleNSDangling && f.Metadata["truncated"] == "true" {
			foundTrunc = true
			if f.Metadata["subjects_dropped"] == "" {
				t.Fatalf("truncated finding missing subjects_dropped")
			}
		}
	}
	if !foundTrunc {
		t.Fatalf("no truncated metadata found for bounded test")
	}
}

func TestDNSRecSPFBoundedAt256(t *testing.T) {
	reg := registerDNSRecPack(t)
	var assets []asset.Identity
	var evs []asset.Evidence
	for i := 0; i < 300; i++ {
		h := mustHost(t, fmt.Sprintf("h%d.example.com", i))
		assets = append(assets, h.Identity())
		evs = append(evs, mustTXTEvidence(t, h.Identity(), "v=spf1 include:_spf.example.net ?all"))
	}
	snap := detect.Snapshot{Assets: assets, Evidence: evs}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, r := range rep.Rules {
		if r.RuleID == ruleSPFWeak {
			if r.Findings != 256 {
				t.Fatalf("spf findings %d, want 256 capped", r.Findings)
			}
		}
	}
}

func TestDNSRecCacheColdWarmParity(t *testing.T) {
	dir := t.TempDir()
	fs, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	reg := registerDNSRecPack(t)
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
	if len(warm.Findings) != len(cold.Findings) {
		t.Fatalf("warm findings %d vs cold %d", len(warm.Findings), len(cold.Findings))
	}
	for i := range warm.Findings {
		if warm.Findings[i].ID() != cold.Findings[i].ID() {
			t.Fatalf("finding %d ID drift: warm %s cold %s", i, warm.Findings[i].ID(), cold.Findings[i].ID())
		}
	}
}

func TestDNSRecDeterminismGolden(t *testing.T) {
	reg := registerDNSRecPack(t)
	snap := buildMixedSnapshot(t)
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Config = map[string]string{ruleNSDangling + ".disabled": "false", "a": "1", "z": "2"}
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
	golden.Compare(t, "testdata/dnsrec_report.golden", b1)
}

func TestDNSRecVersions(t *testing.T) {
	rules, err := Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	for _, r := range rules {
		if r.Version != "1.0.0" {
			t.Errorf("rule %q version %q, want 1.0.0 (new rules start at 1.0.0)", r.ID, r.Version)
		}
	}
}

// TestCapSubjectsContract pins the pack's NEW-135 cap helper: 300
// uniform-score subjects in reverse input order keep the 256 lowest
// identities with 44 dropped, and under-cap input passes through with
// zero dropped. Input order never decides the retained set.
func TestCapSubjectsContract(t *testing.T) {
	var subs []asset.Identity
	for i := 0; i < 300; i++ {
		subs = append(subs, asset.Identity{Kind: asset.KindHost, Value: fmt.Sprintf("host-%03d.example.test", i)})
	}
	rev := append([]asset.Identity(nil), subs...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	kept, dropped := capSubjects(rev, nil)
	if len(kept) != 256 || dropped != 44 {
		t.Fatalf("kept %d dropped %d, want 256/44", len(kept), dropped)
	}
	for i := range kept {
		if kept[i] != subs[i] {
			t.Fatalf("kept[%d] = %s, want %s (identity-ordered head)", i, kept[i], subs[i])
		}
	}
	kept, dropped = capSubjects(append([]asset.Identity(nil), subs[:10]...), nil)
	if len(kept) != 10 || dropped != 0 {
		t.Fatalf("under-cap kept %d dropped %d, want 10/0", len(kept), dropped)
	}
}
