package adapt

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/dns"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// relIDs renders relationships as sorted IDs for deterministic assertions.
func relIDs(rels []asset.Relationship) []string {
	out := make([]string, 0, len(rels))
	for _, r := range rels {
		out = append(out, r.ID())
	}
	sort.Strings(out)
	return out
}

// evStrings renders evidence as sorted "indicator|value|source" triples.
func evStrings(evs []asset.Evidence) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Indicator+"|"+e.Value+"|"+e.Source.String())
	}
	sort.Strings(out)
	return out
}

// TestDNSStagePublishesMXNSSRVEdges pins NEW-126 T2 edge publication through
// the adapter: MX/NS/SRV targets flow into Results.Relationships sorted and
// ID-deduped with the existing host_to_ip/host_to_cname edges, while
// in-domain targets enter the corpus additions.
func TestDNSStagePublishesMXNSSRVEdges(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeMX, "mail.example.com")
	fake.set("www.example.com", dns.TypeNS, "ns1.example.com")
	fake.set("www.example.com", dns.TypeSRV, "sip.example.com:5060")
	fake.set("mail.example.com", dns.TypeA, "192.0.2.25")
	fake.set("ns1.example.com", dns.TypeA, "192.0.2.53")
	fake.set("sip.example.com", dns.TypeA, "192.0.2.70")

	res, err := NewDNSStage(fake).Run(context.Background(), dnsInput(target, []asset.Host{www}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	requireEqualStrings(t, "additions", hostNames(res.Additions.Hosts), []string{
		"mail.example.com", "ns1.example.com", "sip.example.com", "www.example.com",
	})
	requireEqualStrings(t, "relationships", relIDs(res.Results.Relationships), []string{
		"host:mail.example.com" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.25",
		"host:ns1.example.com" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.53",
		"host:sip.example.com" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.70",
		"host:www.example.com" + "\x00" + "host_to_mx\x00" + "host:mail.example.com",
		"host:www.example.com" + "\x00" + "host_to_ns\x00" + "host:ns1.example.com",
		"host:www.example.com" + "\x00" + "host_to_srv\x00" + "host:sip.example.com",
	})
	// SRV evidence rides alongside the edge (ports are detail, not topology).
	found := false
	for _, e := range res.Results.Evidence {
		if e.Indicator == dnsSRVIndicator && e.Value == "sip.example.com:5060" &&
			e.Source.String() == "host:www.example.com" && e.Method == asset.MethodDNS {
			found = true
		}
	}
	if !found {
		t.Fatalf("SRV evidence missing in %+v", evStrings(res.Results.Evidence))
	}
}

// TestDNSStageOutOfDomainMXTargetScoping pins the NEW-121 precedent for the
// new families: a cross-domain mail exchanger is kept in the relationships
// channel (legitimate observation of an in-scope source) but filtered from
// the corpus additions.
func TestDNSStageOutOfDomainMXTargetScoping(t *testing.T) {
	target := mustDomain(t, "example.com")
	shop := mustHost(t, "shop.example.com")

	fake := newFakeResolver()
	fake.set("shop.example.com", dns.TypeMX, "mail.other-corp.net")
	fake.set("mail.other-corp.net", dns.TypeA, "192.0.2.99")

	res, err := NewDNSStage(fake).Run(context.Background(), dnsInput(target, []asset.Host{shop}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	// The observation exists: the engine resolved the cross-domain target's
	// addresses at depth 1.
	if seen := fake.seenHosts(); !seen["mail.other-corp.net"] {
		t.Fatal("engine never resolved the cross-domain MX target (the observation should exist, only the corpus addition is filtered)")
	}
	// Edges keep the cross-domain target.
	wantEdge := "host:shop.example.com" + "\x00" + "host_to_mx\x00" + "host:mail.other-corp.net"
	found := false
	for _, id := range relIDs(res.Results.Relationships) {
		if id == wantEdge {
			found = true
		}
	}
	if !found {
		t.Fatalf("cross-domain MX edge missing; got %v", relIDs(res.Results.Relationships))
	}
	// Corpus filters it.
	for _, name := range hostNames(res.Additions.Hosts) {
		if name == "mail.other-corp.net" {
			t.Fatalf("cross-domain MX target %q leaked into additions", name)
		}
	}
	requireEqualStrings(t, "additions", hostNames(res.Additions.Hosts), []string{"shop.example.com"})
}

// TestDNSStageNXDOMAINSilentNewTypes pins no publication for
// NXDOMAIN/failed new-type observations: no edges, no evidence, host stays
// completed on its A record.
func TestDNSStageNXDOMAINSilentNewTypes(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeA, "93.184.216.34")
	fake.setErr("www.example.com", dns.TypeMX, &dns.QueryError{Kind: dns.ErrNotFound, Host: "www.example.com", Type: dns.TypeMX, Err: failureCause()})
	fake.setErr("www.example.com", dns.TypeNS, &dns.QueryError{Kind: dns.ErrNotFound, Host: "www.example.com", Type: dns.TypeNS, Err: failureCause()})
	fake.setErr("www.example.com", dns.TypeSRV, &dns.QueryError{Kind: dns.ErrNotFound, Host: "www.example.com", Type: dns.TypeSRV, Err: failureCause()})
	fake.setErr("www.example.com", dns.TypeTXT, &dns.QueryError{Kind: dns.ErrNotFound, Host: "www.example.com", Type: dns.TypeTXT, Err: failureCause()})

	res, err := NewDNSStage(fake).Run(context.Background(), dnsInput(target, []asset.Host{www}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (NXDOMAIN is an observation)", res.Outcome)
	}
	for _, r := range res.Results.Relationships {
		if strings.Contains(r.ID(), "host_to_mx") || strings.Contains(r.ID(), "host_to_ns") || strings.Contains(r.ID(), "host_to_srv") {
			t.Fatalf("NXDOMAIN type emitted a new-family edge: %q", r.ID())
		}
	}
	if len(res.Results.Evidence) != 0 {
		t.Fatalf("Evidence = %v, want none for NXDOMAIN types", evStrings(res.Results.Evidence))
	}
}

// TestDNSStageTXTEvidenceBounded pins TXT evidence carriage: one dns:txt
// record per retained string sourced at the queried host, sorted and
// ID-deduped; long strings are bounded to the asset package's 256-byte
// evidence bound (stored with "…" — never unbounded, never dropped).
func TestDNSStageTXTEvidenceBounded(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	long := "v=spf1 " + strings.Repeat("a", 300) // >256, <4096: retained, evidence-truncated
	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeTXT,
		"v=spf1 include:_spf.example.net ~all",
		"v=spf1 include:_spf.example.net ~all", // duplicate collapses
		long,
	)

	res, err := NewDNSStage(fake).Run(context.Background(), dnsInput(target, []asset.Host{www}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	if len(res.Results.Evidence) != 2 {
		t.Fatalf("Evidence = %v, want 2 (deduped TXT strings)", evStrings(res.Results.Evidence))
	}
	for _, e := range res.Results.Evidence {
		if e.Method != asset.MethodDNS || e.Indicator != dnsTXTIndicator {
			t.Fatalf("evidence = %+v, want MethodDNS/dns:txt", e)
		}
		if e.Source.String() != "host:www.example.com" {
			t.Fatalf("evidence source = %q, want the queried host", e.Source.String())
		}
		if len(e.Value) > 256 {
			t.Fatalf("evidence value = %d bytes, want <=256 (bounded, never unbounded)", len(e.Value))
		}
	}
	// The long string is stored truncated with the marker, not dropped.
	foundTruncated := false
	for _, e := range res.Results.Evidence {
		if strings.HasSuffix(e.Value, "…") {
			foundTruncated = true
			if len(e.Value) != 256 {
				t.Fatalf("truncated evidence value = %d bytes, want 256", len(e.Value))
			}
		}
	}
	if !foundTruncated {
		t.Fatalf("long TXT string was not evidence-truncated: %v", evStrings(res.Results.Evidence))
	}
	// Per-value truncation carries no set-truncation flag.
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("Truncated=%v StickyFlags=%v, want false/empty (value truncation is not set truncation)", res.Truncated, res.StickyFlags)
	}
	// Evidence order is pinned sorted by ID.
	ids := make([]string, 0, len(res.Results.Evidence))
	for _, e := range res.Results.Evidence {
		ids = append(ids, e.ID())
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("evidence not sorted by ID: %v", ids)
	}
}

// TestDNSStageSRVEvidencePorts pins SRV evidence carriage: one dns:srv
// record per retained (target, port) pair with value "target:port", while
// the edge stays per distinct target host.
func TestDNSStageSRVEvidencePorts(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeSRV, "sip.example.com:5060", "sip.example.com:5070")

	res, err := NewDNSStage(fake).Run(context.Background(), dnsInput(target, []asset.Host{www}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// One edge for the distinct host, two evidence records for the ports.
	srvEdges := 0
	for _, r := range res.Results.Relationships {
		if strings.Contains(r.ID(), "host_to_srv") {
			srvEdges++
		}
	}
	if srvEdges != 1 {
		t.Fatalf("srv edges = %d, want 1 (per distinct host, ports ride evidence)", srvEdges)
	}
	requireEqualStrings(t, "srv evidence", evStrings(res.Results.Evidence), []string{
		"dns:srv|sip.example.com:5060|host:www.example.com",
		"dns:srv|sip.example.com:5070|host:www.example.com",
	})
}

// TestDNSStageTruncationStickyPropagation pins the truncation chain for the
// new families: a capped MX answer set marks the type truncated, the host
// folds engine-incomplete (adapter partial), and the stage carries
// Truncated with the dns_answers_truncated sticky flag — never silence.
func TestDNSStageTruncationStickyPropagation(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	answers := make([]string, 0, dns.MaxAnswersPerType+1)
	for i := 0; i < dns.MaxAnswersPerType+1; i++ {
		answers = append(answers, fmt.Sprintf("mx%04d.example.net", i))
	}
	fake := newFakeResolver()
	fake.set("www.example.com", dns.TypeMX, answers...)

	res, err := NewDNSStage(fake).Run(context.Background(), dnsInput(target, []asset.Host{www}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomePartial {
		t.Fatalf("Outcome = %q, want partial (capped MX set is engine-incomplete)", res.Outcome)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true (the MX retention cap was hit)")
	}
	if !res.StickyFlags[dnsAnswersTruncated] {
		t.Fatalf("StickyFlags = %v, want %q set", res.StickyFlags, dnsAnswersTruncated)
	}
	// Edges cover exactly the retained head (bounded, never unbounded).
	mxEdges := 0
	for _, r := range res.Results.Relationships {
		if strings.Contains(r.ID(), "host_to_mx") {
			mxEdges++
		}
	}
	if mxEdges != dns.MaxAnswersPerType {
		t.Fatalf("mx edges = %d, want %d (retained head only)", mxEdges, dns.MaxAnswersPerType)
	}
}

// TestDNSStageDeterminismShuffled pins determinism: shuffled resolver answer
// order yields identical StageResults including edge and evidence order.
func TestDNSStageDeterminismShuffled(t *testing.T) {
	target := mustDomain(t, "example.com")
	www := mustHost(t, "www.example.com")

	mkFake := func(mx, txt []string) *fakeResolver {
		f := newFakeResolver()
		f.set("www.example.com", dns.TypeMX, mx...)
		f.set("www.example.com", dns.TypeTXT, txt...)
		f.set("www.example.com", dns.TypeSRV, "sip.example.com:5060", "sip.example.com:5070")
		return f
	}
	run := func(mx, txt []string) pipeline.StageResult {
		t.Helper()
		res, err := NewDNSStage(mkFake(mx, txt)).Run(context.Background(), dnsInput(target, []asset.Host{www}))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}
	mxA := []string{"b.example.net", "a.example.net", "c.example.net"}
	mxB := []string{"c.example.net", "b.example.net", "a.example.net"}
	txtA := []string{"zzz=1", "aaa=2"}
	txtB := []string{"aaa=2", "zzz=1"}
	resA, resB := run(mxA, txtA), run(mxB, txtB)
	if !reflect.DeepEqual(resA, resB) {
		t.Fatalf("shuffled runs differ:\nrun A relationships: %v evidence: %v\nrun B relationships: %v evidence: %v",
			relIDs(resA.Results.Relationships), evStrings(resA.Results.Evidence),
			relIDs(resB.Results.Relationships), evStrings(resB.Results.Evidence))
	}
	if len(resA.Results.Relationships) == 0 || len(resA.Results.Evidence) == 0 {
		t.Fatal("determinism pin exercised no new-family output (relationships/evidence empty)")
	}
}

func failureCause() error {
	return fmt.Errorf("synthetic resolver failure")
}

// TestApplyTruncationMergesStickyFlags pins the LOW-2 fix: applyTruncation
// merges dns_answers_truncated into a pre-seeded StickyFlags map instead of
// replacing it, so an earlier marker (e.g. dns_brute_truncated) survives.
func TestApplyTruncationMergesStickyFlags(t *testing.T) {
	base := pipeline.StageResult{
		StickyFlags: map[string]bool{dnsBruteTruncatedFlag: true},
	}
	got := applyTruncation(base, true)
	if !got.Truncated {
		t.Fatal("Truncated = false, want true")
	}
	if !got.StickyFlags[dnsAnswersTruncated] {
		t.Fatalf("StickyFlags = %v, want %q set", got.StickyFlags, dnsAnswersTruncated)
	}
	if !got.StickyFlags[dnsBruteTruncatedFlag] {
		t.Fatalf("StickyFlags = %v, pre-seeded %q was dropped by applyTruncation", got.StickyFlags, dnsBruteTruncatedFlag)
	}
}
