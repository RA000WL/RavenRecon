package dns

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestAssembleEdgesPerType pins NEW-126 T2 edge emission per host-target
// family: MX->host_to_mx, NS->host_to_ns, SRV->host_to_srv (one edge per
// distinct target host), alongside the existing CNAME edges. Edges are
// deduplicated by identity and sorted deterministically.
func TestAssembleEdgesPerType(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeMX, "mail.example.net", "mail.example.net") // dup collapses
	f.set("www.example.com", TypeNS, "ns1.example.net")
	f.set("www.example.com", TypeSRV, "sip.example.net:5060", "sip.example.net:5070")
	f.set("www.example.com", TypeCNAME, "alias.example.com")
	f.set("mail.example.net", TypeA, "192.0.2.25")
	f.set("ns1.example.net", TypeA, "192.0.2.53")
	f.set("sip.example.net", TypeA, "192.0.2.70")
	f.set("alias.example.com", TypeA, "192.0.2.80")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	// SRV same target on two ports: one edge, two retained pairs.
	srv := typeResultFor(hr, hr.Host, TypeSRV)
	if len(srv.Hosts) != 2 || len(srv.Ports) != 2 {
		t.Fatalf("SRV retained = %d hosts %d ports, want 2/2", len(srv.Hosts), len(srv.Ports))
	}
	requireEqualStrings(t, "Targets", hostNames(hr.Targets), []string{
		"alias.example.com", "mail.example.net", "ns1.example.net", "sip.example.net",
	})
	got := relationshipIDs(hr)
	// Edge order is pinned sorted by ID.
	want := []string{
		"host:alias.example.com" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.80",
		"host:mail.example.net" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.25",
		"host:ns1.example.net" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.53",
		"host:sip.example.net" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.70",
		"host:www.example.com" + "\x00" + "host_to_cname\x00" + "host:alias.example.com",
		"host:www.example.com" + "\x00" + "host_to_mx\x00" + "host:mail.example.net",
		"host:www.example.com" + "\x00" + "host_to_ns\x00" + "host:ns1.example.net",
		"host:www.example.com" + "\x00" + "host_to_srv\x00" + "host:sip.example.net",
	}
	sortStrings(want)
	requireEqualStrings(t, "relationships", got, want)
	// Sortedness itself is pinned (relationshipIDs already sorts; assert the
	// stored slice is in ID order too).
	for i := 1; i < len(hr.Relationships); i++ {
		if hr.Relationships[i-1].ID() >= hr.Relationships[i].ID() {
			t.Fatalf("relationships not sorted at %d: %q >= %q", i, hr.Relationships[i-1].ID(), hr.Relationships[i].ID())
		}
	}
}

// TestAssembleNXDOMAINSilent pins no edges for NXDOMAIN/failed/empty hosts:
// an NXDOMAIN MX/NS/SRV/TXT type contributes no edges and no targets, and a
// fully-NXDOMAIN host-target family leaves no trace beyond its completed
// marker.
func TestAssembleNXDOMAINSilent(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	f.setErr("www.example.com", TypeMX, &QueryError{Kind: ErrNotFound, Host: "www.example.com", Type: TypeMX, Err: errNoSuchHost()})
	f.setErr("www.example.com", TypeNS, &QueryError{Kind: ErrNotFound, Host: "www.example.com", Type: TypeNS, Err: errNoSuchHost()})
	f.setErr("www.example.com", TypeSRV, &QueryError{Kind: ErrNotFound, Host: "www.example.com", Type: TypeSRV, Err: errNoSuchHost()})
	f.setErr("www.example.com", TypeTXT, &QueryError{Kind: ErrNotFound, Host: "www.example.com", Type: TypeTXT, Err: errNoSuchHost()})
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed (NXDOMAIN is an observation)", hr.Status)
	}
	for _, rt := range []RecordType{TypeMX, TypeNS, TypeSRV, TypeTXT} {
		tr := typeResultFor(hr, hr.Host, rt)
		if tr.Status != TypeCompleted || !tr.NXDOMAIN {
			t.Fatalf("%s type = %+v, want completed NXDOMAIN", rt, tr)
		}
	}
	if len(hr.Targets) != 0 {
		t.Fatalf("Targets = %v, want empty (NXDOMAIN contributes nothing)", hostNames(hr.Targets))
	}
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:www.example.com" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.1",
	})
	// A failed MX type is equally silent.
	f2 := newFakeResolver()
	f2.set("api.example.com", TypeA, "192.0.2.2")
	f2.setErr("api.example.com", TypeMX, &QueryError{Kind: ErrFailure, Host: "api.example.com", Type: TypeMX, Err: errors.New("synthetic resolver failure")})
	cfg2 := testConfig(f2)
	rep2 := runOne(t, f2, cfg2, []asset.Host{mustHost(t, "api.example.com")})
	hr2 := hostByName(t, rep2, "api.example.com")
	for _, id := range relationshipIDs(hr2) {
		if strings.Contains(id, "host_to_mx") {
			t.Fatalf("failed MX type emitted an edge: %q", id)
		}
	}
}

// TestAssembleDeterminismShuffled pins determinism: the same answer set in
// shuffled resolver order yields identical relationships and targets.
func TestAssembleDeterminismShuffled(t *testing.T) {
	answers := []string{"b.example.net", "a.example.net", "c.example.net"}
	mkFake := func(order []string) *fakeResolver {
		f := newFakeResolver()
		f.set("www.example.com", TypeMX, order...)
		for _, h := range answers {
			f.set(h, TypeA, "192.0.2.1")
		}
		return f
	}
	run := func(order []string) HostResult {
		f := mkFake(order)
		rep, err := Resolve(context.Background(), mustDomain(t, "example.com"),
			[]asset.Host{mustHost(t, "www.example.com")}, testConfig(f))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		return hostByName(t, rep, "www.example.com")
	}
	a := run([]string{"b.example.net", "a.example.net", "c.example.net"})
	b := run([]string{"c.example.net", "b.example.net", "a.example.net"})
	if len(a.Relationships) != len(b.Relationships) {
		t.Fatalf("shuffled runs differ in edge count: %d vs %d", len(a.Relationships), len(b.Relationships))
	}
	for i := range a.Relationships {
		if a.Relationships[i].ID() != b.Relationships[i].ID() {
			t.Fatalf("shuffled runs differ at edge %d: %q vs %q", i, a.Relationships[i].ID(), b.Relationships[i].ID())
		}
	}
	requireEqualStrings(t, "shuffled targets", hostNames(b.Targets), hostNames(a.Targets))
}

// TestAssembleTruncationCapMirrorsEdges pins the cap rule: answers beyond
// MaxAnswersPerType are dropped before edge derivation, so edges and targets
// cover exactly the retained head and the host folds incomplete.
func TestAssembleTruncationCapMirrorsEdges(t *testing.T) {
	f := newFakeResolver()
	var answers []string
	for i := 0; i < MaxAnswersPerType+5; i++ {
		answers = append(answers, "mx"+itoa(i)+".example.net")
	}
	f.set("big.example.com", TypeMX, answers...)
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "big.example.com")})
	hr := hostByName(t, rep, "big.example.com")

	if hr.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete for a truncated MX set", hr.Status)
	}
	if len(hr.Targets) != MaxAnswersPerType {
		t.Fatalf("targets = %d, want %d (retained head only)", len(hr.Targets), MaxAnswersPerType)
	}
	mxEdges := 0
	for _, r := range hr.Relationships {
		if strings.Contains(r.ID(), "host_to_mx") {
			mxEdges++
		}
	}
	if mxEdges != MaxAnswersPerType {
		t.Fatalf("mx edges = %d, want %d (one per retained target)", mxEdges, MaxAnswersPerType)
	}
}
