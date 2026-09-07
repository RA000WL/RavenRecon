package dns

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// stringsOf renders a type result's TXT payload for deterministic assertions.
func stringsOf(tr TypeResult) []string {
	out := make([]string, len(tr.Strings))
	copy(out, tr.Strings)
	return out
}

// srvPairs renders an SRV type result's (target, port) observations as
// "target:port" strings in retained order.
func srvPairs(tr TypeResult) []string {
	out := make([]string, 0, len(tr.Hosts))
	for i, h := range tr.Hosts {
		var port uint16
		if i < len(tr.Ports) {
			port = tr.Ports[i]
		}
		out = append(out, h.Name+":"+itoa(int(port)))
	}
	return out
}

// TestResolveMXPositive covers MX observations: exchanger hostnames
// normalized through asset.NewHost (casing/trailing dot), sorted,
// deduplicated; self-targets and un-normalizable answers (bad names, IP
// literals — LookupMX may return numeric hosts) counted malformed and
// dropped. The distinct non-self target gets depth-1 A/AAAA closure exactly
// like a CNAME target, and NEW-126 T2 publishes host->exchanger edges
// (host_to_mx) and merges the targets into hr.Targets.
func TestResolveMXPositive(t *testing.T) {
	f := newFakeResolver()
	f.set("shop.example.com", TypeMX,
		"MAIL-PRIMARY.example.net.",
		"mail-primary.example.net", // duplicate identity
		"shop.example.com",         // self-target: no observation
		"bad_host!.example.net",    // malformed
		"192.0.2.99",               // IP literal: not a hostname, malformed
		"mail-backup.example.net",
	)
	f.set("mail-primary.example.net", TypeA, "192.0.2.25")
	f.set("mail-backup.example.net", TypeA, "192.0.2.26")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "shop.example.com")})
	hr := hostByName(t, rep, "shop.example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	mx := typeResultFor(hr, hr.Host, TypeMX)
	if mx.Status != TypeCompleted || mx.NXDOMAIN {
		t.Fatalf("MX type = %+v, want completed non-NXDOMAIN", mx)
	}
	requireEqualStrings(t, "MX targets", hostNames(mx.Hosts),
		[]string{"mail-backup.example.net", "mail-primary.example.net"})
	if mx.Malformed != 2 {
		t.Fatalf("MX malformed = %d, want 2 (bad name + IP literal)", mx.Malformed)
	}
	if len(mx.IPs) != 0 || len(mx.Strings) != 0 || len(mx.Ports) != 0 {
		t.Fatalf("MX type carries non-hostname payload: %+v", mx)
	}

	// Depth-1 closure: both targets' addresses resolved, IPs land in the
	// report with target->address edges, plus NEW-126 T2 host->exchanger
	// edges from the input host. The input host itself has no addresses and
	// no CNAME, so every shop.example.com edge is host_to_mx.
	requireEqualStrings(t, "IPs", ipNames(hr.IPs), []string{"192.0.2.25", "192.0.2.26"})
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:mail-backup.example.net" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.26",
		"host:mail-primary.example.net" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.25",
		"host:shop.example.com" + "\x00" + "host_to_mx\x00" + "host:mail-backup.example.net",
		"host:shop.example.com" + "\x00" + "host_to_mx\x00" + "host:mail-primary.example.net",
	})
	requireEqualStrings(t, "Targets", hostNames(hr.Targets),
		[]string{"mail-backup.example.net", "mail-primary.example.net"})
}

// TestResolveMXPublication pins the NEW-126 T2 publication: MX targets are
// observed on the TypeResult, get address closure, produce host_to_mx edges,
// and merge into hr.Targets.
func TestResolveMXPublication(t *testing.T) {
	f := newFakeResolver()
	f.set("shop.example.com", TypeMX, "mail.example.net")
	f.set("mail.example.net", TypeA, "192.0.2.25")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "shop.example.com")})
	hr := hostByName(t, rep, "shop.example.com")

	requireEqualStrings(t, "Targets", hostNames(hr.Targets), []string{"mail.example.net"})
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:mail.example.net" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.25",
		"host:shop.example.com" + "\x00" + "host_to_mx\x00" + "host:mail.example.net",
	})
	// Query plan: 7 host types + target A/AAAA = 9.
	if got := f.callCount(); got != 9 {
		t.Fatalf("calls = %d, want 9", got)
	}
}

// TestResolveNSPositive covers NS observations: nameserver hostnames with
// depth-1 closure, host_to_ns edges, and target publication (NEW-126 T2).
func TestResolveNSPositive(t *testing.T) {
	f := newFakeResolver()
	f.set("example.com", TypeNS, "NS1.example.net.", "ns2.example.net")
	f.set("ns1.example.net", TypeA, "192.0.2.53")
	// ns2 has no scripted addresses: NODATA-style empty closure.
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "example.com")})
	hr := hostByName(t, rep, "example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	ns := typeResultFor(hr, hr.Host, TypeNS)
	requireEqualStrings(t, "NS targets", hostNames(ns.Hosts),
		[]string{"ns1.example.net", "ns2.example.net"})
	if ns.Malformed != 0 {
		t.Fatalf("NS malformed = %d, want 0", ns.Malformed)
	}
	requireEqualStrings(t, "IPs", ipNames(hr.IPs), []string{"192.0.2.53"})
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:example.com" + "\x00" + "host_to_ns\x00" + "host:ns1.example.net",
		"host:example.com" + "\x00" + "host_to_ns\x00" + "host:ns2.example.net",
		"host:ns1.example.net" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.53",
	})
	requireEqualStrings(t, "Targets", hostNames(hr.Targets),
		[]string{"ns1.example.net", "ns2.example.net"})
	// Query plan: 7 host types + 2 targets x A/AAAA = 11.
	if got := f.callCount(); got != 11 {
		t.Fatalf("calls = %d, want 11", got)
	}
}

// TestResolveTXTPositive covers TXT observations: opaque strings,
// deduplicated exactly, sorted lexicographically, never assets, never edges.
func TestResolveTXTPositive(t *testing.T) {
	f := newFakeResolver()
	f.set("example.com", TypeA, "192.0.2.1")
	f.set("example.com", TypeTXT,
		"v=spf1 include:_spf.example.net ~all",
		"google-site-verification=abc123",
		"v=spf1 include:_spf.example.net ~all", // duplicate
	)
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "example.com")})
	hr := hostByName(t, rep, "example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	txt := typeResultFor(hr, hr.Host, TypeTXT)
	if txt.Status != TypeCompleted || txt.NXDOMAIN {
		t.Fatalf("TXT type = %+v, want completed non-NXDOMAIN", txt)
	}
	requireEqualStrings(t, "TXT strings", stringsOf(txt), []string{
		"google-site-verification=abc123",
		"v=spf1 include:_spf.example.net ~all",
	})
	if txt.Malformed != 0 {
		t.Fatalf("TXT malformed = %d, want 0", txt.Malformed)
	}
	if len(txt.IPs) != 0 || len(txt.Hosts) != 0 || len(txt.Ports) != 0 {
		t.Fatalf("TXT type carries non-string payload: %+v", txt)
	}
	// TXT contributes no assets or edges: only the A observation remains.
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:example.com" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.1",
	})
}

// TestResolveSRVPositive covers SRV observations: "target:port" wire strings
// become Hosts with a parallel Ports slice, ordered by (name, port),
// deduplicated by (identity, port); malformed wire strings and self-targets
// are dropped; the target gets depth-1 closure. NEW-126 T2 publishes one
// host_to_srv edge per distinct target host (ports ride adapter Evidence,
// not the edge) and merges the distinct targets into hr.Targets.
func TestResolveSRVPositive(t *testing.T) {
	f := newFakeResolver()
	f.set("example.com", TypeSRV,
		"sip.example.net:5060",
		"sip.example.net:5060", // duplicate pair
		"SIP2.example.net.:5061",
		"sip.example.net:5070",  // same target, different port: distinct
		"bad.example.net:99999", // port out of u16 range: malformed
		"example.com:5060",      // self-target: no observation
		"not-a-wire-string",     // no separator: malformed
	)
	f.set("sip.example.net", TypeA, "192.0.2.70")
	f.set("sip2.example.net", TypeA, "192.0.2.71")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "example.com")})
	hr := hostByName(t, rep, "example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	srv := typeResultFor(hr, hr.Host, TypeSRV)
	if srv.Status != TypeCompleted || srv.NXDOMAIN {
		t.Fatalf("SRV type = %+v, want completed non-NXDOMAIN", srv)
	}
	requireEqualStrings(t, "SRV pairs", srvPairs(srv), []string{
		"sip.example.net:5060",
		"sip.example.net:5070",
		"sip2.example.net:5061",
	})
	if len(srv.Ports) != len(srv.Hosts) {
		t.Fatalf("SRV ports/hosts misaligned: %d ports for %d hosts", len(srv.Ports), len(srv.Hosts))
	}
	if srv.Malformed != 2 {
		t.Fatalf("SRV malformed = %d, want 2 (bad port + bad wire string)", srv.Malformed)
	}
	requireEqualStrings(t, "IPs", ipNames(hr.IPs), []string{"192.0.2.70", "192.0.2.71"})
	requireEqualStrings(t, "Targets", hostNames(hr.Targets),
		[]string{"sip.example.net", "sip2.example.net"})
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:example.com" + "\x00" + "host_to_srv\x00" + "host:sip.example.net",
		"host:example.com" + "\x00" + "host_to_srv\x00" + "host:sip2.example.net",
		"host:sip.example.net" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.70",
		"host:sip2.example.net" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.71",
	})
	// Query plan: 7 host types + 2 targets x A/AAAA = 11.
	if got := f.callCount(); got != 11 {
		t.Fatalf("calls = %d, want 11", got)
	}
}

// TestResolveSRVPortRange pins the u16-only port rule: 0 and 65535 pass
// (port 0 is retained as data, never interpreted), 65536 / non-numeric /
// empty target / empty port are malformed.
func TestResolveSRVPortRange(t *testing.T) {
	f := newFakeResolver()
	f.set("example.com", TypeSRV,
		"svc.example.net:0",
		"svc.example.net:65535",
		"svc.example.net:65536",
		"svc.example.net:notaport",
		":53",
		"svc.example.net:",
	)
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "example.com")})
	hr := hostByName(t, rep, "example.com")
	srv := typeResultFor(hr, hr.Host, TypeSRV)

	requireEqualStrings(t, "SRV pairs", srvPairs(srv), []string{
		"svc.example.net:0",
		"svc.example.net:65535",
	})
	if srv.Malformed != 4 {
		t.Fatalf("SRV malformed = %d, want 4", srv.Malformed)
	}
}

// TestResolveTXTOverlongString pins the documented TXT byte rule: a string
// of exactly MaxTXTStringBytes is retained; anything longer is counted
// malformed and dropped — never retained, never truncated in place.
func TestResolveTXTOverlongString(t *testing.T) {
	f := newFakeResolver()
	f.set("example.com", TypeTXT,
		"a=1",
		strings.Repeat("x", MaxTXTStringBytes),
		strings.Repeat("y", MaxTXTStringBytes+1),
	)
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "example.com")})
	hr := hostByName(t, rep, "example.com")
	txt := typeResultFor(hr, hr.Host, TypeTXT)

	if txt.Malformed != 1 {
		t.Fatalf("TXT malformed = %d, want 1 (the over-long string)", txt.Malformed)
	}
	if len(txt.Strings) != 2 {
		t.Fatalf("TXT strings = %d, want 2 (short + at-cap)", len(txt.Strings))
	}
	if len(txt.Strings[1]) != MaxTXTStringBytes {
		t.Fatalf("retained long string = %d bytes, want exactly %d (no in-place truncation)", len(txt.Strings[1]), MaxTXTStringBytes)
	}
	for _, s := range txt.Strings {
		if len(s) > MaxTXTStringBytes {
			t.Fatalf("retained over-long string (%d bytes): unbounded retention", len(s))
		}
	}
}

// TestResolveNewTypesNODATA covers legitimate empty answers for the new
// types alongside a working A record: every type completed, host completed.
func TestResolveNewTypesNODATA(t *testing.T) {
	f := newFakeResolver()
	f.set("txt.example.com", TypeA, "192.0.2.1")
	f.set("txt.example.com", TypeMX) // empty
	f.set("txt.example.com", TypeTXT)
	f.set("txt.example.com", TypeNS)
	f.set("txt.example.com", TypeSRV)
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "txt.example.com")})
	hr := hostByName(t, rep, "txt.example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	for _, rt := range []RecordType{TypeMX, TypeTXT, TypeNS, TypeSRV} {
		tr := typeResultFor(hr, hr.Host, rt)
		if tr.Status != TypeCompleted || tr.NXDOMAIN {
			t.Fatalf("%s type = %+v, want completed NODATA-style", rt, tr)
		}
		if len(tr.Hosts)+len(tr.Strings)+len(tr.IPs)+len(tr.Ports) != 0 {
			t.Fatalf("%s type carries answers for an empty response: %+v", rt, tr)
		}
	}
}

// TestResolveNewTypesNXDOMAINIndependence pins per-type negative outcomes: a
// name can exist for A while another type reports NXDOMAIN — the NXDOMAIN
// type is a completed observation with its marker, and the host stays
// completed.
func TestResolveNewTypesNXDOMAINIndependence(t *testing.T) {
	f := newFakeResolver()
	f.set("mix.example.com", TypeA, "192.0.2.1")
	f.setErr("mix.example.com", TypeMX, &QueryError{Kind: ErrNotFound, Host: "mix.example.com", Type: TypeMX, Err: errNoSuchHost()})
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "mix.example.com")})
	hr := hostByName(t, rep, "mix.example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed (NXDOMAIN is an observation)", hr.Status)
	}
	mx := typeResultFor(hr, hr.Host, TypeMX)
	if mx.Status != TypeCompleted || !mx.NXDOMAIN {
		t.Fatalf("MX type = %+v, want completed NXDOMAIN", mx)
	}
	a := typeResultFor(hr, hr.Host, TypeA)
	if len(a.IPs) != 1 {
		t.Fatalf("A observation lost alongside the MX NXDOMAIN: %+v", a)
	}
}

// TestResolveMXCap pins the shared retention cap for host-target answers:
// past MaxAnswersPerType the set is truncated (never silently completed)
// and the host is incomplete.
func TestResolveMXCap(t *testing.T) {
	f := newFakeResolver()
	var answers []string
	for i := 0; i < MaxAnswersPerType+6; i++ {
		answers = append(answers, "mx"+itoa(i)+".example.net")
	}
	f.set("big.example.com", TypeMX, answers...)
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "big.example.com")})
	hr := hostByName(t, rep, "big.example.com")

	if hr.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete for a truncated MX set", hr.Status)
	}
	mx := typeResultFor(hr, hr.Host, TypeMX)
	if !mx.Truncated {
		t.Fatal("MX type must be marked truncated")
	}
	if len(mx.Hosts) != MaxAnswersPerType {
		t.Fatalf("retained = %d, want %d", len(mx.Hosts), MaxAnswersPerType)
	}
	// Closure runs on the retained set: 7 host types + 64 targets x A/AAAA.
	if got := f.callCount(); got != 7+MaxAnswersPerType*2 {
		t.Fatalf("calls = %d, want %d", got, 7+MaxAnswersPerType*2)
	}
}

// TestResolveTXTCap pins the shared retention cap for strings.
func TestResolveTXTCap(t *testing.T) {
	f := newFakeResolver()
	var answers []string
	for i := 0; i < MaxAnswersPerType+1; i++ {
		answers = append(answers, "txt-record-"+itoa(i)+"-example")
	}
	f.set("big.example.com", TypeTXT, answers...)
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "big.example.com")})
	hr := hostByName(t, rep, "big.example.com")

	if hr.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete for a truncated TXT set", hr.Status)
	}
	txt := typeResultFor(hr, hr.Host, TypeTXT)
	if !txt.Truncated {
		t.Fatal("TXT type must be marked truncated")
	}
	if len(txt.Strings) != MaxAnswersPerType {
		t.Fatalf("retained = %d, want %d", len(txt.Strings), MaxAnswersPerType)
	}
}

// TestResolveMXDepth1ClosureDangling is the dangling-MX decidability case:
// one exchanger resolves to addresses (they land in the report with edges),
// the other is NXDOMAIN for A/AAAA (it stays bare of addresses — no IPs,
// no target->address edges — while the MX observation itself is retained
// with its host_to_mx edge, NEW-126 T2).
func TestResolveMXDepth1ClosureDangling(t *testing.T) {
	f := newFakeResolver()
	f.set("shop.example.com", TypeMX, "mail-primary.example.net", "mail-dead.example.net")
	f.set("mail-primary.example.net", TypeA, "192.0.2.25")
	f.setErr("mail-dead.example.net", TypeA,
		&QueryError{Kind: ErrNotFound, Host: "mail-dead.example.net", Type: TypeA, Err: errNoSuchHost()})
	f.setErr("mail-dead.example.net", TypeAAAA,
		&QueryError{Kind: ErrNotFound, Host: "mail-dead.example.net", Type: TypeAAAA, Err: errNoSuchHost()})
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "shop.example.com")})
	hr := hostByName(t, rep, "shop.example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed (NXDOMAIN closure is an observation)", hr.Status)
	}
	mx := typeResultFor(hr, hr.Host, TypeMX)
	requireEqualStrings(t, "MX targets", hostNames(mx.Hosts),
		[]string{"mail-dead.example.net", "mail-primary.example.net"})

	// The live exchanger's addresses land in the report.
	requireEqualStrings(t, "IPs", ipNames(hr.IPs), []string{"192.0.2.25"})
	// The dead exchanger stays bare of addresses: its A/AAAA are completed
	// NXDOMAIN observations with no target->address edge — but the MX
	// observation itself still publishes its host_to_mx edge (dangling-MX
	// decidability needs the edge to know what dangles).
	deadA := typeResultFor(hr, mustHost(t, "mail-dead.example.net"), TypeA)
	if deadA.Status != TypeCompleted || !deadA.NXDOMAIN {
		t.Fatalf("dead target A = %+v, want completed NXDOMAIN", deadA)
	}
	for _, id := range relationshipIDs(hr) {
		if strings.Contains(id, "mail-dead.example.net") && strings.Contains(id, "host_to_ip") {
			t.Fatalf("address edge for a bare NXDOMAIN target: %q", id)
		}
	}
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:mail-primary.example.net" + "\x00" + "host_to_ip\x00" + "ip:192.0.2.25",
		"host:shop.example.com" + "\x00" + "host_to_mx\x00" + "host:mail-dead.example.net",
		"host:shop.example.com" + "\x00" + "host_to_mx\x00" + "host:mail-primary.example.net",
	})
	// Query plan: 7 host types + 2 targets x A/AAAA = 11.
	if got := f.callCount(); got != 11 {
		t.Fatalf("calls = %d, want 11", got)
	}
}

// TestCacheKeyIsolationNewTypes pins per-type key independence across the
// old/new boundary: an A hit with an MX miss re-queries exactly the MX type
// (plus nothing else — the MX target's addresses are already cached).
func TestCacheKeyIsolationNewTypes(t *testing.T) {
	f := newFakeResolver()
	f.set("shop.example.com", TypeA, "192.0.2.1")
	f.set("shop.example.com", TypeMX, "mail.example.net")
	f.set("mail.example.net", TypeA, "192.0.2.25")
	cfg := testConfig(f)
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)

	host := mustHost(t, "shop.example.com")
	runOne(t, f, cfg, []asset.Host{host})

	key, err := typeKey(host, TypeMX)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	if err := cfg.Cache.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	before := f.callCount()
	rep2 := runOne(t, f, cfg, []asset.Host{host})
	hr2 := hostByName(t, rep2, "shop.example.com")

	if got := f.callCount(); got != before+1 {
		t.Fatalf("second run calls = %d -> %d, want exactly one re-query (MX)", before, got)
	}
	for _, tr := range hr2.Types {
		if tr.Host.Name == "shop.example.com" && tr.Type == TypeMX {
			if tr.Cached {
				t.Fatal("deleted MX type must be re-queried, not served")
			}
			requireEqualStrings(t, "fresh MX", hostNames(tr.Hosts), []string{"mail.example.net"})
			continue
		}
		if !tr.Cached {
			t.Fatalf("%s %s not served from cache", tr.Host.Name, tr.Type)
		}
	}
}

// TestCacheTXTRoundTrip pins TXT cache parity: strings survive the
// store/serve round trip byte-identical, and the warm run issues zero
// queries.
func TestCacheTXTRoundTrip(t *testing.T) {
	f := newFakeResolver()
	f.set("example.com", TypeTXT, "v=spf1 -all", "google-site-verification=abc123")
	cfg := testConfig(f)
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	host := mustHost(t, "example.com")

	rep1 := runOne(t, f, cfg, []asset.Host{host})
	want := stringsOf(typeResultFor(hostByName(t, rep1, "example.com"), host, TypeTXT))

	key, err := typeKey(host, TypeTXT)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	out := cfg.Cache.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("TXT record state = %s, want hit", out.State)
	}
	if out.Record.Status != cache.StatusCompleted {
		t.Fatalf("TXT record status = %q, want completed", out.Record.Status)
	}

	before := f.callCount()
	rep2 := runOne(t, f, cfg, []asset.Host{host})
	if got := f.callCount(); got != before {
		t.Fatalf("cache hit issued %d queries; want zero", got-before)
	}
	txt2 := typeResultFor(hostByName(t, rep2, "example.com"), host, TypeTXT)
	if !txt2.Cached {
		t.Fatal("TXT type not served from cache")
	}
	requireEqualStrings(t, "cached TXT strings", stringsOf(txt2), want)
}

// TestCacheTruncatedTXTNeverCompletes pins truncated-never-served for the
// strings payload: a capped TXT set is stored incomplete and re-executed,
// never served as a hit.
func TestCacheTruncatedTXTNeverCompletes(t *testing.T) {
	f := newFakeResolver()
	var answers []string
	for i := 0; i < MaxAnswersPerType+1; i++ {
		answers = append(answers, "txt-record-"+itoa(i)+"-example")
	}
	f.set("big.example.com", TypeTXT, answers...)
	cfg := testConfig(f)
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	host := mustHost(t, "big.example.com")

	rep1 := runOne(t, f, cfg, []asset.Host{host})
	if hr := hostByName(t, rep1, "big.example.com"); hr.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete", hr.Status)
	}

	key, err := typeKey(host, TypeTXT)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	out := cfg.Cache.Get(context.Background(), key)
	if out.State != cache.StateIncomplete {
		t.Fatalf("truncated TXT record state = %s, want incomplete", out.State)
	}

	before := f.callCount()
	rep2 := runOne(t, f, cfg, []asset.Host{host})
	if got := f.callCount(); got <= before {
		t.Fatal("truncated TXT type must be re-executed, never served as a hit")
	}
	tr := typeResultFor(hostByName(t, rep2, "big.example.com"), host, TypeTXT)
	if tr.Cached || !tr.Truncated {
		t.Fatalf("re-executed TXT type = %+v, want truncated and NOT served from cache", tr)
	}
}

// TestDecodeStoredTypePreT1BackwardCompat proves old payloads still decode:
// hand-written pre-T1 JSON (no strings/ports keys, Hosts only under CNAME)
// validates under the extended kind gates.
func TestDecodeStoredTypePreT1BackwardCompat(t *testing.T) {
	host := mustHost(t, "www.example.com")

	cases := []struct {
		name string
		raw  string
		rt   RecordType
	}{
		{"A answers", `{"target":"host:www.example.com","type":"A","ips":[{"addr":"192.0.2.1"}]}`, TypeA},
		{"CNAME answers", `{"target":"host:www.example.com","type":"CNAME","hosts":[{"name":"origin.example.net"}]}`, TypeCNAME},
		{"empty AAAA", `{"target":"host:www.example.com","type":"AAAA"}`, TypeAAAA},
		{"NXDOMAIN A", `{"target":"host:www.example.com","type":"A","nxdomain":true}`, TypeA},
		{"malformed counter", `{"target":"host:www.example.com","type":"A","ips":[{"addr":"192.0.2.1"}],"malformed":2}`, TypeA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := decodeStoredType(json.RawMessage(tc.raw), host, tc.rt)
			if err != nil {
				t.Fatalf("pre-T1 payload rejected: %v", err)
			}
			if st.Type != tc.rt || st.Target != "host:www.example.com" {
				t.Fatalf("decoded payload = %+v, want type %s for the host", st, tc.rt)
			}
		})
	}
}

// TestDecodeStoredTypeKindGates pins the extended gates: every payload
// field is served only for its own record family, parallel arrays must
// align, NXDOMAIN contradicts answers, truncated is refused, and stored
// answers are re-validated (canonical form, TXT byte cap).
func TestDecodeStoredTypeKindGates(t *testing.T) {
	host := mustHost(t, "www.example.com")
	mkHost := func(name string) asset.Host {
		h, err := asset.NewHost(name, asset.Provenance{})
		if err != nil {
			t.Fatalf("NewHost(%q): %v", name, err)
		}
		return h
	}
	mkIP := func(s string) asset.IP {
		ip, err := asset.NewIP(s, asset.Provenance{})
		if err != nil {
			t.Fatalf("NewIP(%q): %v", s, err)
		}
		return ip
	}

	cases := []struct {
		name    string
		payload storedType
		rt      RecordType
		wantErr bool
	}{
		{"MX hosts accepted", storedType{Target: "host:www.example.com", Type: TypeMX, Hosts: []asset.Host{mkHost("mail.example.net")}}, TypeMX, false},
		{"NS hosts accepted", storedType{Target: "host:www.example.com", Type: TypeNS, Hosts: []asset.Host{mkHost("ns1.example.net")}}, TypeNS, false},
		{"SRV hosts+ports accepted", storedType{Target: "host:www.example.com", Type: TypeSRV, Hosts: []asset.Host{mkHost("sip.example.net")}, Ports: []uint16{5060}}, TypeSRV, false},
		{"TXT strings accepted", storedType{Target: "host:www.example.com", Type: TypeTXT, Strings: []string{"v=spf1 -all"}}, TypeTXT, false},
		{"TXT empty strings accepted", storedType{Target: "host:www.example.com", Type: TypeTXT, Strings: []string{""}}, TypeTXT, false},
		{"hosts under TXT rejected", storedType{Target: "host:www.example.com", Type: TypeTXT, Hosts: []asset.Host{mkHost("x.example.net")}}, TypeTXT, true},
		{"hosts under A rejected", storedType{Target: "host:www.example.com", Type: TypeA, Hosts: []asset.Host{mkHost("x.example.net")}}, TypeA, true},
		{"strings under MX rejected", storedType{Target: "host:www.example.com", Type: TypeMX, Strings: []string{"v=spf1 -all"}}, TypeMX, true},
		{"strings under A rejected", storedType{Target: "host:www.example.com", Type: TypeA, Strings: []string{"v=spf1 -all"}}, TypeA, true},
		{"IPs under TXT rejected", storedType{Target: "host:www.example.com", Type: TypeTXT, IPs: []asset.IP{mkIP("192.0.2.1")}}, TypeTXT, true},
		{"IPs under MX rejected", storedType{Target: "host:www.example.com", Type: TypeMX, IPs: []asset.IP{mkIP("192.0.2.1")}}, TypeMX, true},
		{"ports under MX rejected", storedType{Target: "host:www.example.com", Type: TypeMX, Hosts: []asset.Host{mkHost("mail.example.net")}, Ports: []uint16{25}}, TypeMX, true},
		{"SRV ports/hosts misaligned rejected", storedType{Target: "host:www.example.com", Type: TypeSRV, Hosts: []asset.Host{mkHost("a.example.net"), mkHost("b.example.net")}, Ports: []uint16{80}}, TypeSRV, true},
		{"SRV ports without hosts rejected", storedType{Target: "host:www.example.com", Type: TypeSRV, Ports: []uint16{80}}, TypeSRV, true},
		{"NXDOMAIN with strings rejected", storedType{Target: "host:www.example.com", Type: TypeTXT, NXDOMAIN: true, Strings: []string{"v=spf1 -all"}}, TypeTXT, true},
		{"NXDOMAIN with hosts rejected", storedType{Target: "host:www.example.com", Type: TypeMX, NXDOMAIN: true, Hosts: []asset.Host{mkHost("mail.example.net")}}, TypeMX, true},
		{"truncated TXT refused", storedType{Target: "host:www.example.com", Type: TypeTXT, Truncated: true, Strings: []string{"a"}}, TypeTXT, true},
		{"over-long stored TXT rejected", storedType{Target: "host:www.example.com", Type: TypeTXT, Strings: []string{strings.Repeat("z", MaxTXTStringBytes+1)}}, TypeTXT, true},
		{"non-canonical stored host rejected", storedType{Target: "host:www.example.com", Type: TypeMX, Hosts: []asset.Host{{Name: "MAIL.example.net"}}}, TypeMX, true},
		{"type mismatch rejected", storedType{Target: "host:www.example.com", Type: TypeA, IPs: []asset.IP{mkIP("192.0.2.1")}}, TypeAAAA, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			_, derr := decodeStoredType(raw, host, tc.rt)
			if tc.wantErr && derr == nil {
				t.Fatalf("payload %+v decoded under %s; want rejection", tc.payload, tc.rt)
			}
			if !tc.wantErr && derr != nil {
				t.Fatalf("payload %+v rejected under %s: %v", tc.payload, tc.rt, derr)
			}
		})
	}
}

// TestSRVWireFormat pins the single Resolver wire encoding: format/parse
// round-trip, boundary ports, and every malformed shape.
func TestSRVWireFormat(t *testing.T) {
	for _, port := range []uint16{0, 1, 80, 5060, 65535} {
		wire := formatSRVAnswer("sip.example.net.", port)
		target, got, ok := parseSRVAnswer(wire)
		if !ok || target != "sip.example.net." || got != port {
			t.Fatalf("round trip %q = (%q, %d, %v)", wire, target, got, ok)
		}
	}
	for _, bad := range []string{"", "no-colon", ":53", "host:", "host:65536", "host:-1", "host:12a", "host: 80"} {
		if _, _, ok := parseSRVAnswer(bad); ok {
			t.Fatalf("parseSRVAnswer(%q) accepted; want rejection", bad)
		}
	}
}
