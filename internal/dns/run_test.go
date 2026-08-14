package dns

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// resolveScript runs one resolution with the given fake scripts.
func runOne(t *testing.T, f *fakeResolver, cfg Config, hosts []asset.Host) Report {
	t.Helper()
	var rep Report
	mustFinish(t, "Resolve", func() {
		var err error
		rep, err = Resolve(context.Background(), mustDomain(t, "example.com"), hosts, cfg)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	})
	return rep
}

// TestResolveASuccess covers a plain A-record host: typed IP asset, host->IP
// relationship, completed status, provenance from the injectable clock.
func TestResolveASuccess(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	clk := newFakeClock(fixedTime)
	cfg := testConfig(f)
	cfg.Clock = clk

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	a := typeResultFor(hr, hr.Host, TypeA)
	if a.Status != TypeCompleted || a.Cached || a.NXDOMAIN {
		t.Fatalf("A type = %+v, want completed uncached non-NXDOMAIN", a)
	}
	requireEqualStrings(t, "A answers", ipNames(a.IPs), []string{"192.0.2.1"})
	if a.IPs[0].Prov.Source != "dns" || !a.IPs[0].Prov.DiscoveredAt.Equal(fixedTime) {
		t.Fatalf("IP provenance = %+v, want source dns at fixedTime", a.IPs[0].Prov)
	}

	// Typed relationships: host -> ip via RelationshipHostToIP.
	want := []string{
		"host:www.example.com" + "host_to_ip\x00" + "ip:192.0.2.1",
	}
	requireEqualStrings(t, "relationships", relationshipIDs(hr), want)

	// Assets on the report-level merges.
	requireEqualStrings(t, "AllIPs", ipNames(rep.AllIPs()), []string{"192.0.2.1"})
	requireEqualStrings(t, "AllHosts", hostNames(rep.AllHosts()), []string{"www.example.com"})

	// 3 types queried, exactly once each.
	if got := f.callCount(); got != 3 {
		t.Fatalf("calls = %d, want 3", got)
	}
}

// TestResolveAAAASuccess covers AAAA records: IPv6 addresses normalized via
// the Phase 2 IP asset, including IPv4-mapped IPv6 (::ffff:a.b.c.d) which
// the model un-maps to IPv4 for a deterministic identity.
func TestResolveAAAASuccess(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeAAAA, "2001:db8::1", "::ffff:192.0.2.7", "2001:db8::1")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	aaaa := typeResultFor(hr, hr.Host, TypeAAAA)
	if aaaa.Status != TypeCompleted {
		t.Fatalf("AAAA status = %s, want completed", aaaa.Status)
	}
	// Sorted + deduplicated; the mapped address normalizes to its IPv4 form.
	requireEqualStrings(t, "AAAA answers", ipNames(aaaa.IPs), []string{"192.0.2.7", "2001:db8::1"})

	got := relationshipIDs(hr)
	requireEqualStrings(t, "relationships", got, []string{
		"host:www.example.com" + "host_to_ip\x00" + "ip:192.0.2.7",
		"host:www.example.com" + "host_to_ip\x00" + "ip:2001:db8::1",
	})
	requireEqualStrings(t, "AllIPs", ipNames(rep.AllIPs()), []string{"192.0.2.7", "2001:db8::1"})
}

// TestResolveCNAMESuccess covers a single-hop CNAME: host->target typed
// relationship, the target's addresses resolved at depth 1 (the host's own
// A/AAAA answer set contains the chain closure), and target->address edges.
func TestResolveCNAMESuccess(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "198.51.100.9")
	f.set("www.example.com", TypeAAAA, "2001:db8::9")
	f.set("www.example.com", TypeCNAME, "origin.example.net")
	f.set("origin.example.net", TypeA, "198.51.100.9")
	f.set("origin.example.net", TypeAAAA, "2001:db8::9")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	cname := typeResultFor(hr, hr.Host, TypeCNAME)
	if cname.Status != TypeCompleted || cname.NXDOMAIN {
		t.Fatalf("CNAME type = %+v, want completed", cname)
	}
	requireEqualStrings(t, "CNAME targets", hostNames(cname.Hosts), []string{"origin.example.net"})

	// Typed assets: the target becomes a first-class host asset.
	requireEqualStrings(t, "targets", hostNames(hr.Targets), []string{"origin.example.net"})
	requireEqualStrings(t, "all hosts", hostNames(rep.AllHosts()), []string{"origin.example.net", "www.example.com"})
	requireEqualStrings(t, "all IPs", ipNames(rep.AllIPs()), []string{"198.51.100.9", "2001:db8::9"})

	// Relationships: host->target (host_to_cname), host->address (closure),
	// target->address (depth-1 resolution) — all typed edges.
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:origin.example.net" + "host_to_ip\x00" + "ip:198.51.100.9",
		"host:origin.example.net" + "host_to_ip\x00" + "ip:2001:db8::9",
		"host:www.example.com" + "host_to_cname\x00" + "host:origin.example.net",
		"host:www.example.com" + "host_to_ip\x00" + "ip:198.51.100.9",
		"host:www.example.com" + "host_to_ip\x00" + "ip:2001:db8::9",
	})

	// Query plan: www A/AAAA/CNAME + origin A/AAAA = 5 queries; the target's
	// CNAME is NEVER queried (depth exactly 1, CNAME loops impossible by
	// construction). Asserted by the call accounting.
	if got := f.callCount(); got != 5 {
		t.Fatalf("calls = %d, want 5", got)
	}
}

// TestResolveMultipleAnswers covers multiple distinct A and AAAA answers,
// all retained as typed assets with per-address relationships.
func TestResolveMultipleAnswers(t *testing.T) {
	f := newFakeResolver()
	f.set("api.example.com", TypeA, "192.0.2.1", "192.0.2.2", "192.0.2.3")
	f.set("api.example.com", TypeAAAA, "2001:db8::1", "2001:db8::2")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "api.example.com")})
	hr := hostByName(t, rep, "api.example.com")

	a := typeResultFor(hr, hr.Host, TypeA)
	requireEqualStrings(t, "A answers", ipNames(a.IPs), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"})
	aaaa := typeResultFor(hr, hr.Host, TypeAAAA)
	requireEqualStrings(t, "AAAA answers", ipNames(aaaa.IPs), []string{"2001:db8::1", "2001:db8::2"})
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:api.example.com" + "host_to_ip\x00" + "ip:192.0.2.1",
		"host:api.example.com" + "host_to_ip\x00" + "ip:192.0.2.2",
		"host:api.example.com" + "host_to_ip\x00" + "ip:192.0.2.3",
		"host:api.example.com" + "host_to_ip\x00" + "ip:2001:db8::1",
		"host:api.example.com" + "host_to_ip\x00" + "ip:2001:db8::2",
	})
}

// TestResolveEmptyAnswer covers NODATA-style empty answers: the name exists
// but has no records of the requested type. It is a legitimate completed
// result, never a failure.
func TestResolveEmptyAnswer(t *testing.T) {
	f := newFakeResolver()
	f.set("mail.example.com", TypeA) // empty
	f.set("mail.example.com", TypeAAAA)
	f.set("mail.example.com", TypeCNAME)
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "mail.example.com")})
	hr := hostByName(t, rep, "mail.example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed for empty-but-successful answers", hr.Status)
	}
	for _, rt := range []RecordType{TypeA, TypeAAAA, TypeCNAME} {
		tr := typeResultFor(hr, hr.Host, rt)
		if tr.Status != TypeCompleted {
			t.Fatalf("%s type status = %s, want completed", rt, tr.Status)
		}
		if tr.NXDOMAIN {
			t.Fatalf("%s type marked NXDOMAIN for an empty answer; NODATA-style", rt)
		}
	}
	if len(hr.IPs) != 0 || len(hr.Relationships) != 0 {
		t.Fatalf("empty answers must produce no assets or edges: %+v", hr)
	}
}

// TestResolveNXDOMAIN covers NXDOMAIN observations: a legitimate completed
// outcome with an explicit marker — matching Phase 4's "empty-but-successful
// = legitimate completed" convention. The host is completed, not failed.
func TestResolveNXDOMAIN(t *testing.T) {
	f := newFakeResolver()
	f.setErr("gone.example.com", TypeA, &QueryError{Kind: ErrNotFound, Host: "gone.example.com", Type: TypeA, Err: errNoSuchHost()})
	f.setErr("gone.example.com", TypeAAAA, &QueryError{Kind: ErrNotFound, Host: "gone.example.com", Type: TypeAAAA, Err: errNoSuchHost()})
	f.setErr("gone.example.com", TypeCNAME, &QueryError{Kind: ErrNotFound, Host: "gone.example.com", Type: TypeCNAME, Err: errNoSuchHost()})
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "gone.example.com")})
	hr := hostByName(t, rep, "gone.example.com")

	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed for NXDOMAIN observations", hr.Status)
	}
	for _, rt := range []RecordType{TypeA, TypeAAAA, TypeCNAME} {
		tr := typeResultFor(hr, hr.Host, rt)
		if tr.Status != TypeCompleted || !tr.NXDOMAIN {
			t.Fatalf("%s type = %+v, want completed NXDOMAIN", rt, tr)
		}
	}
	if len(hr.IPs) != 0 || len(hr.Relationships) != 0 {
		t.Fatalf("NXDOMAIN must produce no assets or edges: %+v", hr)
	}
}

// errNoSuchHost builds the synthetic NXDOMAIN-style error used by fakes.
func errNoSuchHost() error {
	return &QueryError{Kind: ErrNotFound, Host: "x", Type: TypeA, Err: &dnsErrNotFound{}}
}

// dnsErrNotFound is a tiny marker error for synthetic NXDOMAINs.
type dnsErrNotFound struct{}

func (*dnsErrNotFound) Error() string { return "no such host" }

// TestResolveServfail covers resolver failures: SERVFAIL-classified
// (temporary) and plain errors both map to a failed type, never success.
func TestResolveServfail(t *testing.T) {
	f := newFakeResolver()
	f.setErr("mail.example.com", TypeA, &QueryError{Kind: ErrTemporary, Host: "mail.example.com", Type: TypeA, Err: errors.New("server misbehaving")})
	f.setErr("mail.example.com", TypeAAAA, errors.New("untyped resolver failure"))
	f.setErr("mail.example.com", TypeCNAME, &QueryError{Kind: ErrFailure, Host: "mail.example.com", Type: TypeCNAME, Err: errors.New("refused")})
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "mail.example.com")})
	hr := hostByName(t, rep, "mail.example.com")

	if hr.Status != StatusFailed {
		t.Fatalf("status = %s, want failed when every type failed", hr.Status)
	}
	for _, rt := range []RecordType{TypeA, TypeAAAA, TypeCNAME} {
		tr := typeResultFor(hr, hr.Host, rt)
		if tr.Status != TypeFailed {
			t.Fatalf("%s type status = %s, want failed", rt, tr.Status)
		}
		if tr.NXDOMAIN {
			t.Fatalf("%s type marked NXDOMAIN for a SERVFAIL", rt)
		}
	}
}

// TestApplyAnswersWrappedQueryError is the F5 regression: applyAnswers must
// classify a *QueryError through errors.As, so a WRAPPED typed error (for
// example fmt.Errorf("...: %w", qe)) keeps its kind instead of degrading to
// ErrFailure. A wrapped ErrNotFound stays a completed NXDOMAIN observation.
func TestApplyAnswersWrappedQueryError(t *testing.T) {
	clk := newFakeClock(fixedTime)
	wrapped := fmt.Errorf("resolver note: %w", &QueryError{
		Kind: ErrNotFound,
		Host: "gone.example.com",
		Type: TypeA,
		Err:  errNoSuchHost(),
	})
	tr := applyAnswers(TypeResult{Host: mustHost(t, "gone.example.com"), Type: TypeA}, nil, wrapped, clk)
	if tr.Status != TypeCompleted {
		t.Fatalf("status = %s, want completed for wrapped ErrNotFound", tr.Status)
	}
	if !tr.NXDOMAIN {
		t.Fatal("wrapped ErrNotFound must be recorded as NXDOMAIN, never failed")
	}
	if tr.Err == nil || !errors.Is(tr.Err, wrapped) {
		t.Fatal("cause must be retained and reachable through errors.Is")
	}
}

// TestResolveTimeout covers per-type timeouts: the type is timed out (never
// success, never NXDOMAIN), and a host whose types all time out is
// incomplete — the data is partial by definition.
func TestResolveTimeout(t *testing.T) {
	f := newFakeResolver()
	for _, rt := range hostTypes {
		f.setErr("slow.example.com", rt, &QueryError{Kind: ErrTimeout, Host: "slow.example.com", Type: rt, Err: &dnsErrTimeout{}})
	}
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "slow.example.com")})
	hr := hostByName(t, rep, "slow.example.com")

	if hr.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete (partial) when types time out", hr.Status)
	}
	for _, rt := range hostTypes {
		tr := typeResultFor(hr, hr.Host, rt)
		if tr.Status != TypeTimedOut {
			t.Fatalf("%s type status = %s, want timed-out", rt, tr.Status)
		}
		if tr.Err == nil {
			t.Fatalf("%s type must carry its cause", rt)
		}
	}
}

// dnsErrTimeout is a tiny marker for synthetic timeouts.
type dnsErrTimeout struct{}

func (*dnsErrTimeout) Error() string { return "i/o timeout" }

// TestResolvePartialResults is the N12 scenario: A ok + AAAA timeout +
// CNAME ok. The A and CNAME observations are retained with their
// relationships; the AAAA type is marked with its failure; the host is
// incomplete — and nothing successful is discarded.
func TestResolvePartialResults(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	f.setErr("www.example.com", TypeAAAA, &QueryError{Kind: ErrTimeout, Host: "www.example.com", Type: TypeAAAA, Err: &dnsErrTimeout{}})
	f.set("www.example.com", TypeCNAME, "origin.example.net")
	f.set("origin.example.net", TypeA, "192.0.2.1")
	f.set("origin.example.net", TypeAAAA, "2001:db8::1")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	if hr.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete (A ok + AAAA timeout + CNAME ok)", hr.Status)
	}

	a := typeResultFor(hr, hr.Host, TypeA)
	if a.Status != TypeCompleted || len(a.IPs) != 1 {
		t.Fatalf("A observation lost: %+v", a)
	}
	aaaa := typeResultFor(hr, hr.Host, TypeAAAA)
	if aaaa.Status != TypeTimedOut {
		t.Fatalf("AAAA marked %s, want timed-out with its failure retained", aaaa.Status)
	}
	cname := typeResultFor(hr, hr.Host, TypeCNAME)
	if cname.Status != TypeCompleted || len(cname.Hosts) != 1 {
		t.Fatalf("CNAME observation lost: %+v", cname)
	}

	// Relationships from the successful parts are all retained.
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:origin.example.net" + "host_to_ip\x00" + "ip:192.0.2.1",
		"host:origin.example.net" + "host_to_ip\x00" + "ip:2001:db8::1",
		"host:www.example.com" + "host_to_cname\x00" + "host:origin.example.net",
		"host:www.example.com" + "host_to_ip\x00" + "ip:192.0.2.1",
	})
	requireEqualStrings(t, "all IPs", ipNames(rep.AllIPs()), []string{"192.0.2.1", "2001:db8::1"})

	// The failed type never became success: asserted by status above, and the
	// cache stores it as cancelled (cache_test.go asserts the record).
}

// TestResolveCancellation covers mid-run cancellation: jobs in flight are
// cancelled (never failed, never success), the run returns with the partial
// report, and no further query is issued after cancellation is observed.
func TestResolveCancellation(t *testing.T) {
	f := newFakeResolver()
	ctx, cancel := context.WithCancel(context.Background())
	f.setAutoCancel(cancel)
	f.setBlock() // queries block until the cancelled context unwinds them

	cfg := testConfig(f)
	hosts := []asset.Host{mustHost(t, "www.example.com"), mustHost(t, "api.example.com")}

	var rep Report
	var rerr error
	mustFinish(t, "Resolve", func() {
		rep, rerr = Resolve(ctx, mustDomain(t, "example.com"), hosts, cfg)
	})
	if rerr != nil {
		t.Fatalf("Resolve: %v", rerr)
	}
	for _, hr := range rep.Results {
		if hr.Status != StatusCancelled {
			t.Fatalf("%s status = %s, want cancelled", hr.Host.Name, hr.Status)
		}
		for _, tr := range hr.Types {
			if tr.Status == TypeCompleted {
				t.Fatalf("%s type %s completed despite cancellation", tr.Host.Name, tr.Type)
			}
		}
	}
}

// TestResolveCancellationLastQueryStdlibShape covers the F2 edge: the run
// context fires while the host's LAST query — the depth-1 target AAAA — is
// in flight, leaving no un-attempted types whose cancellation could carry
// the host status. The in-flight query surfaces the exact error the
// production adapter receives from the stdlib pure-Go resolver (a
// *net.DNSError wrapping ctx.Err(), optionally with IsTimeout|IsTemporary),
// so the type must be recorded cancelled and the host must be
// StatusCancelled — never StatusIncomplete, never failed.
func TestResolveCancellationLastQueryStdlibShape(t *testing.T) {
	for _, flags := range []bool{false, true} {
		name := "no flags"
		if flags {
			name = "timeout flags"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeResolver()
			f.set("www.example.com", TypeA, "192.0.2.1")
			f.set("www.example.com", TypeAAAA, "2001:db8::1")
			f.set("www.example.com", TypeCNAME, "origin.example.net")
			f.set("origin.example.net", TypeA, "192.0.2.1")

			ctx, cancel := context.WithCancel(context.Background())
			// Query plan for one host, strictly sequential within its single
			// pool job: host A(1), AAAA(2), CNAME(3), target A(4), target
			// AAAA(5). Cancel while query 5 is in flight.
			f.setCancelInFlight(5, cancel, flags)

			cfg := testConfig(f)
			hosts := []asset.Host{mustHost(t, "www.example.com")}

			var rep Report
			var rerr error
			mustFinish(t, "Resolve", func() {
				rep, rerr = Resolve(ctx, mustDomain(t, "example.com"), hosts, cfg)
			})
			if rerr != nil {
				t.Fatalf("Resolve: %v", rerr)
			}

			hr := hostByName(t, rep, "www.example.com")
			if hr.Status != StatusCancelled {
				t.Fatalf("status = %s, want cancelled (last query cancelled in flight)", hr.Status)
			}
			// The four completed types keep their observations and assets.
			requireEqualStrings(t, "A answers", ipNames(typeResultFor(hr, hr.Host, TypeA).IPs), []string{"192.0.2.1"})
			requireEqualStrings(t, "AAAA answers", ipNames(typeResultFor(hr, hr.Host, TypeAAAA).IPs), []string{"2001:db8::1"})
			requireEqualStrings(t, "CNAME targets", hostNames(typeResultFor(hr, hr.Host, TypeCNAME).Hosts), []string{"origin.example.net"})
			requireEqualStrings(t, "target A answers", ipNames(typeResultFor(hr, mustHost(t, "origin.example.net"), TypeA).IPs), []string{"192.0.2.1"})

			// The in-flight type is cancelled, never failed or timed out.
			tr := typeResultFor(hr, mustHost(t, "origin.example.net"), TypeAAAA)
			if tr.Status != TypeCancelled {
				t.Fatalf("target AAAA status = %s, want cancelled", tr.Status)
			}
			// Exactly 5 queries issued; no query after the context was done.
			if got := f.callCount(); got != 5 {
				t.Fatalf("calls = %d, want 5", got)
			}
		})
	}
}

// TestResolveSelfCNAME covers a resolver returning the queried host itself
// as its CNAME target (what the stdlib LookupCNAME does when no CNAME
// record exists): no observation, no self-edge, and no target resolution.
func TestResolveSelfCNAME(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	f.set("www.example.com", TypeCNAME, "www.example.com") // self-target
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	cname := typeResultFor(hr, hr.Host, TypeCNAME)
	if cname.Status != TypeCompleted {
		t.Fatalf("CNAME status = %s, want completed", cname.Status)
	}
	if len(cname.Hosts) != 0 {
		t.Fatalf("self-target must not become an observation: %v", hostNames(cname.Hosts))
	}
	if len(hr.Targets) != 0 {
		t.Fatalf("self-target must not become a target asset: %v", hostNames(hr.Targets))
	}
	// Only the 3 host queries; the self-target is not resolved further.
	if got := f.callCount(); got != 3 {
		t.Fatalf("calls = %d, want 3", got)
	}
}

// TestResolveCNAMENormalization covers answer normalization: a CNAME answer
// with casing and a trailing root dot (as resolvers may return them)
// normalizes to the canonical Phase 2 host identity.
func TestResolveCNAMENormalization(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeCNAME, "ORIGIN.Example.NET.")
	f.set("origin.example.net", TypeA, "192.0.2.1")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	cname := typeResultFor(hr, hr.Host, TypeCNAME)
	requireEqualStrings(t, "CNAME targets", hostNames(cname.Hosts), []string{"origin.example.net"})
	requireEqualStrings(t, "targets", hostNames(hr.Targets), []string{"origin.example.net"})
	// The target's address resolution ran against the canonical name.
	if got := f.callCount(); got != 5 {
		t.Fatalf("calls = %d, want 5", got)
	}
}

// TestResolveCNAMEMultiHopFlattening documents the observed shape of
// multi-hop CNAME chains: the stdlib flattens the chain, so the pipeline
// observes host -> final canonical target and host -> final addresses (the
// chain closure); intermediate aliases are invisible. This test pins the
// documented limitation rather than the stdlib's internals.
func TestResolveCNAMEMultiHopFlattening(t *testing.T) {
	// Simulated chain: www.example.com -> a.example.com -> origin.example.net
	// The stdlib's LookupCNAME returns the FINAL canonical name and
	// LookupNetIP follows the chain to the final addresses, so the fake
	// scripts exactly what the adapter would surface.
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "203.0.113.5") // chain closure
	f.set("www.example.com", TypeAAAA, "2001:db8::5")
	f.set("www.example.com", TypeCNAME, "origin.example.net") // flattened final target
	f.set("origin.example.net", TypeA, "203.0.113.5")
	f.set("origin.example.net", TypeAAAA, "2001:db8::5")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	// Observed shape: host -> final canonical target; closure addresses on
	// the host; depth-1 resolution of the canonical target. The intermediate
	// alias a.example.com never appears anywhere.
	requireEqualStrings(t, "CNAME targets", hostNames(hr.Targets), []string{"origin.example.net"})
	requireEqualStrings(t, "A answers", ipNames(typeResultFor(hr, hr.Host, TypeA).IPs), []string{"203.0.113.5"})
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:origin.example.net" + "host_to_ip\x00" + "ip:2001:db8::5",
		"host:origin.example.net" + "host_to_ip\x00" + "ip:203.0.113.5",
		"host:www.example.com" + "host_to_cname\x00" + "host:origin.example.net",
		"host:www.example.com" + "host_to_ip\x00" + "ip:2001:db8::5",
		"host:www.example.com" + "host_to_ip\x00" + "ip:203.0.113.5",
	})
}

// TestResolveDepthOneBound verifies the depth-1 boundary precisely: the
// CNAME target's A/AAAA are resolved, its CNAME is never queried, and
// nothing deeper exists by construction (CNAME loops are impossible).
func TestResolveDepthOneBound(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeCNAME, "origin.example.net")
	f.set("origin.example.net", TypeA, "192.0.2.1")
	// Deliberately DO NOT script origin.example.net AAAA or CNAME: the fake
	// would report them as empty answers if queried, so the call accounting
	// below is the assertion.
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	if got := f.callCount(); got != 5 {
		t.Fatalf("calls = %d, want 5 (host A/AAAA/CNAME + target A/AAAA; never target CNAME)", got)
	}
	// The target's empty AAAA (NODATA) is a legitimate completed observation;
	// the queried hosts are exactly the input host and its direct target.
	var queried []string
	for _, tr := range hr.Types {
		queried = append(queried, tr.Host.Name+":"+string(tr.Type))
	}
	want := []string{
		"www.example.com:A", "www.example.com:AAAA", "www.example.com:CNAME",
		"origin.example.net:A", "origin.example.net:AAAA",
	}
	requireEqualStrings(t, "query plan", queried, want)
}

// TestResolveOutOfDomainCNAME verifies a cross-domain CNAME observation: the
// target is a DNS observation and may point outside the target domain; it is
// resolved at depth 1. The INPUT boundary is unaffected (in-scope inputs
// only, asserted in scope_test.go).
func TestResolveOutOfDomainCNAME(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeCNAME, "cdn.other-corp.example")
	f.set("cdn.other-corp.example", TypeA, "192.0.2.77")
	f.set("cdn.other-corp.example", TypeAAAA, "2001:db8::77")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	requireEqualStrings(t, "targets", hostNames(hr.Targets), []string{"cdn.other-corp.example"})
	requireEqualStrings(t, "all hosts", hostNames(rep.AllHosts()), []string{"cdn.other-corp.example", "www.example.com"})
	requireEqualStrings(t, "all IPs", ipNames(rep.AllIPs()), []string{"192.0.2.77", "2001:db8::77"})
}

// TestResolveWildcardDomain covers the bare target domain itself as an input
// host: it is in scope and resolves normally.
func TestResolveWildcardDomain(t *testing.T) {
	f := newFakeResolver()
	f.set("example.com", TypeA, "192.0.2.44")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "example.com")})
	hr := hostByName(t, rep, "example.com")
	if hr.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", hr.Status)
	}
	requireEqualStrings(t, "A answers", ipNames(typeResultFor(hr, hr.Host, TypeA).IPs), []string{"192.0.2.44"})
}

// TestResolveMalformedAnswers covers hostile answers that fail Phase 2
// normalization: they are counted malformed and dropped, never injected into
// the asset model, and never trigger relationships.
func TestResolveMalformedAnswers(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1", "not-an-ip", "999.1.1.1")
	f.set("www.example.com", TypeCNAME, "ok.example.net", "bad_host!.example.net")
	f.set("ok.example.net", TypeA, "192.0.2.2")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	a := typeResultFor(hr, hr.Host, TypeA)
	if a.Malformed != 2 {
		t.Fatalf("A malformed = %d, want 2", a.Malformed)
	}
	requireEqualStrings(t, "A answers", ipNames(a.IPs), []string{"192.0.2.1"})

	cname := typeResultFor(hr, hr.Host, TypeCNAME)
	if cname.Malformed != 1 {
		t.Fatalf("CNAME malformed = %d, want 1", cname.Malformed)
	}
	requireEqualStrings(t, "CNAME targets", hostNames(cname.Hosts), []string{"ok.example.net"})
	if len(hr.IPs) != 2 { // www A 192.0.2.1 + ok.example.net A 192.0.2.2
		t.Fatalf("IPs = %v, want only the valid answers", ipNames(hr.IPs))
	}
}

// TestResolveAnswerCap verifies MaxAnswersPerType enforcement: answer sets
// beyond the cap are retained truncated (never discarded silently), and the
// truncated host is incomplete, matching the Phase 4 truncated-capture
// convention.
func TestResolveAnswerCap(t *testing.T) {
	f := newFakeResolver()
	answers := make([]string, 0, MaxAnswersPerType+17)
	for i := 0; i < MaxAnswersPerType+17; i++ {
		answers = append(answers, mkV4(i))
	}
	f.set("big.example.com", TypeA, answers...)
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "big.example.com")})
	hr := hostByName(t, rep, "big.example.com")

	if hr.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete for a truncated answer set", hr.Status)
	}
	a := typeResultFor(hr, hr.Host, TypeA)
	if !a.Truncated {
		t.Fatal("A type must be marked truncated")
	}
	if len(a.IPs) != MaxAnswersPerType {
		t.Fatalf("retained = %d, want %d", len(a.IPs), MaxAnswersPerType)
	}
	if a.Malformed != 0 {
		t.Fatalf("malformed = %d, want 0 (cap is retention, not malformed)", a.Malformed)
	}
}

// mkV4 renders a synthetic documentation-range IPv4 address (TEST-NET-1).
func mkV4(i int) string {
	return "192.0.2." + itoa(i%250+1)
}

// itoa is a tiny integer formatter (no fmt dependency noise in hot loops).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[n:])
}

// TestResolveDuplicateRelationships verifies edge deduplication: the same
// host->IP edge produced by the host's own closure and by its CNAME target
// resolution appears exactly once (identity-based dedup).
func TestResolveDuplicateRelationships(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	f.set("www.example.com", TypeCNAME, "origin.example.net")
	f.set("origin.example.net", TypeA, "192.0.2.1", "192.0.2.2")
	cfg := testConfig(f)

	rep := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr := hostByName(t, rep, "www.example.com")

	// www->192.0.2.1 appears via the closure AND via the target only once.
	requireEqualStrings(t, "relationships", relationshipIDs(hr), []string{
		"host:origin.example.net" + "host_to_ip\x00" + "ip:192.0.2.1",
		"host:origin.example.net" + "host_to_ip\x00" + "ip:192.0.2.2",
		"host:www.example.com" + "host_to_cname\x00" + "host:origin.example.net",
		"host:www.example.com" + "host_to_ip\x00" + "ip:192.0.2.1",
	})
}

// TestResolveAllHostsMergesProvenance verifies Report.AllHosts/AllIPs merge
// duplicate identities across hosts with earliest-provenance semantics.
func TestResolveAllHostsMergesProvenance(t *testing.T) {
	f := newFakeResolver()
	f.set("a.example.com", TypeCNAME, "shared.example.net")
	f.set("b.example.com", TypeCNAME, "shared.example.net")
	f.set("shared.example.net", TypeA, "192.0.2.9")
	clk := newFakeClock(fixedTime)
	cfg := testConfig(f)
	cfg.Clock = clk

	hosts := []asset.Host{mustHost(t, "a.example.com"), mustHost(t, "b.example.com")}
	rep := runOne(t, f, cfg, hosts)

	all := rep.AllHosts()
	requireEqualStrings(t, "all hosts", hostNames(all), []string{"a.example.com", "b.example.com", "shared.example.net"})
	for _, h := range all {
		if h.Name == "shared.example.net" && h.Prov.Source != "dns" {
			t.Fatalf("shared target provenance source = %q, want dns", h.Prov.Source)
		}
	}
}
