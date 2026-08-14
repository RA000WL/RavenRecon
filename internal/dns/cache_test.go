package dns

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// openTestCache opens a hermetic filesystem cache with an injectable clock.
func openTestCache(t *testing.T, now func() time.Time, ttl time.Duration) *cache.FS {
	t.Helper()
	opts := []cache.Option{cache.WithClock(now)}
	if ttl > 0 {
		opts = append(opts, cache.WithTTL(ttl))
	}
	c, err := cache.Open(t.TempDir(), opts...)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	return c
}

// cacheHits counts how many of a host's types were served from cache.
func cacheHits(hr HostResult) int {
	n := 0
	for _, tr := range hr.Types {
		if tr.Cached {
			n++
		}
	}
	return n
}

// TestCacheMissThenHit verifies cache-before-execute: the first run queries
// and stores completed per-type records; the second run issues ZERO DNS
// requests and serves every type from cache with identical observations.
func TestCacheMissThenHit(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1", "192.0.2.2")
	f.set("www.example.com", TypeAAAA, "2001:db8::1")
	f.set("www.example.com", TypeCNAME, "origin.example.net")
	f.set("origin.example.net", TypeA, "192.0.2.1")
	f.set("origin.example.net", TypeAAAA, "2001:db8::42")

	clk := newFakeClock(fixedTime)
	c := openTestCache(t, clk.Now, 0)
	cfg := testConfig(f)
	cfg.Clock = clk
	cfg.Cache = c
	hosts := []asset.Host{mustHost(t, "www.example.com")}

	rep1 := runOne(t, f, cfg, hosts)
	if got := f.callCount(); got != 5 {
		t.Fatalf("first run calls = %d, want 5", got)
	}
	hr1 := hostByName(t, rep1, "www.example.com")
	if cacheHits(hr1) != 0 {
		t.Fatalf("first run served %d types from cache; want 0", cacheHits(hr1))
	}
	if hr1.Status != StatusCompleted {
		t.Fatalf("first run status = %s, want completed", hr1.Status)
	}

	// Every type stored a completed record (assert directly on the cache).
	for _, rt := range []RecordType{TypeA, TypeAAAA, TypeCNAME} {
		key, err := typeKey(mustHost(t, "www.example.com"), rt)
		if err != nil {
			t.Fatalf("typeKey: %v", err)
		}
		out := c.Get(context.Background(), key)
		if !out.IsHit() {
			t.Fatalf("%s record state = %s, want hit", rt, out.State)
		}
		if out.Record.Status != cache.StatusCompleted {
			t.Fatalf("%s record status = %q, want completed", rt, out.Record.Status)
		}
		if out.Record.Operation != Operation {
			t.Fatalf("record operation = %q, want %q", out.Record.Operation, Operation)
		}
		if out.Record.Target != "host:www.example.com" {
			t.Fatalf("record target = %q, want host:www.example.com", out.Record.Target)
		}
	}

	// Second run: a cache hit must not perform any DNS request.
	rep2 := runOne(t, f, cfg, hosts)
	if got := f.callCount(); got != 5 {
		t.Fatalf("second run calls = %d, want 5 (unchanged: zero queries on hits)", got)
	}
	hr2 := hostByName(t, rep2, "www.example.com")
	if cacheHits(hr2) != 5 {
		t.Fatalf("second run served %d/5 types from cache", cacheHits(hr2))
	}
	if hr2.Status != StatusCompleted {
		t.Fatalf("second run status = %s, want completed", hr2.Status)
	}
	a2 := typeResultFor(hr2, hr2.Host, TypeA)
	requireEqualStrings(t, "cached A answers", ipNames(a2.IPs), []string{"192.0.2.1", "192.0.2.2"})
	c2 := typeResultFor(hr2, hr2.Host, TypeCNAME)
	requireEqualStrings(t, "cached CNAME targets", hostNames(c2.Hosts), []string{"origin.example.net"})
	// The target's addresses also came from cache: no new queries occurred.
	if got := f.callCount(); got != 5 {
		t.Fatalf("cached target resolution issued queries: calls = %d", got)
	}
}

// TestCachePartialPerType verifies the per-type key design: an A hit with a
// fresh AAAA miss is natural — the second run re-queries exactly the missing
// types and serves the cached ones, instead of all-or-nothing.
func TestCachePartialPerType(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	f.set("www.example.com", TypeAAAA, "2001:db8::1")
	f.set("www.example.com", TypeCNAME, "origin.example.net")
	f.set("origin.example.net", TypeA, "192.0.2.1")
	f.set("origin.example.net", TypeAAAA, "2001:db8::7")
	cfg := testConfig(f)
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)

	hostA := mustHost(t, "www.example.com")
	// First run caches every type as completed (www A/AAAA/CNAME and origin
	// A/AAAA).
	runOne(t, f, cfg, []asset.Host{hostA})

	// Remove one cached type entirely to simulate a per-type miss: the
	// pipeline must re-query ONLY that type.
	key, err := typeKey(hostA, TypeAAAA)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	if err := cfg.Cache.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	before := f.callCount()
	rep2 := runOne(t, f, cfg, []asset.Host{hostA})
	hr2 := hostByName(t, rep2, "www.example.com")

	if got := f.callCount(); got != before+1 {
		t.Fatalf("second run calls = %d -> %d, want exactly one re-query (AAAA)", before, got)
	}
	for _, tr := range hr2.Types {
		if tr.Host.Name == "www.example.com" && tr.Type == TypeAAAA {
			if tr.Cached {
				t.Fatal("deleted AAAA type must be re-queried, not served")
			}
			requireEqualStrings(t, "fresh AAAA", ipNames(tr.IPs), []string{"2001:db8::1"})
			continue
		}
		if !tr.Cached {
			t.Fatalf("%s %s not served from cache", tr.Host.Name, tr.Type)
		}
	}
}

// TestCacheFailedTypeNeverSucceeds verifies that a failed or cancelled type
// is stored with a non-success status and can never be served as a hit: the
// next run re-executes it (Phase 4 semantics).
func TestCacheFailedTypeNeverSucceeds(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	f.setErr("www.example.com", TypeAAAA, &QueryError{Kind: ErrTimeout, Host: "www.example.com", Type: TypeAAAA, Err: &dnsErrTimeout{}})
	f.set("www.example.com", TypeCNAME, "origin.example.net")
	f.set("origin.example.net", TypeA, "192.0.2.1")
	f.setErr("origin.example.net", TypeAAAA, &QueryError{Kind: ErrTemporary, Host: "origin.example.net", Type: TypeAAAA, Err: &dnsErrTimeout{}})
	cfg := testConfig(f)
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)

	rep1 := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr1 := hostByName(t, rep1, "www.example.com")
	if hr1.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete", hr1.Status)
	}

	// The failed types are stored with non-success statuses: a timed-out
	// type is stored cancelled and a resolver-failure type is stored failed
	// (the Phase 4 conventions). Neither is ever served as a hit.
	for _, tc := range []struct {
		host string
		rt   RecordType
		want cache.Status
	}{
		{"www.example.com", TypeAAAA, cache.StatusCancelled},  // timeout
		{"origin.example.net", TypeAAAA, cache.StatusFailed},  // resolver failure
		{"www.example.com", TypeA, cache.StatusCompleted},     // sanity: completed types stay completed
		{"www.example.com", TypeCNAME, cache.StatusCompleted}, // sanity
		{"origin.example.net", TypeA, cache.StatusCompleted},  // sanity
	} {
		h, _ := asset.NewHost(tc.host, asset.Provenance{})
		key, err := typeKey(h, tc.rt)
		if err != nil {
			t.Fatalf("typeKey: %v", err)
		}
		out := cfg.Cache.Get(context.Background(), key)
		if out.Record.Status != tc.want {
			t.Fatalf("%s %s record status = %q, want %q", tc.host, tc.rt, out.Record.Status, tc.want)
		}
		if tc.want != cache.StatusCompleted && out.State == cache.StateHit {
			t.Fatalf("%s %s non-success record served as a hit", tc.host, tc.rt)
		}
	}

	// Second run: every completed type is a hit; every non-completed type is
	// re-executed. The successful observations are never discarded.
	before := f.callCount()
	rep2 := runOne(t, f, cfg, []asset.Host{mustHost(t, "www.example.com")})
	hr2 := hostByName(t, rep2, "www.example.com")
	if cacheHits(hr2) != 3 { // www A, www CNAME, origin A
		t.Fatalf("cache hits = %d, want 3", cacheHits(hr2))
	}
	if got := f.callCount(); got != before+2 {
		t.Fatalf("second run calls = %d -> %d, want exactly the two failed types re-queried", before, got)
	}
	requireEqualStrings(t, "retained A", ipNames(typeResultFor(hr2, hr2.Host, TypeA).IPs), []string{"192.0.2.1"})
}

// TestCacheNXDOMAINCompleted verifies the explicit NXDOMAIN semantics:
// an NXDOMAIN observation is stored as a COMPLETED record (it is a
// legitimate observation, matching Phase 4's empty-but-successful
// convention), a second run serves it from cache with zero queries, and the
// NXDOMAIN marker survives the round trip.
func TestCacheNXDOMAINCompleted(t *testing.T) {
	f := newFakeResolver()
	for _, rt := range hostTypes {
		f.setErr("gone.example.com", rt, &QueryError{Kind: ErrNotFound, Host: "gone.example.com", Type: rt, Err: &dnsErrNotFound{}})
	}
	cfg := testConfig(f)
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	host := mustHost(t, "gone.example.com")

	rep1 := runOne(t, f, cfg, []asset.Host{host})
	hr1 := hostByName(t, rep1, "gone.example.com")
	if hr1.Status != StatusCompleted {
		t.Fatalf("first run status = %s, want completed for NXDOMAIN observations", hr1.Status)
	}

	key, err := typeKey(host, TypeA)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	out := cfg.Cache.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("NXDOMAIN record state = %s, want a completed hit", out.State)
	}
	if out.Record.Status != cache.StatusCompleted {
		t.Fatalf("NXDOMAIN record status = %q, want completed", out.Record.Status)
	}
	var st storedType
	if err := json.Unmarshal(out.Record.Data, &st); err != nil {
		t.Fatalf("unmarshal stored NXDOMAIN payload: %v", err)
	}
	if !st.NXDOMAIN {
		t.Fatal("stored payload lost the NXDOMAIN marker")
	}

	// Second run: zero queries, NXDOMAIN marker preserved, host completed.
	before := f.callCount()
	rep2 := runOne(t, f, cfg, []asset.Host{host})
	if got := f.callCount(); got != before {
		t.Fatalf("cache hit issued %d queries; want zero", got-before)
	}
	hr2 := hostByName(t, rep2, "gone.example.com")
	if hr2.Status != StatusCompleted || cacheHits(hr2) != 3 {
		t.Fatalf("second run status = %s (hits %d), want completed with 3 cache hits", hr2.Status, cacheHits(hr2))
	}
	for _, rt := range hostTypes {
		tr := typeResultFor(hr2, hr2.Host, rt)
		if !tr.NXDOMAIN || !tr.Cached {
			t.Fatalf("%s cached result = %+v, want NXDOMAIN from cache", rt, tr)
		}
	}
}

// TestCacheExpiry verifies TTL semantics: entries expire via the injectable
// clock and are re-executed after expiry, never served.
func TestCacheExpiry(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	f.set("www.example.com", TypeAAAA, "2001:db8::1")
	f.set("www.example.com", TypeCNAME, "origin.example.net")
	f.set("origin.example.net", TypeA, "192.0.2.1")
	f.set("origin.example.net", TypeAAAA, "2001:db8::1")

	clk := newFakeClock(fixedTime)
	cfg := testConfig(f)
	cfg.Clock = clk
	cfg.Cache = openTestCache(t, clk.Now, time.Hour)
	hosts := []asset.Host{mustHost(t, "www.example.com")}

	runOne(t, f, cfg, hosts)
	first := f.callCount()
	if first != 5 {
		t.Fatalf("first run calls = %d, want 5", first)
	}

	// A cache hit before expiry serves without queries.
	rep2 := runOne(t, f, cfg, hosts)
	if got := f.callCount(); got != first {
		t.Fatalf("unexpired hit issued %d queries; want zero", got-first)
	}
	hr2 := hostByName(t, rep2, "www.example.com")
	if cacheHits(hr2) != 5 {
		t.Fatalf("unexpired run hits = %d, want 5", cacheHits(hr2))
	}

	// Advance the clock past the TTL: everything is re-executed.
	clk.advance(2 * time.Hour)
	rep3 := runOne(t, f, cfg, hosts)
	if got := f.callCount(); got != first*2 {
		t.Fatalf("expired run calls = %d -> %d, want full re-execution", first, got)
	}
	hr3 := hostByName(t, rep3, "www.example.com")
	if cacheHits(hr3) != 0 {
		t.Fatalf("expired run hits = %d, want 0", cacheHits(hr3))
	}
}

// TestCacheDisabledReexecutesEveryRun verifies that nil Cache means fresh
// execution every time.
func TestCacheDisabledReexecutesEveryRun(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	cfg := testConfig(f)
	hosts := []asset.Host{mustHost(t, "www.example.com")}

	runOne(t, f, cfg, hosts)
	first := f.callCount()
	runOne(t, f, cfg, hosts)
	if got := f.callCount(); got != first*2 {
		t.Fatalf("calls = %d -> %d, want full re-execution without cache", first, got)
	}
}

// TestCacheTruncatedNeverCompletes verifies that a truncated (capped) type
// is stored incomplete and therefore re-executed next run — a truncated
// answer set is never served as a completed result.
func TestCacheTruncatedNeverCompletes(t *testing.T) {
	f := newFakeResolver()
	answers := make([]string, 0, MaxAnswersPerType+1)
	for i := 0; i < MaxAnswersPerType+1; i++ {
		answers = append(answers, mkV4(i))
	}
	f.set("big.example.com", TypeA, answers...)
	cfg := testConfig(f)
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	host := mustHost(t, "big.example.com")

	rep1 := runOne(t, f, cfg, []asset.Host{host})
	if hr := hostByName(t, rep1, "big.example.com"); hr.Status != StatusIncomplete {
		t.Fatalf("status = %s, want incomplete", hr.Status)
	}

	key, err := typeKey(host, TypeA)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	out := cfg.Cache.Get(context.Background(), key)
	if out.State != cache.StateIncomplete {
		t.Fatalf("truncated record state = %s, want incomplete", out.State)
	}
	if out.Record.Status != cache.StatusIncomplete {
		t.Fatalf("truncated record status = %q, want incomplete", out.Record.Status)
	}

	before := f.callCount()
	rep2 := runOne(t, f, cfg, []asset.Host{host})
	if got := f.callCount(); got != before+1 {
		t.Fatalf("second run calls = %d -> %d, want exactly the truncated A type re-executed (AAAA/CNAME completed-empty are cache hits)", before, got)
	}
	hr2 := hostByName(t, rep2, "big.example.com")
	tr := typeResultFor(hr2, hr2.Host, TypeA)
	if tr.Cached || !tr.Truncated {
		t.Fatalf("re-executed A type = %+v, want truncated and NOT served from cache", tr)
	}
	// The non-truncated types are served from cache.
	trA := typeResultFor(hr2, hr2.Host, TypeAAAA)
	if !trA.Cached {
		t.Fatalf("AAAA type re-queried although completed-empty was cached: %+v", trA)
	}
}

// TestCacheTamperedRecordSelfHeals verifies the decode validation: a record
// whose payload disagrees with its key (here: an A-record key holding an
// AAAA-typed payload) is refused, deleted, and recomputed in the same run —
// never served, never wedging the type.
func TestCacheTamperedRecordSelfHeals(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	cfg := testConfig(f)
	c := openTestCache(t, func() time.Time { return fixedTime }, 0)
	cfg.Cache = c
	host := mustHost(t, "www.example.com")

	// First run stores the true A record; then tamper with it directly.
	runOne(t, f, cfg, []asset.Host{host})
	key, err := typeKey(host, TypeA)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	out := c.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("record state = %s, want hit", out.State)
	}
	wrong := storedType{Target: "host:www.example.com", Type: TypeAAAA, IPs: []asset.IP{mustIP(t, "2001:db8::99")}}
	data, err := json.Marshal(wrong)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := *out.Record
	rec.Data = data
	rec.Status = cache.StatusCompleted
	if err := c.Put(context.Background(), key, rec); err != nil {
		t.Fatalf("Put tampered record: %v", err)
	}

	before := f.callCount()
	rep2 := runOne(t, f, cfg, []asset.Host{host})
	hr2 := hostByName(t, rep2, "www.example.com")

	// The A type was re-executed (call count grew) with the true answers,
	// and the tampered record was replaced by the fresh one.
	if got := f.callCount(); got != before+1 {
		t.Fatalf("calls = %d -> %d, want exactly the A query re-executed", before, got)
	}
	if tr := typeResultFor(hr2, hr2.Host, TypeA); tr.Cached {
		t.Fatal("tampered A record was served as a hit; want self-healing re-execution")
	} else {
		requireEqualStrings(t, "healed A answers", ipNames(tr.IPs), []string{"192.0.2.1"})
	}
	fresh := c.Get(context.Background(), key)
	if !fresh.IsHit() {
		t.Fatalf("healed record state = %s, want hit", fresh.State)
	}
}

// TestCacheKeyComposition verifies the key parts contract: distinct record
// types produce distinct keys for the same host; the normalized host
// identity is the target; and timings/limits never enter the payload.
func TestCacheKeyComposition(t *testing.T) {
	h := mustHost(t, "www.example.com")
	ka, err := typeKey(h, TypeA)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	kc, err := typeKey(h, TypeCNAME)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	if ka == kc {
		t.Fatal("A and CNAME keys must differ (per-type caching)")
	}
	kh, err := typeKey(mustHost(t, "WWW.EXAMPLE.COM."), TypeA)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	if kh != ka {
		t.Fatal("key must be derived from the canonical host identity only")
	}
	// Identical parts must reproduce the identical key (determinism).
	ka2, err := typeKey(h, TypeA)
	if err != nil {
		t.Fatalf("typeKey: %v", err)
	}
	if ka2 != ka {
		t.Fatal("same key parts must derive the same key")
	}
}

// mustIP builds a synthetic IP asset.
func mustIP(t *testing.T, s string) asset.IP {
	t.Helper()
	ip, err := asset.NewIP(s, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewIP(%q): %v", s, err)
	}
	return ip
}
