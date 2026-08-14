package dns

import (
	"context"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestResolveRejectsOutOfScopeHosts verifies the resolution boundary: hosts
// that are not the target domain or a subdomain of it reject the whole call,
// and no query is ever issued.
func TestResolveRejectsOutOfScopeHosts(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	cfg := testConfig(f)
	domain := mustDomain(t, "example.com")

	cases := []asset.Host{
		mustHost(t, "evil.org"),
		mustHost(t, "example.net"),
		mustHost(t, "notexample.com"), // suffix but not a label boundary
		mustHost(t, "x.example.com.evil.org"),
	}
	for _, h := range cases {
		mustFinish(t, "Resolve", func() {
			_, err := Resolve(context.Background(), domain, []asset.Host{h}, cfg)
			if err == nil {
				t.Fatalf("Resolve(%q) succeeded; want a scope rejection", h.Name)
			}
		})
		if got := f.callCount(); got != 0 {
			t.Fatalf("Resolve(%q): resolver queried %d times; expected zero", h.Name, got)
		}
	}
}

// TestResolveRejectsNonCanonicalHosts verifies the canonicality boundary:
// non-canonical spellings and hand-built struct literals are rejected before
// any query, exactly like the Phase 4 validateTarget pattern.
func TestResolveRejectsNonCanonicalHosts(t *testing.T) {
	f := newFakeResolver()
	cfg := testConfig(f)
	domain := mustDomain(t, "example.com")

	cases := []asset.Host{
		// Raw user input spellings that asset.NewHost would normalize away:
		// these must be rejected as non-canonical (defense in depth; the
		// caller is expected to normalize first).
		{Name: "WWW.EXAMPLE.COM"},
		{Name: "www.example.com."},
		{Name: " www.example.com"},
		{Name: "www.example.com "},
		// IP literals are not hostnames.
		{Name: "192.0.2.1"},
		// Invalid hostnames.
		{Name: ""},
		{Name: "-bad.example.com"},
		{Name: "bad!.example.com"},
		{Name: "sub..example.com"},
		{Name: "ünïcode.example.com"},
	}
	for _, h := range cases {
		mustFinish(t, "Resolve", func() {
			_, err := Resolve(context.Background(), domain, []asset.Host{h}, cfg)
			if err == nil {
				t.Fatalf("Resolve(%q) succeeded; want a canonicality rejection", h.Name)
			}
		})
	}
	if got := f.callCount(); got != 0 {
		t.Fatalf("resolver queried %d times; expected zero", got)
	}
}

// TestResolveRejectsInvalidDomain verifies the declared scope domain is
// itself re-validated canonically at the boundary.
func TestResolveRejectsInvalidDomain(t *testing.T) {
	f := newFakeResolver()
	cfg := testConfig(f)

	cases := []asset.Domain{
		asset.Domain{Name: "EXAMPLE.COM"},
		asset.Domain{Name: "example.com."},
		asset.Domain{Name: "not a domain"},
		asset.Domain{Name: ""},
	}
	for _, tc := range cases {
		d := tc
		mustFinish(t, "Resolve", func() {
			_, err := Resolve(context.Background(), d, []asset.Host{mustHost(t, "www.example.com")}, cfg)
			if err == nil {
				t.Fatalf("Resolve(domain %q) succeeded; want a rejection", d.Name)
			}
		})
	}
	if got := f.callCount(); got != 0 {
		t.Fatalf("resolver queried %d times; expected zero", got)
	}
}

// TestResolveRejectsBeforeAnyQuery verifies the full-list rejection: one bad
// host rejects the whole call with zero queries, even when the rest of the
// list is valid and in scope.
func TestResolveRejectsBeforeAnyQuery(t *testing.T) {
	f := newFakeResolver()
	f.set("www.example.com", TypeA, "192.0.2.1")
	cfg := testConfig(f)
	domain := mustDomain(t, "example.com")

	hosts := []asset.Host{
		mustHost(t, "www.example.com"),
		mustHost(t, "evil.org"),
		mustHost(t, "api.example.com"),
	}
	mustFinish(t, "Resolve", func() {
		_, err := Resolve(context.Background(), domain, hosts, cfg)
		if err == nil {
			t.Fatal("Resolve succeeded with an out-of-scope host; want a rejection")
		}
	})
	verifyNoQueries(t, f)
}

// TestResolveDeduplicatesAndSortsInputs verifies that duplicate inputs are
// resolved exactly once per identity and results are in sorted canonical
// order, so output is deterministic.
func TestResolveDeduplicatesAndSortsInputs(t *testing.T) {
	f := newFakeResolver()
	for _, h := range []string{"api.example.com", "www.example.com"} {
		f.set(h, TypeA, "192.0.2.10")
		f.set(h, TypeAAAA, "2001:db8::10")
	}
	cfg := testConfig(f)
	domain := mustDomain(t, "example.com")

	hosts := []asset.Host{
		mustHost(t, "www.example.com"),
		mustHost(t, "www.example.com"), // duplicate identity
		mustHost(t, "api.example.com"),
	}
	mustFinish(t, "Resolve", func() {
		rep, err := Resolve(context.Background(), domain, hosts, cfg)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(rep.Results) != 2 {
			t.Fatalf("results = %d, want 2 (deduplicated)", len(rep.Results))
		}
		if rep.Results[0].Host.Name != "api.example.com" || rep.Results[1].Host.Name != "www.example.com" {
			t.Fatalf("results not sorted canonically: %v", hostNames([]asset.Host{rep.Results[0].Host, rep.Results[1].Host}))
		}
	})
	// 2 hosts x 3 types = 6 queries; duplicates must not re-query.
	if got := f.callCount(); got != 6 {
		t.Fatalf("calls = %d, want 6", got)
	}
}

// TestResolveEmptyInput verifies that an empty host list returns an empty
// report without starting a pool or issuing queries.
func TestResolveEmptyInput(t *testing.T) {
	f := newFakeResolver()
	cfg := testConfig(f)
	mustFinish(t, "Resolve", func() {
		rep, err := Resolve(context.Background(), mustDomain(t, "example.com"), nil, cfg)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(rep.Results) != 0 {
			t.Fatalf("results = %d, want 0", len(rep.Results))
		}
	})
	verifyNoQueries(t, f)
}

// TestResolveNilContextAndCancelledContext verifies the immediate error paths
// before any pool or query exists.
func TestResolveNilContextAndCancelledContext(t *testing.T) {
	f := newFakeResolver()
	cfg := testConfig(f)
	hosts := []asset.Host{mustHost(t, "www.example.com")}

	if _, err := Resolve(nil, mustDomain(t, "example.com"), hosts, cfg); err == nil {
		t.Fatal("Resolve(nil ctx) succeeded; want an error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Resolve(ctx, mustDomain(t, "example.com"), hosts, cfg); err == nil {
		t.Fatal("Resolve(cancelled ctx) succeeded; want an error")
	}
	verifyNoQueries(t, f)
}

// TestResolveInvalidPoolConfig verifies that invalid pool bounds surface as
// errors instead of being silently normalized.
func TestResolveInvalidPoolConfig(t *testing.T) {
	f := newFakeResolver()
	cfg := testConfig(f)
	cfg.Concurrency = 0
	_, err := Resolve(context.Background(), mustDomain(t, "example.com"), []asset.Host{mustHost(t, "www.example.com")}, cfg)
	if err == nil {
		t.Fatal("Resolve with zero concurrency succeeded; want an error")
	}
	verifyNoQueries(t, f)
}
