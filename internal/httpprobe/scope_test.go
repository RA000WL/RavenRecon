package httpprobe

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

func TestValidateScope(t *testing.T) {
	cases := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"canonical", "example.com", false},
		{"subdomain-like domain is still a domain", "www.example.com", false},
		{"raw input", "Example.com", true},
		{"trailing dot", "example.com.", true},
		{"empty", "", true},
		{"hand-built garbage", "exa mple.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateScope(asset.Domain{Name: tc.domain})
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateScope(%q) err = %v, wantErr %v", tc.domain, err, tc.wantErr)
			}
		})
	}
}

func TestValidateInputHost(t *testing.T) {
	domain := mustDomain(t, "example.com")
	cases := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"apex", "example.com", false},
		{"subdomain", "www.example.com", false},
		{"deep subdomain", "a.b.example.com", false},
		{"uppercase", "WWW.Example.com", true},
		{"trailing dot", "www.example.com.", true},
		{"IP literal", "192.0.2.1", true},
		{"sibling domain", "example.net", true},
		{"evil suffix", "example.com.evil.net", true},
		{"prefix of domain", "notexample.com", true},
		{"empty", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInputHost(asset.Host{Name: tc.host}, domain)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateInputHost(%q) err = %v, wantErr %v", tc.host, err, tc.wantErr)
			}
		})
	}
}

func TestNormalizeInputHosts(t *testing.T) {
	domain := mustDomain(t, "example.com")
	hosts := []asset.Host{
		mustHost(t, "www.example.com"),
		mustHost(t, "example.com"),
		mustHost(t, "www.example.com"), // duplicate by identity
		mustHost(t, "api.example.com"),
	}
	out, err := normalizeInputHosts(hosts, domain)
	if err != nil {
		t.Fatalf("normalizeInputHosts: %v", err)
	}
	requireEqualStrings(t, "normalized hosts", hostNamesOf(out), []string{
		"api.example.com", "example.com", "www.example.com",
	})

	// The whole list is rejected on the first invalid entry.
	bad := append([]asset.Host{{Name: "evil.net"}}, hosts...)
	if _, err := normalizeInputHosts(bad, domain); err == nil {
		t.Fatal("normalizeInputHosts accepted an out-of-scope host")
	}
}

func hostNamesOf(hosts []asset.Host) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h.Name)
	}
	return out
}

func TestNormalizeInputIPs(t *testing.T) {
	domain := mustDomain(t, "example.com")

	good := map[string]asset.IP{
		"www.example.com": mustIP(t, "192.0.2.1"),
	}
	out, err := normalizeInputIPs(good, domain)
	if err != nil {
		t.Fatalf("normalizeInputIPs: %v", err)
	}
	if len(out) != 1 || out["www.example.com"].Addr.String() != "192.0.2.1" {
		t.Fatalf("normalizeInputIPs = %v", out)
	}

	if _, err := normalizeInputIPs(map[string]asset.IP{"evil.net": mustIP(t, "192.0.2.1")}, domain); err == nil {
		t.Fatal("normalizeInputIPs accepted an out-of-scope key")
	}
	// IPv4-mapped IPv6 must be rejected: the canonical form differs. A
	// hand-built asset can carry a non-canonical (mapped) address; the
	// boundary must refuse it.
	mapped := asset.IP{Addr: netip.MustParseAddr("::ffff:192.0.2.1")}
	if _, err := normalizeInputIPs(map[string]asset.IP{"www.example.com": mapped}, domain); err == nil {
		t.Fatal("normalizeInputIPs accepted a non-canonical address")
	}
	if _, err := normalizeInputIPs(map[string]asset.IP{"www.example.com": {}}, domain); err == nil {
		t.Fatal("normalizeInputIPs accepted a zero address")
	}
}

func TestRecordHop(t *testing.T) {
	domain := mustDomain(t, "example.com")
	clock := runtime.Clock(newFakeClock(fixedTime))
	cur := mustParseURL(t, "http://www.example.com/a")

	cases := []struct {
		name    string
		loc     string
		inScope bool
		want    string // expected hop.Target when in-scope
	}{
		{"absolute in-scope", "http://www.example.com/b", true, "http://www.example.com/b"},
		{"relative in-scope", "/b", true, "http://www.example.com/b"},
		{"relative with dot segments", "b/../c", true, "http://www.example.com/c"},
		{"protocol-relative in-scope", "//www.example.com/x", true, "http://www.example.com/x"},
		{"https scheme change in-scope", "https://www.example.com/x", true, "https://www.example.com/x"},
		{"trailing root dot in-scope", "http://www.example.com./y", true, "http://www.example.com/y"},
		{"out-of-scope host", "https://evil.example.net/x", false, ""},
		{"IP literal", "http://192.0.2.1/x", false, ""},
		{"userinfo target is out of scope", "http://user@evil.example.net/x", false, ""},
		{"unparseable port", "http://www.example.com:99999/x", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hop, inScope := recordHop(cur, tc.loc, domain, clock)
			if inScope != tc.inScope {
				t.Fatalf("inScope = %v, want %v", inScope, tc.inScope)
			}
			if tc.inScope {
				if hop.Followed {
					t.Fatalf("fresh in-scope hop must not be marked followed: %+v", hop)
				}
				if hop.Target != tc.want {
					t.Fatalf("target = %q, want %q", hop.Target, tc.want)
				}
				if hop.URL.String() != tc.want {
					t.Fatalf("URL = %q, want %q", hop.URL.String(), tc.want)
				}
			} else {
				if hop.URL.Scheme != "" || hop.URL.HostPort != "" {
					t.Fatalf("out-of-scope hop must carry no typed URL: %+v", hop)
				}
				if hop.Target == "" {
					t.Fatalf("out-of-scope hop must carry a display target: %+v", hop)
				}
			}
		})
	}
}

func TestRecordHopUserinfoInScope(t *testing.T) {
	// In-scope host with userinfo: followed, but the canonical target AND
	// the typed URL asset must never contain the credentials — including
	// asset.URL.Original, which preserves userinfo by design and is
	// marshaled into reports and cache records (the HIGH-2 leak).
	domain := mustDomain(t, "example.com")
	clock := runtime.Clock(newFakeClock(fixedTime))
	cur := mustParseURL(t, "http://www.example.com/a")
	hop, inScope := recordHop(cur, "http://user:secret@www.example.com/b", domain, clock)
	if !inScope {
		t.Fatalf("in-scope userinfo target not recognized: %+v", hop)
	}
	if hop.Target != "http://www.example.com/b" {
		t.Fatalf("target = %q, want credentials stripped", hop.Target)
	}
	if hop.URL.String() != "http://www.example.com/b" {
		t.Fatalf("URL = %q, want the canonical form", hop.URL.String())
	}
	if hop.URL.Original != "http://www.example.com/b" {
		t.Fatalf("URL.Original = %q, want the canonical form (userinfo dropped)", hop.URL.Original)
	}
	if strings.Contains(hop.URL.Original, "secret") || strings.Contains(hop.URL.Original, "@") {
		t.Fatalf("credentials leaked into URL.Original %q", hop.URL.Original)
	}
}

func TestCanonicalizeTarget(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://Evil.Example.NET:443/x?b=2&a=1", "https://evil.example.net/x?b=2&a=1"},
		{"http://evil.example.net:80/", "http://evil.example.net/"},
		{"http://evil.example.net:8080/x", "http://evil.example.net:8080/x"},
		{"http://user:pass@evil.example.net/x", "http://evil.example.net/x"},
		{"http://[::ffff:192.0.2.1]/x", "http://192.0.2.1/x"},
		{"http://[2001:db8::1]:8080/x", "http://[2001:db8::1]:8080/x"},
		{"http://evil.example.net/x#frag", "http://evil.example.net/x"},
		{"http://evil.example.net", "http://evil.example.net/"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.raw, err)
			}
			if got := canonicalizeTarget(u); got != tc.want {
				t.Fatalf("canonicalizeTarget(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func mustParseURL(t *testing.T, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u
}
