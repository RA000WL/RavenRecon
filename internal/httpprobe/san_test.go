package httpprobe

import (
	"fmt"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// sanTestDomain normalizes a domain or fails the test.
func sanTestDomain(t testing.TB, name string) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewDomain(%q): %v", name, err)
	}
	return d
}

// sanTestHost normalizes a host or fails the test.
func sanTestHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost(%q): %v", name, err)
	}
	return h
}

// sanTestCert builds a certificate asset carrying the given SAN DNS names.
func sanTestCert(t testing.TB, fp string, names ...string) asset.TLSCertificate {
	t.Helper()
	c, err := asset.NewTLSCertificate(fp, asset.Provenance{Source: "synthetic"})
	if err != nil {
		t.Fatalf("NewTLSCertificate: %v", err)
	}
	c, err = asset.WithDNSNames(c, names)
	if err != nil {
		t.Fatalf("WithDNSNames: %v", err)
	}
	return c
}

// sanHostNames renders synthesized hosts as canonical names.
func sanHostNames(hosts []asset.Host) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h.Name)
	}
	return out
}

func requireSANHosts(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", what, got, want)
		}
	}
}

// TestSynthesizeSANProbeTargetsExtraction pins the happy path: valid
// in-domain SANs become sorted probe hosts with tls-san provenance, and
// the counters stay zero.
func TestSynthesizeSANProbeTargetsExtraction(t *testing.T) {
	domain := sanTestDomain(t, "example.com")
	certs := []asset.TLSCertificate{
		sanTestCert(t, fmt.Sprintf("%064x", 1), "www.example.com", "hidden.example.com"),
		sanTestCert(t, fmt.Sprintf("%064x", 2), "api.example.com"),
	}
	out := SynthesizeSANProbeTargets(domain, certs, nil)
	requireSANHosts(t, "Hosts", sanHostNames(out.Hosts),
		[]string{"api.example.com", "hidden.example.com", "www.example.com"})
	if out.WildcardsSkipped != 0 || out.InvalidSkipped != 0 ||
		out.OutOfScopeDropped != 0 || out.DuplicatesDropped != 0 || out.Truncated {
		t.Fatalf("counters = %+v, want all zero and untruncated", out)
	}
	for _, h := range out.Hosts {
		if h.Prov.Source != sanProvenance {
			t.Fatalf("host %q provenance = %q, want %q", h.Name, h.Prov.Source, sanProvenance)
		}
	}
}

// TestSynthesizeSANProbeTargetsWildcardSkipped pins the documented
// wildcard rule: "*.example.com" is skipped and counted, never expanded
// to the apex or any other guessed name.
func TestSynthesizeSANProbeTargetsWildcardSkipped(t *testing.T) {
	domain := sanTestDomain(t, "example.com")
	certs := []asset.TLSCertificate{
		sanTestCert(t, fmt.Sprintf("%064x", 3), "*.example.com", "fresh.example.com"),
	}
	out := SynthesizeSANProbeTargets(domain, certs, nil)
	requireSANHosts(t, "Hosts", sanHostNames(out.Hosts), []string{"fresh.example.com"})
	if out.WildcardsSkipped != 1 {
		t.Fatalf("WildcardsSkipped = %d, want 1", out.WildcardsSkipped)
	}
	for _, h := range out.Hosts {
		if h.Name == "example.com" {
			t.Fatal("wildcard expanded to the apex: forbidden")
		}
	}
}

// TestSynthesizeSANProbeTargetsScopeWall pins the absolute scope wall:
// out-of-domain SANs are dropped and counted, and can never appear in
// the probe host list.
func TestSynthesizeSANProbeTargetsScopeWall(t *testing.T) {
	domain := sanTestDomain(t, "example.com")
	certs := []asset.TLSCertificate{
		sanTestCert(t, fmt.Sprintf("%064x", 4),
			"evil.example.net", "siblingexample.com", "fresh.example.com"),
	}
	out := SynthesizeSANProbeTargets(domain, certs, nil)
	requireSANHosts(t, "Hosts", sanHostNames(out.Hosts), []string{"fresh.example.com"})
	if out.OutOfScopeDropped != 2 {
		t.Fatalf("OutOfScopeDropped = %d, want 2", out.OutOfScopeDropped)
	}
	for _, h := range out.Hosts {
		if !asset.InDomain(h.Name, domain.Name) {
			t.Fatalf("out-of-scope host %q leaked into probe targets", h.Name)
		}
	}
}

// TestSynthesizeSANProbeTargetsInvalidSkipped pins that non-Host SAN
// entries (IP literals) are skipped and counted separately from
// wildcards.
func TestSynthesizeSANProbeTargetsInvalidSkipped(t *testing.T) {
	domain := sanTestDomain(t, "example.com")
	certs := []asset.TLSCertificate{
		sanTestCert(t, fmt.Sprintf("%064x", 5), "192.168.1.1", "fresh.example.com"),
	}
	out := SynthesizeSANProbeTargets(domain, certs, nil)
	requireSANHosts(t, "Hosts", sanHostNames(out.Hosts), []string{"fresh.example.com"})
	if out.InvalidSkipped != 1 {
		t.Fatalf("InvalidSkipped = %d, want 1", out.InvalidSkipped)
	}
	if out.WildcardsSkipped != 0 {
		t.Fatalf("WildcardsSkipped = %d, want 0 (IP literals are invalid, not wildcards)", out.WildcardsSkipped)
	}
}

// TestSynthesizeSANProbeTargetsDedup pins dedup against the known corpus
// and across certificates: no name is ever synthesized twice.
func TestSynthesizeSANProbeTargetsDedup(t *testing.T) {
	domain := sanTestDomain(t, "example.com")
	known := []asset.Host{sanTestHost(t, "www.example.com"), sanTestHost(t, "api.example.com")}
	certs := []asset.TLSCertificate{
		sanTestCert(t, fmt.Sprintf("%064x", 6), "www.example.com", "api.example.com", "hidden.example.com"),
		sanTestCert(t, fmt.Sprintf("%064x", 7), "hidden.example.com", "other.example.com"),
	}
	out := SynthesizeSANProbeTargets(domain, certs, known)
	requireSANHosts(t, "Hosts", sanHostNames(out.Hosts),
		[]string{"hidden.example.com", "other.example.com"})
	// www + api (corpus) + hidden (second cert repeats the first's
	// synthesis) = 3 duplicates.
	if out.DuplicatesDropped != 3 {
		t.Fatalf("DuplicatesDropped = %d, want 3", out.DuplicatesDropped)
	}
}

// TestSynthesizeSANProbeTargetsCap pins the bound: beyond
// maxSANProbeTargets only the sorted head is kept and Truncated marks
// the cut (never silent, §0.6).
func TestSynthesizeSANProbeTargetsCap(t *testing.T) {
	domain := sanTestDomain(t, "example.com")
	var names []string
	for i := 0; i < maxSANProbeTargets+4; i++ {
		names = append(names, fmt.Sprintf("h%02d.example.com", i))
	}
	certs := []asset.TLSCertificate{sanTestCert(t, fmt.Sprintf("%064x", 8), names...)}
	out := SynthesizeSANProbeTargets(domain, certs, nil)
	if len(out.Hosts) != maxSANProbeTargets {
		t.Fatalf("Hosts = %d, want the %d cap", len(out.Hosts), maxSANProbeTargets)
	}
	if !out.Truncated {
		t.Fatal("Truncated = false, want true (the cut must never be silent)")
	}
	// Sorted head: h00..h15, the h16+ tail cut.
	if out.Hosts[0].Name != "h00.example.com" || out.Hosts[len(out.Hosts)-1].Name != "h15.example.com" {
		t.Fatalf("capped hosts = [%s..%s], want [h00..h15]",
			out.Hosts[0].Name, out.Hosts[len(out.Hosts)-1].Name)
	}
}

// TestSynthesizeSANProbeTargetsEmpty pins the inert paths: no
// certificates, or certificates with no qualifying names, yield no
// hosts and no truncation.
func TestSynthesizeSANProbeTargetsEmpty(t *testing.T) {
	domain := sanTestDomain(t, "example.com")
	if out := SynthesizeSANProbeTargets(domain, nil, nil); len(out.Hosts) != 0 || out.Truncated {
		t.Fatalf("nil certs = %+v, want empty and untruncated", out)
	}
	certs := []asset.TLSCertificate{
		sanTestCert(t, fmt.Sprintf("%064x", 9), "*.example.com", "evil.example.net"),
	}
	out := SynthesizeSANProbeTargets(domain, certs, nil)
	if len(out.Hosts) != 0 || out.Truncated {
		t.Fatalf("all-dropped certs = %+v, want empty and untruncated", out)
	}
	if out.WildcardsSkipped != 1 || out.OutOfScopeDropped != 1 {
		t.Fatalf("counters = %+v, want 1 wildcard + 1 out-of-scope", out)
	}
}
