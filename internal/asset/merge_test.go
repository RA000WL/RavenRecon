package asset

import (
	"testing"
	"time"
)

func fixedTime(hour int) time.Time {
	return time.Date(2026, 8, 13, hour, 0, 0, 0, time.UTC)
}

func TestMergeDomains(t *testing.T) {
	p1 := Provenance{Source: "passive-discovery", DiscoveredAt: fixedTime(10)}
	p2 := Provenance{Source: "dns", DiscoveredAt: fixedTime(12)}

	a, err := NewDomain("api.example.com", p1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDomain("API.EXAMPLE.COM", p2)
	if err != nil {
		t.Fatal(err)
	}

	m, err := MergeDomains(a, b)
	if err != nil {
		t.Fatalf("MergeDomains: %v", err)
	}
	if m.ID() != a.ID() {
		t.Fatalf("merged ID = %q, want %q", m.ID(), a.ID())
	}
	if m.Prov.DiscoveredAt != fixedTime(10) {
		t.Errorf("expected earliest provenance, got %v", m.Prov.DiscoveredAt)
	}
	if m.Original != "api.example.com" {
		t.Errorf("expected first original representation, got %q", m.Original)
	}

	// Different identities must refuse to merge.
	c, _ := NewDomain("other.example.com", p2)
	if _, err := MergeDomains(a, c); err == nil {
		t.Fatal("MergeDomains with different identities must error")
	}
}

func TestMergeEmptyOriginal(t *testing.T) {
	p1 := Provenance{Source: "manual", DiscoveredAt: fixedTime(1)}
	p2 := Provenance{Source: "manual", DiscoveredAt: fixedTime(2)}

	a := Domain{Name: "example.com", Prov: p1}
	b := Domain{Name: "example.com", Original: "EXAMPLE.COM", Prov: p2}

	m, err := MergeDomains(a, b)
	if err != nil {
		t.Fatalf("MergeDomains: %v", err)
	}
	if m.Original != "EXAMPLE.COM" {
		t.Errorf("Original = %q, want EXAMPLE.COM preserved from b", m.Original)
	}
	if m.Prov.DiscoveredAt != fixedTime(1) {
		t.Errorf("expected earliest provenance, got %v", m.Prov.DiscoveredAt)
	}
}

func TestMergeURLsPreservesFragment(t *testing.T) {
	p1 := Provenance{Source: "manual", DiscoveredAt: fixedTime(1)}
	p2 := Provenance{Source: "manual", DiscoveredAt: fixedTime(2)}

	a, _ := ParseURL("https://example.com/p", p1)
	b, _ := ParseURL("https://example.com/p#sec", p2)

	m, err := MergeURLs(a, b)
	if err != nil {
		t.Fatalf("MergeURLs: %v", err)
	}
	if m.Fragment != "sec" {
		t.Errorf("Fragment = %q, want sec", m.Fragment)
	}
	if m.Prov.DiscoveredAt != fixedTime(1) {
		t.Errorf("expected earliest provenance, got %v", m.Prov.DiscoveredAt)
	}
}

func TestMergeIPsAndServices(t *testing.T) {
	p1 := Provenance{Source: "a", DiscoveredAt: fixedTime(1)}
	p2 := Provenance{Source: "b", DiscoveredAt: fixedTime(2)}

	ipA, _ := NewIP("1.2.3.4", p1)
	ipB, _ := NewIP("1.2.3.4", p2)
	mip, err := MergeIPs(ipA, ipB)
	if err != nil {
		t.Fatalf("MergeIPs: %v", err)
	}
	if mip.ID() != "ip:1.2.3.4" || mip.Prov.Source != "a" {
		t.Errorf("unexpected merge result %v", mip)
	}

	ipC, _ := NewIP("5.6.7.8", p2)
	if _, err := MergeIPs(ipA, ipC); err == nil {
		t.Fatal("MergeIPs with different addresses must error")
	}

	portA, _ := NewPort(443, "tcp", p1)
	portB, _ := NewPort(443, "tcp", p2)
	mp, err := MergePorts(portA, portB)
	if err != nil {
		t.Fatalf("MergePorts: %v", err)
	}
	if mp.ID() != "port:443/tcp" {
		t.Errorf("port merge ID = %q", mp.ID())
	}

	svcA, _ := NewService("https", portA, p1)
	svcB, _ := NewService("https", portB, p2)
	ms, err := MergeServices(svcA, svcB)
	if err != nil {
		t.Fatalf("MergeServices: %v", err)
	}
	if ms.ID() != "service:443/tcp/https" {
		t.Errorf("service merge ID = %q", ms.ID())
	}
}

func TestMergeEndpointsAndJavaScripts(t *testing.T) {
	p1 := Provenance{Source: "a", DiscoveredAt: fixedTime(1)}
	p2 := Provenance{Source: "b", DiscoveredAt: fixedTime(2)}

	eA, _ := NewEndpoint("GET", "https://example.com/api", p1)
	eB, _ := NewEndpoint("get", "https://example.com/api", p2)

	me, err := MergeEndpoints(eA, eB)
	if err != nil {
		t.Fatalf("MergeEndpoints: %v", err)
	}
	if me.Method != "GET" || me.ID() != "endpoint:GET https://example.com/api" {
		t.Errorf("unexpected endpoint merge %v", me)
	}

	jA, _ := NewJavaScript("https://example.com/app.js", p1)
	jB, _ := NewJavaScript("https://example.com/app.js", p2)
	jB.Hash = "abc123"

	mj, err := MergeJavaScripts(jA, jB)
	if err != nil {
		t.Fatalf("MergeJavaScripts: %v", err)
	}
	if mj.Hash != "abc123" {
		t.Errorf("Hash = %q, want abc123 preserved from b", mj.Hash)
	}
}
