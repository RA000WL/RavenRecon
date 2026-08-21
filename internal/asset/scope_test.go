package asset

import "testing"

func TestInDomain(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		domain string
		want   bool
	}{
		{"exact domain", "example.com", "example.com", true},
		{"subdomain", "www.example.com", "example.com", true},
		{"deep subdomain", "a.b.example.com", "example.com", true},
		{"unrelated domain", "other.net", "example.com", false},
		{"suffix without dot boundary", "notexample.com", "example.com", false},
		{"empty name", "", "example.com", false},
		{"empty domain", "www.example.com", "", false},
		{"both empty", "", "", false},
	}
	for _, tc := range cases {
		if got := InDomain(tc.in, tc.domain); got != tc.want {
			t.Errorf("InDomain(%q, %q) = %v, want %v", tc.in, tc.domain, got, tc.want)
		}
	}
}
