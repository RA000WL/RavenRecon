package asset

import (
	"strings"
	"testing"
)

// TestURLNormalizationPins pins the Phase 2 URL canonicalization rules the
// Phase 6 URL intelligence engine (roadmap v0.7) will build on. Each row
// asserts the canonical identity for a raw input. These rows are the
// engine's contract: if a row fails, the pinned Phase 2 behavior changed
// and the engine stage must be re-checked — the pin itself is not adjusted
// to match new behavior.
//
// The percent-encoding rule is "the as-observed escaped form is the
// identity": the identity is built from url.EscapedPath(), which keeps the
// raw escaped form when it is a valid encoding ("%2F", "%41") and otherwise
// emits the canonical re-escape (raw space -> "%20", non-ASCII -> Go's
// uppercase-hex UTF-8 escaping).
func TestURLNormalizationPins(t *testing.T) {
	p := NewProvenance("manual")

	tests := []struct {
		name    string
		in      string
		want    string // canonical identity, without the "url:" prefix
		check   func(*testing.T, URL)
		wantErr string // when set, the error must contain this substring
	}{
		// Scheme and host: lowercased; trailing root dot removed.
		{name: "scheme lowercased", in: "HTTP://X.COM/", want: "http://x.com/"},
		{name: "host lowercased", in: "http://X.COM/", want: "http://x.com/"},
		{name: "trailing root dot removed", in: "http://x.com./", want: "http://x.com/"},

		// Ports: default removed, non-default preserved, leading zeros
		// canonicalized to the numeric form.
		{name: "http default port removed", in: "http://example.com:80/", want: "http://example.com/"},
		{name: "https default port removed", in: "https://example.com:443/", want: "https://example.com/"},
		{name: "non-default port preserved", in: "http://example.com:8080/", want: "http://example.com:8080/"},
		{name: "port leading zeros canonicalized", in: "http://example.com:08080/", want: "http://example.com:8080/"},

		// Dot segments, root-clamped; duplicate slashes are NEVER collapsed
		// (deliberate Phase 2 behavior, see removeDotSegments).
		{name: "dot segment ..", in: "http://example.com/a/../b", want: "http://example.com/b"},
		{name: "dot segment .", in: "http://example.com/a/./b", want: "http://example.com/a/b"},
		{name: "dot segment clamped at root", in: "http://example.com/../x", want: "http://example.com/x"},
		{name: "duplicate slashes preserved", in: "http://example.com//a", want: "http://example.com//a"},
		{name: "duplicate slashes preserved mid-path", in: "http://example.com/a//b", want: "http://example.com/a//b"},

		// Percent-encoding determinism: the as-observed escaped form is the
		// identity. Raw space escapes to %20; "%2F" and "%41" keep their
		// escaped form; a plain "A" stays plain.
		{name: "raw space in path escapes", in: "https://example.com/a b", want: "https://example.com/a%20b"},
		{name: "raw space and pct-20 merge in query", in: "https://example.com/p?q=a b", want: "https://example.com/p?q=a%20b"},
		{name: "pct-2F stays as-observed", in: "https://example.com/a%2Fb", want: "https://example.com/a%2Fb"},
		{name: "pct-41 stays as-observed", in: "https://example.com/%41", want: "https://example.com/%41"},
		{name: "plain A stays as-is", in: "https://example.com/A", want: "https://example.com/A"},

		// Query: keys sorted; empty query equals absent; values are
		// value-preserving (distinct raw forms stay distinct).
		{name: "query keys sorted", in: "https://example.com/p?b=2&a=1", want: "https://example.com/p?a=1&b=2"},
		{name: "empty query equals absent", in: "https://example.com/p?", want: "https://example.com/p"},
		{name: "pct-20 query value preserved", in: "https://example.com/p?x=a%20b", want: "https://example.com/p?x=a%20b"},
		{name: "plus query value preserved", in: "https://example.com/p?x=a+b", want: "https://example.com/p?x=a+b"},

		// Fragment: excluded from the identity, preserved in Original.
		{name: "fragment excluded from identity", in: "https://example.com/p#frag", want: "https://example.com/p",
			check: func(t *testing.T, u URL) {
				if u.Fragment != "frag" {
					t.Errorf("Fragment = %q, want frag", u.Fragment)
				}
				if u.Original != "https://example.com/p#frag" {
					t.Errorf("Original = %q, want the raw form preserved", u.Original)
				}
			}},

		// Paths: empty becomes "/"; the trailing slash is significant.
		{name: "empty path becomes root", in: "https://example.com", want: "https://example.com/"},
		{name: "root slash", in: "https://example.com/", want: "https://example.com/"},
		{name: "trailing slash significant", in: "https://example.com/a/", want: "https://example.com/a/"},
		{name: "no trailing slash", in: "https://example.com/a", want: "https://example.com/a"},

		// IP literals: canonical IPv6 form; IPv4-mapped IPv6 unmaps.
		{name: "ipv6 literal", in: "https://[2001:db8::1]/", want: "https://[2001:db8::1]/"},
		{name: "ipv4-mapped ipv6 unmapped", in: "https://[::ffff:1.2.3.4]/", want: "https://1.2.3.4/"},

		// Unicode: non-ASCII hosts are REJECTED (the Phase 2 decision
		// documented in normalize.go — no IDN/punycode; URLs reject through
		// host validation). Non-ASCII paths and queries are accepted and
		// canonicalize deterministically: paths via Go's escaping (path) or
		// raw pass-through (query, value-preserving).
		{name: "non-ascii host rejected", in: "https://éxample.com/", wantErr: "invalid host"},
		{name: "non-ascii path escaped deterministically", in: "https://example.com/café", want: "https://example.com/caf%C3%A9"},
		{name: "non-ascii query deterministic", in: "https://example.com/p?q=café", want: "https://example.com/p?q=café"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseURL(tt.in, p)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseURL(%q) expected error, got %v", tt.in, u)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParseURL(%q) error %q does not contain %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseURL(%q) unexpected error: %v", tt.in, err)
			}
			if got := u.ID(); got != "url:"+tt.want {
				t.Errorf("ParseURL(%q).ID() = %q, want %q", tt.in, got, "url:"+tt.want)
			}
			if tt.check != nil {
				tt.check(t, u)
			}
		})
	}
}

// TestURLNormalizationPinDistinctness pins that deliberately distinct raw
// forms stay distinct identities.
func TestURLNormalizationPinDistinctness(t *testing.T) {
	p := NewProvenance("manual")

	groups := []struct {
		name  string
		forms []string
	}{
		{"trailing slash", []string{"https://example.com/", "https://example.com/a", "https://example.com/a/"}},
		{"query value forms", []string{"https://example.com/p?x=a%20b", "https://example.com/p?x=a+b"}},
		{"escaped vs plain path byte", []string{"https://example.com/%41", "https://example.com/A"}},
		{"escaped slash vs slash", []string{"https://example.com/a%2Fb", "https://example.com/a/b"}},
		{"raw vs escaped unicode query", []string{"https://example.com/p?q=café", "https://example.com/p?q=caf%C3%A9"}},
	}
	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			ids := make([]string, 0, len(g.forms))
			for _, raw := range g.forms {
				u, err := ParseURL(raw, p)
				if err != nil {
					t.Fatalf("ParseURL(%q): %v", raw, err)
				}
				ids = append(ids, u.ID())
			}
			for i := 0; i < len(ids); i++ {
				for j := i + 1; j < len(ids); j++ {
					if ids[i] == ids[j] {
						t.Errorf("distinct forms collided: %q and %q both %q", g.forms[i], g.forms[j], ids[i])
					}
				}
			}
		})
	}
}

// TestURLNormalizationPinEquivalence pins that deliberately equivalent raw
// forms merge to a single identity.
func TestURLNormalizationPinEquivalence(t *testing.T) {
	p := NewProvenance("manual")

	groups := [][]string{
		{"https://example.com", "https://example.com/", "HTTPS://EXAMPLE.COM/"},
		{"http://example.com:80/", "http://example.com/"},
		{"https://example.com/p?q=a b", "https://example.com/p?q=a%20b"},
		{"https://example.com/café", "https://example.com/caf%C3%A9"},
	}
	for _, group := range groups {
		t.Run(group[0], func(t *testing.T) {
			ids := make([]string, 0, len(group))
			for _, raw := range group {
				u, err := ParseURL(raw, p)
				if err != nil {
					t.Fatalf("ParseURL(%q): %v", raw, err)
				}
				ids = append(ids, u.ID())
			}
			for i := 1; i < len(ids); i++ {
				if ids[i] != ids[0] {
					t.Errorf("equivalent URLs differ: %q (from %q) != %q (from %q)",
						ids[i], group[i], ids[0], group[0])
				}
			}
		})
	}
}
