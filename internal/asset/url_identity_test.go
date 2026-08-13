package asset

import (
	"strings"
	"sync"
	"testing"
)

func TestParseURL(t *testing.T) {
	p := NewProvenance("manual")

	tests := []struct {
		name    string
		in      string
		want    string // canonical identity
		check   func(*testing.T, URL)
		wantErr bool
	}{
		{name: "lowercase scheme and host", in: "HTTPS://EXAMPLE.COM", want: "https://example.com/"},
		{name: "trailing dot host", in: "https://example.com.", want: "https://example.com/"},
		{name: "leading/trailing space", in: "  https://example.com  ", want: "https://example.com/"},
		{name: "http default port removed", in: "http://example.com:80/x", want: "http://example.com/x"},
		{name: "http leading-zero default port removed", in: "http://example.com:080/x", want: "http://example.com/x"},
		{name: "https leading-zero default port removed", in: "https://example.com:0443/x", want: "https://example.com/x"},
		{name: "leading-zero port canonicalized", in: "http://example.com:08080/x", want: "http://example.com:8080/x"},
		{name: "https default port removed", in: "https://example.com:443/x", want: "https://example.com/x"},
		{name: "non-default port kept", in: "http://example.com:8080/x", want: "http://example.com:8080/x"},
		{name: "https on http port kept", in: "https://example.com:80/x", want: "https://example.com:80/x"},
		{name: "empty path equals root", in: "https://example.com", want: "https://example.com/"},
		{name: "explicit root", in: "https://example.com/", want: "https://example.com/"},
		{name: "query sorted", in: "https://example.com/p?b=2&a=1", want: "https://example.com/p?a=1&b=2"},
		{name: "query order rewritten", in: "https://example.com/p?a=1&b=2", want: "https://example.com/p?a=1&b=2"},
		{name: "query same key stable", in: "https://example.com/p?b=0&a=1&a=2", want: "https://example.com/p?a=1&a=2&b=0"},
		{name: "query space value escaped", in: "https://example.com/p?q=a b", want: "https://example.com/p?q=a%20b"},
		{name: "query space key escaped", in: "https://example.com/p?a b=1", want: "https://example.com/p?a%20b=1"},
		{name: "query raw equals in value escaped", in: "https://example.com/p?x=y=1", want: "https://example.com/p?x=y%3D1"},
		{name: "query value escaping preserved", in: "https://example.com/p?r=/x%2Fy&a=1", want: "https://example.com/p?a=1&r=/x%2Fy"},
		{name: "fragment dropped from identity", in: "https://example.com/p?x=1#frag", want: "https://example.com/p?x=1",
			check: func(t *testing.T, u URL) {
				if u.Fragment != "frag" {
					t.Errorf("Fragment = %q, want frag", u.Fragment)
				}
			}},
		{name: "userinfo dropped from identity", in: "https://user:pass@example.com/x", want: "https://example.com/x",
			check: func(t *testing.T, u URL) {
				if u.Original != "https://user:pass@example.com/x" {
					t.Errorf("Original = %q, want preserved with userinfo", u.Original)
				}
			}},
		{name: "dot segments removed", in: "http://example.com/a/./b/../c", want: "http://example.com/a/c"},
		{name: "dot segments ../../ collapse", in: "http://example.com/a/b/../../x", want: "http://example.com/x"},
		{name: "dot segments a/.. under root", in: "http://example.com/a/..", want: "http://example.com/"},
		{name: "dot segments a/b/..", in: "http://example.com/a/b/..", want: "http://example.com/a"},
		{name: "dot segments double slash kept", in: "http://example.com//a/../b", want: "http://example.com//b"},
		{name: "empty dot segment path under root", in: "http://example.com/../x", want: "http://example.com/x"},
		{name: "double slash preserved", in: "http://example.com/a//b", want: "http://example.com/a//b"},
		{name: "encoded space normalizes", in: "https://example.com/a b", want: "https://example.com/a%20b"},
		{name: "encoded space equivalent", in: "https://example.com/a%20b", want: "https://example.com/a%20b"},
		{name: "encoded slash distinct", in: "https://example.com/a%2Fb", want: "https://example.com/a%2Fb"},
		{name: "ipv4 literal", in: "http://1.2.3.4:80/", want: "http://1.2.3.4/"},
		{name: "ipv4 literal port kept", in: "http://1.2.3.4:8080/", want: "http://1.2.3.4:8080/"},
		{name: "ipv6 literal", in: "https://[2001:db8::1]/", want: "https://[2001:db8::1]/"},
		{name: "ipv6 default port removed", in: "https://[2001:db8::1]:443/x", want: "https://[2001:db8::1]/x"},
		{name: "ipv6 port kept", in: "http://[2001:db8::1]:8080/x", want: "http://[2001:db8::1]:8080/x"},
		{name: "ipv6 unmap mapped addr", in: "https://[::ffff:1.2.3.4]/", want: "https://1.2.3.4/"},
		{name: "queryless trailing qmark", in: "https://example.com/y?", want: "https://example.com/y"},

		{name: "empty", in: "", wantErr: true},
		{name: "no scheme", in: "example.com", wantErr: true},
		{name: "no host", in: "https://", wantErr: true},
		{name: "space in host", in: "https://exa mple.com/", wantErr: true},
		{name: "invalid port", in: "https://example.com:99999/", wantErr: true},
		{name: "non-ascii host", in: "https://éxample.com/", wantErr: true},
		{name: "bad scheme", in: "9http://example.com/", wantErr: true},
		{name: "no scheme colon", in: "://x", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseURL(tt.in, p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseURL(%q) expected error, got %v", tt.in, u)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseURL(%q) unexpected error: %v", tt.in, err)
			}
			if u.ID() != "url:"+tt.want {
				t.Errorf("ParseURL(%q).ID() = %q, want %q", tt.in, u.ID(), "url:"+tt.want)
			}
			if tt.check != nil {
				tt.check(t, u)
			}
		})
	}
}

func TestURLDistinctness(t *testing.T) {
	p := NewProvenance("manual")

	pairs := []struct {
		name string
		a, b string
	}{
		{"http vs https", "http://example.com/", "https://example.com/"},
		{"different non-default ports", "http://example.com:8080/", "http://example.com:9090/"},
		{"path case", "https://example.com/A", "https://example.com/a"},
		{"path trailing slash", "https://example.com/a", "https://example.com/a/"},
		{"query key", "https://example.com/p?a=1", "https://example.com/p?b=1"},
		{"query value", "https://example.com/p?a=1", "https://example.com/p?a=2"},
		{"enc slash vs slash", "https://example.com/a%2Fb", "https://example.com/a/b"},
		{"different host", "https://example.com/", "https://example.org/"},
		{"enc ampersand key vs raw amp key", "https://example.com/p?a%26b=1&c=2", "https://example.com/p?a&b=1&c=2"},
		{"enc equals key vs raw equals key", "https://example.com/p?x%3Dy=1", "https://example.com/p?x=y=1"},
		{"pct-space key vs plus key", "https://example.com/p?a%20b=1", "https://example.com/p?a+b=1"},
		{"raw space value vs plus value", "https://example.com/p?q=a b", "https://example.com/p?q=a+b"},
		{"pct-hash key vs double-encoded", "https://example.com/p?a%23b=1", "https://example.com/p?a%2523b=1"},
	}

	for _, pp := range pairs {
		t.Run(pp.name, func(t *testing.T) {
			a, err := ParseURL(pp.a, p)
			if err != nil {
				t.Fatalf("ParseURL(%q): %v", pp.a, err)
			}
			b, err := ParseURL(pp.b, p)
			if err != nil {
				t.Fatalf("ParseURL(%q): %v", pp.b, err)
			}
			if a.ID() == b.ID() {
				t.Errorf("distinct URLs collided:\n  %q\n  %q\nboth %q", pp.a, pp.b, a.ID())
			}
		})
	}
}

// TestURLQueryRawKeyPreservation locks in that query keys are sorted by their
// decoded form but emitted in their original raw form (with the raw bytes
// ' ', '#', '&', '=' percent-encoded), so distinct raw keys never share an
// identity except where a raw space merges with its already-encoded "%20"
// form, and no identity ever contains raw characters ('#', ' ') that would
// alter how the query is parsed.
func TestURLQueryRawKeyPreservation(t *testing.T) {
	p := NewProvenance("manual")
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ampersand key", "https://example.com/p?a%26b=1&c=2", "url:https://example.com/p?a%26b=1&c=2"},
		{"equals key", "https://example.com/p?x%3Dy=1", "url:https://example.com/p?x%3Dy=1"},
		{"hash key", "https://example.com/p?a%23b=1", "url:https://example.com/p?a%23b=1"},
		{"space key", "https://example.com/p?a%20b=1", "url:https://example.com/p?a%20b=1"},
		{"plus key", "https://example.com/p?a+b=1", "url:https://example.com/p?a+b=1"},
		{"raw space value", "https://example.com/p?q=a b", "url:https://example.com/p?q=a%20b"},
		{"raw space key", "https://example.com/p?a b=1", "url:https://example.com/p?a%20b=1"},
		{"raw equals in value", "https://example.com/p?x=y=1", "url:https://example.com/p?x=y%3D1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseURL(tt.in, p)
			if err != nil {
				t.Fatalf("ParseURL(%q): %v", tt.in, err)
			}
			if got := u.ID(); got != tt.want {
				t.Errorf("ParseURL(%q).ID() = %q, want %q", tt.in, got, tt.want)
			}
			if strings.ContainsAny(u.ID(), "# ") {
				t.Errorf("ParseURL(%q).ID() contains raw '#' or space: %q", tt.in, u.ID())
			}
		})
	}
}

func TestURLEquivalence(t *testing.T) {
	p := NewProvenance("manual")

	groups := [][]string{
		{"https://example.com", "https://example.com/", "HTTPS://EXAMPLE.COM/"},
		{"http://example.com:80/x", "http://example.com/x"},
		{"https://example.com:443/x", "https://example.com/x"},
		{"https://example.com/p?a=1&b=2", "https://example.com/p?b=2&a=1"},
		{"https://example.com/p?q=a b", "https://example.com/p?q=a%20b"},
		{"https://example.com/a/./b", "https://example.com/a/b"},
		{"https://[2001:db8::1]:443/x", "https://[2001:db8::1]/x"},
		{"http://1.2.3.4/", "http://[::ffff:1.2.3.4]/"},
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

func TestIdentityNamespacing(t *testing.T) {
	p := NewProvenance("manual")

	d, err := NewDomain("example.com", p)
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	h, err := NewHost("example.com", p)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	if d.Identity() == h.Identity() {
		t.Fatal("domain and host must not share an identity")
	}
	if d.ID() == h.ID() {
		t.Fatal("domain and host must not share an identity string")
	}
	if d.Identity().String() != "domain:example.com" {
		t.Errorf("domain identity = %q", d.Identity().String())
	}
	if h.Identity().String() != "host:example.com" {
		t.Errorf("host identity = %q", h.Identity().String())
	}
}

func TestIdentityConcurrentReads(t *testing.T) {
	p := NewProvenance("manual")
	urls := make([]URL, 32)
	for i := range urls {
		u, err := ParseURL("https://example.com/p?i="+strings.Repeat("x", i+1), p)
		if err != nil {
			t.Fatalf("ParseURL: %v", err)
		}
		urls[i] = u
	}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, u := range urls {
				if !u.Identity().Equal(u.Identity()) {
					t.Error("identity not stable")
				}
			}
		}()
	}
	wg.Wait()
}
