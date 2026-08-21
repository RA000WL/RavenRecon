package asset

import (
	"strings"
	"testing"
)

// FuzzParseURL exercises the untrusted-URL ingest boundary (ParseURL) with
// arbitrary raw input. Only documented invariants are asserted (see
// url.go's type comment):
//
//   - ParseURL never panics and never hangs (linear parsers over bounded
//     fuzz-engine inputs; the harness fails the run otherwise)
//   - a successful parse yields the canonical shape contract: non-empty
//     scheme/hostport/path, canonical string prefixed scheme+"://"
//   - the canonical form is a fixed point: re-parsing u.String() succeeds,
//     produces the identical Identity, and reproduces the exact same
//     canonical string
//
// Rejection (error return) is always acceptable behavior; nothing about
// WHICH inputs are accepted is pinned here — the normalization table lives
// in url_normalization_pin_test.go.
//
// Seeds are synthetic inline rows only: valid shapes, edge forms (IPv6,
// default ports, leading-zero ports, underscore service labels, dot
// segments, duplicate query keys), hostile junk (control bytes, missing
// parts, invalid ports/labels), multibyte UTF-8, and bounded huge-field
// shapes. No field-trial samples exist; none are referenced.
func FuzzParseURL(f *testing.F) {
	seeds := []string{
		"https://example.com",
		"http://Example.COM.:80/a/../b/./c?x=1&y=2&x=3#frag",
		"https://[2001:0DB8::0001]:443/",
		"http://[::ffff:127.0.0.1]:8080/path//double?q=%41",
		"https://user:pass@example.com/pa th?q=a+b&r=%2F#seg ment",
		"https://_dmarc.example.com/lookup?name=_dmarc",
		"ftp://host.invalid/x/y/../z",
		"HTTP://EXAMPLE.COM./.",
		"https://example.com:99999/",
		"https://example.com:080/a?b",
		"https://exa_mple.com/",
		"https://",
		"//example.com/path",
		"not-a-url",
		"",
		"https://\u4f8b\u3048.jp/%E3%83%91%E3%82%B9?q=\u5024", // multibyte host is rejected, multibyte path/query accepted
		"https://example.com/\x00\x01\x02?q=\x7f",
		"https://long.example.com/" + strings.Repeat("s/", 512),
		"https://q.example.com/?" + strings.Repeat("k=v&", 2048),
		"https://deep.example.com/" + strings.Repeat("../", 256) + "leaf",
		// Regression seeds (FuzzParseURL finding): invalid percent escapes
		// in query keys used to canonicalize non-idempotently.
		"A://0? %0& 0",
		"https://s.example.com/?%2& %G=1",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	fuzzProv := Provenance{Source: "fuzz", DiscoveredAt: fixedTime(0)}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := ParseURL(raw, fuzzProv)
		if err != nil {
			return // rejection is acceptable; no panic/hang is the contract
		}
		if u.Scheme == "" {
			t.Errorf("ParseURL(%q): success with empty scheme", raw)
		}
		if u.HostPort == "" {
			t.Errorf("ParseURL(%q): success with empty hostport", raw)
		}
		if u.Path == "" {
			t.Errorf("ParseURL(%q): success with empty path (must default to \"/\")", raw)
		}
		canonical := u.String()
		if !strings.HasPrefix(canonical, u.Scheme+"://") {
			t.Errorf("ParseURL(%q): canonical form %q lacks scheme prefix", raw, canonical)
		}
		again, err := ParseURL(canonical, fuzzProv)
		if err != nil {
			t.Fatalf("ParseURL(%q): canonical form %q does not re-parse: %v", raw, canonical, err)
		}
		if again.Identity() != u.Identity() {
			t.Errorf("ParseURL(%q): canonical re-parse changed identity %s -> %s",
				raw, u.Identity(), again.Identity())
		}
		if got := again.String(); got != canonical {
			t.Errorf("ParseURL(%q): canonical form is not a fixed point: %q -> %q", raw, canonical, got)
		}
	})
}
