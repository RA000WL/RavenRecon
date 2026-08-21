package urlintel

import (
	"strings"
	"testing"
)

// FuzzParseRawURL exercises the pure ingest boundary parseRawURL
// (engine.go:554) — the only place a raw line becomes an asset.URL. It has
// no network, exec, cache, or filesystem seams: its inputs are the raw line,
// a fixed adapter name, and an injected clock, so arbitrary lines can be
// fuzzed hermetically.
//
// Asserted invariants are exactly the documented ones (see parseRawURL and
// asset/url.go):
//
//   - no panic, no hang on any line
//   - error ⇒ the zero URL is returned (a malformed line never yields a
//     half-populated asset)
//   - success ⇒ scheme/hostport/path are populated, and — the credential
//     redaction postcondition — Original always equals the canonical form,
//     so userinfo carried by a raw line can never survive past this
//     boundary (the hostport itself can therefore never contain "@")
//   - the canonical form re-parses through the same boundary to the
//     identical Identity with Original still equal to its canonical form
//
// Rejection is always acceptable behavior; which lines are accepted is not
// pinned here. Seeds are synthetic inline rows only.
func FuzzParseRawURL(f *testing.F) {
	seeds := []string{
		"https://example.com/a?b=c",
		"http://user:pass@Example.COM.:80/x/../y?Q=1&q=2#F",
		"https://user@example.com",
		"HTTPS://[2001:db8::1]:8443/p",
		"javascript:alert(1)",
		"//example.com/path",
		"",
		"   ",
		"https://\u4f8b\u3048.jp/\u30d1\u30b9?\u5024=1",
		"https://example.com/\x00\x7f?q=\x01",
		strings.Repeat("https://q.test/?", 1) + strings.Repeat("a%20b=1&", 1024),
		"https://example.com:08080/x",
		" https://spaces.example.com/in line \t",
		"https://exa_mple.com/",
		"https://-bad.example.com/",
		"https://[::ffff:127.0.0.1]:0/",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	clk := newFakeClock(fixedTime) // parseRawURL only reads Now(); frozen is fine
	f.Fuzz(func(t *testing.T, line string) {
		u, err := parseRawURL(line, "fuzz-adapter", clk)
		if err != nil {
			if !u.IsZero() {
				t.Errorf("parseRawURL(%q): error with non-zero URL %+v", line, u)
			}
			return
		}
		if u.Scheme == "" || u.HostPort == "" || u.Path == "" {
			t.Errorf("parseRawURL(%q): success missing canonical fields (%q %q %q)",
				line, u.Scheme, u.HostPort, u.Path)
		}
		if strings.Contains(u.HostPort, "@") {
			t.Errorf("parseRawURL(%q): hostport %q leaked a userinfo separator", line, u.HostPort)
		}
		if u.Original != u.String() {
			t.Errorf("parseRawURL(%q): credential-redaction postcondition broken: Original %q != canonical %q",
				line, u.Original, u.String())
		}
		again, err := parseRawURL(u.String(), "fuzz-adapter", clk)
		if err != nil {
			t.Fatalf("parseRawURL(%q): canonical form %q does not re-parse: %v",
				line, u.String(), err)
		}
		if again.Identity() != u.Identity() || again.Original != again.String() {
			t.Errorf("parseRawURL(%q): canonical re-parse unstable: identity %s -> %s, original %q -> %q",
				line, u.ID(), again.ID(), u.Original, again.Original)
		}
	})
}
