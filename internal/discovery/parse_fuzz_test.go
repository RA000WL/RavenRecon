package discovery

import (
	"reflect"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// FuzzParseHostLines exercises the untrusted tool-stdout boundary
// (parse.go parseHostLines) with arbitrary bytes. Only documented
// invariants are asserted (see the function's doc comment):
//
//   - it never panics and never hangs on any input
//   - the malformed count is never negative, and every emitted host has a
//     valid identity: Kind==host, non-empty canonical name that re-validates
//     through asset.NewHost to the same identity (no second normalizer)
//   - output is strictly ascending by canonical name — which subsumes both
//     "sorted" and "duplicates removed"
//   - parsing is deterministic: the same input yields the same hosts and
//     malformed count on a second run
//
// Rejection (malformed++) is always acceptable; nothing pins WHICH tokens
// are accepted. Seeds are synthetic inline rows only.
func FuzzParseHostLines(f *testing.F) {
	seeds := []string{
		"api.example.com\nwww.example.com\n",
		"API.Example.COM.\napi.example.com\n api.example.com \n",
		"example.com (FQDN) --> 1.2.3.4\nwww.example.com\n",
		"\n   \n\t\n\n",
		"ok.example.com\n.example.com\nbad..name\n192.168.1.1\n",
		"a.example.com\r\nb.example.com\r\n",
		"\x00\x01\x02\n\x7f\nok.example.com\n",
		"-lead.example.com\ntrail-.example.com\nunder_score.example.com\nok.example.com\n",
		strings.Repeat("h", 64) + ".example.com\n" + strings.Repeat("i", 65) + ".example.com\n",
		strings.Repeat("x", 300) + ".example.com\nsub.\u4f8b.jp\n\u4f8b\u3048.example.com\n",
		"...\n-\n_\n_.example.com\nx-.example.com\n_dmarc.example.com\n",
		"a.b.c.d.e.f.example.com:8443\n[2001:db8::1]\nnetwork.example.com\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, stdout []byte) {
		hosts, malformed := parseHostLines(stdout, testProv())
		if malformed < 0 {
			t.Errorf("parseHostLines(%q): negative malformed count %d", stdout, malformed)
		}
		for i, h := range hosts {
			id := h.Identity()
			if id.Kind != asset.KindHost || id.Value == "" || id.Value != h.Name {
				t.Errorf("parseHostLines(%q): host %d (%q) has invalid identity %v",
					stdout, i, h.Name, id)
			}
			again, err := asset.NewHost(h.Name, testProv())
			if err != nil || again.Identity() != id {
				t.Errorf("parseHostLines(%q): emitted host %q does not re-validate: (%v, %v)",
					stdout, h.Name, again.Identity(), err)
			}
			if i > 0 && hosts[i-1].Name >= h.Name {
				t.Errorf("parseHostLines(%q): output not strictly ascending at %d: %q >= %q",
					stdout, i, hosts[i-1].Name, h.Name)
			}
		}
		hosts2, malformed2 := parseHostLines(stdout, testProv())
		if malformed2 != malformed || !reflect.DeepEqual(hosts, hosts2) {
			t.Errorf("parseHostLines(%q) is nondeterministic: (%v, %d) vs (%v, %d)",
				stdout, hosts, malformed, hosts2, malformed2)
		}
	})
}
