package asset

import (
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
)

// Property tests for the asset model (OPT-P1-3 batch 2a): the properties
// asserted here are exactly the ones the model documents —
//
//   - round-trip: for any input ParseURL accepts, the canonical form
//     re-parses to the identical Identity and is a String() fixed point
//   - merge idempotence: MergeX(x, x) == x for every representative asset
//     kind, and merge(a,b) folded again with a stays stable
//   - dedup invariants: merging never grows an identity set, first-seen
//     wins deterministically, bounded observation lists stay deduplicated
//
// All inputs are synthetic; generation is seeded so runs are deterministic.

// ---- generation of valid URLs -------------------------------------------

// urlShape models one randomly generated valid URL. It implements
// quick.Generator so testing/quick can drive the round-trip property.
type urlShape struct {
	Scheme string
	Host   string
	Port   string
	Path   string
	Query  string
	Frag   string
}

var (
	urlSchemes    = []string{"http", "https"}
	urlLabels     = []string{"www", "api", "a1", "x-y", "m", "s107", "_dmarc"}
	urlPathPieces = []string{"a", "b-c", "%20", "de%2Ff", "..", ".", "g+h", "~tilde"}
	urlQueryKeys  = []string{"q", "id", "x%5Fy", "z"}
	urlQueryVals  = []string{"1", "a%2Fb", "v+w", "%26", "=", "%2B"}
)

func urlPick(r *rand.Rand, xs []string) string { return xs[r.Intn(len(xs))] }

// Generate implements quick.Generator: it always yields a URL ParseURL must
// accept (valid scheme, ASCII host, bounded parts). Non-canonical surface
// forms (uppercase, trailing dot, default ports, leading-zero ports, dot
// segments, userinfo) are sprinkled in deliberately: the property is about
// the CANONICAL output, and exercising normalization keeps the generator
// honest about it.
func (s urlShape) Generate(r *rand.Rand, size int) reflect.Value {
	out := urlShape{Scheme: urlPick(r, urlSchemes)}

	switch r.Intn(8) {
	case 0:
		out.Host = "192.0.2.10" // RFC 5737 documentation range
	case 1:
		out.Host = "[2001:db8::" + strconv.Itoa(r.Intn(16)) + "]" // RFC 3849 documentation range
	default:
		labels := make([]string, 1+r.Intn(3))
		for i := range labels {
			labels[i] = urlPick(r, urlLabels)
		}
		out.Host = strings.Join(labels, ".")
		if r.Intn(4) == 0 {
			out.Host = strings.ToUpper(out.Host)
		}
		if r.Intn(6) == 0 {
			out.Host += "." // trailing root dot collapses in canonical form
		}
	}

	switch r.Intn(5) {
	case 0:
		out.Port = ":80"
	case 1:
		out.Port = ":443"
	case 2:
		out.Port = ":" + strconv.Itoa(1024+r.Intn(55536))
	case 3:
		out.Port = ":0" + strconv.Itoa(1+r.Intn(99)) // leading-zero form canonicalizes numerically
	}

	segs := make([]string, r.Intn(4))
	for i := range segs {
		segs[i] = urlPick(r, urlPathPieces)
	}
	out.Path = "/" + strings.Join(segs, "/")

	pairs := make([]string, r.Intn(4))
	for i := range pairs {
		pairs[i] = urlPick(r, urlQueryKeys) + "=" + urlPick(r, urlQueryVals)
	}
	out.Query = strings.Join(pairs, "&")

	if r.Intn(3) == 0 {
		out.Frag = "fr ag%41"
	}
	return reflect.ValueOf(out)
}

// raw assembles the generated shape into one raw URL line, varying the
// presence of userinfo, query, and fragment separators.
func (s urlShape) raw(r *rand.Rand) string {
	var b strings.Builder
	b.WriteString(s.Scheme)
	b.WriteString("://")
	if r != nil && r.Intn(4) == 0 {
		b.WriteString("user:pass@") // synthetic dummy credential; excluded from identity
	}
	b.WriteString(s.Host)
	b.WriteString(s.Port)
	b.WriteString(s.Path)
	if s.Query != "" || (r != nil && r.Intn(8) == 0) {
		b.WriteByte('?')
		b.WriteString(s.Query)
	}
	if s.Frag != "" {
		b.WriteByte('#')
		b.WriteString(s.Frag)
	}
	return b.String()
}

// TestPropertyURLIdentityRoundTrip drives the parse→Identity→parse
// round-trip with testing/quick: whatever ParseURL accepts, its canonical
// form re-parses cleanly to the identical identity and reproduces itself.
func TestPropertyURLIdentityRoundTrip(t *testing.T) {
	prop := func(s urlShape) bool {
		raw := s.raw(rand.New(rand.NewSource(int64(len(s.Host) + len(s.Path)))))
		u, err := ParseURL(raw, Provenance{Source: "prop"})
		if err != nil {
			t.Logf("generated URL %q must parse, got error: %v", raw, err)
			return false
		}
		again, err := ParseURL(u.String(), Provenance{Source: "prop"})
		if err != nil {
			t.Logf("canonical %q does not re-parse: %v", u.String(), err)
			return false
		}
		return again.Identity() == u.Identity() && again.String() == u.String()
	}
	cfg := &quick.Config{
		MaxCount: 2000,
		Rand:     rand.New(rand.NewSource(42)), // deterministic runs
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatalf("round-trip property violated: %v", err)
	}
}

// TestPropertyURLFixedPointTable pins the same round-trip property on a
// hand-picked table of tricky-but-valid inputs (deterministic, always run).
func TestPropertyURLFixedPointTable(t *testing.T) {
	rows := []string{
		"https://example.com",
		"HTTP://EXAMPLE.COM.:80",
		"http://[2001:0DB8::0001]:80/?a=1&a=2&a=3#f",
		"https://user:pass@WWW.example.COM:8443/a/b/../c//d?x=a+b&x=%61#frag",
		"https://192.0.2.10:8080/",
		"https://[::ffff:192.0.2.128]/%7Euser?q=%2F",
		"https://_acme-challenge.example.com/token",
		"https://example.com/sp%20ace/q?a%20b=c%20d&ab=1",
		"https://example.com/?q=a%26b&q=c%3Dd",
		// Invalid-escape keys: regression for the FuzzParseURL finding —
		// emission rewrites these keys, and sorting must stay stable across
		// that rewrite (identity must not change on canonical re-parse).
		"https://example.com/? %0& 0",
		"https://e.example.com/?a=%ZZ&b c=%-1&%2x=0",
	}
	prov := Provenance{Source: "prop", DiscoveredAt: fixedTime(1)}
	for _, raw := range rows {
		u, err := ParseURL(raw, prov)
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", raw, err)
		}
		canonical := u.String()
		again, err := ParseURL(canonical, prov)
		if err != nil {
			t.Fatalf("ParseURL(canonical of %q = %q): %v", raw, canonical, err)
		}
		if again.Identity() != u.Identity() {
			t.Errorf("ParseURL(%q): re-parse changed identity %s -> %s", raw, u.ID(), again.ID())
		}
		if got := again.String(); got != canonical {
			t.Errorf("ParseURL(%q): not a fixed point: %q -> %q", raw, canonical, got)
		}
	}
}

// ---- merge idempotence ----------------------------------------------------

// propObservations builds, for each representative kind, two distinct
// observations x and y sharing one identity (different provenance times,
// originals, or observation payloads).
type propPair struct {
	name string
	id   func() string
	self func(t *testing.T)            // MergeX(x,x) must equal x
	fold func(t *testing.T) (any, any) // returns (m12, x) for the stability check
	comm func(t *testing.T)            // optional order-independence check (may be nil)
}

func TestPropertyMergeIdempotence(t *testing.T) {
	provA := Provenance{Source: "probe-a", DiscoveredAt: fixedTime(1)}
	provB := Provenance{Source: "probe-b", DiscoveredAt: fixedTime(2)}

	mustDomain := func(name string, p Provenance) Domain {
		d, err := NewDomain(name, p)
		if err != nil {
			t.Fatalf("NewDomain(%q): %v", name, err)
		}
		return d
	}
	mustHost := func(name string, p Provenance) Host {
		h, err := NewHost(name, p)
		if err != nil {
			t.Fatalf("NewHost(%q): %v", name, err)
		}
		return h
	}
	mustURL := func(raw string, p Provenance) URL {
		u, err := ParseURL(raw, p)
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", raw, err)
		}
		return u
	}
	mustParam := func(value, source string, p Provenance, at int) Parameter {
		param, err := NewParameter("id", "query", value, source, fixedTime(at), p)
		if err != nil {
			t.Fatalf("NewParameter: %v", err)
		}
		return param
	}
	certFingerprint := strings.Repeat("ab", 32) // synthetic 64-hex digest
	mustCert := func(subject string, names []string, depth int, p Provenance) TLSCertificate {
		c, err := NewTLSCertificate(certFingerprint, p)
		if err != nil {
			t.Fatalf("NewTLSCertificate: %v", err)
		}
		if subject != "" {
			if c, err = WithSubject(c, subject); err != nil {
				t.Fatalf("WithSubject: %v", err)
			}
		}
		if names != nil {
			if c, err = WithDNSNames(c, names); err != nil {
				t.Fatalf("WithDNSNames: %v", err)
			}
		}
		c.ChainDepth = depth
		return c
	}
	srcHostID := mustHost("www.example.com", provA).Identity()
	mustEvidence := func(indicator, value string, p Provenance) Evidence {
		e, err := NewEvidence(MethodHeader, indicator, value, srcHostID, p)
		if err != nil {
			t.Fatalf("NewEvidence: %v", err)
		}
		return e
	}
	mustFinding := func(confidence float64, evs []Evidence, created int, meta map[string]string) Finding {
		f, err := NewFinding(Finding{
			RuleID:     "rule.prop.test",
			RuleName:   "Prop Rule",
			Category:   "test",
			Subject:    srcHostID,
			Confidence: confidence,
			Evidence:   evs,
			Priority:   "p3",
			Status:     "new",
			Created:    fixedTime(created),
			Metadata:   meta,
		})
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		return f
	}

	pairs := []propPair{
		{
			name: "domain",
			id:   func() string { return mustDomain("EXAMPLE.com", provA).ID() },
			self: func(t *testing.T) {
				x := mustDomain("EXAMPLE.com", provA)
				m, err := MergeDomains(x, x)
				if err != nil || !reflect.DeepEqual(m, x) {
					t.Fatalf("MergeDomains(x,x) = (%+v, %v), want x unchanged", m, err)
				}
			},
			fold: func(t *testing.T) (any, any) {
				x, y := mustDomain("EXAMPLE.com", provA), mustDomain("example.com", provB)
				m, err := MergeDomains(x, y)
				if err != nil {
					t.Fatalf("MergeDomains: %v", err)
				}
				return m, x
			},
		},
		{
			name: "host",
			id:   func() string { return mustHost("Api.EXAMPLE.com.", provA).ID() },
			self: func(t *testing.T) {
				x := mustHost("Api.EXAMPLE.com.", provA)
				m, err := MergeHosts(x, x)
				if err != nil || !reflect.DeepEqual(m, x) {
					t.Fatalf("MergeHosts(x,x) = (%+v, %v), want x unchanged", m, err)
				}
			},
			fold: func(t *testing.T) (any, any) {
				x, y := mustHost("Api.EXAMPLE.com.", provA), mustHost("api.example.com", provB)
				m, err := MergeHosts(x, y)
				if err != nil {
					t.Fatalf("MergeHosts: %v", err)
				}
				return m, x
			},
		},
		{
			name: "url",
			id:   func() string { return mustURL("https://Example.COM/a", provA).ID() },
			self: func(t *testing.T) {
				x := mustURL("https://Example.COM/a", provA)
				m, err := MergeURLs(x, x)
				if err != nil || !reflect.DeepEqual(m, x) {
					t.Fatalf("MergeURLs(x,x) = (%+v, %v), want x unchanged", m, err)
				}
			},
			fold: func(t *testing.T) (any, any) {
				x := mustURL("https://Example.COM:443/a#seen", provA)
				y := mustURL("https://example.com/a#other", provB)
				m, err := MergeURLs(x, y)
				if err != nil {
					t.Fatalf("MergeURLs: %v", err)
				}
				return m, x
			},
		},
		{
			name: "parameter",
			id:   func() string { return mustParam("v1", "src-a", provA, 1).ID() },
			self: func(t *testing.T) {
				x := mustParam("v1", "src-a", provA, 1)
				m, err := MergeParameters(x, x)
				if err != nil || !reflect.DeepEqual(m, x) {
					t.Fatalf("MergeParameters(x,x) = (%+v, %v), want x unchanged", m, err)
				}
			},
			fold: func(t *testing.T) (any, any) {
				x := mustParam("v1", "src-a", provA, 1)
				y := mustParam("v2", "src-b", provB, 2)
				m, err := MergeParameters(x, y)
				if err != nil {
					t.Fatalf("MergeParameters: %v", err)
				}
				return m, x
			},
		},
		{
			name: "tls_certificate",
			id: func() string {
				c, _ := NewTLSCertificate(certFingerprint, provA)
				return c.ID()
			},
			self: func(t *testing.T) {
				x := mustCert("*.example.com", []string{"a.example.com", "b.example.com"}, 1, provA)
				m, err := MergeTLSCertificates(x, x)
				if err != nil || !reflect.DeepEqual(m, x) {
					t.Fatalf("MergeTLSCertificates(x,x) = (%+v, %v), want x unchanged", m, err)
				}
			},
			fold: func(t *testing.T) (any, any) {
				x := mustCert("*.example.com", []string{"a.example.com", "b.example.com"}, 1, provA)
				y := mustCert("", []string{"b.example.com", "c.example.com"}, 2, provB)
				m, err := MergeTLSCertificates(x, y)
				if err != nil {
					t.Fatalf("MergeTLSCertificates: %v", err)
				}
				return m, x
			},
			// Documented order-independence (distinct DiscoveredAt resolve
			// conflicts deterministically): merge(a,b) == merge(b,a).
			comm: func(t *testing.T) {
				x := mustCert("*.example.com", []string{"a.example.com", "b.example.com"}, 1, provA)
				y := mustCert("", []string{"b.example.com", "c.example.com"}, 2, provB)
				ab, err := MergeTLSCertificates(x, y)
				if err != nil {
					t.Fatalf("MergeTLSCertificates: %v", err)
				}
				ba, err := MergeTLSCertificates(y, x)
				if err != nil {
					t.Fatalf("MergeTLSCertificates: %v", err)
				}
				if !reflect.DeepEqual(ab, ba) {
					t.Fatalf("MergeTLSCertificates not order-independent:\n ab=%+v\n ba=%+v", ab, ba)
				}
			},
		},
		{
			name: "finding",
			id: func() string {
				f := mustFinding(0.5, []Evidence{mustEvidence("header:server", "nginx", provA)}, 1,
					map[string]string{"env": "lab"})
				return f.ID()
			},
			self: func(t *testing.T) {
				x := mustFinding(0.5, []Evidence{mustEvidence("header:server", "nginx", provA)}, 1,
					map[string]string{"env": "lab"})
				m, err := MergeFindings(x, x)
				if err != nil || !reflect.DeepEqual(m, x) {
					t.Fatalf("MergeFindings(x,x) = (%+v, %v), want x unchanged", m, err)
				}
			},
			fold: func(t *testing.T) (any, any) {
				x := mustFinding(0.5, []Evidence{mustEvidence("header:server", "nginx", provA)}, 1,
					map[string]string{"env": "lab"})
				y := mustFinding(0.9, []Evidence{
					mustEvidence("header:server", "nginx", provB),
					mustEvidence("html:generator_meta", "wordpress", provB),
				}, 2, map[string]string{"env": ""})
				m, err := MergeFindings(x, y)
				if err != nil {
					t.Fatalf("MergeFindings: %v", err)
				}
				return m, x
			},
			comm: func(t *testing.T) {
				x := mustFinding(0.5, []Evidence{mustEvidence("header:server", "nginx", provA)}, 1,
					map[string]string{"env": "lab"})
				y := mustFinding(0.9, []Evidence{mustEvidence("html:generator_meta", "wp", provB)}, 2, nil)
				ab, err := MergeFindings(x, y)
				if err != nil {
					t.Fatalf("MergeFindings: %v", err)
				}
				ba, err := MergeFindings(y, x)
				if err != nil {
					t.Fatalf("MergeFindings: %v", err)
				}
				if !reflect.DeepEqual(ab, ba) {
					t.Fatalf("MergeFindings not order-independent:\n ab=%+v\n ba=%+v", ab, ba)
				}
			},
		},
	}

	for _, p := range pairs {
		p := p
		t.Run(p.name, func(t *testing.T) {
			p.self(t)
			m12, x := p.fold(t)
			if got := propIdentityOf(m12); got.String() != p.id() {
				t.Fatalf("%s: merged identity %s, want %s", p.name, got, p.id())
			}
			// Stability: folding the result with an earlier operand is a
			// fixed point (merge(result, a) == result).
			if !propFoldStable(t, p.name, m12, x) {
				t.Fatalf("%s: merge(merge(x,y), x) != merge(x,y):\n got %+v", p.name, m12)
			}
			if p.comm != nil {
				p.comm(t)
			}
		})
	}
}

// propIdentityOf returns the Identity of a merged asset without reflection:
// every representative kind carries an Identity method.
func propIdentityOf(v any) Identity {
	switch a := v.(type) {
	case Domain:
		return a.Identity()
	case Host:
		return a.Identity()
	case URL:
		return a.Identity()
	case Parameter:
		return a.Identity()
	case TLSCertificate:
		return a.Identity()
	case Finding:
		return a.Identity()
	default:
		return Identity{}
	}
}

// propFoldStable applies the package's own Merge primitive for the value's
// dynamic kind: it dispatches on type so each branch can call the strongly
// typed MergeX(m12, x) and compare with DeepEqual.
func propFoldStable(t *testing.T, name string, m12, x any) bool {
	t.Helper()
	errEq := func(m any, err error) bool {
		if err != nil {
			t.Fatalf("%s: refold: %v", name, err)
		}
		return reflect.DeepEqual(m, m12)
	}
	switch a := m12.(type) {
	case Domain:
		return errEq(MergeDomains(a, x.(Domain)))
	case Host:
		return errEq(MergeHosts(a, x.(Host)))
	case URL:
		return errEq(MergeURLs(a, x.(URL)))
	case Parameter:
		return errEq(MergeParameters(a, x.(Parameter)))
	case TLSCertificate:
		return errEq(MergeTLSCertificates(a, x.(TLSCertificate)))
	case Finding:
		return errEq(MergeFindings(a, x.(Finding)))
	default:
		t.Fatalf("%s: unhandled kind %T", name, m12)
		return false
	}
}

// ---- dedup invariants -----------------------------------------------------

// TestPropertyDedupInvariants pins the deduplication contract:
//
//   - folding many observations of one asset through the merge primitive
//     never grows the identity set (it stays exactly one identity)
//   - first-seen wins deterministically (Original, observed-value order)
//   - bounded observation lists stay deduplicated and subset-closed
func TestPropertyDedupInvariants(t *testing.T) {
	t.Run("url_fold_single_identity_first_seen_wins", func(t *testing.T) {
		obs := []struct{ raw string }{
			{"https://first.example.com/path"},
			{"https://FIRST.example.com:443/path#frag-a"},
			{"https://first.example.com./path"},
			{"HTTPS://first.example.com/path#frag-b"},
			{"https://first.example.com/path#frag-c"},
		}
		acc, err := ParseURL(obs[0].raw, Provenance{Source: "s1", DiscoveredAt: fixedTime(1)})
		if err != nil {
			t.Fatalf("ParseURL: %v", err)
		}
		first := acc.Original
		for i, o := range obs[1:] {
			next, err := ParseURL(o.raw, Provenance{Source: "sx", DiscoveredAt: fixedTime(i + 2)})
			if err != nil {
				t.Fatalf("ParseURL(%q): %v", o.raw, err)
			}
			if next.Identity() != acc.Identity() {
				t.Fatalf("observation %q produced foreign identity %s", o.raw, next.ID())
			}
			acc, err = MergeURLs(acc, next)
			if err != nil {
				t.Fatalf("MergeURLs: %v", err)
			}
			if acc.Identity() != next.Identity() {
				t.Fatalf("fold grew identity set: %s != %s", acc.ID(), next.ID())
			}
		}
		if acc.Original != first {
			t.Errorf("first-seen Original lost: got %q, want %q", acc.Original, first)
		}
	})

	t.Run("parameter_values_union_dedup_order", func(t *testing.T) {
		provA := Provenance{Source: "sa", DiscoveredAt: fixedTime(1)}
		provB := Provenance{Source: "sb", DiscoveredAt: fixedTime(2)}
		x, err := NewParameter("session", "query", "v1", "src-a", fixedTime(1), provA)
		if err != nil {
			t.Fatalf("NewParameter: %v", err)
		}
		x, err = WithValue(x, "v2", "src-a", fixedTime(2))
		if err != nil {
			t.Fatalf("WithValue: %v", err)
		}
		y, err := NewParameter("session", "query", "v2", "src-b", fixedTime(3), provB)
		if err != nil {
			t.Fatalf("NewParameter: %v", err)
		}
		y, err = WithValue(y, "v3", "src-b", fixedTime(4))
		if err != nil {
			t.Fatalf("WithValue: %v", err)
		}
		m, err := MergeParameters(x, y)
		if err != nil {
			t.Fatalf("MergeParameters: %v", err)
		}
		want := []string{"v1", "v2", "v3"} // x's first-seen order, then y's new values
		if !reflect.DeepEqual(m.ObservedValues, want) {
			t.Errorf("ObservedValues = %v, want %v", m.ObservedValues, want)
		}
		if len(m.Sources) != 2 || m.Sources[0] != "src-a" || m.Sources[1] != "src-b" {
			t.Errorf("Sources = %v, want first-seen [src-a src-b]", m.Sources)
		}
		// Re-merging with x changes nothing (dedup is idempotent).
		m2, err := MergeParameters(m, x)
		if err != nil || !reflect.DeepEqual(m2, m) {
			t.Errorf("MergeParameters(m,x) = (%+v, %v), want m unchanged", m2, err)
		}
	})

	t.Run("certificate_dns_names_sorted_unique_subset", func(t *testing.T) {
		provA := Provenance{Source: "pa", DiscoveredAt: fixedTime(1)}
		provB := Provenance{Source: "pb", DiscoveredAt: fixedTime(2)}
		fp := strings.Repeat("cd", 32)
		build := func(names []string, p Provenance) TLSCertificate {
			c, err := NewTLSCertificate(fp, p)
			if err != nil {
				t.Fatalf("NewTLSCertificate: %v", err)
			}
			if names != nil {
				c, err = WithDNSNames(c, names)
				if err != nil {
					t.Fatalf("WithDNSNames: %v", err)
				}
			}
			return c
		}
		a := build([]string{"b.example.com", "a.example.com"}, provA)
		b := build([]string{"a.example.com", "c.example.com", "a.example.com"}, provB)
		m, err := MergeTLSCertificates(a, b)
		if err != nil {
			t.Fatalf("MergeTLSCertificates: %v", err)
		}
		want := []string{"a.example.com", "b.example.com", "c.example.com"} // sorted unique union
		if !reflect.DeepEqual(m.DNSNames, want) {
			t.Errorf("DNSNames = %v, want sorted unique union %v", m.DNSNames, want)
		}
		if m.DNSNamesTruncated {
			t.Errorf("union under the cap must not set DNSNamesTruncated")
		}
	})

	t.Run("finding_evidence_dedup_subset", func(t *testing.T) {
		provA := Provenance{Source: "fa", DiscoveredAt: fixedTime(1)}
		provB := Provenance{Source: "fb", DiscoveredAt: fixedTime(2)}
		src := func() Identity {
			h, err := NewHost("srv.example.com", provA)
			if err != nil {
				t.Fatalf("NewHost: %v", err)
			}
			return h.Identity()
		}()
		ev := func(indicator, value string, p Provenance) Evidence {
			e, err := NewEvidence(MethodHTML, indicator, value, src, p)
			if err != nil {
				t.Fatalf("NewEvidence: %v", err)
			}
			return e
		}
		build := func(evs []Evidence, at int) Finding {
			f, err := NewFinding(Finding{
				RuleID: "rule.dedup", RuleName: "Dedup Rule", Category: "test",
				Subject: src, Confidence: 0.5, Evidence: evs,
				Priority: "p3", Status: "new", Created: fixedTime(at),
			})
			if err != nil {
				t.Fatalf("NewFinding: %v", err)
			}
			return f
		}
		a := build([]Evidence{ev("html:form", "login", provA), ev("html:link", "reset", provA)}, 1)
		b := build([]Evidence{ev("html:link", "reset", provB), ev("html:meta", "csrf", provB)}, 2)
		m, err := MergeFindings(a, b)
		if err != nil {
			t.Fatalf("MergeFindings: %v", err)
		}
		union := map[string]struct{}{
			a.Evidence[0].ID(): {}, a.Evidence[1].ID(): {}, b.Evidence[1].ID(): {},
		}
		if len(m.Evidence) != len(union) {
			t.Errorf("merged evidence count = %d, want %d distinct union records", len(m.Evidence), len(union))
		}
		for _, e := range m.Evidence {
			if _, ok := union[e.ID()]; !ok {
				t.Errorf("merged evidence %s is outside the input union", e.ID())
			}
		}
	})
}
