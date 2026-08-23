package techintel

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

func TestPrepareObservationMalformed(t *testing.T) {
	now := fixedTime.Add(time.Minute)
	bad := func(o Observation) bool {
		_, _, err := prepareObservation(o, now)
		return err != nil
	}

	// Broken URL.
	o := Observation{URL: mustURL(t, "https://ok.example/"), Source: "t", ObservedAt: now}
	o.URL = asset.URL{} // zero URL is not canonical
	if !bad(o) {
		t.Error("zero URL should be malformed")
	}

	// Too many headers.
	o = newObs(t, "https://ok.example/")
	for i := 0; i <= maxObservationHeaders; i++ {
		o.Headers = append(o.Headers, HeaderEntry{Name: "X-H", Value: "v"})
	}
	if !bad(o) {
		t.Error("header overflow should be malformed")
	}

	// Endpoint whose URL disagrees with the observation URL.
	ep, err := asset.NewEndpoint("GET", "https://different.example/", asset.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	o = newObs(t, "https://ok.example/")
	o.Endpoint = &ep
	if !bad(o) {
		t.Error("endpoint URL mismatch should be malformed")
	}
}

func TestPrepareObservationBounds(t *testing.T) {
	now := fixedTime.Add(time.Minute)

	// Body over 1 MiB is truncated with the flag set.
	o := newObs(t, "https://ok.example/")
	o.Body = strings.Repeat("a", maxObservationBody+1)
	prepared, truncated, err := prepareObservation(o, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Body) != maxObservationBody {
		t.Errorf("body = %d, want %d", len(prepared.Body), maxObservationBody)
	}
	if !truncated {
		t.Error("body truncation not flagged")
	}

	// Oversized header value truncated.
	o = newObs(t, "https://ok.example/")
	o.Headers = []HeaderEntry{{Name: "X-Long", Value: strings.Repeat("b", maxHeaderValueBytes+100)}}
	prepared, _, err = prepareObservation(o, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Headers[0].Value) != maxHeaderValueBytes {
		t.Errorf("header value = %d, want %d", len(prepared.Headers[0].Value), maxHeaderValueBytes)
	}

	// Oversized cookie name/value truncated.
	o = newObs(t, "https://ok.example/")
	o.Cookies = []CookieEntry{{Name: strings.Repeat("n", maxCookieNameBytes+10), Value: strings.Repeat("v", maxCookieValueBytes+10)}}
	prepared, truncated, err = prepareObservation(o, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Cookies[0].Name) != maxCookieNameBytes {
		t.Errorf("cookie name = %d, want %d", len(prepared.Cookies[0].Name), maxCookieNameBytes)
	}
	if len(prepared.Cookies[0].Value) != maxCookieValueBytes {
		t.Errorf("cookie value = %d, want %d", len(prepared.Cookies[0].Value), maxCookieValueBytes)
	}
	if !truncated {
		t.Error("cookie truncation not flagged")
	}

	// TLS / DNS list bounds truncate and flag.
	o = newObs(t, "https://ok.example/")
	o.TLS = &TLSInfo{ALPN: []string{"h1", "h2", "h3"}}
	o.DNS = &DNSInfo{CNAMEChain: []string{"a", "b", "c"}}
	prepared, truncated, err = prepareObservation(o, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.TLS.ALPN) != 3 || len(prepared.DNS.CNAMEChain) != 3 || truncated {
		t.Fatalf("small TLS/DNS lists must pass through untouched (truncated=%v)", truncated)
	}
	o.TLS = &TLSInfo{ALPN: make([]string, maxTLSEntries+1)}
	o.DNS = &DNSInfo{CNAMEChain: make([]string, maxCNAMEChain+1)}
	prepared, truncated, err = prepareObservation(o, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.TLS.ALPN) != maxTLSEntries || len(prepared.DNS.CNAMEChain) != maxCNAMEChain || !truncated {
		t.Errorf("TLS/DNS lists must truncate to their caps with the flag set (alpn=%d chain=%d truncated=%v)",
			len(prepared.TLS.ALPN), len(prepared.DNS.CNAMEChain), truncated)
	}
}

// TestPrepareObservationRejectsOversizedCanonicalURL is the M1 regression
// test: a caller-composed observation whose canonical URL exceeds
// maxCanonicalURLLen (8 KiB, exactly asset.ParseURL's constructor cap) is
// REJECTED as malformed at ingest — counted, never analyzed. The
// defense-in-depth re-check runs BEFORE any re-parse, so an oversized
// canonical URL never reaches the parser. The boundary is pinned exactly: a
// canonical string of exactly maxCanonicalURLLen bytes passes ingest, one
// byte more is malformed.
func TestPrepareObservationRejectsOversizedCanonicalURL(t *testing.T) {
	now := fixedTime.Add(time.Minute)
	prefix := "https://ok.example/"

	// Constructor layer (authoritative): asset.ParseURL owns the bound on
	// RAW input and rejects anything beyond the shared 8 KiB cap outright.
	overRaw := prefix + strings.Repeat("a", maxCanonicalURLLen-len(prefix)+1)
	if _, err := asset.ParseURL(overRaw, asset.Provenance{}); err == nil {
		t.Fatal("asset.ParseURL must reject raw input beyond the shared 8 KiB cap")
	}

	// Ingest layer: a hand-built struct that skipped the constructor still
	// cannot enter analysis — the canonical-length re-check fires before any
	// parser work.
	u := asset.URL{Scheme: "https", HostPort: "ok.example", Path: "/" + strings.Repeat("a", 40<<10)}
	if n := len(u.String()); n <= maxCanonicalURLLen {
		t.Fatalf("fixture canonical URL = %d bytes, need > %d", n, maxCanonicalURLLen)
	}

	o := Observation{URL: u, Source: "test", ObservedAt: now}
	_, _, err := prepareObservation(o, now)
	if err == nil {
		t.Fatal("an observation with an oversized canonical URL must be rejected")
	}
	if !strings.Contains(err.Error(), "exceeding cap") ||
		!strings.Contains(err.Error(), fmt.Sprintf("%d", maxCanonicalURLLen)) {
		t.Errorf("error %q does not mention the %d-byte cap", err, maxCanonicalURLLen)
	}
	if _, _, err := prepareObservation(o, now); err == nil {
		t.Fatal("an oversized canonical URL must be rejected deterministically")
	}

	// Boundary: a canonical string of EXACTLY maxCanonicalURLLen bytes
	// passes ingest (the rejection is strictly > cap).
	atCap := prefix + strings.Repeat("b", maxCanonicalURLLen-len(prefix))
	uAt, err := asset.ParseURL(atCap, asset.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(uAt.String()); n != maxCanonicalURLLen {
		t.Fatalf("boundary fixture = %d bytes, want exactly %d", n, maxCanonicalURLLen)
	}
	if _, _, err := prepareObservation(Observation{URL: uAt, Source: "test", ObservedAt: now}, now); err != nil {
		t.Errorf("a canonical URL of exactly the cap must pass ingest: %v", err)
	}

	// One byte more is malformed. The raw form is refused by the
	// constructor; a hand-built struct with that canonical string is refused
	// by the ingest re-check.
	overCap := prefix + strings.Repeat("b", maxCanonicalURLLen-len(prefix)+1)
	if _, err := asset.ParseURL(overCap, asset.Provenance{}); err == nil {
		t.Error("asset.ParseURL must reject raw input one byte over the shared cap")
	}
	uOver := asset.URL{Scheme: "https", HostPort: "ok.example", Path: "/" + strings.Repeat("b", maxCanonicalURLLen-len(prefix)+1)}
	if _, _, err := prepareObservation(Observation{URL: uOver, Source: "test", ObservedAt: now}, now); err == nil {
		t.Error("a canonical URL one byte over the cap must be rejected")
	}
}

func TestPrepareObservationDefaults(t *testing.T) {
	now := fixedTime.Add(2 * time.Minute)
	o := newObs(t, "https://ok.example/")
	o.Source = ""
	o.ObservedAt = time.Time{}

	prepared, truncated, err := prepareObservation(o, now)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Source != defaultSourceName {
		t.Errorf("Source = %q, want default %q", prepared.Source, defaultSourceName)
	}
	if !prepared.ObservedAt.Equal(now) {
		t.Errorf("ObservedAt = %v, want filled %v", prepared.ObservedAt, now)
	}
	if truncated {
		t.Error("a small observation must not be flagged truncated")
	}
}

func TestSourcesMask(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Observation)
		want string
	}{
		{"empty", func(o *Observation) {}, ""},
		{"headers only", func(o *Observation) { o.Headers = []HeaderEntry{{Name: "X", Value: "y"}} }, "h"},
		{"body only", func(o *Observation) { o.Body = "x" }, "b"},
		{"cookies only", func(o *Observation) { o.Cookies = []CookieEntry{{Name: "c"}} }, "c"},
		{"tls only", func(o *Observation) { o.TLS = &TLSInfo{} }, "t"},
		{"dns only", func(o *Observation) { o.DNS = &DNSInfo{} }, "d"},
		{"endpoint only", func(o *Observation) {
			ep, err := asset.NewEndpoint("GET", o.URL.String(), asset.Provenance{})
			if err != nil {
				t.Fatal(err)
			}
			o.Endpoint = &ep
		}, "e"},
		{"all sorted", func(o *Observation) {
			o.Body = "x"
			o.Headers = []HeaderEntry{{Name: "X", Value: "y"}}
			o.Cookies = []CookieEntry{{Name: "c"}}
			o.TLS = &TLSInfo{}
			o.DNS = &DNSInfo{}
		}, "bcdht"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			o := newObs(t, "https://ok.example/")
			tt.mut(&o)
			if got := sourcesMask(o); got != tt.want {
				t.Errorf("sourcesMask = %q, want %q", got, tt.want)
			}
		})
	}

	// The status code is observation material, never part of the mask.
	a := newObs(t, "https://ok.example/")
	a.StatusCode = 200
	b := newObs(t, "https://ok.example/")
	b.StatusCode = 404
	if sourcesMask(a) != sourcesMask(b) {
		t.Error("status code must not enter the sources mask")
	}
}

// insertionSortMaskReference is the exact hand-rolled insertion sort that
// sourcesMask used before the L-11 cleanup. It stays here as the reference
// implementation the replacement's output is pinned against.
func insertionSortMaskReference(mask []byte) {
	for i := 1; i < len(mask); i++ {
		for j := i; j > 0 && mask[j] < mask[j-1]; j-- {
			mask[j], mask[j-1] = mask[j-1], mask[j]
		}
	}
}

// TestSourcesMaskMatchesInsertionReferenceOnAllSubsets proves the stdlib
// sort orders exactly like the old insertion sort: every one of the 2^6
// family-flag subsets is exercised (an exhaustive determinism pin, not a
// sample), with the reference fed the same unsorted h,b,c,t,d,e append order
// production uses.
func TestSourcesMaskMatchesInsertionReferenceOnAllSubsets(t *testing.T) {
	for subset := 0; subset < 1<<6; subset++ {
		o := newObs(t, "https://ok.example/")
		var raw []byte // production append order: h, b, c, t, d, e
		if subset&1 != 0 {
			o.Headers = []HeaderEntry{{Name: "X", Value: "y"}}
			raw = append(raw, 'h')
		}
		if subset&2 != 0 {
			o.Body = "x"
			raw = append(raw, 'b')
		}
		if subset&4 != 0 {
			o.Cookies = []CookieEntry{{Name: "c"}}
			raw = append(raw, 'c')
		}
		if subset&8 != 0 {
			o.TLS = &TLSInfo{}
			raw = append(raw, 't')
		}
		if subset&16 != 0 {
			o.DNS = &DNSInfo{}
			raw = append(raw, 'd')
		}
		if subset&32 != 0 {
			ep, err := asset.NewEndpoint("GET", o.URL.String(), asset.Provenance{})
			if err != nil {
				t.Fatal(err)
			}
			o.Endpoint = &ep
			raw = append(raw, 'e')
		}

		want := append([]byte(nil), raw...)
		insertionSortMaskReference(want)
		got := sourcesMask(o)
		if got != string(want) {
			t.Errorf("subset %#06b: sourcesMask = %q, insertion-sort reference = %q", subset, got, want)
		}
	}
}

func TestObservationIdentity(t *testing.T) {
	o := newObs(t, "https://ok.example/")
	if o.identity() != o.URL.Identity() {
		t.Error("URL-keyed observation identity must be the URL identity")
	}
	ep, err := asset.NewEndpoint("GET", "https://ok.example/", asset.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	o.Endpoint = &ep
	if o.identity() != ep.Identity() {
		t.Error("endpoint-keyed observation identity must be the endpoint identity")
	}
}

// NEW-83: ingest byte cuts are rune-safe — truncated body, header, and
// cookie values stay valid UTF-8 and survive a JSON round-trip unchanged.
func TestPrepareObservationTruncationRuneSafe(t *testing.T) {
	now := fixedTime.Add(time.Minute)

	o := newObs(t, "https://ok.example/")
	// Each oversized value ends in multi-byte runes so a raw cut at the cap
	// would tear one.
	o.Body = strings.Repeat("a", maxObservationBody-1) + strings.Repeat("é", 8)
	o.Headers = []HeaderEntry{{Name: "X-Long", Value: strings.Repeat("b", maxHeaderValueBytes-1) + strings.Repeat("é", 8)}}
	o.Cookies = []CookieEntry{
		{Name: strings.Repeat("n", maxCookieNameBytes-1) + "éé", Value: strings.Repeat("v", maxCookieValueBytes-1) + "éé"},
	}
	prepared, truncated, err := prepareObservation(o, now)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("truncation not flagged")
	}

	check := func(kind string, got string) {
		t.Helper()
		if !utf8.ValidString(got) {
			t.Errorf("%s is not valid UTF-8 after truncation", kind)
		}
		data, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("%s marshal: %v", kind, err)
		}
		var back string
		if err := json.Unmarshal(data, &back); err != nil || back != got {
			t.Errorf("%s JSON round-trip mismatch", kind)
		}
	}
	check("body", prepared.Body)
	if len(prepared.Body) > maxObservationBody {
		t.Errorf("body = %d bytes, want ≤ %d", len(prepared.Body), maxObservationBody)
	}
	for i, h := range prepared.Headers {
		check(fmt.Sprintf("header[%d]", i), h.Value)
		if len(h.Value) > maxHeaderValueBytes {
			t.Errorf("header[%d] = %d bytes, want ≤ %d", i, len(h.Value), maxHeaderValueBytes)
		}
	}
	for i, c := range prepared.Cookies {
		check(fmt.Sprintf("cookie[%d] name", i), c.Name)
		check(fmt.Sprintf("cookie[%d] value", i), c.Value)
	}
}
