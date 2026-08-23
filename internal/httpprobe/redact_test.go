package httpprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/techintel"
	"github.com/RA000WL/RavenRecon/internal/techintel/fingerprints"
)

// TestRedactSetCookieValue pins the Set-Cookie retention transform: pair
// values are replaced with "[redacted]" (empty values stay empty), names and
// bare attributes survive byte-for-byte, and quoted ';' never tears a
// segment.
func TestRedactSetCookieValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"simple session cookie", "sessionid=SECRET123", "sessionid=[redacted]"},
		{
			"multi-pair single header value",
			"sid=abc; Path=/app; HttpOnly",
			"sid=[redacted]; Path=[redacted]; HttpOnly",
		},
		{
			"valued attributes redacted too",
			"sid=abc; Max-Age=3600; SameSite=Lax",
			"sid=[redacted]; Max-Age=[redacted]; SameSite=[redacted]",
		},
		{"empty value stays empty", "sid=", "sid="},
		{"empty value with attributes", "sid=; HttpOnly", "sid=; HttpOnly"},
		{"quoted value", `token="abc"`, "token=[redacted]"},
		{"quoted value with semicolon", `tok="a;b"; HttpOnly`, "tok=[redacted]; HttpOnly"},
		{"attribute-only untouched", "HttpOnly; Secure", "HttpOnly; Secure"},
		// The space after '=' belongs to the value span and is redacted
		// with it: everything from the first '=' on becomes exactly
		// "[redacted]" (the invariant storedSetCookieValuesRedacted checks).
		{"name spacing preserved", "sid = abc", "sid =[redacted]"},
		{"bare attribute only", "HttpOnly", "HttpOnly"},
		{"leading equals junk", "=xyz", "=[redacted]"},
		{"first equals splits", "a=b=c", "a=[redacted]"},
		{"empty input", "", ""},
		{
			"unbalanced quote swallows the rest",
			`a="x; HttpOnly`,
			"a=[redacted]",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactSetCookieValue(tc.in); got != tc.want {
				t.Fatalf("redactSetCookieValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestBoundedHeadersRedactsOnlySetCookie proves the transform is scoped to
// Set-Cookie inside boundedHeaders: other headers keep their values verbatim,
// Location keeps its own userinfo rule, and the observed header map is never
// mutated.
func TestBoundedHeadersRedactsOnlySetCookie(t *testing.T) {
	h := http.Header{}
	h["Set-Cookie"] = []string{"sessionid=SECRET123; HttpOnly", `tok="a;b"`}
	h.Set("Server", "unit-test")
	h.Set("X-Custom-Header", "keepme; token=untouched")
	h.Set("Location", "https://user:pass@example.com/next")

	before := map[string][]string{}
	for k, v := range h {
		before[k] = append([]string(nil), v...)
	}

	entries, truncated := boundedHeaders(h)
	if truncated {
		t.Fatal("boundedHeaders reported truncation for a small header block")
	}

	got := map[string][]string{}
	for _, e := range entries {
		got[e.Key] = e.Values
	}

	wantSetCookie := []string{
		// Values keep their original order under the key.
		"sessionid=[redacted]; HttpOnly",
		"tok=[redacted]",
	}
	requireEqualStrings(t, "Set-Cookie values", got["Set-Cookie"], wantSetCookie)

	if v := got["Server"]; len(v) != 1 || v[0] != "unit-test" {
		t.Fatalf("Server = %v, want [unit-test] (non-Set-Cookie headers untouched)", v)
	}
	if v := got["X-Custom-Header"]; len(v) != 1 || v[0] != "keepme; token=untouched" {
		t.Fatalf("X-Custom-Header = %v, want verbatim value", v)
	}
	if v := got["Location"]; len(v) != 1 || strings.Contains(v[0], "user:pass") {
		t.Fatalf("Location = %v, want userinfo-stripped value (existing rule unchanged)", v)
	}
	for k, want := range before {
		requireEqualStrings(t, "observed header "+k+" unmutated", h[k], want)
	}
}

// TestStoredSetCookieValuesRedacted pins the read-side compliance predicate.
func TestStoredSetCookieValuesRedacted(t *testing.T) {
	tests := []struct {
		name string
		vals []string
		want bool
	}{
		{"nil", nil, true},
		{"redacted pairs", []string{"sessionid=[redacted]; HttpOnly"}, true},
		{"empty value pair", []string{"sid="}, true},
		{"bare attributes only", []string{"HttpOnly; Secure"}, true},
		{"plain empty string", []string{""}, true},
		{"verbatim secret refused", []string{"sessionid=SECRET123; HttpOnly"}, false},
		{"verbatim attribute value refused", []string{"Path=/"}, false},
		{"one bad value among good ones", []string{"sid=[redacted]", "tok=abc"}, false},
		{"quoted verbatim refused", []string{`token="abc"`}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := storedSetCookieValuesRedacted(tc.vals); got != tc.want {
				t.Fatalf("storedSetCookieValuesRedacted(%q) = %v, want %v", tc.vals, got, tc.want)
			}
		})
	}
}

// TestDecodeStoredLiveRefusesUnredactedSetCookie is the live-record self-heal
// regression: a cached record written before Set-Cookie redaction still
// carries verbatim pair values and must be refused (deleted and recomputed),
// while a record written by the current writer decodes cleanly.
func TestDecodeStoredLiveRefusesUnredactedSetCookie(t *testing.T) {
	host := mustHost(t, "www.example.com")
	target := mustProbeURL(t, host, "http", newFakeClock(fixedTime))
	domain := mustDomain(t, "example.com")

	build := func(t *testing.T, setCookie []string) []byte {
		t.Helper()
		raw, err := json.Marshal(storedLive{
			Target:     target.String(),
			StatusCode: 200,
			Headers: []HeaderEntry{
				{Key: "Content-Type", Values: []string{"text/plain"}},
				{Key: setCookieHeader, Values: setCookie},
			},
		})
		if err != nil {
			t.Fatalf("marshal storedLive: %v", err)
		}
		return raw
	}

	if _, err := decodeStoredLive(build(t, []string{"sessionid=SECRET123; HttpOnly"}), target, domain); err == nil {
		t.Fatal("decodeStoredLive accepted a record with a verbatim Set-Cookie value")
	} else if !strings.Contains(err.Error(), "unredacted cookie values") {
		t.Fatalf("decodeStoredLive error = %v, want an unredacted-cookie refusal", err)
	}

	compliant := build(t, []string{"sessionid=[redacted]; HttpOnly", "sid="})
	s, err := decodeStoredLive(compliant, target, domain)
	if err != nil {
		t.Fatalf("decodeStoredLive rejected a redacted record: %v", err)
	}
	if v := s.Headers[1].Values; len(v) != 2 || v[0] != "sessionid=[redacted]; HttpOnly" || v[1] != "sid=" {
		t.Fatalf("decoded Set-Cookie values = %q, want the retained placeholders", v)
	}
}

// TestDecodeStoredProbeRefusesUnredactedSetCookie is the probe-record
// counterpart of the live-record self-heal above.
func TestDecodeStoredProbeRefusesUnredactedSetCookie(t *testing.T) {
	host := mustHost(t, "www.example.com")
	target := mustProbeURL(t, host, "http", newFakeClock(fixedTime))
	domain := mustDomain(t, "example.com")

	build := func(t *testing.T, setCookie []string) []byte {
		t.Helper()
		raw, err := json.Marshal(storedProbe{
			Target:     target.String(),
			Scheme:     "http",
			StatusCode: 200,
			FinalURL:   target,
			Headers: []HeaderEntry{
				{Key: setCookieHeader, Values: setCookie},
			},
			ResponseSize: 2,
		})
		if err != nil {
			t.Fatalf("marshal storedProbe: %v", err)
		}
		return raw
	}

	if _, err := decodeStoredProbe(build(t, []string{"sessionid=SECRET123; HttpOnly"}), target, "http", domain); err == nil {
		t.Fatal("decodeStoredProbe accepted a record with a verbatim Set-Cookie value")
	} else if !strings.Contains(err.Error(), "unredacted cookie values") {
		t.Fatalf("decodeStoredProbe error = %v, want an unredacted-cookie refusal", err)
	}

	if _, err := decodeStoredProbe(build(t, []string{"sessionid=[redacted]; HttpOnly"}), target, "http", domain); err != nil {
		t.Fatalf("decodeStoredProbe rejected a redacted record: %v", err)
	}
}

// TestProbeRecordRedactsSetCookieValues is the end-to-end proof: a canned
// loopback response carrying session cookies produces a probe report whose
// retained headers contain the placeholder — cookie names and bare
// attributes intact — and never the secret values.
func TestProbeRecordRedactsSetCookieValues(t *testing.T) {
	const (
		sessionSecret = "SECRET123"
		csrfSecret    = "BLAH42"
	)
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add(setCookieHeader, "sessionid="+sessionSecret+"; HttpOnly; Path=/")
		w.Header().Add(setCookieHeader, "csrftoken="+csrfSecret+"; Secure")
		w.Header().Set("Server", "unit-test")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	rep := probeOne(t, cs.srv, []asset.Host{mustHost(t, "www.example.com")}, testConfig())
	pr := probeResultFor(hostByName(t, rep, "www.example.com"), "http")
	if pr.Status != ProbeCompleted {
		t.Fatalf("http probe status = %s, want completed", pr.Status)
	}

	var setCookieVals []string
	serverSeen := ""
	for _, he := range pr.Headers {
		switch he.Key {
		case setCookieHeader:
			setCookieVals = append(setCookieVals, he.Values...)
		case "Server":
			if len(he.Values) == 1 {
				serverSeen = he.Values[0]
			}
		}
	}
	requireEqualStrings(t, "retained Set-Cookie values", setCookieVals, []string{
		// Insertion order is preserved under the key; every pair value is
		// the placeholder, every name and bare attribute survives.
		"sessionid=[redacted]; HttpOnly; Path=[redacted]",
		"csrftoken=[redacted]; Secure",
	})
	if serverSeen != "unit-test" {
		t.Fatalf("retained Server header = %q, want %q (other headers untouched)", serverSeen, "unit-test")
	}

	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	for _, secret := range []string{sessionSecret, csrfSecret} {
		if strings.Contains(string(blob), secret) {
			t.Fatalf("serialized report contains the secret %q", secret)
		}
	}
}

// TestRedactedSetCookiePreservesTechintelNameMatching is the techintel parity
// check: technology fingerprints key on cookie NAMES (__cf_bm, cf_clearance,
// PHPSESSID, sessionid, ...), so after boundedHeaders redaction a fingerprint
// whose ONLY indicator is a cookie name must still fire off the retained
// Set-Cookie header — and no evidence may carry the redacted secret.
func TestRedactedSetCookiePreservesTechintelNameMatching(t *testing.T) {
	const (
		fpName   = "test cookie mark"
		cookieNm = "__cf_bm"
		secret   = "SECRET123"
	)

	vals := redactSetCookieValues([]string{cookieNm + "=" + secret + "; HttpOnly; Secure"})
	db, err := fingerprints.CompileForTest([]fingerprints.Fingerprint{{
		Name:     fpName,
		Category: asset.CategoryCDN,
		Indicators: []fingerprints.Indicator{{
			Kind:   fingerprints.IndicatorCookie,
			Match:  cookieNm,
			Weight: 0.9,
		}},
	}})
	if err != nil {
		t.Fatalf("compile test fingerprints: %v", err)
	}

	cfg := techintel.DefaultConfig()
	cfg.DB = db
	cfg.Concurrency = 1
	cfg.QueueSize = 1

	host := mustHost(t, "www.example.com")
	target := mustProbeURL(t, host, "http", newFakeClock(fixedTime))
	hdrs := make([]techintel.HeaderEntry, 0, len(vals))
	for _, v := range vals {
		hdrs = append(hdrs, techintel.HeaderEntry{Name: setCookieHeader, Value: v})
	}
	obs := techintel.Observation{URL: target, StatusCode: 200, Headers: hdrs}

	rep, err := techintel.Ingest(context.Background(), cfg, &techintel.SliceObservationSource{obs})
	if err != nil {
		t.Fatalf("Ingest over redacted observation: %v", err)
	}
	if rep.Observations.Completed != 1 {
		t.Fatalf("observations completed = %+v, want exactly 1", rep.Observations)
	}

	techFound := false
	var nameMatched, httpOnlyFlag bool
	for _, tech := range rep.Technologies {
		if tech.Name == fpName && tech.Category == asset.CategoryCDN {
			techFound = true
		}
	}
	for _, ev := range rep.Evidence {
		if ev.Indicator == "cookie_flag:httponly" && ev.Value == cookieNm {
			httpOnlyFlag = true // preserved bare attribute fired on the name
		}
		if strings.HasPrefix(ev.Indicator, "cookie:") && ev.Value == cookieNm {
			nameMatched = true // the cookie-name indicator matched post-redaction
		}
	}
	if !techFound {
		t.Fatalf("technologies = %+v, want %q (cookie-name fingerprint must match post-redaction)", rep.Technologies, fpName)
	}
	if !nameMatched {
		t.Fatalf("evidence = %+v, want a cookie-name match on %q", rep.Evidence, cookieNm)
	}
	if !httpOnlyFlag {
		t.Fatalf("evidence = %+v, want cookie_flag:httponly evidence (bare attributes must survive redaction)", rep.Evidence)
	}

	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal techintel report: %v", err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatalf("techintel report carries the secret %q: %s", secret, blob)
	}
}
