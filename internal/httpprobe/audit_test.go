package httpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// probeOneDomain runs one Probe over the given server and host under an
// EXPLICIT declared domain, with the standard test routing: http probes to
// the given plain test server, https probes to a deterministic plain-HTTP
// responder (completed, ReasonTLS). probeOne hardcodes example.com; the
// scope-boundary regression tests need to drive the declared domain, which
// is a cache-key input and the redirect-scope boundary.
func probeOneDomain(t *testing.T, domain asset.Domain, srv *httptest.Server, hosts []asset.Host, cfg Config) Report {
	t.Helper()
	pr := newPlainResponder(t)
	cfg.Transport = schemeRouter{
		httpRT:  transportFor(t, srv),
		httpsRT: newTestTransport(pr.addr, nil),
	}
	rep, err := Probe(context.Background(), domain, hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return rep
}

// TestProbeSpoofTLSNoMisclassification is the M-1 spoof regression (a): a
// hostile server embeds "tls:" in bytes the stdlib quotes verbatim in its
// error text, and the REAL transport surfaces them. The pre-fix classifier
// matched error TEXT, so this fabricated a completed TLS observation
// (ProbeCompleted/ReasonTLS) — an open https port and a completed cache
// record the server could not actually serve. Classification is structural
// now: this error is no typed TLS error, so it must classify
// failed/other.
//
// Hostile bytes (empirically verified): the raw responder serves
//
//	"tls:fake\r\n"
//
// which is not a valid HTTP status line ("tls:fake" contains no space).
// net/http rejects it with badStringError — quoting the raw line with %q —
// and the real transport surfaces:
//
//	net/http: HTTP/1.x transport connection broken: malformed HTTP
//	response "tls:fake"
//
// whose text contains "tls:" — a text-matching classifier would
// misclassify this as a TLS handshake failure.
func TestProbeSpoofTLSNoMisclassification(t *testing.T) {
	rr := newRawResponder(t, "tls:fake\r\n")
	plain := newPlainResponder(t)

	cfg := testConfig()
	cfg.Transport = schemeRouter{
		httpRT:  newTestTransport(rr.addr, nil),
		httpsRT: newTestTransport(plain.addr, nil),
	}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")

	// Positive control: the https probe hits the deterministic plain-HTTP
	// responder, fails its handshake, and legitimately classifies
	// completed/ReasonTLS — exactly like probeOne's https probe.
	httpsPr := probeResultFor(hr, "https")
	if httpsPr.Status != ProbeCompleted || httpsPr.FailureReason != ReasonTLS {
		t.Fatalf("https probe = %+v (want completed tls)", httpsPr)
	}

	// The spoofed http probe must classify failed/other and have actually
	// executed — never completed/ReasonTLS (a TLS observation requires a
	// typed TLS failure, which a malformed status line is not).
	httpPr := probeResultFor(hr, "http")
	if httpPr.Status != ProbeFailed || httpPr.FailureReason != ReasonOther || !httpPr.Executed {
		t.Fatalf("http probe = %+v (want failed/other, executed; never completed/ReasonTLS)", httpPr)
	}
	// Prove the spoof worked: the surfaced error text contains "tls:", so
	// the pre-fix substring matcher would have misclassified this probe —
	// the test would fail against the pre-fix code.
	if httpPr.Err == nil {
		t.Fatal("http probe surfaced no error")
	}
	if !strings.Contains(httpPr.Err.Error(), "tls:") {
		t.Fatalf("http probe error %q does not contain the spoof text \"tls:\"; this test would not catch the pre-fix bug", httpPr.Err)
	}
}

// TestProbeSpoofHeaderCapNoMisclassification is the M-1 spoof regression
// (b): a hostile server embeds the exact words of the stdlib header-cap
// abort message in a malformed no-colon header line, and the REAL transport
// surfaces them (textproto rejects the line and quotes the raw server
// bytes). The pre-fix classifier matched "server response headers exceeded"
// as a substring, so this fabricated a truncated probe (ProbeTruncated).
// Classification is structural now: the header-cap abort is recognized only
// by EXACT equality with the stdlib-constructed message — "net/http: server
// response headers exceeded %d bytes; aborted" with OUR cap — so this
// spoofed error classifies failed/other.
//
// Hostile bytes (empirically verified): the raw responder serves
//
//	"HTTP/1.1 200 OK\r\n"
//	"server response headers exceeded 65536 bytes; aborted\r\n"
//	"\r\n"
//
// (the spoof line deliberately names OUR cap, 65536 = MaxHeaderBytes, so a
// substring matcher would have produced exactly the fabricated truncation).
// The line has no colon, so textproto rejects it and the real transport
// surfaces:
//
//	net/http: HTTP/1.x transport connection broken: malformed MIME
//	header: missing colon: "server response headers exceeded 65536
//	bytes; aborted"
//
// whose text contains the spoof string — a text-matching classifier would
// misclassify this as truncated.
func TestProbeSpoofHeaderCapNoMisclassification(t *testing.T) {
	rr := newRawResponder(t, "HTTP/1.1 200 OK\r\nserver response headers exceeded 65536 bytes; aborted\r\n\r\n")
	plain := newPlainResponder(t)

	cfg := testConfig()
	cfg.Transport = schemeRouter{
		httpRT:  newTestTransport(rr.addr, nil),
		httpsRT: newTestTransport(plain.addr, nil),
	}
	rep, err := Probe(context.Background(), mustDomain(t, "example.com"),
		[]asset.Host{mustHost(t, "www.example.com")}, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr := hostByName(t, rep, "www.example.com")

	// The https probe is the positive control, exactly as in
	// TestProbeSpoofTLSNoMisclassification.
	httpsPr := probeResultFor(hr, "https")
	if httpsPr.Status != ProbeCompleted || httpsPr.FailureReason != ReasonTLS {
		t.Fatalf("https probe = %+v (want completed tls)", httpsPr)
	}

	// The spoofed http probe must classify failed/other and have actually
	// executed — never ProbeTruncated: truncation requires the exact
	// stdlib abort message, which only the transport's own cap can
	// construct.
	httpPr := probeResultFor(hr, "http")
	if httpPr.Status != ProbeFailed || httpPr.FailureReason != ReasonOther || !httpPr.Executed {
		t.Fatalf("http probe = %+v (want failed/other, executed; never ProbeTruncated)", httpPr)
	}
	// Prove the spoof worked: the surfaced error text contains the spoof
	// string, so the pre-fix substring matcher would have misclassified
	// this probe — the test would fail against the pre-fix code.
	if httpPr.Err == nil {
		t.Fatal("http probe surfaced no error")
	}
	if !strings.Contains(httpPr.Err.Error(), "server response headers exceeded") {
		t.Fatalf("http probe error %q does not contain the spoof text \"server response headers exceeded\"; this test would not catch the pre-fix bug", httpPr.Err)
	}
}

// TestProbeCacheKeyIncludesDeclaredDomain pins the M-2 key shape: the
// declared domain is a cache-key input (the redirect scope boundary is part
// of the walk semantics), so the same target under different declared
// domains yields DIFFERENT keys, identical domains yield identical
// (deterministic) keys, and the domain is material to the key — a key
// without it (the pre-M-2 shape) differs.
func TestProbeCacheKeyIncludesDeclaredDomain(t *testing.T) {
	host := mustHost(t, "www.example.com")
	keyA := probeKeyFor(t, host, "http", mustDomain(t, "a.example.com"))
	keyB := probeKeyFor(t, host, "http", mustDomain(t, "example.com"))
	if keyA == keyB {
		t.Fatalf("keys equal for different declared domains: %s", keyA)
	}
	// Deterministic: the same inputs always produce the same key.
	if again := probeKeyFor(t, host, "http", mustDomain(t, "a.example.com")); again != keyA {
		t.Fatalf("key not deterministic: %s vs %s", again, keyA)
	}
	// Pin the exact key shape: the canonical payload carries the operation,
	// the probe target's canonical URL identity, and the declared domain in
	// Config. cache.Key itself is an opaque digest (no input bytes), so the
	// domain's presence is pinned through the KeyParts that must reproduce
	// the key exactly.
	want, err := cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    "url:http://www.example.com/",
		Config:    map[string]string{"domain": "a.example.com"},
	})
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if keyA != want {
		t.Fatalf("key = %s, want the pinned shape %s (operation %q, target %q, config domain)",
			keyA, want, Operation, "url:http://www.example.com/")
	}
	// The domain is material: a key built without it (the pre-M-2 shape)
	// must not collide with either domain-scoped key.
	noDomain, err := cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    "url:http://www.example.com/",
	})
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if noDomain == keyA || noDomain == keyB {
		t.Fatalf("key without the declared domain (%s) collides with a domain-scoped key", noDomain)
	}
}

// TestProbeScopeBroadeningNeverServedFromCache is the M-2 behavioral
// regression: a narrow-scope run (declared domain a.example.com) probes a
// target whose redirect walks out of that scope (the hop to b.example.com
// is observed, never followed; the probe completes on the 302). A later
// broader-scope run (declared domain example.com) against the SAME target
// and the SAME cache must NOT be served that scope-truncated record: the
// key includes the declared domain, so the broad run misses, re-executes,
// and follows the hop to its terminal 404.
func TestProbeScopeBroadeningNeverServedFromCache(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Location", "http://b.example.com/x")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(404)
	})

	cfg := testConfig()
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	host := mustHost(t, "a.example.com")
	hosts := []asset.Host{host}

	// Run 1 under the narrow domain: the hop to b.example.com is OUT of
	// a.example.com scope — observed, never requested; the 302 itself is
	// the terminal response. The record is stored under the narrow key.
	// probeOneDomain routes the http probe to the counting server and the
	// https probe to the deterministic plain responder.
	rep1 := probeOneDomain(t, mustDomain(t, "a.example.com"), cs.srv, hosts, cfg)
	pr1 := probeResultFor(hostByName(t, rep1, "a.example.com"), "http")
	if pr1.Status != ProbeCompleted || pr1.StatusCode != 302 || pr1.Cached {
		t.Fatalf("narrow run http probe = %+v (want fresh completed 302)", pr1)
	}
	if len(pr1.RedirectChain) != 1 || pr1.RedirectChain[0].InScope || pr1.RedirectChain[0].Followed ||
		pr1.RedirectChain[0].Target != "http://b.example.com/x" {
		t.Fatalf("narrow run chain = %+v (want one observed-not-followed out-of-scope hop)", pr1.RedirectChain)
	}
	out := cfg.Cache.Get(context.Background(), probeKeyFor(t, host, "http", mustDomain(t, "a.example.com")))
	if !out.IsHit() {
		t.Fatalf("narrow record state = %s, want hit under the narrow key", out.State)
	}
	if got := cs.requestCount(); got != 1 {
		t.Fatalf("narrow run requests = %d, want 1 (the out-of-scope hop is never requested)", got)
	}

	// Run 2 under the broad domain with the SAME cache: b.example.com IS in
	// scope, so the hop is followed to its terminal 404. The narrow record
	// sits under a different key (the domain is a key input), so the probe
	// re-executes instead of being served the scope-truncated walk.
	rep2 := probeOneDomain(t, mustDomain(t, "example.com"), cs.srv, hosts, cfg)
	pr2 := probeResultFor(hostByName(t, rep2, "a.example.com"), "http")
	if !pr2.Executed || pr2.Cached {
		t.Fatalf("broad run http probe = %+v (want a fresh execution, never a cache hit)", pr2)
	}
	if pr2.Status != ProbeCompleted || pr2.StatusCode != 404 {
		t.Fatalf("broad run http probe = %+v (want completed 404 at the followed hop)", pr2)
	}
	if len(pr2.RedirectChain) != 1 || !pr2.RedirectChain[0].InScope || !pr2.RedirectChain[0].Followed ||
		pr2.RedirectChain[0].Target != "http://b.example.com/x" {
		t.Fatalf("broad run chain = %+v (want one followed in-scope hop)", pr2.RedirectChain)
	}
	if pr2.FinalURL.String() != "http://b.example.com/x" {
		t.Fatalf("broad run final url = %q, want http://b.example.com/x", pr2.FinalURL.String())
	}
	// The broad run re-executed: the followed hop hit the server again. A
	// (wrong) cache hit would have served zero additional requests.
	if got := cs.requestCount(); got != 3 {
		t.Fatalf("total requests = %d, want 3 (narrow 302 + broad 302 + followed hop)", got)
	}
	// The broad run stored its own record under the broad key.
	if out := cfg.Cache.Get(context.Background(), probeKeyFor(t, host, "http", mustDomain(t, "example.com"))); !out.IsHit() {
		t.Fatalf("broad record state = %s, want hit under the broad key", out.State)
	}
}
