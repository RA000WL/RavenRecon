package httpprobe

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// openTestCache opens a hermetic filesystem cache with an injectable clock.
// The clock function must be safe for concurrent use (the fake clock's Now
// is).
func openTestCache(t testing.TB, now func() time.Time, ttl time.Duration) *cache.FS {
	t.Helper()
	opts := []cache.Option{cache.WithClock(now)}
	if ttl > 0 {
		opts = append(opts, cache.WithTTL(ttl))
	}
	c, err := cache.Open(t.TempDir(), opts...)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	return c
}

// probeKeyFor builds the cache key of one scheme's probe target of a host.
func probeKeyFor(t testing.TB, host asset.Host, scheme string) cache.Key {
	t.Helper()
	u, err := probeTargetURL(host, scheme, newFakeClock(fixedTime))
	if err != nil {
		t.Fatalf("probeTargetURL: %v", err)
	}
	key, err := probeKey(u)
	if err != nil {
		t.Fatalf("probeKey: %v", err)
	}
	return key
}

// TestCacheHitServesZeroRequests verifies cache-before-execute end to end:
// the first run probes and stores completed records; the second run issues
// ZERO network requests and serves identical observations from cache —
// including the legitimate TLS-failure negative observation of the https
// probe.
func TestCacheHitServesZeroRequests(t *testing.T) {
	cs := newCountingServer(t, 200, "hello")
	cfg := testConfig()
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	hosts := []asset.Host{mustHost(t, "www.example.com")}

	rep1 := probeOne(t, cs.srv, hosts, cfg)
	if got := cs.requestCount(); got != 1 {
		t.Fatalf("first run requests = %d, want 1 (only the http probe reaches the plain server)", got)
	}
	if probeResultFor(hostByName(t, rep1, "www.example.com"), "http").Cached {
		t.Fatal("first run served a cache hit")
	}

	rep2 := probeOne(t, cs.srv, hosts, cfg)
	if got := cs.requestCount(); got != 1 {
		t.Fatalf("second run requests = %d, want 1 (unchanged: a cache hit performs zero requests)", got)
	}
	hr2 := hostByName(t, rep2, "www.example.com")
	httpPr := probeResultFor(hr2, "http")
	if !httpPr.Cached || httpPr.StatusCode != 200 || httpPr.ResponseSize != 5 || httpPr.TLS {
		t.Fatalf("second run http probe = %+v (want a completed cache hit)", httpPr)
	}
	httpsPr := probeResultFor(hr2, "https")
	if !httpsPr.Cached || httpsPr.FailureReason != ReasonTLS || httpsPr.StatusCode != 0 {
		t.Fatalf("second run https probe = %+v (want a cached tls negative)", httpsPr)
	}
}

// TestCacheMissStoresExactlyOneRequest verifies the miss side of
// cache-before-execute: exactly one request per probe target, then a
// completed record whose identity fields match the probe and whose payload
// round-trips the observation.
func TestCacheMissStoresExactlyOneRequest(t *testing.T) {
	cs := newCountingServer(t, 204, "")
	cfg := testConfig()
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	host := mustHost(t, "www.example.com")

	rep := probeOne(t, cs.srv, []asset.Host{host}, cfg)
	if got := cs.requestCount(); got != 1 {
		t.Fatalf("requests = %d, want 1 (miss: exactly one request for the http probe)", got)
	}
	pr := probeResultFor(hostByName(t, rep, "www.example.com"), "http")
	if pr.Status != ProbeCompleted || pr.StatusCode != 204 || pr.Cached {
		t.Fatalf("http probe = %+v", pr)
	}

	key := probeKeyFor(t, host, "http")
	out := cfg.Cache.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("record state = %s, want hit", out.State)
	}
	if out.Record.Status != cache.StatusCompleted || out.Record.Operation != Operation {
		t.Fatalf("record = %+v", out.Record)
	}
	if out.Record.Target != "url:http://www.example.com/" {
		t.Fatalf("record target = %q, want the canonical URL identity", out.Record.Target)
	}
	var st storedProbe
	if err := json.Unmarshal(out.Record.Data, &st); err != nil {
		t.Fatalf("unmarshal stored payload: %v", err)
	}
	if st.Target != "http://www.example.com/" || st.Scheme != "http" || st.StatusCode != 204 {
		t.Fatalf("stored payload = %+v", st)
	}
}

// TestCacheExpiry verifies TTL semantics through the injectable clock: an
// unexpired record is a zero-request hit; advancing the clock past the TTL
// makes the same target a miss again and the probe re-executes.
func TestCacheExpiry(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	clk := newFakeClock(fixedTime)
	cfg := testConfig()
	cfg.Clock = clk
	cfg.Cache = openTestCache(t, clk.Now, time.Hour)
	hosts := []asset.Host{mustHost(t, "www.example.com")}

	probeOne(t, cs.srv, hosts, cfg)
	first := cs.requestCount()
	if first != 1 {
		t.Fatalf("first run requests = %d, want 1", first)
	}

	// A hit before expiry serves without requests.
	probeOne(t, cs.srv, hosts, cfg)
	if got := cs.requestCount(); got != first {
		t.Fatalf("unexpired hit issued %d requests; want zero", got-first)
	}

	// Advance the clock past the TTL: the record is expired, the probe
	// re-executes.
	clk.advance(2 * time.Hour)
	probeOne(t, cs.srv, hosts, cfg)
	if got := cs.requestCount(); got != first*2 {
		t.Fatalf("expired run requests = %d -> %d, want full re-execution", first, got)
	}
}

// TestCacheFailedNeverServed verifies that a failed probe (here: DNS
// failure on both schemes) is stored failed and can never be served as a
// hit: the next run re-executes both probes.
func TestCacheFailedNeverServed(t *testing.T) {
	var calls atomic.Int64
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DisableKeepAlives = true
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}

	cfg := testConfig()
	cfg.Transport = tr
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	domain := mustDomain(t, "example.com")

	rep1, err := Probe(context.Background(), domain, hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if hr := hostByName(t, rep1, "www.example.com"); hr.Status != StatusFailed {
		t.Fatalf("first run status = %s, want failed", hr.Status)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("first run dials = %d, want 2 (http + https)", got)
	}

	// Second run: the failed records are not served; both probes execute
	// again.
	rep2, err := Probe(context.Background(), domain, hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr2 := hostByName(t, rep2, "www.example.com")
	for _, pr := range hr2.Probes {
		if pr.Cached {
			t.Fatalf("%s probe served from cache although the record is failed: %+v", pr.Scheme, pr)
		}
		if pr.Status != ProbeFailed {
			t.Fatalf("%s probe = %+v, want failed again", pr.Scheme, pr)
		}
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("second run dials = %d, want 4 (both probes re-executed)", got)
	}
}

// TestCacheTimeoutNeverServed verifies that a probe which timed out is
// stored failed and can never be served as a hit: the next run re-executes
// it.
func TestCacheTimeoutNeverServed(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // stall until the per-job deadline fires
	})
	cfg := testConfig()
	cfg.Timeout = 300 * time.Millisecond
	cfg.Transport = transportFor(t, cs.srv)
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	domain := mustDomain(t, "example.com")

	rep1, err := Probe(context.Background(), domain, hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if pr := probeResultFor(hostByName(t, rep1, "www.example.com"), "http"); pr.Status != ProbeFailed || pr.FailureReason != ReasonTimeout {
		t.Fatalf("first run http probe = %+v (want failed timeout)", pr)
	}
	// The https probe dials the plain-HTTP responder and never reaches this
	// server, so the timed-out http probe is the only request it serves.
	first := cs.requestCount()
	if first != 1 {
		t.Fatalf("first run requests = %d, want 1", first)
	}

	// Serve normally from now on; the second run must re-execute both
	// probes (the timed-out http record is never a hit).
	cs.setHandler(nil)
	rep2, err := Probe(context.Background(), domain, hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr2 := hostByName(t, rep2, "www.example.com")
	for _, pr := range hr2.Probes {
		if pr.Cached {
			t.Fatalf("%s probe served from cache although its record was failed: %+v", pr.Scheme, pr)
		}
		if pr.Status != ProbeCompleted {
			t.Fatalf("%s probe = %+v, want a fresh completed probe", pr.Scheme, pr)
		}
	}
	// The https probe targets the plain-HTTP responder and never reaches
	// this server, so only the re-executed http probe adds a request.
	if got := cs.requestCount(); got != first+1 {
		t.Fatalf("requests = %d -> %d, want %d (first run's timed-out request + the re-executed http probe)",
			first, got, first+1)
	}
}

// TestCacheCancelledNeverServed verifies that probes cancelled mid-flight
// are stored cancelled and can never be served as hits: the next run
// re-executes them.
func TestCacheCancelledNeverServed(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cs.setFirstHook(cancel) // cancel the run when the first request lands

	cfg := testConfig()
	cfg.Transport = transportFor(t, cs.srv)
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	domain := mustDomain(t, "example.com")

	if _, err := Probe(ctx, domain, hosts, nil, cfg); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	first := cs.requestCount()
	if first != 1 {
		t.Fatalf("cancelled run requests = %d, want 1", first)
	}

	// Serve normally from now on; the second run must re-execute both
	// probes (the cancelled records are never hits).
	cs.setHandler(nil)
	rep2, err := Probe(context.Background(), domain, hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	hr2 := hostByName(t, rep2, "www.example.com")
	for _, pr := range hr2.Probes {
		if pr.Cached {
			t.Fatalf("%s probe served from cache although its record was cancelled: %+v", pr.Scheme, pr)
		}
		if pr.Status != ProbeCompleted {
			t.Fatalf("%s probe = %+v, want a fresh completed probe", pr.Scheme, pr)
		}
	}
	// The https probe targets the plain-HTTP responder and never reaches
	// this server, so only the re-executed http probe adds a request.
	if got := cs.requestCount(); got != first+1 {
		t.Fatalf("requests = %d -> %d, want %d (first run's cancelled request + the re-executed http probe)",
			first, got, first+1)
	}
}

// TestCacheTruncatedNeverServed verifies that a probe which hit a hard cap
// (here: the body cap) is stored incomplete and can never be served as a
// hit: the next run re-executes it.
func TestCacheTruncatedNeverServed(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	body := make([]byte, MaxBodyBytes+4096)
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(body)
	})
	cfg := testConfig()
	cfg.Transport = transportFor(t, cs.srv)
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	hosts := []asset.Host{mustHost(t, "www.example.com")}
	domain := mustDomain(t, "example.com")

	rep1, err := Probe(context.Background(), domain, hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	pr1 := probeResultFor(hostByName(t, rep1, "www.example.com"), "http")
	if pr1.Status != ProbeTruncated || !pr1.Truncated || pr1.ResponseSize != MaxBodyBytes {
		t.Fatalf("first run http probe = %+v (want truncated at the body cap)", pr1)
	}
	out := cfg.Cache.Get(context.Background(), probeKeyFor(t, mustHost(t, "www.example.com"), "http"))
	if out.State != cache.StateIncomplete {
		t.Fatalf("truncated record state = %s, want incomplete", out.State)
	}
	if out.Record.Status != cache.StatusIncomplete {
		t.Fatalf("truncated record status = %q, want incomplete", out.Record.Status)
	}

	rep2, err := Probe(context.Background(), domain, hosts, nil, cfg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	pr2 := probeResultFor(hostByName(t, rep2, "www.example.com"), "http")
	if pr2.Cached || pr2.Status != ProbeTruncated {
		t.Fatalf("second run http probe = %+v (want re-executed truncated, never served)", pr2)
	}
}

// TestCacheTamperedRecordSelfHeals verifies the decode validation: a
// tampered completed record — payload contradicting its key, an out-of-range
// status, a truncated flag on a completed record, a non-canonical URL, a
// contradictory terminal redirect, or credentials smuggled in a URL's
// original form — is refused, deleted, and recomputed in the same run; the
// tampered observation is never served and never wedges the probe.
func TestCacheTamperedRecordSelfHeals(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cfg := testConfig()
	c := openTestCache(t, func() time.Time { return fixedTime }, 0)
	cfg.Cache = c
	host := mustHost(t, "www.example.com")
	hosts := []asset.Host{host}

	probeOne(t, cs.srv, hosts, cfg)
	key := probeKeyFor(t, host, "http")
	out := c.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("record state = %s, want hit", out.State)
	}

	tamperAndRerun := func(t *testing.T, name string, mutate func(*storedProbe)) {
		t.Helper()
		var st storedProbe
		if err := json.Unmarshal(out.Record.Data, &st); err != nil {
			t.Fatalf("unmarshal stored payload: %v", err)
		}
		mutate(&st)
		data, err := json.Marshal(st)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rec := *out.Record
		rec.Data = data
		rec.Status = cache.StatusCompleted
		if err := c.Put(context.Background(), key, rec); err != nil {
			t.Fatalf("Put tampered record: %v", err)
		}

		before := cs.requestCount()
		rep2 := probeOne(t, cs.srv, hosts, cfg)
		pr2 := probeResultFor(hostByName(t, rep2, "www.example.com"), "http")
		if pr2.Cached {
			t.Fatalf("%s: tampered record was served as a hit: %+v", name, pr2)
		}
		if got := cs.requestCount(); got != before+1 {
			t.Fatalf("%s: requests = %d -> %d, want exactly the http probe re-executed", name, before, got)
		}
		// The tampered record was deleted and replaced by a fresh one.
		fresh := c.Get(context.Background(), key)
		if !fresh.IsHit() {
			t.Fatalf("%s: healed record state = %s, want hit", name, fresh.State)
		}
	}

	tamperAndRerun(t, "wrong target identity", func(st *storedProbe) {
		st.Target = "http://www.example.com/other"
	})
	tamperAndRerun(t, "out-of-range status", func(st *storedProbe) {
		st.StatusCode = 999
	})
	tamperAndRerun(t, "truncated flag inconsistency", func(st *storedProbe) {
		st.Truncated = true
	})
	tamperAndRerun(t, "non-canonical final url", func(st *storedProbe) {
		st.FinalURL = asset.URL{Scheme: "http", HostPort: "WWW.Example.com", Path: "/x"}
	})
	tamperAndRerun(t, "terminal redirect with location", func(st *storedProbe) {
		st.StatusCode = 302
		st.Redirects = []RedirectHop{{
			Target:  "http://www.example.com/a",
			URL:     mustParseURL(t, "http://www.example.com/a"),
			InScope: true, Followed: true,
		}}
		st.FinalURL = mustParseURL(t, "http://www.example.com/a")
		st.Headers = []HeaderEntry{{Key: "Location", Values: []string{"http://www.example.com/a"}}}
	})
	tamperAndRerun(t, "credentials in final url original", func(st *storedProbe) {
		st.FinalURL = mustParseURL(t, "http://user:supersecret@www.example.com/x")
	})
}

// TestDecodeRejectsStoredUserinfo pins the decode-side credential defense
// directly: a stored record whose URL assets carry userinfo in Original
// (for example written by a pre-redaction build of this pipeline) is
// refused and can never be served as a hit.
func TestDecodeRejectsStoredUserinfo(t *testing.T) {
	domain := mustDomain(t, "example.com")
	target := mustParseURL(t, "http://www.example.com/")
	for _, tc := range []struct {
		name string
		st   storedProbe
	}{
		{
			name: "final url",
			st: storedProbe{
				Target: target.String(), Scheme: "http", StatusCode: 200,
				FinalURL: mustParseURL(t, "http://user:supersecret@www.example.com/"),
			},
		},
		{
			name: "redirect hop",
			st: storedProbe{
				Target: target.String(), Scheme: "http", StatusCode: 200,
				FinalURL: target,
				Redirects: []RedirectHop{{
					Target:  "http://www.example.com/a",
					URL:     mustParseURL(t, "http://user:supersecret@www.example.com/a"),
					InScope: true, Followed: true,
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.st)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := decodeStoredProbe(data, target, "http", domain); err == nil {
				t.Fatal("decode accepted a stored URL carrying credentials")
			}
		})
	}
}

// TestCacheTerminalRedirectWithoutLocationServed is the MEDIUM-4 regression:
// a probe that followed in-scope hops and then received a terminal 3xx
// WITHOUT a Location header is a legitimate completed observation (Go client
// semantics: a 3xx without Location is terminal). Its stored record must be
// served as a zero-request hit on the next run — never rejected, deleted,
// and re-probed forever.
func TestCacheTerminalRedirectWithoutLocationServed(t *testing.T) {
	cs := newCountingServer(t, 200, "ok")
	cs.setHandler(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Location", "/a")
			w.WriteHeader(302)
		case "/a":
			w.WriteHeader(301) // terminal: NO Location header
		default:
			w.WriteHeader(404)
		}
	})

	cfg := testConfig()
	cfg.Cache = openTestCache(t, func() time.Time { return fixedTime }, 0)
	hosts := []asset.Host{mustHost(t, "www.example.com")}

	rep1 := probeOne(t, cs.srv, hosts, cfg)
	pr1 := probeResultFor(hostByName(t, rep1, "www.example.com"), "http")
	if pr1.Status != ProbeCompleted || pr1.StatusCode != 301 {
		t.Fatalf("first run http probe = %+v (want completed 301)", pr1)
	}
	if len(pr1.RedirectChain) != 1 || !pr1.RedirectChain[0].Followed {
		t.Fatalf("chain = %+v, want one followed hop", pr1.RedirectChain)
	}
	if pr1.FinalURL.String() != "http://www.example.com/a" {
		t.Fatalf("final url = %q, want /a", pr1.FinalURL.String())
	}
	if got := cs.requestCount(); got != 2 {
		t.Fatalf("first run requests = %d, want 2 (the followed hop)", got)
	}

	// Second run: the completed 301-no-Location observation must be served
	// from cache with ZERO network requests.
	rep2 := probeOne(t, cs.srv, hosts, cfg)
	hr2 := hostByName(t, rep2, "www.example.com")
	pr2 := probeResultFor(hr2, "http")
	if !pr2.Cached || pr2.Status != ProbeCompleted || pr2.StatusCode != 301 {
		t.Fatalf("second run http probe = %+v (want a completed cache hit)", pr2)
	}
	if pr2.FinalURL.String() != "http://www.example.com/a" || len(pr2.RedirectChain) != 1 {
		t.Fatalf("cached observation = %+v, want the stored chain and final url", pr2)
	}
	if got := cs.requestCount(); got != 2 {
		t.Fatalf("second run requests = %d, want 2 (unchanged: zero requests on hits)", got)
	}
}
