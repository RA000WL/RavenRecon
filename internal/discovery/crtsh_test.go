package discovery

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeHTTP is a scripted httpDoer: canned crt.sh payloads without the
// network. It captures the request so tests pin the query shape and headers.
type fakeHTTP struct {
	t   *testing.T
	got *http.Request
	fn  func(*http.Request) (*http.Response, error)
}

func (f *fakeHTTP) Do(r *http.Request) (*http.Response, error) {
	f.got = r
	return f.fn(r)
}

func crtshJSONResponse(body string) *http.Response {
	return &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func crtshEnv() toolEnv {
	// Only name + clock: Discover/Detect never touch runner, lookup,
	// limits, or detectTimeout (no executable exists), so injecting them
	// here would imply seams the adapter does not have.
	return toolEnv{
		name: "crtsh",
		now:  func() time.Time { return fixedTime },
	}
}

// crtshSource builds the adapter under test; the fake client injects through
// the struct seam (same-package), mirroring how runner fakes inject via env.
func crtshSource(env toolEnv, client httpDoer) crtsh {
	env.name = "crtsh"
	return crtsh{env: env, client: client}
}

func TestCrtshName(t *testing.T) {
	c := crtsh{env: toolEnv{name: "crtsh"}}
	if c.Name() != "crtsh" {
		t.Fatalf("Name() = %q, want crtsh", c.Name())
	}
}

func TestCrtshDiscoverParses(t *testing.T) {
	const canned = `[{"name_value":"www.example.com"},` +
		`{"name_value":"*.mail.example.com"},` +
		`{"name_value":"shop.example.com\nshop.example.com"},` +
		`{"name_value":"evil.com"},` +
		`{"name_value":"justaword"}]`
	f := &fakeHTTP{t: t, fn: func(*http.Request) (*http.Response, error) {
		return crtshJSONResponse(canned), nil
	}}
	s := crtshSource(crtshEnv(), f)
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	// Request shape: crt.sh wildcard query for the target, JSON accepted.
	if f.got == nil {
		t.Fatal("fake client never called")
	}
	if got := f.got.URL.Query().Get("q"); got != "%.example.com" {
		t.Fatalf("q = %q, want %q (full URL %v)", got, "%.example.com", f.got.URL)
	}
	if got := f.got.URL.Query().Get("output"); got != "json" {
		t.Fatalf("output = %q, want json", got)
	}
	if got := f.got.Header.Get("Accept"); got != "application/json" {
		t.Fatalf("Accept = %q, want application/json", got)
	}
	// Exact hosts: plain, wildcard-stripped, and multiline-deduped —
	// sorted; out-of-scope and bare word excluded.
	want := []string{"mail.example.com", "shop.example.com", "www.example.com"}
	if !reflect.DeepEqual(names(dres.Hosts), want) {
		t.Fatalf("hosts = %v, want %v", names(dres.Hosts), want)
	}
	// Malformed: evil.com (out-of-scope) + justaword (NEW-130 dot-guard).
	if dres.Malformed != 2 {
		t.Fatalf("malformed = %d, want 2 (out-of-scope + bare word)", dres.Malformed)
	}
	if dres.Truncated {
		t.Fatal("unexpected truncation")
	}
	for _, h := range dres.Hosts {
		if !h.Prov.DiscoveredAt.Equal(fixedTime) {
			t.Fatalf("prov = %v, want %v", h.Prov.DiscoveredAt, fixedTime)
		}
		if h.Prov.Source != "crtsh" {
			t.Fatalf("prov source = %q, want crtsh", h.Prov.Source)
		}
	}
}

func TestCrtshDiscoverLoneObjectRejected(t *testing.T) {
	// Strict array-only: crt.sh always returns an array, so a lone object
	// is rejected rather than special-cased (single decode path).
	f := &fakeHTTP{t: t, fn: func(*http.Request) (*http.Response, error) {
		return crtshJSONResponse(`{"name_value":"solo.example.com"}`), nil
	}}
	s := crtshSource(crtshEnv(), f)
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err == nil {
		t.Fatal("expected an error for a lone-object body")
	}
	if !strings.Contains(err.Error(), "unexpected response shape") {
		t.Fatalf("err = %v, want unexpected-shape rejection", err)
	}
	if len(dres.Hosts) != 0 {
		t.Fatalf("hosts = %v, want zero on shape rejection", names(dres.Hosts))
	}
}

func TestCrtshWildcardCaseInsensitive(t *testing.T) {
	// crt.sh mirrors back mixed-case names; the "*." strip must not depend
	// on the wildcard's case.
	f := &fakeHTTP{t: t, fn: func(*http.Request) (*http.Response, error) {
		return crtshJSONResponse(`[{"name_value":"*.Example.COM"}]`), nil
	}}
	s := crtshSource(crtshEnv(), f)
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !reflect.DeepEqual(names(dres.Hosts), []string{"example.com"}) {
		t.Fatalf("hosts = %v, want [example.com]", names(dres.Hosts))
	}
	if dres.Malformed != 0 {
		t.Fatalf("malformed = %d, want 0", dres.Malformed)
	}
}

func TestCrtshDiscoverTruncatedMidObject(t *testing.T) {
	// Body cut mid-object (not just mid-array): the parsed prefix is kept
	// AND an error reports the truncation — never silently empty, never
	// silently complete.
	f := &fakeHTTP{t: t, fn: func(*http.Request) (*http.Response, error) {
		return crtshJSONResponse(`[{"name_value":"a.example.com"},{"name_value":"b.exa`), nil
	}}
	s := crtshSource(crtshEnv(), f)
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err == nil {
		t.Fatal("expected an error for JSON cut mid-object")
	}
	if !reflect.DeepEqual(names(dres.Hosts), []string{"a.example.com"}) {
		t.Fatalf("hosts = %v, want [a.example.com] prefix kept", names(dres.Hosts))
	}
}

func TestCrtshDiscoverMalformedJSONKeepsPrefix(t *testing.T) {
	// Body cut mid-array: the parsed prefix is kept AND an error reports
	// the truncation — never silently empty, never silently complete.
	f := &fakeHTTP{t: t, fn: func(*http.Request) (*http.Response, error) {
		return crtshJSONResponse(`[{"name_value":"a.example.com"},`), nil
	}}
	s := crtshSource(crtshEnv(), f)
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
	if !reflect.DeepEqual(names(dres.Hosts), []string{"a.example.com"}) {
		t.Fatalf("hosts = %v, want [a.example.com] prefix kept", names(dres.Hosts))
	}
}

func TestCrtshDiscoverClientError(t *testing.T) {
	boom := errors.New("dial: connection refused")
	f := &fakeHTTP{t: t, fn: func(*http.Request) (*http.Response, error) {
		return nil, boom
	}}
	s := crtshSource(crtshEnv(), f)
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err == nil {
		t.Fatal("expected an error for a failed request")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped %v", err, boom)
	}
	if len(dres.Hosts) != 0 {
		t.Fatalf("hosts = %v, want zero on transport failure", names(dres.Hosts))
	}
	if dres.Malformed != 0 {
		t.Fatalf("malformed = %d, want 0", dres.Malformed)
	}
}

func TestCrtshDiscoverNonOKStatus(t *testing.T) {
	f := &fakeHTTP{t: t, fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{
			Status:     "500 Internal Server Error",
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("boom")),
		}, nil
	}}
	s := crtshSource(crtshEnv(), f)
	if _, err := s.Discover(context.Background(), mustDomain(t, "example.com")); err == nil {
		t.Fatal("expected an error for a non-200 status")
	}
}

func TestCrtshDiscoverTruncated(t *testing.T) {
	// Oversized body: capped at 1 MiB, Truncated set. The capped prefix is
	// not valid JSON, so an error accompanies the flag (partial kept).
	f := &fakeHTTP{t: t, fn: func(*http.Request) (*http.Response, error) {
		return crtshJSONResponse(strings.Repeat("x", (1<<20)+64)), nil
	}}
	s := crtshSource(crtshEnv(), f)
	dres, err := s.Discover(context.Background(), mustDomain(t, "example.com"))
	if err == nil {
		t.Fatal("expected an error for an undecodable oversized body")
	}
	if !dres.Truncated {
		t.Fatal("expected Truncated for an oversized body")
	}
}

func TestCrtshDetect(t *testing.T) {
	s := crtshSource(crtshEnv(), &fakeHTTP{fn: func(*http.Request) (*http.Response, error) {
		return crtshJSONResponse(`[]`), nil
	}})
	d := s.Detect(context.Background())
	if d.Source != "crtsh" {
		t.Fatalf("Source = %q, want crtsh", d.Source)
	}
	if d.Status != StatusOK {
		t.Fatalf("Status = %v, want ok", d.Status)
	}
	if !d.Exists {
		t.Fatal("Exists = false, want true (no binary gates a network source)")
	}
	if !d.Capable {
		t.Fatal("Capable = false, want true")
	}
	if !strings.Contains(d.Reason, "crt.sh") || !strings.Contains(d.Reason, "Discover") {
		t.Fatalf("Reason = %q, want network-source note with Discover reachability", d.Reason)
	}
	// Synthetic stable cache identity (no upstream version exists): the
	// pipeline keys on a non-empty version, so this must never be "".
	if d.Version != crtshVersion {
		t.Fatalf("Version = %q, want synthetic %q", d.Version, crtshVersion)
	}
}

func TestCrtshRegistry(t *testing.T) {
	if _, ok := registry["crtsh"]; !ok {
		t.Fatal("registry missing crtsh")
	}
	// Opt-in like asnmap: selectable via --sources, never in the default set,
	// so the 4-source determinism pins stay intact.
	for _, n := range builtInNames() {
		if n == "crtsh" {
			t.Fatalf("builtInNames() = %v, crtsh must stay opt-in", builtInNames())
		}
	}
	src := registry["crtsh"](toolEnv{name: "crtsh"})
	if src.Name() != "crtsh" {
		t.Fatalf("registry-built Name() = %q, want crtsh", src.Name())
	}
}

func TestCrtshDiscoverCancelled(t *testing.T) {
	// A cancelled context surfaces through the transport as a context
	// error, and the pipeline classifies it as cancelled — never failed
	// with data loss, never completed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeHTTP{t: t, fn: func(r *http.Request) (*http.Response, error) {
		return nil, r.Context().Err()
	}}
	s := crtshSource(crtshEnv(), f)
	dres, err := s.Discover(ctx, mustDomain(t, "example.com"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want wrapped context.Canceled", err)
	}
	if got := classify(ctx, dres, err); got != OutCancelled {
		t.Fatalf("classify = %s, want cancelled", got)
	}
}

func TestCrtshProductionBounds(t *testing.T) {
	// Pin the production transport bounds: the default client carries the
	// 30s timeout and responses are capped at 1 MiB.
	if crtshMaxBody != 1<<20 {
		t.Fatalf("crtshMaxBody = %d, want 1 MiB", crtshMaxBody)
	}
	c := crtsh{env: toolEnv{name: "crtsh"}} // nil client: production path
	cl, ok := c.httpClient().(*http.Client)
	if !ok {
		t.Fatalf("httpClient() = %T, want *http.Client", c.httpClient())
	}
	if cl.Timeout != 30*time.Second {
		t.Fatalf("client timeout = %s, want 30s", cl.Timeout)
	}
}

func TestCrtshVersionBoundCacheKey(t *testing.T) {
	// MEDIUM pin: the synthetic version participates in the cache key, so
	// an adapter-contract bump misses instead of replaying stale parses.
	target := mustDomain(t, "example.com")
	src := registry["crtsh"](toolEnv{name: "crtsh"})
	det := src.Detect(context.Background())
	if det.Version == "" {
		t.Fatal("detection version must be non-empty (else runs bypass the cache)")
	}
	qc := NormalizeQualityConfig(QualityConfig{})
	k1, err := cacheKey(target, src, det, qc)
	if err != nil {
		t.Fatalf("cacheKey: %v", err)
	}
	det.Version = "crtsh-json-v2"
	k2, err := cacheKey(target, src, det, qc)
	if err != nil {
		t.Fatalf("cacheKey bumped: %v", err)
	}
	if k1 == k2 {
		t.Fatal("cache key unchanged across adapter versions: bumped contract would replay stale parses")
	}
}

func TestCrtshPipelineOptIn(t *testing.T) {
	// End-to-end opt-in: `--sources crtsh` selects the adapter through Run
	// with a fake transport (never live crt.sh). The versioned identity is
	// cacheable, so the completed run also stores exactly one record.
	const canned = `[{"name_value":"www.example.com"},` +
		`{"name_value":"*.mail.example.com"}]`
	calls := 0
	oldNew := crtshClientNew
	crtshClientNew = func() httpDoer {
		return &fakeHTTP{fn: func(*http.Request) (*http.Response, error) {
			calls++
			return crtshJSONResponse(canned), nil
		}}
	}
	defer func() { crtshClientNew = oldNew }()
	cfg := testConfig(&fakeRunner{}, newFakeLookup())
	cfg.Sources = []string{"crtsh"}
	fc := &fakeCache{}
	cfg.Cache = fc
	rep, err := Run(context.Background(), mustDomain(t, "example.com"), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1 (cache miss executes once)", calls)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("results = %d slots, want 1 (crtsh only)", len(rep.Results))
	}
	res := rep.Results[0]
	if res.Source != "crtsh" {
		t.Fatalf("source = %q, want crtsh", res.Source)
	}
	if res.Status != OutCompleted {
		t.Fatalf("status = %s, want completed (err %v)", res.Status, res.Err)
	}
	if res.Version != crtshVersion {
		t.Fatalf("version = %q, want %q", res.Version, crtshVersion)
	}
	if res.Cached {
		t.Fatal("Cached = true on a first-run miss")
	}
	if !reflect.DeepEqual(names(res.Hosts), []string{"mail.example.com", "www.example.com"}) {
		t.Fatalf("hosts = %v, want [mail.example.com www.example.com]", names(res.Hosts))
	}
	if got := fc.putCount(); got != 1 {
		t.Fatalf("cache puts = %d, want 1 (versioned crtsh runs store)", got)
	}
}
