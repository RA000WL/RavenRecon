package jsintel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// fixedTime is the deterministic provenance timestamp used by tests.
var fixedTime = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

// fakeClock is a deterministic runtime.Clock. It starts at fixedTime and only
// advances when advance is called. After timers fire when advance passes
// their target, matching the runtime limiter's expectations.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters map[chan time.Time]time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start, waiters: make(map[chan time.Time]time.Time)}
}

// Now implements runtime.Clock.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After implements runtime.Clock.
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.waiters[ch] = c.now.Add(d)
	return ch
}

// advance moves the clock forward by d and fires every After timer whose
// target has been reached.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for ch, target := range c.waiters {
		if !target.After(c.now) {
			ch <- c.now
			delete(c.waiters, ch)
		}
	}
}

var _ runtime.Clock = (*fakeClock)(nil)

// openTestCache opens a fresh filesystem-backed cache in a temp directory.
func openTestCache(t *testing.T) *cache.FS {
	t.Helper()
	c, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("cache open: %v", err)
	}
	return c
}

// cacheFetchConfig returns the config used by the cache tests: a hermetic
// transport for srv, one explicit retry, and no pacing.
func cacheFetchConfig(t *testing.T, srv *httptest.Server) FetchConfig {
	t.Helper()
	cfg := testFetchConfig()
	cfg.Transport = transportFor(t, srv)
	return cfg
}

// fetchAndStore runs the full cache-before-execute write path for one URL
// (miss): fetch, then store.
func fetchAndStore(t *testing.T, ctx context.Context, cfg FetchConfig, c cache.Cache, clock runtime.Clock, u asset.URL) (FetchResult, error) {
	t.Helper()
	res := fetchOrTimeout(t, ctx, cfg, u)
	if err := storeFetch(ctx, cfg, c, clock, res, []string{"test-source"}, time.Time{}, time.Time{}); err != nil {
		return res, err
	}
	return res, nil
}

func TestCacheRoundTrip(t *testing.T) {
	body := []byte("var app = {x: 1};\n")
	lm := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("ETag", `"v7"`)
		w.Header().Set("Last-Modified", lm.Format(http.TimeFormat))
		w.Header().Set("X-SourceMap", "/app.js.map")
		w.Write(body)
	})
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	counting := countingRT{inner: transportFor(t, srv.srv)}
	cfg := cacheFetchConfig(t, srv.srv)
	cfg.Transport = &counting
	u := mustURL(t, srv.url()+"/app.js")

	fresh, err := fetchAndStore(t, context.Background(), cfg, c, clock, u)
	if err != nil {
		t.Fatalf("storeFetch: %v", err)
	}
	if counting.calls() != 1 {
		t.Fatalf("requests after miss+store = %d, want 1", counting.calls())
	}

	lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source")
	if !lu.Hit {
		t.Fatalf("lookup = hit false (err %v), want a hit", lu.Err)
	}
	if lu.Err != nil {
		t.Fatalf("lookup err = %v, want nil", lu.Err)
	}
	hit := lu.Result
	// Fresh-vs-cached equality: byte-identical content, hash, and metadata.
	if !bytes.Equal(hit.Content, fresh.Content) {
		t.Errorf("cached content differs from fresh content")
	}
	if hit.Hash != fresh.Hash {
		t.Errorf("cached hash = %s, want %s", hit.Hash, fresh.Hash)
	}
	if hit.Size != fresh.Size || hit.StatusCode != fresh.StatusCode || hit.Redirects != fresh.Redirects {
		t.Errorf("cached size/status/redirects = %d/%d/%d, want %d/%d/%d",
			hit.Size, hit.StatusCode, hit.Redirects, fresh.Size, fresh.StatusCode, fresh.Redirects)
	}
	if hit.ContentType != fresh.ContentType || hit.ETag != fresh.ETag ||
		hit.XSourceMap != fresh.XSourceMap || hit.ContentLength != fresh.ContentLength {
		t.Errorf("cached metadata differs from fresh metadata")
	}
	if !hit.LastModified.Equal(fresh.LastModified) {
		t.Errorf("cached last modified = %v, want %v", hit.LastModified, fresh.LastModified)
	}
	if hit.FinalURL.String() != fresh.FinalURL.String() {
		t.Errorf("cached final url = %s, want %s", hit.FinalURL.String(), fresh.FinalURL.String())
	}
	if hit.Status != FetchCompleted || hit.Reason != ReasonNone || hit.Err != nil {
		t.Errorf("cached status/reason/err = %s/%s/%v, want completed/none/nil", hit.Status, hit.Reason, hit.Err)
	}
	if !lu.FirstSeen.Equal(fixedTime) || !lu.LastSeen.Equal(fixedTime) {
		t.Errorf("window = %v..%v, want %v..%v", lu.FirstSeen, lu.LastSeen, fixedTime, fixedTime)
	}
	// The hit performed ZERO network requests.
	if counting.calls() != 1 {
		t.Errorf("requests after hit = %d, want 1 (a hit performs zero requests)", counting.calls())
	}
	// The hit was served by the cache: the entry exists as a completed
	// record for the exact key.
	key, err := fetchKey(u)
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}
	if out := c.Get(context.Background(), key); !out.IsHit() {
		t.Errorf("cache state = %v, want hit", out.State)
	}
}

func TestCacheHitPerformsZeroLimiterWaits(t *testing.T) {
	// Deterministic ordering proof: the bucket holds exactly one token. The
	// miss consumes it; a cache hit must NOT wait for a refill (~1 s at
	// rate 1/s), while a subsequent miss must. Margins are generous so a
	// loaded machine cannot flip the result.
	limiter, err := runtime.NewLimiter(1, 1)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("body-" + r.URL.Path))
	})
	c := openTestCache(t)
	cfg := cacheFetchConfig(t, srv.srv)
	cfg.Limiter = limiter
	clock := newFakeClock(fixedTime)

	ua := mustURL(t, srv.url()+"/a.js")
	ub := mustURL(t, srv.url()+"/b.js")
	if _, err := fetchAndStore(t, context.Background(), cfg, c, clock, ua); err != nil {
		t.Fatalf("miss fetch: %v", err)
	}
	// The lookup happens BEFORE any limiter wait: with the bucket depleted
	// the hit must still return immediately.
	start := time.Now()
	lu := lookupFetch(context.Background(), ua, cfg, c, clock, "test-source")
	hitElapsed := time.Since(start)
	if !lu.Hit {
		t.Fatalf("lookup = hit false (err %v), want a hit", lu.Err)
	}
	if hitElapsed > 400*time.Millisecond {
		t.Errorf("cache hit took %v; a hit performs zero limiter waits (refill would take ~1s)", hitElapsed)
	}
	// Control: the bucket is genuinely depleted, so the next MISS must wait
	// for the refill — proving the hit above was served without a token.
	start = time.Now()
	res := fetchOrTimeout(t, context.Background(), cfg, ub)
	missElapsed := time.Since(start)
	if res.Status != FetchCompleted {
		t.Fatalf("control fetch status = %s, want completed", res.Status)
	}
	if missElapsed < 700*time.Millisecond {
		t.Errorf("control miss took %v; want >= 700ms (bucket depleted, refill ~1s)", missElapsed)
	}
}

func TestCacheMissExecutesOnceAndRefetchesAfterDelete(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("once"))
	})
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	counting := countingRT{inner: transportFor(t, srv.srv)}
	cfg := cacheFetchConfig(t, srv.srv)
	cfg.Transport = &counting
	u := mustURL(t, srv.url()+"/once.js")

	if _, err := fetchAndStore(t, context.Background(), cfg, c, clock, u); err != nil {
		t.Fatalf("storeFetch: %v", err)
	}
	if lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source"); !lu.Hit {
		t.Fatalf("lookup = hit false, want a hit")
	}
	if counting.calls() != 1 {
		t.Fatalf("requests = %d, want 1", counting.calls())
	}

	// Delete the entry: the next lookup misses and the fetch executes once
	// more.
	key, err := fetchKey(u)
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}
	if err := c.Delete(context.Background(), key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source"); lu.Hit {
		t.Fatalf("lookup after delete = hit, want miss")
	}
	if _, err := fetchAndStore(t, context.Background(), cfg, c, clock, u); err != nil {
		t.Fatalf("storeFetch after delete: %v", err)
	}
	if counting.calls() != 2 {
		t.Errorf("requests = %d, want 2 (refetch after delete)", counting.calls())
	}
}

// TestCacheTamperTable writes a valid completed record, mutates one field in
// its payload, and asserts the lookup rejects and deletes it (self-healing),
// so a tampered record is never served as a hit.
func TestCacheTamperTable(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var t = 1;"))
	})
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	cfg := cacheFetchConfig(t, srv.srv)
	u := mustURL(t, srv.url()+"/tamper.js")
	key, err := fetchKey(u)
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}

	// The valid base record every mutation starts from.
	if _, err := fetchAndStore(t, context.Background(), cfg, c, clock, u); err != nil {
		t.Fatalf("base storeFetch: %v", err)
	}
	baseOut := c.Get(context.Background(), key)
	if !baseOut.IsHit() {
		t.Fatalf("base record: state %v, want hit", baseOut.State)
	}
	var base storedFetch
	if err := json.Unmarshal(baseOut.Record.Data, &base); err != nil {
		t.Fatalf("decode base: %v", err)
	}

	hex64 := strings.Repeat("ab", 32)
	otherHash := sha256.Sum256([]byte("other content"))

	cases := []struct {
		name   string
		mutate func(*storedFetch)
	}{
		{"wrong target", func(s *storedFetch) { s.Target = "url:http://other.example/x.js" }},
		{"truncated with content", func(s *storedFetch) { s.Truncated = true; s.Content = []byte("x") }},
		{"truncated with hash", func(s *storedFetch) { s.Truncated = true; s.Hash = hex64 }},
		{"completed negative with content", func(s *storedFetch) { s.Reason = "conn_refused"; s.Content = []byte("x"); s.Size = 1 }},
		{"bad hash form", func(s *storedFetch) { s.Hash = "not-hex!" }},
		{"hash without content", func(s *storedFetch) { s.Hash = hex64; s.Content = nil; s.Size = 0 }},
		{"hash mismatch", func(s *storedFetch) { s.Hash = hex.EncodeToString(otherHash[:]) }},
		{"size mismatch", func(s *storedFetch) { s.Size++ }},
		{"oversized content", func(s *storedFetch) {
			s.Content = bytes.Repeat([]byte("x"), maxStoredContent+1)
			s.Size = int64(len(s.Content))
		}},
		{"inverted timestamps", func(s *storedFetch) { s.LastSeen = s.FirstSeen.Add(-time.Hour) }},
		{"zero timestamps", func(s *storedFetch) { s.LastSeen = time.Time{} }},
		{"oversized content type", func(s *storedFetch) { s.ContentType = strings.Repeat("a", maxContentTypeBytes+1) }},
		{"non-printable content type", func(s *storedFetch) { s.ContentType = "app\x01lication" }},
		{"oversized etag", func(s *storedFetch) { s.ETag = strings.Repeat("e", maxETagBytes+1) }},
		{"oversized x-source-map", func(s *storedFetch) { s.XSourceMap = strings.Repeat("m", maxSourceMapBytes+1) }},
		{"unknown reason", func(s *storedFetch) { s.Reason = "bogus" }},
		{"empty sources", func(s *storedFetch) { s.Sources = nil }},
		{"empty source entry", func(s *storedFetch) { s.Sources = []string{""} }},
		{"oversized source", func(s *storedFetch) { s.Sources = []string{strings.Repeat("s", maxStoredSourceBytes+1)} }},
		{"status code out of range", func(s *storedFetch) { s.StatusCode = 99 }},
		{"redirects out of range", func(s *storedFetch) { s.Redirects = MaxRedirects + 1 }},
		{"content length out of range", func(s *storedFetch) { s.ContentLength = -2 }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := base
			tc.mutate(&mut)
			putRecord(t, c, key, mut)

			lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source")
			if lu.Hit {
				t.Fatal("tampered record served as a hit")
			}
			if lu.Err == nil {
				t.Fatal("lookup err = nil, want the rejection diagnostic")
			}
			// Self-healing: the unusable record was deleted, and the next
			// lookup falls through to execution.
			if out := c.Get(context.Background(), key); out.State != cache.StateMiss {
				t.Fatalf("state after rejection = %v, want miss (deleted)", out.State)
			}
		})
	}

	// A real fetch after the last rejection recomputes a valid record
	// (self-healing in the same run).
	if _, err := fetchAndStore(t, context.Background(), cfg, c, clock, u); err != nil {
		t.Fatalf("recompute storeFetch: %v", err)
	}
	if lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source"); !lu.Hit {
		t.Fatalf("recomputed record not served (err %v)", lu.Err)
	}
}

func TestCacheMismatchedRecordIdentity(t *testing.T) {
	// A completed record stored under this key whose Record-level identity
	// contradicts the key is deleted and never served.
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) })
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	cfg := cacheFetchConfig(t, srv.srv)
	u := mustURL(t, srv.url()+"/mismatch.js")
	key, err := fetchKey(u)
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}
	if _, err := fetchAndStore(t, context.Background(), cfg, c, clock, u); err != nil {
		t.Fatalf("base storeFetch: %v", err)
	}
	baseOut := c.Get(context.Background(), key)
	rec := *baseOut.Record
	rec.Operation = "dns.resolve"
	if err := c.Put(context.Background(), key, rec); err != nil {
		t.Fatalf("put tampered record: %v", err)
	}

	lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source")
	if lu.Hit {
		t.Fatal("mismatched record served as a hit")
	}
	if lu.Err == nil {
		t.Fatal("lookup err = nil, want the mismatch diagnostic")
	}
	if out := c.Get(context.Background(), key); out.State != cache.StateMiss {
		t.Fatalf("state after rejection = %v, want miss (deleted)", out.State)
	}
}

func TestCacheIncompleteNeverHit(t *testing.T) {
	// The server first declares a huge body (truncated fetch), then — after
	// a flag flip — serves a small one, so the same URL exercises both the
	// incomplete-store and the re-fetch paths.
	var huge atomicBool
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if huge.get() {
			w.Header().Set("Content-Length", "10737418240")
			w.Write([]byte("prefix"))
			return
		}
		w.Write([]byte("small"))
	})
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	cfg := cacheFetchConfig(t, srv.srv)
	u := mustURL(t, srv.url()+"/big.js")
	key, err := fetchKey(u)
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}

	huge.set(true)
	res, err := fetchAndStore(t, context.Background(), cfg, c, clock, u)
	if err != nil {
		t.Fatalf("storeFetch (truncated): %v", err)
	}
	if res.Status != FetchTruncated {
		t.Fatalf("status = %s, want incomplete", res.Status)
	}
	// The record exists but is INCOMPLETE: the cache never reports it as a
	// usable outcome, and lookupFetch falls through to execution.
	if out := c.Get(context.Background(), key); out.State != cache.StateIncomplete {
		t.Fatalf("cache state = %v, want incomplete", out.State)
	}
	if lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source"); lu.Hit {
		t.Fatal("incomplete record served as a hit")
	}

	// A later run re-fetches; the now-small body is stored completed and
	// served.
	huge.set(false)
	if _, err := fetchAndStore(t, context.Background(), cfg, c, clock, u); err != nil {
		t.Fatalf("storeFetch (refetch): %v", err)
	}
	lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source")
	if !lu.Hit {
		t.Fatalf("refetched record not served (err %v)", lu.Err)
	}
	if string(lu.Result.Content) != "small" {
		t.Errorf("content = %q, want %q", lu.Result.Content, "small")
	}
}

func TestCacheKeyStability(t *testing.T) {
	ua := mustURL(t, "http://example.com/app.js")
	ub := mustURL(t, "http://example.com/other.js")
	uc := mustURL(t, "https://example.com/app.js")

	ka1, err := fetchKey(ua)
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}
	ka2, err := fetchKey(mustURL(t, "http://example.com/app.js"))
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}
	if ka1 != ka2 {
		t.Errorf("same URL produced different keys")
	}
	if ka1 == "" || len(ka1) != 64 {
		t.Errorf("key = %q, want a 64-char digest", ka1)
	}
	// The key equals the canonical construction: operation + identity only.
	canon, err := cache.NewKey(cache.KeyParts{Operation: FetchOperation, Target: ua.Identity().String()})
	if err != nil {
		t.Fatalf("canonical key: %v", err)
	}
	if ka1 != canon {
		t.Errorf("key %s != canonical construction %s", ka1, canon)
	}
	// Distinct URLs produce distinct keys.
	if kb, _ := fetchKey(ub); kb == ka1 {
		t.Error("different path produced the same key")
	}
	if kc, _ := fetchKey(uc); kc == ka1 {
		t.Error("different scheme produced the same key")
	}
	// Caps and retries are not part of the key by construction: fetchKey
	// takes no configuration. Documented, not asserted mechanically beyond
	// the signature.
}

func TestCacheCompletedNegativeRoundTrip(t *testing.T) {
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)

	t.Run("conn_refused", func(t *testing.T) {
		addr := refusedLoopbackAddr(t)
		cfg := testFetchConfig()
		cfg.Transport = newTestTransport(addr, nil)
		u := mustURL(t, "http://"+addr+"/")

		res, err := fetchAndStore(t, context.Background(), cfg, c, clock, u)
		if err != nil {
			t.Fatalf("storeFetch: %v", err)
		}
		if res.Status != FetchCompleted || res.Reason != ReasonConnRefused {
			t.Fatalf("status/reason = %s/%s, want completed/conn_refused", res.Status, res.Reason)
		}
		// A completed negative is cacheable and served as a completed hit
		// with its reason and no response observation.
		lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source")
		if !lu.Hit {
			t.Fatalf("lookup = hit false (err %v), want a hit", lu.Err)
		}
		if lu.Result.Reason != ReasonConnRefused {
			t.Errorf("cached reason = %q, want conn_refused", lu.Result.Reason)
		}
		if lu.Result.StatusCode != 0 || lu.Result.Content != nil || lu.Result.Size != 0 || lu.Result.Hash != "" {
			t.Errorf("cached negative carries a response observation: %+v", lu.Result)
		}
	})

	t.Run("tls", func(t *testing.T) {
		pr := newPlainResponder(t)
		cfg := testFetchConfig()
		cfg.Transport = newTestTransport(pr.addr, nil)
		u := mustURL(t, "https://"+pr.addr+"/")

		res, err := fetchAndStore(t, context.Background(), cfg, c, clock, u)
		if err != nil {
			t.Fatalf("storeFetch: %v", err)
		}
		if res.Status != FetchCompleted || res.Reason != ReasonTLS {
			t.Fatalf("status/reason = %s/%s, want completed/tls", res.Status, res.Reason)
		}
		lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source")
		if !lu.Hit || lu.Result.Reason != ReasonTLS {
			t.Fatalf("lookup = hit %v with reason %q, want hit with tls", lu.Hit, lu.Result.Reason)
		}
	})
}

func TestCacheFailedNeverStored(t *testing.T) {
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)

	t.Run("failed", func(t *testing.T) {
		cfg := testFetchConfig()
		cfg.Transport = errorRT{err: &net.DNSError{Err: "no such host", Name: "none.invalid", IsNotFound: true}}
		u := mustURL(t, "http://none.invalid/a.js")
		res := fetchOrTimeout(t, context.Background(), cfg, u)
		if res.Status != FetchFailed {
			t.Fatalf("status = %s, want failed", res.Status)
		}
		if err := storeFetch(context.Background(), cfg, c, clock, res, []string{"test-source"}, time.Time{}, time.Time{}); err != nil {
			t.Fatalf("storeFetch of a failed result must be a no-op, got error %v", err)
		}
		key, err := fetchKey(u)
		if err != nil {
			t.Fatalf("fetchKey: %v", err)
		}
		if out := c.Get(context.Background(), key); out.State != cache.StateMiss {
			t.Errorf("state = %v, want miss (failed is never cached)", out.State)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		cfg := testFetchConfig()
		u := mustURL(t, "http://example.com/a.js")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res := Fetch(ctx, cfg, u)
		if res.Status != FetchCancelled {
			t.Fatalf("status = %s, want cancelled", res.Status)
		}
		if err := storeFetch(ctx, cfg, c, clock, res, []string{"test-source"}, time.Time{}, time.Time{}); err != nil {
			t.Fatalf("storeFetch of a cancelled result must be a no-op, got error %v", err)
		}
		key, err := fetchKey(u)
		if err != nil {
			t.Fatalf("fetchKey: %v", err)
		}
		if out := c.Get(context.Background(), key); out.State != cache.StateMiss {
			t.Errorf("state = %v, want miss (cancelled is never cached)", out.State)
		}
	})
}

func TestStoreDetachedOnCancelledContext(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("persist")) })
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	cfg := cacheFetchConfig(t, srv.srv)
	u := mustURL(t, srv.url()+"/p.js")

	res := fetchOrTimeout(t, context.Background(), cfg, u)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The cancelled run still persists its terminal completed record using
	// a detached, bounded store context.
	if err := storeFetch(ctx, cfg, c, clock, res, []string{"test-source"}, time.Time{}, time.Time{}); err != nil {
		t.Fatalf("storeFetch on cancelled ctx: %v", err)
	}
	lu := lookupFetch(context.Background(), u, cfg, c, clock, "test-source")
	if !lu.Hit {
		t.Fatalf("record not served after detached store (err %v)", lu.Err)
	}
	if string(lu.Result.Content) != "persist" {
		t.Errorf("content = %q, want %q", lu.Result.Content, "persist")
	}
}

func TestStoreSourceValidation(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) })
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	cfg := cacheFetchConfig(t, srv.srv)
	u := mustURL(t, srv.url()+"/s.js")
	res := fetchOrTimeout(t, context.Background(), cfg, u)
	if res.Status != FetchCompleted {
		t.Fatalf("status = %s, want completed", res.Status)
	}

	for name, sources := range map[string][]string{
		"empty":            {},
		"empty entry":      {""},
		"oversized entry":  {strings.Repeat("s", maxStoredSourceBytes+1)},
		"mixed with empty": {"good", ""},
		"mixed oversized":  {"good", strings.Repeat("s", maxStoredSourceBytes+1)},
	} {
		if err := storeFetch(context.Background(), cfg, c, clock, res, sources, time.Time{}, time.Time{}); err == nil {
			t.Errorf("%s: storeFetch accepted invalid sources %q", name, sources)
		}
	}
	// Nothing was stored by the rejected writes.
	key, err := fetchKey(u)
	if err != nil {
		t.Fatalf("fetchKey: %v", err)
	}
	if out := c.Get(context.Background(), key); out.State != cache.StateMiss {
		t.Errorf("state = %v, want miss", out.State)
	}
	// A valid source list stores fine.
	if err := storeFetch(context.Background(), cfg, c, clock, res, []string{"good-source"}, time.Time{}, time.Time{}); err != nil {
		t.Fatalf("storeFetch with valid sources: %v", err)
	}
	if lu := lookupFetch(context.Background(), u, cfg, c, clock, "good-source"); !lu.Hit {
		t.Fatalf("lookup = hit false (err %v), want a hit", lu.Err)
	}
}

func TestCacheConcurrent(t *testing.T) {
	const workers = 8
	body := []byte("var concurrency = 1;")
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})
	c := openTestCache(t)
	clock := newFakeClock(fixedTime)
	counting := countingRT{inner: transportFor(t, srv.srv)}
	cfg := cacheFetchConfig(t, srv.srv)
	cfg.Transport = &counting

	urls := make([]asset.URL, workers)
	for i := range urls {
		urls[i] = mustURL(t, srv.url()+"/c"+string(rune('0'+i))+".js")
	}

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := range urls {
		wg.Add(1)
		go func(u asset.URL) {
			defer wg.Done()
			// Bounded per-goroutine context: a regression that hangs a fetch
			// surfaces as a failed result here instead of wedging the suite
			// (t helpers must not run on non-test goroutines).
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			if lu := lookupFetch(ctx, u, cfg, c, clock, "test-source"); lu.Hit {
				errs <- errors.New("unexpected hit on first lookup")
				return
			}
			res := Fetch(ctx, cfg, u)
			if res.Status != FetchCompleted {
				errs <- fmt.Errorf("fetch failed: status %s", res.Status)
				return
			}
			if err := storeFetch(ctx, cfg, c, clock, res, []string{"test-source"}, time.Time{}, time.Time{}); err != nil {
				errs <- err
				return
			}
			lu := lookupFetch(ctx, u, cfg, c, clock, "test-source")
			if !lu.Hit {
				errs <- errors.New("no hit after store")
				return
			}
			if !bytes.Equal(lu.Result.Content, body) {
				errs <- errors.New("cached content mismatch")
				return
			}
			errs <- nil
		}(urls[i])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := counting.calls(); n != workers {
		t.Errorf("requests = %d, want %d (exactly one per URL)", n, workers)
	}
}

// putRecord writes a completed record carrying the given storedFetch payload
// under key.
func putRecord(t *testing.T, c cache.Cache, key cache.Key, st storedFetch) {
	t.Helper()
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("encode tampered record: %v", err)
	}
	if err := c.Put(context.Background(), key, cache.Record{
		Operation: FetchOperation,
		Target:    st.Target,
		Status:    cache.StatusCompleted,
		Data:      data,
	}); err != nil {
		t.Fatalf("put tampered record: %v", err)
	}
}

// atomicBool is a tiny mutex-guarded boolean for flipping server behavior
// between test phases.
type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) set(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.v = v
}

func (b *atomicBool) get() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}
