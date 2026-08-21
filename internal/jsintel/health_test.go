package jsintel

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
)

// failingTransport fails every request with a DNS error, classified as FetchFailed.
type failingTransport struct {
	n atomic.Int64
}

func (f *failingTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	f.n.Add(1)
	return nil, &mockDNSError{msg: "no such host", isNotFound: true}
}

func (f *failingTransport) count() int64 { return f.n.Load() }

type mockDNSError struct {
	msg        string
	isNotFound bool
	isTimeout  bool
}

func (e *mockDNSError) Error() string   { return e.msg }
func (e *mockDNSError) Timeout() bool   { return e.isTimeout }
func (e *mockDNSError) Temporary() bool { return true }

// selectiveTransport fails for URLs containing "fail" in path.
type selectiveTransport struct {
	n       atomic.Int64
	success http.RoundTripper
}

func (s *selectiveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.n.Add(1)
	if req.URL.Path == "/fail.js" || req.URL.Path == "/fail2.js" {
		return nil, &mockDNSError{msg: "no such host", isNotFound: true}
	}
	// For success, delegate to success transport which serves JS content.
	if s.success != nil {
		return s.success.RoundTrip(req)
	}
	// Fallback: return successful JS response via test server? We use a real server for success.
	return nil, &mockDNSError{msg: "no success transport", isNotFound: true}
}

func TestHealthGateAbortsAfter50Failures(t *testing.T) {
	// 500 URLs, all failing => health gate should trigger after 50 and abort
	// remaining. Fetches should be ~50, not 500.
	tr := &failingTransport{}
	cfg := DefaultConfig()
	cfg.Concurrency = 8
	cfg.QueueSize = 256
	cfg.Timeout = 15 * 1000000000 // 15s
	cfg.Rate = 0
	cfg.Transport = tr
	cfg.Source = "test-source"
	// Ensure MaxScripts 500 allows all
	cfg.MaxScripts = 500

	var items []Item
	for i := 0; i < 500; i++ {
		items = append(items, Item{Kind: ItemLine, Line: fmt.Sprintf("http://js.test/f%d.js", i)})
	}
	rep, err := Run(context.Background(), cfg, SliceSource(items))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.HealthAborted {
		t.Fatal("expected HealthAborted true after 50 >90% failures")
	}
	fetches := rep.Metrics().Fetches
	// With concurrency 8 and queueing, a few extra fetches may race past the
	// 50th before the gate is observed. Allow moderate overshoot, but must be
	// far less than 500 (early stop).
	if fetches < 50 || fetches > 150 {
		t.Fatalf("fetches = %d, want ~50 (health gate early stop, allow concurrency overshoot)", fetches)
	}
	// Each failed fetch retries once (default Retries=1), so transport calls
	// are ~2x fetches. The gate counts fetches, not round trips, so check that
	// transport is within that window.
	if tc := tr.count(); tc < int64(fetches) || tc > int64(fetches*3) {
		t.Fatalf("transport count = %d, want ~%d (retries)", tc, fetches*2)
	}
	// Aborted remaining are not read from source (early break), so
	// Skipped may be small (only the in-flight overshoot that was aborted at
	// processJob entry). The key signal is fetches limited and HealthAborted.
	_ = rep.Metrics().Skipped
	// Entries should be only the ~50 fetched plus in-flight, not 500.
	if len(rep.Entries) < 50 || len(rep.Entries) > 150 {
		t.Fatalf("entries = %d, want ~50 (allow overshoot)", len(rep.Entries))
	}
	for _, e := range rep.Entries {
		if e.Status != StatusFailed {
			t.Errorf("%s status = %s, want failed", e.URL.String(), e.Status)
		}
	}
}

func TestHealthGateNotTriggeredWhenSuccess(t *testing.T) {
	// Mixed: 40 fails out of first 50 => not >90%, so gate should NOT trigger,
	// all 500 should be attempted.
	// Use a real test server for success paths, and failing for /fail.js
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var x = 1;\n"))
	})
	successTr := transportFor(t, srv.srv)
	// Failing for specific paths
	tr := &selectiveTransport{success: successTr}
	// But we need 500 items with known pattern: for first 50, 40 are fail, 10 success, rest success.
	cfg := DefaultConfig()
	cfg.Concurrency = 4
	cfg.QueueSize = 256
	cfg.Timeout = 15 * 1000000000
	cfg.Rate = 0
	cfg.Transport = tr
	cfg.Source = "test-source"
	cfg.MaxScripts = 500

	var items []Item
	// First 40: fail
	for i := 0; i < 40; i++ {
		items = append(items, Item{Kind: ItemLine, Line: fmt.Sprintf("http://js.test/fail.js?%d", i)})
	}
	// Next 10: success (reuse same URL? But dedup will collapse duplicates. Use distinct)
	for i := 0; i < 10; i++ {
		items = append(items, Item{Kind: ItemLine, Line: fmt.Sprintf("http://js.test/success%d.js", i)})
	}
	// Remaining 450: success distinct
	for i := 10; i < 460; i++ {
		items = append(items, Item{Kind: ItemLine, Line: fmt.Sprintf("http://js.test/success%d.js", i)})
	}
	// Note: fail URLs are distinct via query, but our selectiveTransport checks path only, so they will all be /fail.js with different query -> still fail (we check path == /fail.js, query ignored? req.URL.Path is path without query, so all those will be /fail.js -> fail. Good.)
	// But we have 40 fail items with same path different query? They are distinct URLs due to query, but our transport check uses Path, which is same for all 40, so they all fail. Good.
	// Success items have distinct paths.

	rep, err := Run(context.Background(), cfg, SliceSource(items))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.HealthAborted {
		t.Fatal("expected HealthAborted false when <90% failed in first 50")
	}
	// All 500 should have been attempted (fetches ~500, but successes are real fetches).
	// However our selectiveTransport counts every RoundTrip, including failures and successes.
	// With no health abort, all 500 should be fetched.
	if got := rep.Metrics().Fetches; got != 500 {
		t.Fatalf("fetches = %d, want 500 (no early stop)", got)
	}
	if len(rep.Entries) != 500 {
		t.Fatalf("entries = %d, want 500", len(rep.Entries))
	}
}

func TestHealthGateEmitsFlagCompleted(t *testing.T) {
	tr := &failingTransport{}
	cfg := DefaultConfig()
	cfg.Concurrency = 4
	cfg.QueueSize = 16
	cfg.Timeout = 15 * 1000000000
	cfg.Rate = 0
	cfg.Transport = tr
	cfg.Source = "test-source"
	cfg.MaxScripts = 500

	var items []Item
	for i := 0; i < 500; i++ {
		items = append(items, Item{Kind: ItemLine, Line: fmt.Sprintf("http://js.test/a%d.js", i)})
	}
	rep, err := Run(context.Background(), cfg, SliceSource(items))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.HealthAborted {
		t.Fatal("HealthAborted flag not set")
	}
	// The run should not return an error for health abort — it is completed with flag.
	// Run returns nil error on success (health abort is not an engine error).
	// Our implementation should return nil error (or at least not failed). Check that all
	// entries are failed but HealthAborted true, which pipeline will map to completed.
	// For engine alone, just ensure flag and fetches limited (allow concurrency overshoot + retries).
	if fetches := rep.Metrics().Fetches; fetches > 150 {
		t.Fatalf("too many fetches after health abort: %d", fetches)
	}
	if tc := tr.count(); tc > 350 {
		t.Fatalf("too many round trips after health abort: %d", tc)
	}
}
