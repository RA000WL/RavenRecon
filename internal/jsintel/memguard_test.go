package jsintel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Memory guard (byte tier) — locked decision D3 on TODO.md NEW-56.
//
// This is a COARSE retained-heap guard, not a peak-memory measurement: the
// protocol is runtime.GC(); ReadMemStats(before) → representative engine
// run → runtime.GC(); ReadMemStats(after), and the assertion bounds the
// post-GC HeapInuse delta. That is exactly the quantity an unbounded-growth
// bug moves (retained heap); transient peaks are the structural caps' job
// and are pinned by the cap-behavior unit tests (the hard gate).
//
// The ceiling is an order of magnitude of headroom above the documented
// C-4 bound (jsintel 2 MiB JS per fetch), not an exact-MiB equality —
// exact equality would be a flake factory across Go versions and GC pacing.
//
// Skipped under -race (raceEnabled, build-tag exact) and in -short mode:
// the race detector multiplies heap retention several-fold, making any
// HeapInuse delta meaningless.

// memGuardMaxHeapDelta is the retained-heap ceiling for one cold full-pipe-
// line Run over four 2 MiB (defaultMaxJSBytes, the C-4 bound) scripts.
// 32 MiB = 2× the total fed content and 16× the per-document bound:
// headroom for parse/analyze working set, but far below unbounded growth.
const memGuardMaxHeapDelta int64 = 32 << 20

// memGuardScripts is the number of at-cap documents the guard feeds.
const memGuardScripts = 4

// TestMemGuardRunHeapDelta runs the full jsintel pipeline cold against a
// loopback server serving four 2 MiB JavaScript bodies (each exactly at the
// documented defaultMaxJSBytes retention cap), then asserts the post-GC
// retained-heap delta stays within memGuardMaxHeapDelta.
func TestMemGuardRunHeapDelta(t *testing.T) {
	if raceEnabled {
		t.Skip("memory guard is meaningless under the race detector's inflated heap (D3)")
	}
	if testing.Short() {
		t.Skip("memory guard skipped in -short mode")
	}

	// Build an at-cap (2 MiB) JS document that stays BELOW every parser
	// cap (same discipline as genLargeBundle): a handful of real string
	// literals up front, then comment-line padding. A monolithic minified
	// body would legitimately trip the parser's token/retention caps and
	// surface as an honest incomplete entry — a workload bug, not an
	// engine one.
	var sb strings.Builder
	sb.WriteString("const api=\"/api/v1/status\";\n")
	sb.WriteString("const cdn=\"https://cdn.example.net/lib/core.js\";\n")
	const padLine = "// memguard padding pad pad pad pad pad pad pad pad pad pad pad\n" // 64 bytes
	for sb.Len() < 2<<20 {
		sb.WriteString(padLine)
	}
	body := []byte(sb.String())
	if len(body) > 2<<20 {
		body = body[:2<<20]
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	var page strings.Builder
	page.WriteString("<!doctype html><html><head>")
	for i := 0; i < memGuardScripts; i++ {
		fmt.Fprintf(&page, "<script src=\"/g%d.js\"></script>", i)
	}
	page.WriteString("</head><body></body></html>")

	item := Item{
		Kind: ItemHTML,
		URL:  mustURL(t, "http://example.com/"),
		Body: page.String(),
	}

	cfg := DefaultConfig()
	cfg.Concurrency = 4
	cfg.QueueSize = 16
	cfg.Timeout = 0 // loopback never blocks; no per-job deadline needed
	cfg.Rate = 0    // pacing disabled: the guard measures the raw run
	cfg.Transport = transportFor(t, srv)
	c, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	cfg.Cache = c

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	rep, err := Run(context.Background(), cfg, SliceSource([]Item{item}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Entries) != memGuardScripts {
		t.Fatalf("entries = %d, want %d", len(rep.Entries), memGuardScripts)
	}
	for _, e := range rep.Entries {
		if e.Status != StatusCompleted || e.JS == nil {
			t.Fatalf("entry %s: status=%s js=%v; guard workload broken", e.URL.String(), e.Status, e.JS != nil)
		}
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	delta := int64(after.HeapInuse) - int64(before.HeapInuse)
	if delta < 0 {
		delta = 0 // heap shrank below the pre-run baseline; nothing retained
	}
	t.Logf("retained heap delta: %d bytes (ceiling %d)", delta, int64(memGuardMaxHeapDelta))
	if delta > memGuardMaxHeapDelta {
		t.Fatalf("retained heap delta = %d bytes exceeds guard %d bytes (%.1f× the 2 MiB C-4 document bound); possible unbounded growth — investigate before raising",
			delta, int64(memGuardMaxHeapDelta), float64(delta)/(2<<20))
	}
}
