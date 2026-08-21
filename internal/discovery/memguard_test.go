package discovery

import (
	"bytes"
	"context"
	"runtime"
	"testing"
)

// Memory guard (byte tier) — locked decision D3 on TODO.md NEW-56.
//
// This is a COARSE retained-heap guard, not a peak-memory measurement: the
// protocol is runtime.GC(); ReadMemStats(before) → representative run →
// runtime.GC(); ReadMemStats(after), and the assertion bounds the post-GC
// HeapInuse delta. That is exactly the quantity an unbounded-growth bug
// moves (retained heap); transient peaks are the structural caps' job and
// are pinned by the cap-behavior unit tests (the hard gate).
//
// The ceiling is an order of magnitude of headroom above the documented
// C-4 bound (discovery 4 MiB per stream), not an exact-MiB equality —
// exact equality would be a flake factory across Go versions and GC pacing.
//
// Skipped under -race (raceEnabled, build-tag exact) and in -short mode:
// the race detector multiplies heap retention several-fold, making any
// HeapInuse delta meaningless.

// memGuardMaxHeapDelta is the retained-heap ceiling for one full pipeline
// run over four sources each emitting a full-cap (4 MiB, DefaultMaxOutput)
// stdout stream. 32 MiB = 8× the documented per-stream bound: generous
// headroom for parse/merge working set, but far below any unbounded growth.
const memGuardMaxHeapDelta int64 = 32 << 20

// TestMemGuardPipelineHeapDelta runs the full discovery pipeline against
// fake sources whose every stream is at the documented 4 MiB capture cap,
// then asserts the post-GC retained-heap delta stays within
// memGuardMaxHeapDelta. Host lines repeat a small identity set so the
// workload exercises capture + parse + dedup at full stream size without
// conflating the guard with legitimately large result sets.
func TestMemGuardPipelineHeapDelta(t *testing.T) {
	if raceEnabled {
		t.Skip("memory guard is meaningless under the race detector's inflated heap (D3)")
	}
	if testing.Short() {
		t.Skip("memory guard skipped in -short mode")
	}

	const streamBytes = int64(4 << 20) // == DefaultMaxOutput; kept literal so drift is caught by TestC4BoundConstants, not by this test silently shrinking
	payload := bytes.Repeat([]byte("www.example.com\n"), int(streamBytes/16))
	if int64(len(payload)) > streamBytes {
		payload = payload[:streamBytes]
	}

	script := standardScript()
	for _, key := range []string{
		"subfinder -d example.com -silent",
		"assetfinder example.com",
		"amass enum -passive -d example.com",
		"chaos -d example.com -silent -json",
	} {
		// Each source gets its OWN copy of the full-cap stream: sharing
		// one backing array would alias four logical streams onto a
		// single 4 MiB allocation, capping the observable retained delta
		// at ~4 MiB even under a realistic retain-everything bug.
		p := append([]byte(nil), payload...)
		script[key] = func(Cmd) (RunResult, error) {
			return RunResult{Stdout: p}, nil
		}
	}

	cfg := testConfig(newFakeRunner(t, script), newFakeLookup())
	cfg.Cache = &fakeCache{}
	cfg.Concurrency = 2

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	rep, err := Run(context.Background(), mustDomain(t, "example.com"), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Results) != 4 {
		t.Fatalf("results = %d, want 4", len(rep.Results))
	}
	// Workload sanity: the line-format sources must have parsed the
	// full-cap streams (chaos expects JSON and legitimately reports the
	// payload as malformed lines — its capture buffer is exercised either
	// way, which is what this guard measures).
	if len(rep.All()) == 0 {
		t.Fatal("no hosts merged from full-cap streams; guard workload broken")
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
		t.Fatalf("retained heap delta = %d bytes exceeds guard %d bytes (%.1f× the 4 MiB C-4 stream bound); possible unbounded growth — investigate before raising",
			delta, int64(memGuardMaxHeapDelta), float64(delta)/(4<<20))
	}
}
