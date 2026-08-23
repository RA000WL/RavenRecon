package importer

import (
	"bytes"
	"context"
	"runtime"
	"testing"
)

// Memory guard (v1.7 pattern — internal/discovery/memguard_test.go, locked
// decision D3 on TODO.md NEW-56).
//
// This is a COARSE retained-heap guard, not a peak-memory measurement: the
// protocol is runtime.GC(); ReadMemStats(before) → representative run →
// runtime.GC(); ReadMemStats(after), and the assertion bounds the post-GC
// HeapInuse delta. That is exactly the quantity an unbounded-growth bug
// moves (retained heap); transient peaks are the structural caps' job and
// are pinned by the cap-behavior unit tests (the hard gate: MaxLineBytes,
// MaxDecompressedBytes, MaxOutput — see bounds_c4_test.go for the drift
// detectors and the truncation tests for behavior).
//
// The ceiling is an order-of-magnitude headroom above the documented
// "<8 MiB streaming overhead" bound (TODO.md NEW-59 batches 1-4 measured
// sub-MiB streaming deltas over 100k+ record streams with a small retained
// set), NOT an exact-MiB equality — exact equality would be a flake factory
// across Go versions and GC pacing.
//
// Skipped under -race (raceEnabled, build-tag exact) and in -short mode:
// the race detector multiplies heap retention several-fold, making any
// HeapInuse delta meaningless.

// memGuardMaxHeapDelta is the retained-heap ceiling for one bounded import
// of a 10 MB synthetic stream. 8 MiB matches the documented streaming
// overhead claim from the v1.8 batches while staying far below any
// unbounded growth of a 10 MB workload.
const memGuardMaxHeapDelta int64 = 8 << 20

// TestMemGuardBoundedImportHeapDelta imports a 10 MB synthetic plain-text
// stream whose lines repeat a SMALL identity set (dedup trick, mirroring the
// discovery guard): parse + normalize + dedup machinery runs at full stream
// size while the legitimately-retained result set stays tiny, so the guard
// measures streaming overhead without conflating it with assets the caller
// asked to keep. Retained-set growth at scale is bounded by MaxOutput
// (tail-drop, pinned by unit tests), not by this guard.
func TestMemGuardBoundedImportHeapDelta(t *testing.T) {
	if raceEnabled {
		t.Skip("memory guard is meaningless under the race detector's inflated heap (D3)")
	}
	if testing.Short() {
		t.Skip("memory guard skipped in -short mode")
	}

	const streamBytes = int64(10 << 20)
	// 16 distinct hosts rotated over the whole stream: full-size I/O and
	// per-record work, tiny retained set. Kept literal so drift in the
	// workload size is caught by review, not silently shrunk here; the C-4
	// constants themselves are pinned by TestC4BoundConstants.
	hostLines := make([]string, 16)
	for i := range hostLines {
		hostLines[i] = "host" + string(rune('a'+i)) + ".example.com\n"
	}
	var buf bytes.Buffer
	buf.Grow(int(streamBytes) + 64)
	var written int64
	for i := 0; written < streamBytes; i++ {
		n, _ := buf.WriteString(hostLines[i%len(hostLines)])
		written += int64(n)
	}

	path := writeBenchCorpus(t, "memguard-subdomains.txt", buf.Bytes())

	env := ImportEnv{Clock: fixedClock(), Bounds: Bounds{MaxOutput: 100000}}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	sink := NewSink()
	stats, err := NewPlainSubdomainsImporter().Import(context.Background(), env, path, sink)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// Workload sanity + sink pinning (HIGH-2 pattern from the v1.8 batches):
	// the sink must still be referenced past the m2 snapshot, or GC could
	// free every retained asset before ReadMemStats and make any delta
	// assertion vacuous. len() reads below force the slice headers to stay
	// live; runtime.KeepAlive pins the whole sink.
	if stats.ItemsProcessed != len(hostLines) {
		t.Fatalf("ItemsProcessed = %d, want %d distinct hosts; guard workload broken", stats.ItemsProcessed, len(hostLines))
	}
	if stats.ItemsFailed != 0 || stats.Truncated {
		t.Fatalf("unexpected import outcome: failed=%d truncated=%v", stats.ItemsFailed, stats.Truncated)
	}
	if len(sink.Hosts) == 0 {
		t.Fatal("no hosts retained; guard workload broken")
	}

	delta := int64(after.HeapInuse) - int64(before.HeapInuse)
	if delta < 0 {
		delta = 0 // heap shrank below the pre-run baseline; nothing retained
	}
	t.Logf("retained heap delta: %d bytes (ceiling %d)", delta, int64(memGuardMaxHeapDelta))
	if delta > memGuardMaxHeapDelta {
		t.Fatalf("retained heap delta = %d bytes exceeds guard %d bytes (%.1f× the 10 MiB stream); possible unbounded growth — investigate before raising",
			delta, int64(memGuardMaxHeapDelta), float64(delta)/float64(streamBytes))
	}
	runtime.KeepAlive(sink)
}
