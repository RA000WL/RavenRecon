package jsintel

import "testing"

// Drift detector for OPTIMIZATION.md §7 C-4 ("Output bounding"). Pins the
// documented content-retention caps to their C-4 values; clamp/truncation
// behavior is covered by the fetch and engine unit tests.

// TestC4BoundConstants pins jsintel's documented retention bounds.
func TestC4BoundConstants(t *testing.T) {
	// C-4: "jsintel 2 MiB JS / 1 MiB HTML".
	if defaultMaxJSBytes != 2<<20 {
		t.Fatalf("defaultMaxJSBytes = %d, want 2 MiB (2<<20) per OPTIMIZATION.md C-4", defaultMaxJSBytes)
	}
	if MaxHTMLBody != 1<<20 {
		t.Fatalf("MaxHTMLBody = %d, want 1 MiB (1<<20) per OPTIMIZATION.md C-4", MaxHTMLBody)
	}
	// The clamp window around the JS cap is part of the same contract
	// (jsintel/fetch.go): below-minimum raised, above-maximum lowered.
	if minMaxJSBytes != 64<<10 {
		t.Fatalf("minMaxJSBytes = %d, want 64 KiB (64<<10) per the fetch clamp window", minMaxJSBytes)
	}
	if maxMaxJSBytes != 8<<20 {
		t.Fatalf("maxMaxJSBytes = %d, want 8 MiB (8<<20) per the fetch clamp window", maxMaxJSBytes)
	}
}
