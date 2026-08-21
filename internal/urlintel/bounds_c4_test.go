package urlintel

import "testing"

// Drift detector for OPTIMIZATION.md §7 C-4 ("Output bounding"). Pins the
// documented line cap to its C-4 value; truncation behavior is covered by
// the engine unit tests.

// TestC4BoundConstants pins urlintel's documented line cap.
func TestC4BoundConstants(t *testing.T) {
	// C-4: "urlintel line 32 KiB" per raw URL line.
	if maxRawURLLen != 32<<10 {
		t.Fatalf("maxRawURLLen = %d, want 32 KiB (32<<10) per OPTIMIZATION.md C-4", maxRawURLLen)
	}
}
