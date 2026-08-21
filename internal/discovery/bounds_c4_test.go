package discovery

import "testing"

// Drift detector for OPTIMIZATION.md §7 C-4 ("Output bounding"). Pins the
// documented stream cap to its C-4 value; truncation behavior is covered by
// the runner/pipeline unit tests.

// TestC4BoundConstants pins discovery's documented stream cap.
func TestC4BoundConstants(t *testing.T) {
	// C-4: "discovery 4 MiB" per captured stdout/stderr stream.
	if DefaultMaxOutput != 4<<20 {
		t.Fatalf("DefaultMaxOutput = %d, want 4 MiB (4<<20) per OPTIMIZATION.md C-4", DefaultMaxOutput)
	}
}
