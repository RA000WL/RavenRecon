package importer

import "testing"

// Drift detector for OPTIMIZATION.md §7 C-4 ("Output bounding") — importer
// row. Pins the documented caps to their C-4 values; truncation behavior
// (tail-drop with sticky flag, honest Truncated=true) is covered by the
// streaming/truncation unit tests.
//
// All three constants are exported and participate in cache keys
// (max_output / max_line_bytes / max_decompressed_bytes in CacheKeyForFile),
// so a value change is both a documented C-4 change AND a key-invalidating
// change — it must be deliberate, never accidental drift.

// TestC4BoundConstants pins the importer's documented C-4 bounds.
func TestC4BoundConstants(t *testing.T) {
	// C-4: bounded line buffer for plain-text importers.
	if MaxLineBytes != 32*1024 {
		t.Fatalf("MaxLineBytes = %d, want 32 KiB (32*1024) per OPTIMIZATION.md C-4", MaxLineBytes)
	}
	// C-4: decompressed gzip cap streamed through openStream/readLines.
	if MaxDecompressedBytes != 100<<20 {
		t.Fatalf("MaxDecompressedBytes = %d, want 100 MiB (100<<20) per OPTIMIZATION.md C-4", MaxDecompressedBytes)
	}
	// C-4: default retained-set cap per import (tail-drop beyond it).
	if MaxOutput != 100000 {
		t.Fatalf("MaxOutput = %d, want 100000 per OPTIMIZATION.md C-4", MaxOutput)
	}
}
