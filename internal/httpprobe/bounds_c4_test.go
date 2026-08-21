package httpprobe

import "testing"

// Drift detector for OPTIMIZATION.md §7 C-4 ("Output bounding"). Pins the
// documented probe bounds to their C-4 values; truncation behavior is
// covered by the run unit tests.

// TestC4BoundConstants pins httpprobe's documented response bounds.
func TestC4BoundConstants(t *testing.T) {
	// C-4: "httpprobe 64 KiB/128/1 MiB/10 redirects" — header bytes,
	// retained headers, counted body bytes, redirect hops.
	if MaxHeaderBytes != 64<<10 {
		t.Fatalf("MaxHeaderBytes = %d, want 64 KiB (64<<10) per OPTIMIZATION.md C-4", MaxHeaderBytes)
	}
	if MaxHeaders != 128 {
		t.Fatalf("MaxHeaders = %d, want 128 per OPTIMIZATION.md C-4", MaxHeaders)
	}
	if MaxBodyBytes != 1<<20 {
		t.Fatalf("MaxBodyBytes = %d, want 1 MiB (1<<20) per OPTIMIZATION.md C-4", MaxBodyBytes)
	}
	if MaxRedirects != 10 {
		t.Fatalf("MaxRedirects = %d, want 10 per OPTIMIZATION.md C-4", MaxRedirects)
	}
}
