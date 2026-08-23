package golden

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiffIdentical(t *testing.T) {
	// The lifted LCS renderer emits context lines even with no changes
	// (detect only invoked it after a byte mismatch); the contract here is
	// "no change markers".
	got := Diff("a\nb\n", "a\nb\n")
	if strings.Contains(got, "- ") || strings.Contains(got, "+ ") {
		t.Fatalf("Diff(identical) = %q, want no change markers", got)
	}
}

func TestDiffShowsChanges(t *testing.T) {
	got := Diff("a\nb\nc\n", "a\nx\nc\n")
	for _, want := range []string{"- b", "+ x"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Diff = %q, missing %q", got, want)
		}
	}
}

func TestDiffCollapsesLongRuns(t *testing.T) {
	var oldB, newB strings.Builder
	for i := 0; i < 50; i++ {
		oldB.WriteString("same\n")
	}
	newB.WriteString(oldB.String())
	newB.WriteString("tail\n")
	got := Diff(oldB.String(), newB.String())
	if !strings.Contains(got, "unchanged lines") {
		t.Fatalf("Diff = %q, want a collapsed-run marker", got)
	}
	if !strings.Contains(got, "+ tail") {
		t.Fatalf("Diff = %q, missing the added line", got)
	}
}

// TestDiffOversizedFallbackCapped pins that the oversized-input fallback
// (LCS cell-cap exceeded) is byte-capped like the LCS path: it returns a
// labeled dump of both documents, each truncated at half the output budget,
// never the unbounded texts.
func TestDiffOversizedFallbackCapped(t *testing.T) {
	var oldB, newB strings.Builder
	for range 3000 {
		oldB.WriteString("same\n")
	}
	for range 2500 { // 3000*2500 lines ≫ the 4M-cell LCS cap
		newB.WriteString("changed\n")
	}
	got := Diff(oldB.String(), newB.String())
	if !strings.HasPrefix(got, "old:\n") || !strings.Contains(got, "\nnew:\n") {
		t.Fatalf("fallback = %q, want the old:/new: labeled dump", got)
	}
	if !strings.Contains(got, "(diff truncated)") {
		t.Fatalf("fallback = %q, want a truncation marker", got)
	}
	// Both halves capped at fallbackCap/2 plus labels and markers: the
	// result stays far below the combined raw input size (~44 KiB).
	const fallbackCap = 8 << 10
	if len(got) > fallbackCap+128 {
		t.Fatalf("fallback is %d bytes, want within the %d-byte output budget", len(got), fallbackCap)
	}
}

func TestWriteAtomicAndByteStable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "x.golden")
	if err := Write(path, []byte("v1\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if re, err := os.ReadFile(path); err != nil || string(re) != "v1\n" {
		t.Fatalf("re-read = %q, %v; want \"v1\\n\"", re, err)
	}
	// Overwrite: rename must replace cleanly, no temp litter left behind.
	if err := Write(path, []byte("v2\n")); err != nil {
		t.Fatalf("Write (overwrite): %v", err)
	}
	if re, err := os.ReadFile(path); err != nil || string(re) != "v2\n" {
		t.Fatalf("re-read after overwrite = %q, %v; want \"v2\\n\"", re, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".golden.tmp") {
			t.Fatalf("temp file %s left behind", e.Name())
		}
	}
}

func TestCompareDetectsDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.golden")
	if err := Write(path, []byte("old\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	err := checkFile(path, []byte("new\n"))
	if err == nil {
		t.Fatal("checkFile did not report drift")
	}
	for _, want := range []string{"golden drifted", "- old", "+ new"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("drift error = %q, missing %q", err.Error(), want)
		}
	}
}

func TestCompareMissingGoldenErrors(t *testing.T) {
	err := checkFile(filepath.Join(t.TempDir(), "absent.golden"), []byte("x\n"))
	if err == nil || !strings.Contains(err.Error(), "read golden") {
		t.Fatalf("checkFile(missing) = %v, want a read-golden error", err)
	}
}

func TestComparePassesOnMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.golden")
	if err := Write(path, []byte("same\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := checkFile(path, []byte("same\n")); err != nil {
		t.Fatalf("checkFile(match) = %v, want nil", err)
	}
}
