// Package golden is the shared golden-snapshot home for RavenRecon's
// acceptance and surface tests (NEW-56 D2). It lifts the golden pattern
// that previously lived test-file-local in internal/detect
// (surface_snapshot_test.go) into one reusable, stdlib-only package:
//
//   - Update: the opt-in `-update` regeneration flag (a normal run never
//     writes; regeneration happens ONLY through the explicit flag);
//   - Compare: compare-or-regenerate against a golden file, failing with
//     an LCS line diff on drift;
//   - Write: atomic golden writes (temp file + fsync + rename), so a
//     crashed regeneration never leaves a half-written golden;
//   - Diff: a bounded LCS line diff for failure messages.
//
// The package is ordinary non-test code so several packages' test binaries
// can link it (the second consumer beside internal/detect is the pipeline
// acceptance harness in internal/pipeline/adapt); it contains no testing
// logic of its own beyond the *testing.TB plumbing in Compare.
//
// # Hard constraint: TEST-SUPPORT ONLY — never import from non-test code
//
// Despite linking into ordinary builds, this package must NEVER be
// imported by non-test code. Update registers a process-global "-update"
// flag (flag.Bool at package init), so:
//
//   - a production import would silently add -update to every CLI binary
//     that parses flags, exposing test-only behavior in shipped tools; and
//   - any second registration of an "update" flag anywhere in the same
//     binary panics at init.
//
// Only _test.go files may depend on this package.
package golden

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// updateFlag is the ONLY regeneration path for every golden consumer:
// a normal `go test` run never writes.
var updateFlag = flag.Bool("update", false, "regenerate golden files instead of comparing")

// Update reports whether the -update flag was set for this test binary.
func Update() bool { return *updateFlag }

// Compare pins got against the golden file at path.
//
// When Update() is set, Compare regenerates the golden atomically instead
// of comparing, re-reads it, and fails unless the regeneration is
// byte-stable. Otherwise it compares byte-for-byte: a missing or drifted
// golden fails the test with an LCS line diff (Diff).
func Compare(t testing.TB, path string, got []byte) {
	t.Helper()
	if *updateFlag {
		if err := Write(path, got); err != nil {
			t.Fatalf("regenerate golden %s: %v", path, err)
		}
		re, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("re-read regenerated golden %s: %v", path, err)
		}
		if !bytes.Equal(re, got) {
			t.Fatalf("regenerated golden %s is not byte-stable (rerun without -update)", path)
		}
		t.Logf("regenerated %s (%d bytes)", path, len(got))
		return
	}

	if err := checkFile(path, got); err != nil {
		t.Fatal(err.Error())
	}
}

// checkFile compares got against the golden file at path: nil on
// byte-equality, otherwise an error carrying the LCS line diff (missing
// goldens included). Split from Compare so tests can exercise the drift
// path without failing the test binary.
func checkFile(path string, got []byte) error {
	want, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read golden %s: %w (generate it with: go test <package> -run <test> -update)", path, err)
	}
	if bytes.Equal(want, got) {
		return nil
	}
	return fmt.Errorf("golden drifted from %s:\n%s", path, Diff(string(want), string(got)))
}

// Write writes data to path atomically (temp file + fsync + rename): a
// failed or interrupted regeneration never leaves a truncated golden, and
// readers never observe a partial file.
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("golden: create directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".golden.tmp*")
	if err != nil {
		return fmt.Errorf("golden: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("golden: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("golden: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("golden: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("golden: chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("golden: rename: %w", err)
	}
	return nil
}
