//go:build windows

package discovery

import "testing"

// assertDescendantReaped is not reachable on Windows: every test that calls
// it skips with skipOnWindows first. It exists only so the shared test files
// compile for GOOS=windows (no POSIX kill probe exists there).
func assertDescendantReaped(t *testing.T, _ string) {
	t.Helper()
	t.Skip("process liveness probing is unix-only")
}
