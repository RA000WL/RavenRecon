//go:build windows

package discovery

// countOpenFDs is unavailable on Windows (no /proc/self/fd); the fd-leak
// assertions skip and the goroutine-leak assertions still run. It exists
// only so the hardening tests compile for GOOS=windows (they skip before
// probing).
func countOpenFDs() (int, bool) { return 0, false }
