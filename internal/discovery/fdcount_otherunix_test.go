//go:build unix && !linux

package discovery

// countOpenFDs is unavailable outside Linux (no /proc/self/fd); the fd-leak
// assertions skip and the goroutine-leak assertions still run.
func countOpenFDs() (int, bool) { return 0, false }
