//go:build linux

package discovery

import "os"

// countOpenFDs returns the number of open file descriptors in this process
// and whether the count is available. On Linux the /proc/self/fd directory
// counts exactly the process's open descriptors, which is how the hardening
// tests prove Run leaks no pipe descriptors.
func countOpenFDs() (int, bool) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(entries), true
}
