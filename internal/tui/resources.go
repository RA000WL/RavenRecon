package tui

import (
	"os"
	"runtime"
	"strconv"
)

// Resources is one bounded sample of the process's resource state, taken at
// render time only (never per event). Every field degrades honestly:
// OpenFDs is -1 when the platform cannot report it (anything but Linux) or
// the read failed, and HeapBytes is 0 when sampling failed.
type Resources struct {
	// HeapBytes is the in-use heap (runtime.MemStats.HeapInuse).
	HeapBytes uint64
	// Goroutines is runtime.NumGoroutine().
	Goroutines int
	// OpenFDs is the number of open file descriptors (Linux
	// /proc/self/fd), or -1 when unavailable.
	OpenFDs int
	// QueueDepth is the number of submitted-but-not-started tasks (pool
	// stats derived from task events: submitted - started, clamped at 0).
	QueueDepth int
	// ActiveWorkers is the number of workers in waiting or running state.
	ActiveWorkers int
}

// sampleResources is the production sampler: stdlib runtime metrics plus a
// best-effort /proc/self/fd count on Linux. It is a field on State so tests
// can inject a fixed sampler (the renderer must stay deterministic).
func sampleResources() Resources {
	res := Resources{OpenFDs: -1}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	res.HeapBytes = ms.HeapInuse
	res.Goroutines = runtime.NumGoroutine()
	if n := countOpenFDs(); n >= 0 {
		res.OpenFDs = n
	}
	return res
}

// countOpenFDs counts the entries of /proc/self/fd on Linux. On any other
// platform the directory does not exist and -1 is returned (documented
// unsupported; stdlib only). A read failure also degrades to -1.
func countOpenFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		// The directory's own fd entry and the readdir fd are counted by
		// the kernel; only skip clearly non-numeric names (defensive).
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		n++
	}
	return n
}

// formatBytes renders a byte count deterministically: "12.3 MiB", "512 KiB",
// "900 B".
func formatBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return formatFloat1(float64(n)/(1<<30)) + " GiB"
	case n >= 1<<20:
		return formatFloat1(float64(n)/(1<<20)) + " MiB"
	case n >= 1<<10:
		return formatFloat1(float64(n)/(1<<10)) + " KiB"
	default:
		return strconv.FormatUint(n, 10) + " B"
	}
}

// formatFloat1 renders v with one decimal place, dropping a trailing ".0"
// ("12.3", "512", "0.5"). Deterministic via strconv.
func formatFloat1(v float64) string {
	s := strconv.FormatFloat(v, 'f', 1, 64)
	if len(s) > 2 && s[len(s)-2:] == ".0" {
		s = s[:len(s)-2]
	}
	return s
}
