//go:build unix

package urlintel

import (
	"math"
	"syscall"
	"testing"
)

// freeInodesOnVolume reports the number of free inodes on the volume holding
// dir, or math.MaxInt64 when the volume allocates inodes dynamically
// (btrfs and similar filesystems statfs-report a Files==0/Ffree==0 "no fixed
// inode table", which means uncounted capacity rather than zero). ok is
// false only when capacity cannot be established at all (statfs failure), so
// capacity-dependent benchmarks skip loudly instead of guessing. A
// dynamically-inoded volume can still run out of BYTE space mid-pass; that
// failure surfaces loudly through the engine's run diagnostics and the
// benchmark's per-entry assertions.
func freeInodesOnVolume(dir string) (free uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	if st.Files == 0 {
		return uint64(math.MaxInt64), true
	}
	return st.Ffree, true
}

func TestFreeInodesOnVolume(t *testing.T) {
	free, ok := freeInodesOnVolume(t.TempDir())
	if !ok {
		t.Fatal("freeInodesOnVolume could not statfs a fresh temp directory")
	}
	if free == 0 {
		t.Fatal("freeInodesOnVolume = 0 free inodes on a fresh temp directory")
	}
}
