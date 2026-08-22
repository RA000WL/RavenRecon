//go:build !unix

package urlintel

// freeInodesOnVolume cannot establish inode capacity without statfs (the
// portable stub): ok is false so capacity-dependent benchmarks skip loudly
// instead of guessing.
func freeInodesOnVolume(dir string) (free uint64, ok bool) {
	return 0, false
}
