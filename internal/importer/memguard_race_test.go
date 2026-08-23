//go:build race

package importer

// raceEnabled reports that this test binary WAS built with the race
// detector. See memguard_test.go / memguard_norace_test.go — this is
// the v1.7 build-tag pair (internal/discovery, locked decision D3 on
// TODO.md NEW-56): the race detector multiplies heap retention several-fold,
// so any HeapInuse delta assertion is meaningless under -race and every
// memory guard must skip instead.
const raceEnabled = true
