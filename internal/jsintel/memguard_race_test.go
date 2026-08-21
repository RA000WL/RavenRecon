//go:build race

package jsintel

// raceEnabled reports that this test binary WAS built with the race detector
// (-race). The memory guards skip under -race (locked decision D3 on
// TODO.md NEW-56): the detector inflates heap retention several-fold and
// serializes allocation, so any HeapInuse delta assertion would be noise.
// The mechanism is exact — a build tag evaluated by the compiler, not a
// heuristic like environment sniffing or testing.Short() alone.
const raceEnabled = true
