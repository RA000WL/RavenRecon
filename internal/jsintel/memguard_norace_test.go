//go:build !race

package jsintel

// raceEnabled reports that this test binary was NOT built with the race
// detector. See memguard_race_test.go for why the guard skips under -race.
const raceEnabled = false
