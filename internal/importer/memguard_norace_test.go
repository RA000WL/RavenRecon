//go:build !race

package importer

// raceEnabled reports that this test binary was NOT built with the race
// detector. See memguard_race_test.go for why the guards skip under -race.
const raceEnabled = false
