package config

import "time"

// Config contains global RavenRecon runtime configuration.
//
// Keep this structure intentionally small during v0.1.
// New configuration should be introduced together with the
// feature that consumes it.
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Rate        float64
	UserAgent   string
}

// Default returns the default runtime configuration.
func Default() Config {
	return Config{
		Concurrency: 10,
		Timeout:     10 * time.Second,
		Rate:        5,
		UserAgent:   "RavenRecon/0.1",
	}
}
