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

	// Cache controls RavenRecon's persistent result cache (internal/cache).
	Cache CacheConfig
}

// CacheConfig configures the persistent, filesystem-backed result cache.
type CacheConfig struct {
	// Enabled turns the cache on. It defaults to false: the cache is
	// infrastructure until a runtime stage exists that consumes it, so
	// nothing is read or written by default.
	Enabled bool

	// Dir is the cache directory. Empty means the platform default
	// (os.UserCacheDir()/ravenrecon, see cache.DefaultDir in internal/cache).
	Dir string

	// TTL is how long completed entries stay valid, measured from creation.
	// Zero disables expiration (entries are valid indefinitely).
	TTL time.Duration
}

// Default returns the default runtime configuration.
func Default() Config {
	return Config{
		Concurrency: 10,
		Timeout:     10 * time.Second,
		Rate:        5,
		UserAgent:   "RavenRecon/0.2.0",
		Cache: CacheConfig{
			Enabled: false,
			Dir:     "",
			TTL:     0,
		},
	}
}
