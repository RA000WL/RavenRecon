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

	// Discovery configures passive subdomain discovery (internal/discovery,
	// roadmap v0.5).
	Discovery DiscoveryConfig
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

// DiscoveryConfig configures the passive discovery stage (roadmap v0.5,
// internal/discovery). Zero values defer to the stage's own documented
// defaults, so the defaults stay safe: no discovery-specific tuning is
// required to run.
type DiscoveryConfig struct {
	// Sources selects built-in passive sources by name ("subfinder",
	// "assetfinder", "amass"). Nil or empty means every built-in source.
	Sources []string

	// Bin optionally overrides the executable path per source name. An empty
	// map (or an absent entry) means PATH lookup of the tool's default name.
	Bin map[string]string

	// Timeout is the per-tool execution deadline for discovery runs. Zero
	// defers to the global Timeout; if that is also zero, to the discovery
	// stage default.
	Timeout time.Duration

	// DetectTimeout bounds each tool detection invocation. Zero defers to
	// the discovery stage default.
	DetectTimeout time.Duration

	// MaxOutputSize caps each captured stdout/stderr stream in bytes during
	// tool execution. Zero defers to the discovery stage default (4 MiB per
	// stream).
	MaxOutputSize int64
}

// Default returns the default runtime configuration.
func Default() Config {
	return Config{
		Concurrency: 10,
		Timeout:     10 * time.Second,
		Rate:        5,
		UserAgent:   "RavenRecon/0.5.0",
		Cache: CacheConfig{
			Enabled: false,
			Dir:     "",
			TTL:     0,
		},
	}
}
