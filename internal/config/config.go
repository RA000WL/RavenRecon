package config

import (
	"fmt"
	"math"
	"time"
)

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

	// TUI configures the terminal observability layer (internal/tui,
	// roadmap v1.2, phase 12). The TUI is observer-only and disabled by
	// default: nothing is rendered and no terminal interaction happens
	// until a caller explicitly enables it.
	TUI TUIConfig
}

// TUIConfig configures the terminal observability library (internal/tui,
// roadmap v1.2, phase 12). Zero values defer to the library's documented
// defaults, so the observable defaults stay safe: the TUI is never enabled
// implicitly.
type TUIConfig struct {
	// Enabled turns the terminal observability layer on. It defaults to
	// false; nothing renders and no terminal state is touched when it is
	// false.
	Enabled bool

	// Compact renders a condensed frame (fewer lines). False renders the
	// full frame.
	Compact bool

	// Quiet suppresses routine output and renders only the error feed and
	// the final run summary. False renders the full frame.
	Quiet bool

	// Color selects ANSI color usage: "auto" (the caller resolves it from
	// its own terminal detection), "on", or "off". The library renders
	// color only when the resolved mode is "on".
	Color string

	// RefreshInterval is the ticker period between frame renders. It must
	// be positive (Validate rejects zero); DefaultTUI supplies the sane
	// default (250 ms).
	RefreshInterval time.Duration

	// MaxEventHistory bounds the TUI's in-memory event history (the replay
	// buffer) measured in events. It must be in [1, 4096] (Validate rejects
	// anything else); DefaultTUI supplies the sane default (1024).
	MaxEventHistory int

	// InterestingRate is the interesting-asset feed admission rate cap in
	// items per second (per-second token budget, burst 1). Zero defers to
	// the library default (10/s); a negative or NaN value is invalid.
	InterestingRate float64
}

// DefaultTUI returns the default terminal observability configuration.
func DefaultTUI() TUIConfig {
	return TUIConfig{
		Enabled:         false,
		Compact:         false,
		Quiet:           false,
		Color:           "auto",
		RefreshInterval: 250 * time.Millisecond,
		MaxEventHistory: 1024,
		InterestingRate: 10,
	}
}

// Validate checks the TUI configuration contract: the refresh interval must
// be positive, the event history must be bounded within [1, 4096], the color
// mode must be one of the canonical values, and the interesting-feed rate
// must not be negative or NaN. It returns an error describing the first
// violation; a nil error means the configuration is usable.
func (c TUIConfig) Validate() error {
	if c.RefreshInterval <= 0 {
		return &tuiConfigError{field: "RefreshInterval", problem: fmt.Sprintf("must be positive, got %s", c.RefreshInterval)}
	}
	if c.MaxEventHistory < 1 || c.MaxEventHistory > 4096 {
		return &tuiConfigError{field: "MaxEventHistory", problem: fmt.Sprintf("must be in [1, 4096], got %d", c.MaxEventHistory)}
	}
	switch c.Color {
	case "auto", "on", "off":
	default:
		return &tuiConfigError{field: "Color", problem: fmt.Sprintf("must be \"auto\", \"on\", or \"off\", got %q", c.Color)}
	}
	if math.IsNaN(c.InterestingRate) || c.InterestingRate < 0 {
		return &tuiConfigError{field: "InterestingRate", problem: fmt.Sprintf("must not be negative or NaN, got %v", c.InterestingRate)}
	}
	return nil
}

// tuiConfigError is a structured TUI configuration validation error.
type tuiConfigError struct {
	field   string
	problem string
}

// Error implements error.
func (e *tuiConfigError) Error() string {
	return "config: tui " + e.field + ": " + e.problem
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
		TUI: DefaultTUI(),
	}
}
