package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// File is the file-backed configuration surface (JSON): every field is a
// pointer (or nil-able) so presence is explicit — an absent key leaves the
// lower-precedence value untouched, and an explicit null decodes
// identically to absent (encoding/json leaves the pointer nil; null is
// NOT rejected, it is absence spelled twice). Precedence across sources:
// CLI flags > environment > file > defaults. The file therefore only ever
// fills values the operator did not set elsewhere; see WithFile and WithEnv.
//
// Scope: the file tunes the run (concurrency/timeout/rate feed discover
// directly and scan's per-stage bounds when the matching flag is unset —
// see runScan; user_agent is display/reserved: doctor shows it, while the
// engines probe with their built-in UA, so a file user_agent never
// changes scan/discover traffic); Bin (per-tool executable overrides)
// stays CLI/API-only: paths in a shared file are a footgun across
// machines.
//
// Durations are Go duration strings ("30s", "2m", "1h"); numbers are
// rejected (a bare 30 is seconds-or-milliseconds ambiguity — fail closed).
type File struct {
	Concurrency *int           `json:"concurrency,omitempty"`
	Timeout     *FileDuration  `json:"timeout,omitempty"`
	Rate        *float64       `json:"rate,omitempty"`
	UserAgent   *string        `json:"user_agent,omitempty"`
	Cache       *FileCache     `json:"cache,omitempty"`
	Discovery   *FileDiscovery `json:"discovery,omitempty"`
}

// FileCache mirrors CacheConfig with presence.
type FileCache struct {
	Enabled *bool         `json:"enabled,omitempty"`
	Dir     *string       `json:"dir,omitempty"`
	TTL     *FileDuration `json:"ttl,omitempty"`
}

// FileDiscovery mirrors the tunable DiscoveryConfig subset with presence.
// Bin (per-tool executable overrides) stays CLI/API-only: paths in a
// shared file are a footgun across machines. An explicit empty sources
// list applies nothing (unlike a set-but-empty
// RAVENRECON_DISCOVERY_SOURCES, which fails closed).
type FileDiscovery struct {
	Sources       []string      `json:"sources,omitempty"`
	Timeout       *FileDuration `json:"timeout,omitempty"`
	DetectTimeout *FileDuration `json:"detect_timeout,omitempty"`
	MaxOutputSize *int64        `json:"max_output_size,omitempty"`
}

// FileDuration is a time.Duration marshaled as a Go duration string.
type FileDuration time.Duration

// UnmarshalJSON implements json.Unmarshaler: strings parsed with
// time.ParseDuration; anything else (numbers, bools) is rejected. A JSON
// null never reaches this method (the pointer stays nil and decodes as
// absent — see File).
func (d *FileDuration) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("config: duration must be a string like \"30s\", got %s", string(raw))
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("config: invalid duration %q: %w", s, err)
	}
	*d = FileDuration(v)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d FileDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// LoadFile reads and validates a JSON config file. Unknown keys are
// rejected (a typo must fail, never silently mean "default"), explicit
// nulls decode as absent (identical to a missing key — see File), and
// every range is checked with the same bounds the CLI enforces on flags:
// concurrency >= 1, timeouts/TTLs >= 0, rate finite and >= 0, max output
// > 0.
func LoadFile(path string) (File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return File{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if dec.More() {
		return File{}, fmt.Errorf("config: parse %s: trailing data after JSON document", path)
	}
	if err := f.validate(); err != nil {
		return File{}, fmt.Errorf("config: %s: %w", path, err)
	}
	return f, nil
}

func (f File) validate() error {
	if f.Concurrency != nil && *f.Concurrency < 1 {
		return fmt.Errorf("concurrency must be >= 1 (got %d)", *f.Concurrency)
	}
	if f.Timeout != nil && time.Duration(*f.Timeout) < 0 {
		return fmt.Errorf("timeout must be >= 0 (got %s)", time.Duration(*f.Timeout))
	}
	if f.Rate != nil && (math.IsNaN(*f.Rate) || math.IsInf(*f.Rate, 0) || *f.Rate < 0) {
		return fmt.Errorf("rate must be finite and >= 0 (got %v)", *f.Rate)
	}
	if f.Cache != nil {
		if f.Cache.TTL != nil && time.Duration(*f.Cache.TTL) < 0 {
			return fmt.Errorf("cache.ttl must be >= 0 (got %s)", time.Duration(*f.Cache.TTL))
		}
	}
	if f.Discovery != nil {
		if f.Discovery.Timeout != nil && time.Duration(*f.Discovery.Timeout) < 0 {
			return fmt.Errorf("discovery.timeout must be >= 0")
		}
		if f.Discovery.DetectTimeout != nil && time.Duration(*f.Discovery.DetectTimeout) < 0 {
			return fmt.Errorf("discovery.detect_timeout must be >= 0")
		}
		if f.Discovery.MaxOutputSize != nil && *f.Discovery.MaxOutputSize < 1 {
			return fmt.Errorf("discovery.max_output_size must be >= 1")
		}
	}
	return nil
}

// WithFile returns c with file-backed values applied wherever c still
// carries the DEFAULT (see Default): the file beats defaults, while
// explicit CLI flags and environment override later (WithEnv runs after
// WithFile in resolveBaseConfig, then the per-flag *Set gates at use
// sites — so a flag the operator typed always wins over file and env).
// Fields the operator set programmatically to non-default values always
// win over the file. Cache.Enabled applies only when true (false is both
// the default and an explicit off — indistinguishable and identical here;
// use flags (--no-cache) or env (RAVENRECON_CACHE_ENABLED=false) to force
// the cache off over an enabled base: the file can enable the cache,
// never disable it).
func (c Config) WithFile(f File) Config {
	out := c
	def := Default()
	if f.Concurrency != nil && out.Concurrency == def.Concurrency {
		out.Concurrency = *f.Concurrency
	}
	if f.Timeout != nil && out.Timeout == def.Timeout {
		out.Timeout = time.Duration(*f.Timeout)
	}
	if f.Rate != nil && out.Rate == def.Rate {
		out.Rate = *f.Rate
	}
	if f.UserAgent != nil && out.UserAgent == def.UserAgent {
		out.UserAgent = *f.UserAgent
	}
	if f.Cache != nil {
		if f.Cache.Enabled != nil && *f.Cache.Enabled {
			out.Cache.Enabled = true
		}
		if f.Cache.Dir != nil && out.Cache.Dir == "" {
			out.Cache.Dir = *f.Cache.Dir
		}
		if f.Cache.TTL != nil && out.Cache.TTL == 0 {
			out.Cache.TTL = time.Duration(*f.Cache.TTL)
		}
	}
	if f.Discovery != nil {
		if len(f.Discovery.Sources) > 0 && len(out.Discovery.Sources) == 0 {
			out.Discovery.Sources = append([]string(nil), f.Discovery.Sources...)
		}
		if f.Discovery.Timeout != nil && out.Discovery.Timeout == 0 {
			out.Discovery.Timeout = time.Duration(*f.Discovery.Timeout)
		}
		if f.Discovery.DetectTimeout != nil && out.Discovery.DetectTimeout == 0 {
			out.Discovery.DetectTimeout = time.Duration(*f.Discovery.DetectTimeout)
		}
		if f.Discovery.MaxOutputSize != nil && out.Discovery.MaxOutputSize == 0 {
			out.Discovery.MaxOutputSize = *f.Discovery.MaxOutputSize
		}
	}
	return out
}

// WithEnv returns c overridden by the environment (os.LookupEnv): the env <-
// file precedence step. Presence is explicit — a SET variable is always
// honored, so set-but-empty (RAVENRECON_TIMEOUT="") is an ERROR, never a
// silent "unset" (silently ignoring operator intent is worse than
// failing); only truly unset variables leave the value untouched.
// Unparsable values are ERRORS for the same reason. Recognized variables:
//
//	RAVENRECON_CONCURRENCY              int >= 1
//	RAVENRECON_TIMEOUT                  Go duration, >= 0
//	RAVENRECON_RATE                     float, finite, >= 0
//	RAVENRECON_USER_AGENT               string (non-empty)
//	RAVENRECON_CACHE_ENABLED            bool (1/true/yes/on, 0/false/no/off)
//	RAVENRECON_CACHE_DIR                string (non-empty)
//	RAVENRECON_CACHE_TTL                Go duration, >= 0
//	RAVENRECON_DISCOVERY_SOURCES        comma-separated source names (a set-but-empty value fails closed, unlike a file sources: [] which applies nothing)
//	RAVENRECON_DISCOVERY_TIMEOUT        Go duration, >= 0
//	RAVENRECON_DISCOVERY_DETECT_TIMEOUT Go duration, >= 0
//	RAVENRECON_DISCOVERY_MAX_OUTPUT_SIZE int >= 1

// envPrefix namespaces every configuration environment variable.
const envPrefix = "RAVENRECON_"

func (c Config) WithEnv() (Config, error) {
	return c.withEnv(func(key string) (string, bool) {
		return os.LookupEnv(envPrefix + key)
	})
}

func (c Config) withEnv(lookup func(string) (string, bool)) (Config, error) {
	out := c
	if v, ok := lookup("CONCURRENCY"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 {
			return c, fmt.Errorf("config: %sCONCURRENCY must be an int >= 1 (got %q)", envPrefix, v)
		}
		out.Concurrency = n
	}
	if v, ok := lookup("TIMEOUT"); ok {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil || d < 0 {
			return c, fmt.Errorf("config: %sTIMEOUT must be a duration >= 0 (got %q)", envPrefix, v)
		}
		out.Timeout = d
	}
	if v, ok := lookup("RATE"); ok {
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			return c, fmt.Errorf("config: %sRATE must be finite and >= 0 (got %q)", envPrefix, v)
		}
		out.Rate = f
	}
	if v, ok := lookup("USER_AGENT"); ok {
		if strings.TrimSpace(v) == "" {
			return c, fmt.Errorf("config: %sUSER_AGENT must not be empty", envPrefix)
		}
		out.UserAgent = strings.TrimSpace(v)
	}
	if v, ok := lookup("CACHE_ENABLED"); ok {
		b, err := parseEnvBool(v)
		if err != nil {
			return c, fmt.Errorf("config: %sCACHE_ENABLED: %w", envPrefix, err)
		}
		out.Cache.Enabled = b
	}
	if v, ok := lookup("CACHE_DIR"); ok {
		if strings.TrimSpace(v) == "" {
			return c, fmt.Errorf("config: %sCACHE_DIR must not be empty", envPrefix)
		}
		out.Cache.Dir = strings.TrimSpace(v)
	}
	if v, ok := lookup("CACHE_TTL"); ok {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil || d < 0 {
			return c, fmt.Errorf("config: %sCACHE_TTL must be a duration >= 0 (got %q)", envPrefix, v)
		}
		out.Cache.TTL = d
	}
	if v, ok := lookup("DISCOVERY_SOURCES"); ok {
		var srcs []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				srcs = append(srcs, s)
			}
		}
		if len(srcs) == 0 {
			return c, fmt.Errorf("config: %sDISCOVERY_SOURCES must name at least one source", envPrefix)
		}
		out.Discovery.Sources = srcs
	}
	if v, ok := lookup("DISCOVERY_TIMEOUT"); ok {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil || d < 0 {
			return c, fmt.Errorf("config: %sDISCOVERY_TIMEOUT must be a duration >= 0 (got %q)", envPrefix, v)
		}
		out.Discovery.Timeout = d
	}
	if v, ok := lookup("DISCOVERY_DETECT_TIMEOUT"); ok {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil || d < 0 {
			return c, fmt.Errorf("config: %sDISCOVERY_DETECT_TIMEOUT must be a duration >= 0 (got %q)", envPrefix, v)
		}
		out.Discovery.DetectTimeout = d
	}
	if v, ok := lookup("DISCOVERY_MAX_OUTPUT_SIZE"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 {
			return c, fmt.Errorf("config: %sDISCOVERY_MAX_OUTPUT_SIZE must be an int >= 1 (got %q)", envPrefix, v)
		}
		out.Discovery.MaxOutputSize = int64(n)
	}
	return out, nil
}

// parseEnvBool parses 1/true/yes/on and 0/false/no/off
// (case-insensitive, surrounding space tolerated).
func parseEnvBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("must be a bool (1/true/yes/on, 0/false/no/off), got %q", v)
}
