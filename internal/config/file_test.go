package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ravenrecon.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFileValid(t *testing.T) {
	path := writeFile(t, `{
		"concurrency": 4,
		"timeout": "60s",
		"rate": 10.5,
		"user_agent": "test/1.0",
		"cache": {"enabled": true, "dir": "/tmp/c", "ttl": "1h"},
		"discovery": {"sources": ["subfinder", "amass"], "timeout": "30s", "detect_timeout": "5s", "max_output_size": 8388608}
	}`)
	f, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if *f.Concurrency != 4 || time.Duration(*f.Timeout) != time.Minute || *f.Rate != 10.5 {
		t.Errorf("scalars wrong: %+v", f)
	}
	if !*f.Cache.Enabled || *f.Cache.Dir != "/tmp/c" || time.Duration(*f.Cache.TTL) != time.Hour {
		t.Errorf("cache wrong: %+v", f.Cache)
	}
	if len(f.Discovery.Sources) != 2 || *f.Discovery.MaxOutputSize != 8388608 {
		t.Errorf("discovery wrong: %+v", f.Discovery)
	}
	base := Default().WithFile(f)
	if base.Concurrency != 4 || base.Timeout != time.Minute || base.Rate != 10.5 || base.UserAgent != "test/1.0" {
		t.Errorf("WithFile scalars wrong: %+v", base)
	}
	if !base.Cache.Enabled || base.Cache.Dir != "/tmp/c" || base.Cache.TTL != time.Hour {
		t.Errorf("WithFile cache wrong: %+v", base.Cache)
	}
	if len(base.Discovery.Sources) != 2 || base.Discovery.Timeout != 30*time.Second {
		t.Errorf("WithFile discovery wrong: %+v", base.Discovery)
	}
}

func TestLoadFileRejects(t *testing.T) {
	for name, content := range map[string]string{
		"unknown key":      `{"concurrenc": 4}`,
		"bad concurrency":  `{"concurrency": 0}`,
		"bad duration":     `{"timeout": 30}`,
		"bad duration str": `{"timeout": "soon"}`,
		"negative timeout": `{"timeout": "-1s"}`,
		"nan rate":         `{"rate": "fast"}`,
		"bad ttl":          `{"cache": {"ttl": "-1s"}}`,
		"bad max output":   `{"discovery": {"max_output_size": 0}}`,
		"trailing data":    `{} {}`,
	} {
		if _, err := LoadFile(writeFile(t, content)); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file must be rejected")
	}
}

func TestWithFilePreservesSetValues(t *testing.T) {
	base := Default()
	base.Concurrency = 16
	base.Cache.Dir = "/explicit"
	f, err := LoadFile(writeFile(t, `{"concurrency": 4, "cache": {"enabled": true, "dir": "/file"}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := base.WithFile(f)
	if got.Concurrency != 16 {
		t.Errorf("explicit concurrency overwritten: %d", got.Concurrency)
	}
	if got.Cache.Dir != "/explicit" {
		t.Errorf("explicit cache dir overwritten: %q", got.Cache.Dir)
	}
	if !got.Cache.Enabled {
		t.Error("file cache.enabled must apply")
	}
	// Empty file changes nothing.
	empty, err := LoadFile(writeFile(t, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := Default().WithFile(empty); !reflect.DeepEqual(got, Default()) {
		t.Errorf("empty file changed defaults: %+v", got)
	}
}

func TestWithEnv(t *testing.T) {
	get := func(env map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	}
	c, err := Default().withEnv(get(map[string]string{
		"CONCURRENCY":               "8",
		"TIMEOUT":                   "45s",
		"RATE":                      "2.5",
		"USER_AGENT":                "env/2.0",
		"CACHE_ENABLED":             "yes",
		"CACHE_DIR":                 "/env-cache",
		"CACHE_TTL":                 "30m",
		"DISCOVERY_SOURCES":         "subfinder, amass",
		"DISCOVERY_TIMEOUT":         "20s",
		"DISCOVERY_DETECT_TIMEOUT":  "7s",
		"DISCOVERY_MAX_OUTPUT_SIZE": "4194304",
	}))
	if err != nil {
		t.Fatalf("withEnv: %v", err)
	}
	if c.Concurrency != 8 || c.Timeout != 45*time.Second || c.Rate != 2.5 || c.UserAgent != "env/2.0" {
		t.Errorf("scalars wrong: %+v", c)
	}
	if !c.Cache.Enabled || c.Cache.Dir != "/env-cache" || c.Cache.TTL != 30*time.Minute {
		t.Errorf("cache wrong: %+v", c.Cache)
	}
	if len(c.Discovery.Sources) != 2 || c.Discovery.Timeout != 20*time.Second {
		t.Errorf("discovery wrong: %+v", c.Discovery)
	}
	if c.Discovery.DetectTimeout != 7*time.Second || c.Discovery.MaxOutputSize != 4194304 {
		t.Errorf("discovery tuning wrong: %+v", c.Discovery)
	}
	// Unset env leaves values alone.
	same, err := Default().withEnv(get(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(same, Default()) {
		t.Errorf("empty env changed defaults: %+v", same)
	}
	// Invalid values fail, never silently ignored.
	for name, env := range map[string]map[string]string{
		"bad concurrency": {"CONCURRENCY": "0"},
		"bad timeout":     {"TIMEOUT": "soon"},
		"bad rate":        {"RATE": "-1"},
		"empty ua":        {"USER_AGENT": "  "},
		"bad bool":        {"CACHE_ENABLED": "maybe"},
		"empty sources":   {"DISCOVERY_SOURCES": " , "},
		"bad detect":      {"DISCOVERY_DETECT_TIMEOUT": "-1s"},
		"bad max output":  {"DISCOVERY_MAX_OUTPUT_SIZE": "0"},
	} {
		if _, err := Default().withEnv(get(env)); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestWithEnvSetEmptyFails(t *testing.T) {
	// Presence is explicit (os.LookupEnv): a SET-but-empty variable is
	// operator intent with no value — an error, never a silent "unset".
	for _, key := range []string{
		"CONCURRENCY", "TIMEOUT", "RATE", "USER_AGENT", "CACHE_ENABLED",
		"CACHE_DIR", "CACHE_TTL", "DISCOVERY_SOURCES", "DISCOVERY_TIMEOUT",
		"DISCOVERY_DETECT_TIMEOUT", "DISCOVERY_MAX_OUTPUT_SIZE",
	} {
		get := func(k string) (string, bool) {
			if k == key {
				return "", true
			}
			return "", false
		}
		if _, err := Default().withEnv(get); err == nil {
			t.Errorf("set-empty %s must fail closed", key)
		}
	}
}

func TestLoadFileNullIsAbsent(t *testing.T) {
	// Explicit nulls decode as absent: every field stays nil and the
	// effective configuration is byte-identical to defaults.
	f, err := LoadFile(writeFile(t, `{
		"concurrency": null, "timeout": null, "rate": null, "user_agent": null,
		"cache": null, "discovery": null
	}`))
	if err != nil {
		t.Fatalf("LoadFile with nulls: %v", err)
	}
	if f.Concurrency != nil || f.Timeout != nil || f.Rate != nil || f.UserAgent != nil {
		t.Errorf("null scalars must stay nil: %+v", f)
	}
	if f.Cache != nil || f.Discovery != nil {
		t.Errorf("null sections must stay nil: %+v", f)
	}
	if got := Default().WithFile(f); !reflect.DeepEqual(got, Default()) {
		t.Errorf("null file changed defaults: %+v", got)
	}
	// Nested nulls behave the same.
	nested, err := LoadFile(writeFile(t, `{"cache": {"enabled": null, "dir": null, "ttl": null}}`))
	if err != nil {
		t.Fatalf("LoadFile with nested nulls: %v", err)
	}
	if got := Default().WithFile(nested); !reflect.DeepEqual(got, Default()) {
		t.Errorf("nested-null file changed defaults: %+v", got)
	}
}

func TestPrecedenceEnvOverFile(t *testing.T) {
	f, err := LoadFile(writeFile(t, `{"concurrency": 4, "timeout": "60s"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Default().WithFile(f).withEnv(func(k string) (string, bool) {
		if k == "CONCURRENCY" {
			return "8", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Concurrency != 8 {
		t.Errorf("env must beat file: %d", got.Concurrency)
	}
	if got.Timeout != time.Minute {
		t.Errorf("file must beat defaults: %v", got.Timeout)
	}
}

func TestPrecedenceEndToEnd(t *testing.T) {
	// The full flags > env > file > defaults chain at the config layer:
	// each key resolves from exactly one source, and an explicitly set
	// (flag-applied) programmatic value survives both later layers. The
	// CLI's per-flag *Set gates apply flags after this base (see
	// internal/cli), so a typed flag always wins over file and env.
	f, err := LoadFile(writeFile(t, `{
		"concurrency": 4, "timeout": "60s", "rate": 10.5,
		"cache": {"enabled": true, "dir": "/file-cache", "ttl": "1h"},
		"discovery": {"sources": ["subfinder"], "timeout": "30s"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"TIMEOUT": "45s", "CACHE_DIR": "/env-cache"}
	got, err := Default().WithFile(f).withEnv(func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Concurrency != 4 {
		t.Errorf("concurrency = %d, want 4 (file, env silent)", got.Concurrency)
	}
	if got.Timeout != 45*time.Second {
		t.Errorf("timeout = %v, want 45s (env beats file)", got.Timeout)
	}
	if got.Rate != 10.5 {
		t.Errorf("rate = %v, want 10.5 (file beats defaults)", got.Rate)
	}
	if !got.Cache.Enabled || got.Cache.Dir != "/env-cache" || got.Cache.TTL != time.Hour {
		t.Errorf("cache = %+v, want enabled+ttl from file, dir from env", got.Cache)
	}
	if len(got.Discovery.Sources) != 1 || got.Discovery.Timeout != 30*time.Second {
		t.Errorf("discovery = %+v, want file values", got.Discovery)
	}
	// Explicit (flag-applied) values beat file and env alike.
	explicit := Default()
	explicit.Concurrency = 16
	explicit.Timeout = 5 * time.Second
	explicit.Cache.Dir = "/flag-cache"
	after, err := explicit.WithFile(f).withEnv(func(k string) (string, bool) {
		if k == "CACHE_DIR" {
			return "/env-cache", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if after.Concurrency != 16 || after.Timeout != 5*time.Second {
		t.Errorf("explicit scalars overwritten: %+v", after)
	}
	if after.Cache.Dir != "/env-cache" {
		t.Errorf("env must beat even explicit file-held values for unset-by-flag keys: %q", after.Cache.Dir)
	}
}

func TestWithFileCacheEnabledFalseNeverDisables(t *testing.T) {
	// A file cache.enabled:false never applies: over an enabled base the
	// cache stays enabled (only flags and env force it off), and over a
	// disabled base it stays disabled. The file can enable the cache,
	// never disable it.
	f, err := LoadFile(writeFile(t, `{"cache": {"enabled": false}}`))
	if err != nil {
		t.Fatal(err)
	}
	enabled := Default()
	enabled.Cache.Enabled = true
	if got := enabled.WithFile(f); !got.Cache.Enabled {
		t.Error("file cache.enabled:false disabled an enabled base (want still enabled)")
	}
	if got := Default().WithFile(f); got.Cache.Enabled {
		t.Error("file cache.enabled:false enabled a disabled base (want still disabled)")
	}
}

func TestWithEnvStoresTrimmedStrings(t *testing.T) {
	// Surrounding whitespace is tolerated on the way in but never stored:
	// USER_AGENT and CACHE_DIR keep their trimmed forms.
	get := func(env map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	}
	got, err := Default().withEnv(get(map[string]string{
		"USER_AGENT": "  env/2.0  ",
		"CACHE_DIR":  "  /env-cache  ",
	}))
	if err != nil {
		t.Fatalf("withEnv: %v", err)
	}
	if got.UserAgent != "env/2.0" {
		t.Errorf("UserAgent = %q, want trimmed %q", got.UserAgent, "env/2.0")
	}
	if got.Cache.Dir != "/env-cache" {
		t.Errorf("Cache.Dir = %q, want trimmed %q", got.Cache.Dir, "/env-cache")
	}
}
