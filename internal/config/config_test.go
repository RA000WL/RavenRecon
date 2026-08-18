package config

import (
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg.Concurrency <= 0 {
		t.Fatalf("expected positive concurrency, got %d", cfg.Concurrency)
	}

	if cfg.Timeout <= 0 {
		t.Fatalf("expected positive timeout, got %s", cfg.Timeout)
	}

	if cfg.Rate <= 0 {
		t.Fatalf("expected positive rate, got %f", cfg.Rate)
	}

	if cfg.UserAgent == "" {
		t.Fatal("expected non-empty user agent")
	}

	if cfg.Timeout != 120*time.Second {
		t.Fatalf("expected 120s timeout, got %s", cfg.Timeout)
	}
}

func TestDefaultCache(t *testing.T) {
	cfg := Default()

	if cfg.Cache.Enabled {
		t.Fatal("cache must default to disabled")
	}
	if cfg.Cache.Dir != "" {
		t.Fatalf("cache dir must default to empty (platform default), got %q", cfg.Cache.Dir)
	}
	if cfg.Cache.TTL != 0 {
		t.Fatalf("cache TTL must default to disabled (0), got %s", cfg.Cache.TTL)
	}
}

func TestDefaultDiscovery(t *testing.T) {
	cfg := Default()

	if len(cfg.Discovery.Sources) != 0 {
		t.Fatalf("discovery sources must default to empty (all built-in), got %v", cfg.Discovery.Sources)
	}
	if len(cfg.Discovery.Bin) != 0 {
		t.Fatalf("discovery bin overrides must default to empty (PATH lookup), got %v", cfg.Discovery.Bin)
	}
	if cfg.Discovery.Timeout != 0 {
		t.Fatalf("discovery timeout must default to 0 (defer to global/stage default), got %s", cfg.Discovery.Timeout)
	}
	if cfg.Discovery.DetectTimeout != 0 {
		t.Fatalf("discovery detect timeout must default to 0 (stage default), got %s", cfg.Discovery.DetectTimeout)
	}
	if cfg.Discovery.MaxOutputSize != 0 {
		t.Fatalf("discovery max output size must default to 0 (stage default), got %d", cfg.Discovery.MaxOutputSize)
	}
}
