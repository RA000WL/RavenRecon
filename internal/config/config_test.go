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

	if cfg.Timeout != 10*time.Second {
		t.Fatalf("expected 10s timeout, got %s", cfg.Timeout)
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
