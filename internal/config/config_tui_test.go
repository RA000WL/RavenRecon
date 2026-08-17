package config

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestDefaultTUI(t *testing.T) {
	cfg := DefaultTUI()

	if cfg.Enabled {
		t.Fatal("TUI must default to disabled")
	}
	if cfg.Compact || cfg.Quiet {
		t.Fatal("TUI compact/quiet must default to false")
	}
	if cfg.Color != "auto" {
		t.Fatalf("TUI color must default to \"auto\", got %q", cfg.Color)
	}
	if cfg.RefreshInterval <= 0 {
		t.Fatalf("TUI refresh interval must default positive, got %s", cfg.RefreshInterval)
	}
	if cfg.MaxEventHistory < 1 || cfg.MaxEventHistory > 4096 {
		t.Fatalf("TUI max event history must default within [1,4096], got %d", cfg.MaxEventHistory)
	}
	if cfg.InterestingRate <= 0 {
		t.Fatalf("TUI interesting rate must default positive, got %v", cfg.InterestingRate)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default TUI config must validate: %v", err)
	}
}

func TestDefaultIncludesTUI(t *testing.T) {
	cfg := Default()

	if cfg.TUI.Enabled {
		t.Fatal("global default must keep the TUI disabled")
	}
	if err := cfg.TUI.Validate(); err != nil {
		t.Fatalf("global default TUI section must validate: %v", err)
	}
}

func TestTUIValidateRejectsNonPositiveRefreshInterval(t *testing.T) {
	cfg := DefaultTUI()
	for _, d := range []time.Duration{0, -time.Second, -1} {
		cfg.RefreshInterval = d
		if err := cfg.Validate(); err == nil {
			t.Fatalf("refresh interval %s must be rejected", d)
		} else if !strings.Contains(err.Error(), "RefreshInterval") {
			t.Fatalf("error must name the field, got %v", err)
		}
	}
}

func TestTUIValidateRejectsUnboundedEventHistory(t *testing.T) {
	cfg := DefaultTUI()
	for _, n := range []int{0, -1, 4097, 1 << 20} {
		cfg.MaxEventHistory = n
		if err := cfg.Validate(); err == nil {
			t.Fatalf("max event history %d must be rejected", n)
		}
	}
	cfg.MaxEventHistory = 1
	if err := cfg.Validate(); err != nil {
		t.Fatalf("max event history 1 is the valid lower bound: %v", err)
	}
	cfg.MaxEventHistory = 4096
	if err := cfg.Validate(); err != nil {
		t.Fatalf("max event history 4096 is the valid upper bound: %v", err)
	}
}

func TestTUIValidateRejectsUnknownColorMode(t *testing.T) {
	cfg := DefaultTUI()
	for _, c := range []string{"", "Auto", "ON", "sometimes", "auto "} {
		cfg.Color = c
		if err := cfg.Validate(); err == nil {
			t.Fatalf("color mode %q must be rejected", c)
		}
	}
	for _, c := range []string{"auto", "on", "off"} {
		cfg.Color = c
		if err := cfg.Validate(); err != nil {
			t.Fatalf("color mode %q must validate: %v", c, err)
		}
	}
}

func TestTUIValidateRejectsNegativeOrNaNInterestingRate(t *testing.T) {
	cfg := DefaultTUI()
	for _, r := range []float64{-1, -0.5, math.NaN()} {
		cfg.InterestingRate = r
		if err := cfg.Validate(); err == nil {
			t.Fatalf("interesting rate %v must be rejected", r)
		}
	}
	cfg.InterestingRate = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("0 (defer to default) must validate: %v", err)
	}
	cfg.InterestingRate = 25
	if err := cfg.Validate(); err != nil {
		t.Fatalf("positive rate must validate: %v", err)
	}
}
