package web

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// The pins in this file are the REVIEW-2026-08-25.md regressions for the
// web pack: R2-M1 (the 256-subject cap must carry an explicit truncation
// marker on every retained finding, never silently) and R2-M2 (a ".map"
// substring inside a host name is not a source map).

// TestWebPackCSPTruncationMarker is the R2-M1 regression: with more than
// 256 CSP-less hosts the rule returns exactly 256 findings and EVERY one
// carries meta["truncated"]="true" and meta["subjects_dropped"]="44".
// Before the fix the cap was silent — the same count with no markers.
func TestWebPackCSPTruncationMarker(t *testing.T) {
	reg := registerWebPack(t)
	const total = 300
	const wantKept = 256
	wantDropped := fmt.Sprintf("%d", total-wantKept)

	assets := make([]asset.Identity, 0, total)
	for i := 0; i < total; i++ {
		h := mustHost(t, fmt.Sprintf("host%03d.example.test", i))
		assets = append(assets, h.Identity())
	}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, detect.Snapshot{Assets: assets})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	count := 0
	for _, f := range rep.Findings {
		if f.RuleID != ruleCSPMissing {
			continue
		}
		count++
		if got := f.Metadata["truncated"]; got != "true" {
			t.Errorf("csp finding %d meta[truncated] = %q, want \"true\"", count, got)
		}
		if got := f.Metadata["subjects_dropped"]; got != wantDropped {
			t.Errorf("csp finding %d meta[subjects_dropped] = %q, want %q", count, got, wantDropped)
		}
	}
	if count != wantKept {
		t.Fatalf("csp findings = %d, want exactly %d", count, wantKept)
	}
}

// TestWebPackSourceMapIgnoresMapboxHost is the R2-M2 regression: ".map"
// occurring inside a HOST name ("api.mapbox.com") is not a source map.
// Only typed carriers fire — a .map path suffix, a sourcemap discovery
// label, or a sourcemap content type. Before the fix the rule matched
// ".map"/"sourcemap" anywhere in the full URL string and the mapbox script
// produced a finding. The control asset guards against the fix collapsing
// into silence.
func TestWebPackSourceMapIgnoresMapboxHost(t *testing.T) {
	reg := registerWebPack(t)

	mapboxJS := mustJS(t, "https://api.mapbox.com/mapbox-gl.js")
	mapboxJS, err := asset.WithContentType(mapboxJS, "application/javascript")
	if err != nil {
		t.Fatalf("WithContentType: %v", err)
	}
	controlJS := mustJS(t, "https://www.example.com/app.js.map")

	snap := detect.Snapshot{JavaScript: []asset.JavaScript{mapboxJS, controlJS}}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	count := 0
	for _, f := range rep.Findings {
		if f.RuleID != ruleSourceMapExposed {
			continue
		}
		count++
		if !strings.Contains(f.Subject.Value, "/app.js.map") {
			t.Errorf("sourcemap finding on unexpected subject %q, want only the typed .map carrier", f.Subject.Value)
		}
	}
	if count != 1 {
		t.Fatalf("sourcemap findings = %d, want 1 (typed .map carrier only; mapbox host must stay silent)", count)
	}
}
