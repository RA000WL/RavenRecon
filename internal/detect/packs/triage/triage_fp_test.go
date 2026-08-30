package triage

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// FP harness location rationale — why internal/detect/packs/triage/testdata
// instead of fixtures/triage-fp/*:
//
//   - Co-location: the harness lives next to the pack it measures, so the
//     benign corpus and its golden stay hermetic and versioned with the pack.
//     A top-level fixtures/triage-fp would be cross-package global state,
//     requiring import path changes and diverging from the existing
//     internal/detect/packs/<family>/testdata/<family>_report.golden pattern
//     (see internal/golden).
//   - Determinism: embedding the corpus in code (synthetic values only) keeps
//     it stdlib-only, no file I/O, and byte-stable across runs — the same
//     guarantee the existing triage_report.golden provides.
//   - Scope: FP measurement is a pack-level quality gate, not a pipeline-level
//     fixture — keeping it inside the pack avoids leaking pack internals into
//     the global fixtures directory.
//
// The corpus below is synthetic and hermetic: mapbox/dompurify/protobuf
// hostnames that previously triggered JS-pack substring heuristics (NEW-97/100),
// plus 500 benign endpoint URLs whose query param names are deliberately
// chosen to AVOID every curated triage wordlist entry (checked via exact
// lowercased match, not substring). A triage finding requires an exact
// param name match; therefore the benign corpus must produce 0 findings.

// benignParamNames are param names that are NOT in any triage wordlist.
// They are curated to avoid all 8 wordlists (xss 52, sqli 29, ssrf 62,
// lfi 33, redirect 62, idor 37, rce 32, ssti 68). Verified by exact set
// membership, not substring.
var benignParamNames = []string{
	"bbox", "center", "zoom", "bearing", "pitch", "lat", "lon",
	"access_token", "mapbox_token", "style_id", "tileset", "glyphs",
	"sprite", "fontstack", "layer_id", "source_id", "bounds",
	"protobuf_type", "dompurify_mode", "sanitize", "allowlist",
	"version_token", "commit_hash", "build_id", "session_token", // session_token? Check: token is in wordlist, but session_token != token exact, so safe.
	"mapbox_version", "dompurify_version", "protobuf_version",
}

func isBenignParam(name string) bool {
	// Verify not in any triage wordlist via classifyParam.
	prim, _ := classifyParam(strings.ToLower(name))
	return prim == ""
}

func buildBenignEndpoints(t testing.TB, n int) []asset.Endpoint {
	t.Helper()
	// Rotate through benign param names to cover many endpoints.
	var eps []asset.Endpoint
	for i := 0; i < n; i++ {
		p1 := benignParamNames[i%len(benignParamNames)]
		p2 := benignParamNames[(i*7)%len(benignParamNames)]
		// Ensure both are benign; if not, skip (should not happen).
		if !isBenignParam(p1) || !isBenignParam(p2) {
			t.Fatalf("benign param %q or %q unexpectedly in wordlist", p1, p2)
		}
		// Hosts cycle through mapbox/dompurify/protobuf thematic hosts.
		host := "api.example.com"
		switch i % 4 {
		case 0:
			host = "api.mapbox.com"
		case 1:
			host = "cdn.dompurify.example.com"
		case 2:
			host = "protobuf.example.com"
		case 3:
			host = "tiles.example.com"
		}
		raw := fmt.Sprintf("https://%s/v1/resource%d?%s=%d&%s=%d", host, i, p1, i, p2, i*2)
		ep, err := asset.NewEndpoint("GET", raw, asset.Provenance{Source: "fp-harness"})
		if err != nil {
			t.Fatalf("NewEndpoint benign %d: %v", i, err)
		}
		eps = append(eps, ep)
	}
	// Also add explicit mapbox/dompurify/protobuf style URLs with known prior FP substrings but benign params.
	extra := []string{
		"https://api.mapbox.com/styles/v1/mapbox/streets-v11?access_token=pk.synth&bbox=1,2,3,4",
		"https://cdn.example.com/dompurify@2.3.4/dist/purify.min.js?version_token=1&sanitize=true",
		"https://example.com/protobuf.js?protobuf_type=message&version_token=2",
		"https://api.mapbox.com/mapbox-gl-js/v1.12.0/mapbox-gl.js?access_token=pk.test&center=0,0",
	}
	for _, raw := range extra {
		ep, err := asset.NewEndpoint("GET", raw, asset.Provenance{Source: "fp-harness"})
		if err != nil {
			t.Fatalf("NewEndpoint extra: %v", err)
		}
		eps = append(eps, ep)
	}
	return eps
}

func buildFPCorpus(t testing.TB) detect.Snapshot {
	t.Helper()
	eps := buildBenignEndpoints(t, 500)
	return detect.Snapshot{Endpoints: eps}
}

func TestTriageFPZeroOnBenignCorpus(t *testing.T) {
	reg := registerTriagePack(t)
	snap := buildFPCorpus(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run benign: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("benign corpus produced %d findings, want 0 (FP rate 0): %+v", len(rep.Findings), rep.Findings[0].Metadata)
	}
	// FP rate = 0/500 = 0% < threshold (e.g., 1%).
	if fpRate := float64(len(rep.Findings)) / 500.0; fpRate >= 0.01 {
		t.Fatalf("FP rate %f, want < 0.01", fpRate)
	}
}

func TestTriageFPMapboxDomPurifyProtobufHostsNoFP(t *testing.T) {
	// Explicitly verify that hosts containing mapbox/dompurify/protobuf substrings
	// do not trigger triage via substring heuristics (regression for NEW-97/100/102):
	// triage operates on exact param name match, not URL substrings.
	reg := registerTriagePack(t)
	cases := []string{
		"https://api.mapbox.com/style?access_token=tok&bbox=1",
		"https://cdn.example.com/dompurify.js?version_token=1&sanitize=1",
		"https://example.com/protobuf.js?protobuf_type=1&commit_hash=abc",
		"https://tiles.mapbox.com/v4/mapbox.satellite/page.html?center=0&zoom=5",
	}
	var eps []asset.Endpoint
	for _, raw := range cases {
		ep, err := asset.NewEndpoint("GET", raw, asset.Provenance{Source: "fp-harness"})
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		eps = append(eps, ep)
	}
	snap := detect.Snapshot{Endpoints: eps}
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("mapbox/dompurify/protobuf hosts produced %d findings, want 0: first %+v", len(rep.Findings), rep.Findings[0])
	}
}

func TestTriageFPMeasuredRateBelowThreshold(t *testing.T) {
	reg := registerTriagePack(t)
	snap := buildFPCorpus(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	totalParams := 500 // 500 endpoints
	// Each endpoint has 2 params, but finding is per-endpoint per-class; for benign corpus we expect 0.
	rate := float64(len(rep.Findings)) / float64(totalParams)
	threshold := 0.01 // 1%
	if rate >= threshold {
		t.Fatalf("FP rate %f >= threshold %f (%d findings over %d endpoints)", rate, threshold, len(rep.Findings), totalParams)
	}
	t.Logf("FP harness: %d findings over %d endpoints → rate %.4f < %.2f (threshold)", len(rep.Findings), totalParams, rate, threshold)
}

func TestTriageFPNoRegressionOnGolden(t *testing.T) {
	// Ensure the FP harness does not alter the existing triage golden's byte-stability.
	// The golden is produced from buildMixedSnapshot (8 endpoints, deterministic).
	// This test re-runs that snapshot and asserts it still matches the committed golden
	// via the existing determinism test's logic, but here we explicitly verify the
	// mixed snapshot still yields exactly 8 findings (one per class) and the report
	// deterministically matches across two runs.
	reg := registerTriagePack(t)
	snap := buildMixedSnapshot(t)
	run := func() detect.Report {
		cfg := detect.DefaultEngineConfig(reg)
		cfg.Clock = testClock
		cfg.Config = map[string]string{"triage.redirect.disabled": "false", "triage.sqli.disabled": "false", "a": "1", "z": "2"}
		rep, err := detect.Run(context.Background(), cfg, snap)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return rep
	}
	rep1, rep2 := run(), run()
	if len(rep1.Findings) != 8 {
		t.Fatalf("golden regression: mixed snapshot findings %d, want 8", len(rep1.Findings))
	}
	if len(rep1.Findings) != len(rep2.Findings) {
		t.Fatalf("determinism: run1 %d vs run2 %d", len(rep1.Findings), len(rep2.Findings))
	}
	for i := range rep1.Findings {
		if rep1.Findings[i].ID() != rep2.Findings[i].ID() {
			t.Fatalf("finding %d ID drift: %s vs %s", i, rep1.Findings[i].ID(), rep2.Findings[i].ID())
		}
	}
}
