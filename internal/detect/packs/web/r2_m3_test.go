package web

import (
	"context"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// TestWebPackCSPPerHostIsolation is the REVIEW-2026-08-25.md R2-M3 regression:
// CSP/HSTS absence was corpus-global (hasCSP/hasHSTS scans whole corpus);
// fix added hostHasCSP/hostHasHSTS per-host functions. This pin proves
// per-host isolation: two hosts where only hostA carries CSP evidence must
// produce exactly one web.csp.missing finding for hostB, not 0 (global
// hasCSP would suppress all) and not 2 (leaking hostA).
func TestWebPackCSPPerHostIsolation(t *testing.T) {
	reg := registerWebPack(t)

	hostA := mustHost(t, "a.example.test")
	hostB := mustHost(t, "b.example.test")

	// hostA carries CSP evidence; hostB carries none. Indicator intentionally
	// contains "content-security-policy" so hasCSP/hostHasCSP recognise it.
	ev := mustEvidence(t, asset.MethodHeader, "header:content-security-policy", "default-src 'self'", hostA.Identity())

	snap := detect.Snapshot{
		Assets:   []asset.Identity{hostA.Identity(), hostB.Identity()},
		Evidence: []asset.Evidence{ev},
	}

	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock

	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var cspFindings []asset.Finding
	for _, f := range rep.Findings {
		if f.RuleID == ruleCSPMissing {
			cspFindings = append(cspFindings, f)
		}
	}

	if len(cspFindings) != 1 {
		t.Fatalf("web.csp.missing findings = %d, want 1 (exactly hostB; global hasCSP would give 0)", len(cspFindings))
	}

	got := cspFindings[0]
	if !got.Subject.Equal(hostB.Identity()) {
		t.Fatalf("csp missing subject = %q, want %q (per-host subject for hostB)", got.Subject.String(), hostB.Identity().String())
	}
	if got.Subject.Value != hostB.Name {
		t.Fatalf("csp missing subject value = %q, want %q", got.Subject.Value, hostB.Name)
	}
	// Ensure hostA is not erroneously flagged.
	if got.Subject.Equal(hostA.Identity()) {
		t.Fatalf("csp missing incorrectly flagged hostA %q, want hostB", hostA.Identity().String())
	}
}
