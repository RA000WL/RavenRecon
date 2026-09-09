package adapt

import (
	"testing"

	"github.com/RA000WL/RavenRecon/internal/httpprobe"
)

// TestSANProvenancePin pins the single shared SAN provenance literal: the
// passive TLS-SAN expansion (expandTLSSANHosts) and the engine's SAN-target
// synthesis (httpprobe.SynthesizeSANProbeTargets) must carry the same
// provenance source, or a SAN host probed via feedback and a SAN host
// expanded passively would disagree on origin. Both call sites reference
// httpprobe.SANProvenance directly — there is no second literal — so this
// test pins the shared value against the persisted provenance contract and
// fails loudly if either side reintroduces its own copy with a
// diverged spelling.
func TestSANProvenancePin(t *testing.T) {
	if httpprobe.SANProvenance != "tls-san" {
		t.Fatalf("httpprobe.SANProvenance = %q, want %q", httpprobe.SANProvenance, "tls-san")
	}
}
