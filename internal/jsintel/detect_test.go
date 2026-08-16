// Technology detection tests: the fixed marker table, deterministic
// retention order, per-marker evidence, per-file caps, and the
// technology_to_evidence edge derivation.
package jsintel

import (
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// testDetectConfig returns a Config for detection unit tests.
func testDetectConfig() Config {
	return Config{Source: "test-src", Clock: newFakeClock(fixedTime)}
}

func TestDetectTechnologies(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u, Prov: asset.Provenance{Source: "test-src"}}
	content := []byte(`React.createElement("a"); import "react-dom";`)
	out := detectTechnologies(js, content, testDetectConfig())

	if len(out.techs) != 1 {
		t.Fatalf("techs = %d, want 1", len(out.techs))
	}
	tech := out.techs[0]
	if tech.Name != "react" || tech.Category != asset.CategoryFramework {
		t.Errorf("tech = %+v, want react/framework", tech)
	}
	// Two matched markers (0.6 and 0.5): score = 1 - 0.4*0.5 = 0.8 = High.
	if tech.Prov.Confidence != 0.8 {
		t.Errorf("confidence = %v, want 0.8", tech.Prov.Confidence)
	}
	if tech.Prov.Source != "test-src" || !tech.Prov.DiscoveredAt.Equal(fixedTime) {
		t.Errorf("provenance = %+v, want test-src at %v", tech.Prov, fixedTime)
	}
	// One Evidence record per matched marker, MethodJS, js_content: indicator.
	if len(out.evidence) != 2 {
		t.Fatalf("evidence = %d, want 2 (one per matched marker)", len(out.evidence))
	}
	needles := map[string]bool{}
	for _, ev := range out.evidence {
		if ev.Method != asset.MethodJS {
			t.Errorf("evidence method = %q, want js", ev.Method)
		}
		if !ev.Source.Equal(js.Identity()) {
			t.Errorf("evidence source = %q, want %q", ev.Source, js.Identity())
		}
		needle, ok := strings.CutPrefix(ev.Indicator, "js_content:")
		if !ok || needle == "" || ev.Value != needle {
			t.Errorf("evidence indicator/value = %q/%q, want a js_content marker", ev.Indicator, ev.Value)
		}
		needles[needle] = true
	}
	if !needles["React.createElement"] || !needles["react-dom"] {
		t.Errorf("matched markers = %v, want both react markers", needles)
	}
	if out.dropped != 0 {
		t.Errorf("dropped = %d, want 0", out.dropped)
	}
}

func TestDetectTechnologiesNoMatch(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	out := detectTechnologies(js, []byte("var x = 1;"), testDetectConfig())
	if len(out.techs) != 0 || len(out.evidence) != 0 {
		t.Errorf("techs/evidence = %d/%d, want none", len(out.techs), len(out.evidence))
	}
}

func TestDetectTechnologiesOrderDeterministic(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}

	// react: 0.8 (React.createElement + react-dom), vue: 0.6 (one marker).
	// Retention order is score desc, then name asc.
	content := []byte(`React.createElement("a"); import "react-dom"; window.__VUE__ = 1;`)
	out := detectTechnologies(js, content, testDetectConfig())
	if len(out.techs) != 2 {
		t.Fatalf("techs = %d, want 2", len(out.techs))
	}
	if out.techs[0].Name != "react" || out.techs[1].Name != "vue" {
		t.Errorf("order = %q/%q, want react then vue (score desc)", out.techs[0].Name, out.techs[1].Name)
	}

	// Score tie: bootstrap (0.2) and cloudflare (0.2). Name asc: bootstrap
	// before cloudflare.
	content2 := []byte(`bootstrap; cloudflare;`)
	out2 := detectTechnologies(js, content2, testDetectConfig())
	if len(out2.techs) != 2 {
		t.Fatalf("techs = %d, want 2", len(out2.techs))
	}
	if out2.techs[0].Name != "bootstrap" || out2.techs[1].Name != "cloudflare" {
		t.Errorf("tie order = %q/%q, want bootstrap then cloudflare (name asc)", out2.techs[0].Name, out2.techs[1].Name)
	}
}

func TestDetectTechnologiesCaps(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	// webpack: 0.91 (three markers), react: 0.6 (one marker). Cap techs at
	// 1: webpack retained, react dropped. Cap evidence at 2: the first two
	// markers' evidence retained (webpack's, in table order); the rest
	// dropped — INCLUDING react's marker, whose technology was capped (the
	// marker is a real observation but the evidence cap applies).
	content := []byte(`__webpack_require__(1); webpackChunk; __webpack_modules__; React.createElement("a");`)
	cfg := testDetectConfig()
	cfg.MaxTechPerFile = 1
	cfg.MaxEvidencePerFile = 2
	out := detectTechnologies(js, content, cfg)

	if len(out.techs) != 1 || out.techs[0].Name != "webpack" {
		t.Fatalf("techs = %+v, want only webpack (react dropped past the tech cap)", out.techs)
	}
	if len(out.evidence) != 2 {
		t.Fatalf("evidence = %d, want 2 (evidence cap)", len(out.evidence))
	}
	// dropped: react tech (1) + webpack's third marker (1) + react's marker (1).
	if out.dropped != 3 {
		t.Errorf("dropped = %d, want 3", out.dropped)
	}
}

func TestTechnologyEvidenceEdges(t *testing.T) {
	u := mustURL(t, "https://example.com/app.js")
	js := asset.JavaScript{URL: u}
	content := []byte(`__webpack_require__(1); webpackChunk; __webpack_modules__; React.createElement("a");`)
	cfg := testDetectConfig()
	cfg.MaxTechPerFile = 1 // webpack retained; react's evidence retained without an edge
	out := detectTechnologies(js, content, cfg)
	if len(out.techs) != 1 || len(out.evidence) != 4 {
		t.Fatalf("techs/evidence = %d/%d, want 1/4", len(out.techs), len(out.evidence))
	}

	edges := technologyEvidenceEdges(out.techs, out.evidence)
	// Only webpack's three markers link: react's evidence has no retained
	// technology, so it has no technology_to_evidence edge.
	if len(edges) != 3 {
		t.Fatalf("edges = %d, want 3 (webpack's markers only)", len(edges))
	}
	wantFrom := out.techs[0].Identity()
	for _, e := range edges {
		if e.Kind != asset.RelationshipTechnologyToEvidence {
			t.Errorf("edge kind = %q, want technology_to_evidence", e.Kind)
		}
		if !e.From.Equal(wantFrom) {
			t.Errorf("edge from = %q, want %q", e.From, wantFrom)
		}
	}
}
