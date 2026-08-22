package importer

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Format detection waterfall for Phase 1 plain-text family:
//
//   1. signature: <?xml / json.Valid / gzip magic (0x1f 0x8b)
//   2. structure probe: json.Decoder / xml token peek (on peek slice)
//   3. MIME + extension tie-break: extension hints confidence but never solely decides
//   4. line-shape classifier: asset.ParseURL/NewHost, netip.ParseAddr/Prefix, js heuristic
//
// This file implements steps 1-4 for plain-text. Future phases add JSON/XML
// importers; the waterfall ordering is preserved so those outrank plain.

// isXMLSignature reports whether peek looks like XML (<?xml prefix).
func isXMLSignature(peek []byte) bool {
	trim := bytes.TrimSpace(peek)
	return bytes.HasPrefix(trim, []byte("<?xml"))
}

// isJSONStructure reports whether peek is JSON (object/array) via json.Valid
// after trimming leading BOM/whitespace.
func isJSONStructure(peek []byte) bool {
	trim := bytes.TrimSpace(peek)
	// strip UTF-8 BOM
	trim = bytes.TrimPrefix(trim, []byte{0xef, 0xbb, 0xbf})
	if len(trim) == 0 {
		return false
	}
	if trim[0] != '{' && trim[0] != '[' {
		return false
	}
	return json.Valid(trim)
}

// extensionHint returns a confidence bump for extension tie-break.
func extensionHint(path, expectedExt string) float64 {
	if expectedExt == "" {
		return 0
	}
	if ext(path) == expectedExt {
		return 0.05
	}
	return 0
}

// LineShape classifies a single line's shape.
type LineShape int

const (
	ShapeUnknown LineShape = iota
	ShapeDomain
	ShapeHost
	ShapeURL
	ShapeIP
	ShapeCIDR
	ShapeJS
)

// classifyLine returns the shape of a single non-empty line without side effects.
func classifyLine(line string) LineShape {
	s := strings.TrimSpace(line)
	if s == "" {
		return ShapeUnknown
	}
	// JS heuristic first for URLs that are JS assets (e.g. https://example.com/app.js).
	// This ensures js.txt files are classified as JS rather than generic URL, so the
	// plain-js importer outranks plain-urls on .js content.
	if isJSLike(s) {
		if _, err := asset.NewJavaScript(s, asset.Provenance{}); err == nil {
			return ShapeJS
		}
		if looksLikeJSPath(s) {
			return ShapeJS
		}
	}
	// URL — has scheme://
	if isURLLike(s) {
		if _, err := asset.ParseURL(s, asset.Provenance{}); err == nil {
			return ShapeURL
		}
		// If URL-like but invalid, fall through to other shapes (counts as unknown)
	}
	// CIDR — contains slash and parses as prefix
	if strings.Contains(s, "/") {
		if _, err := netip.ParsePrefix(s); err == nil {
			return ShapeCIDR
		}
	}
	// IP — parses as addr
	if _, err := netip.ParseAddr(s); err == nil {
		return ShapeIP
	}
	// Host/domain — via NewHost/NewDomain. Host covers subdomains.
	// We prefer Host for subdomains, Domain for apex-like.
	if _, err := asset.NewHost(s, asset.Provenance{}); err == nil {
		// Heuristic: if it has at least one dot, treat as host (subdomain)
		// Domains are also hosts at asset level; classifier distinguishes by shape
		// but both are validated via same builder.
		return ShapeHost
	}
	if _, err := asset.NewDomain(s, asset.Provenance{}); err == nil {
		return ShapeDomain
	}
	return ShapeUnknown
}

func isURLLike(s string) bool {
	// Minimal scheme check: contains "://"
	return strings.Contains(s, "://")
}

func isJSLike(s string) bool {
	lower := strings.ToLower(s)
	// URL with .js extension
	if strings.Contains(lower, ".js") {
		return true
	}
	return false
}

func looksLikeJSPath(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	if strings.HasSuffix(lower, ".js") {
		// Bare path without scheme — must be plausible hostname/path chars, no spaces
		if strings.Contains(s, " ") {
			return false
		}
		return true
	}
	return false
}

// lineShapeHistogram builds a count of shapes over at most sample lines.
func lineShapeHistogram(peek []byte, maxSample int) map[LineShape]int {
	hist := make(map[LineShape]int)
	lines := bytes.Split(peek, []byte{'\n'})
	sampled := 0
	for _, l := range lines {
		if sampled >= maxSample {
			break
		}
		s := strings.TrimSpace(string(l))
		if s == "" {
			continue
		}
		shape := classifyLine(s)
		hist[shape]++
		sampled++
	}
	return hist
}

// mimeExtensionConfidence is the extension tie-break delta used in CanImport
// table tests (verified via renamed-file cases).
func mimeExtensionConfidence(path string, peek []byte) float64 {
	// Future: MIME sniff; for now extension only.
	_ = peek
	return 0
}

// plainConfidence computes confidence for a plain importer given peek and
// shape expectation. Used by each plain importer's CanImport.
func plainConfidence(path string, peek []byte, want LineShape, expectedExts []string) (float64, bool) {
	// Signature stage: if peek is XML / JSON / gzip, plain importers decline
	// (low confidence) — those belong to future phases.
	if isXMLSignature(peek) || isJSONStructure(peek) || isGzipped(peek) {
		return 0, false
	}
	if len(bytes.TrimSpace(peek)) == 0 {
		// empty file — no claim
		return 0, false
	}
	hist := lineShapeHistogram(peek, 50)
	total := 0
	for _, c := range hist {
		total += c
	}
	if total == 0 {
		return 0, false
	}
	wantCount := hist[want]
	// For hosts, accept both host and domain shapes (domains are subset)
	effectiveWant := wantCount
	if want == ShapeHost {
		effectiveWant += hist[ShapeDomain]
	}
	if want == ShapeDomain {
		// domains are also hosts at builder level; accept host as domain for now
		effectiveWant += hist[ShapeHost]
	}
	ratio := float64(effectiveWant) / float64(total)
	if ratio < 0.5 {
		return 0, false
	}
	// Base confidence scales with ratio, plus extension bump.
	conf := 0.6 + ratio*0.3 // 0.6..0.9
	for _, ext := range expectedExts {
		if ext != "" && strings.EqualFold(filepath.Ext(path), "."+ext) {
			conf += 0.05
			break
		}
	}
	// Renamed-file case: content still determines claim even if extension mismatches
	// (e.g., urls.txt content renamed .dat still detected as urls). Confidence
	// without extension bump stays >=0.6 when ratio >=0.5, so ok==true.
	if conf > 0.95 {
		conf = 0.95
	}
	return conf, true
}
