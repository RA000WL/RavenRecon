package importer

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Format detection waterfall for the importer families:
//
//   1. signature: <?xml / json.Valid / gzip magic (0x1f 0x8b)
//   2. structure probe: json.Decoder / xml.Decoder root-element token peek
//      (on the bounded peek slice — see jsonProbeShape / xmlProbeShape)
//   3. MIME + extension tie-break: extension hints confidence but never solely decides
//   4. line-shape classifier: asset.ParseURL/NewHost, netip.ParseAddr/Prefix, js heuristic
//
// The XML branch maps root elements <items>/<issues> → "burp" and
// <OWASPZAPReport> (case-insensitive; zaproxy emits the same root) → "zap".
// Unknown XML roots yield no claim from either XML importer — there is no
// generic-XML fallback by design; such files fall through honestly to
// plain-generic's last-resort catch-all. Specific plain importers decline
// any XML-looking peek (looksLikeXMLPeek) so tag-laden content is never
// mis-ranked above an XML importer.

// looksLikeXMLPeek lives in xml_stream.go beside the rest of the XML
// streaming machinery; it is the single definition of "peek looks like XML".

// isJSONStructure reports whether peek is JSON (object/array) via json.Valid
// after trimming leading BOM/whitespace. For NDJSON (multiple JSON values
// separated by newline) json.Valid on the whole peek will be false (multiple
// top-level values), so we also probe via Decoder for the first value.
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
	if json.Valid(trim) {
		return true
	}
	// NDJSON or streaming array: check if first value is JSON
	return isJSONLike(peek)
}

// isJSONLike reports whether peek starts with a JSON object/array and the first
// value decodes successfully. This handles NDJSON (one JSON per line) where
// json.Valid on the whole peek is false but the first line is valid JSON.
func isJSONLike(peek []byte) bool {
	trim := bytes.TrimSpace(peek)
	trim = bytes.TrimPrefix(trim, []byte{0xef, 0xbb, 0xbf})
	if len(trim) == 0 {
		return false
	}
	if trim[0] != '{' && trim[0] != '[' {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(trim))
	dec.UseNumber()
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return false
	}
	// Ensure the decoded first value itself is valid JSON object/array
	rv := bytes.TrimSpace(raw)
	if len(rv) == 0 {
		return false
	}
	if rv[0] == '{' || rv[0] == '[' {
		return json.Valid(rv)
	}
	return false
}

// jsonProbeShape classifies the JSON peek into one of the JSON importer
// shapes: httpx, dnsx, naabu, katana, nuclei, or generic. Returns "" if not
// JSON. It decodes only the first JSON value (bounded 32 KiB peek) and inspects
// its keys without loading the whole file. For JSON arrays, it inspects the
// first element.
func jsonProbeShape(peek []byte) string {
	trim := bytes.TrimSpace(peek)
	trim = bytes.TrimPrefix(trim, []byte{0xef, 0xbb, 0xbf})
	if len(trim) == 0 {
		return ""
	}
	if trim[0] != '{' && trim[0] != '[' {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(trim))
	dec.UseNumber()
	var first json.RawMessage
	if err := dec.Decode(&first); err != nil {
		return ""
	}
	rv := bytes.TrimSpace(first)
	if len(rv) == 0 {
		return ""
	}
	// Array case: inspect first element
	if rv[0] == '[' {
		var arr []map[string]json.RawMessage
		if err := json.Unmarshal(first, &arr); err != nil {
			return "generic"
		}
		if len(arr) == 0 {
			return "generic"
		}
		return classifyJSONObject(arr[0])
	}
	if rv[0] == '{' {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(first, &m); err != nil {
			return ""
		}
		return classifyJSONObject(m)
	}
	return "generic"
}

func hasKey(m map[string]json.RawMessage, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func classifyJSONObject(m map[string]json.RawMessage) string {
	// Nuclei has highest specificity: template-id family
	if hasKey(m, "template-id", "templateID", "template_id", "templateId") {
		return "nuclei"
	}
	// Naabu: port + ip/host (port is integer)
	if hasKey(m, "port") && (hasKey(m, "ip") || hasKey(m, "host")) {
		return "naabu"
	}
	// DNSx: host + a/cname/resolver (but not port)
	if hasKey(m, "host") && (hasKey(m, "a") || hasKey(m, "aaaa") || hasKey(m, "cname") || hasKey(m, "resolver") || hasKey(m, "answer")) {
		return "dnsx"
	}
	// httpx vs katana: both have url
	if hasKey(m, "url") {
		hasStatus := hasKey(m, "status_code", "status-code", "statusCode", "status")
		hasTech := hasKey(m, "title", "tech", "technologies", "webserver", "content_length", "content-length", "contentLength", "body_preview", "body-preview")
		hasMethod := hasKey(m, "method")
		if hasStatus || hasTech {
			return "httpx"
		}
		if hasMethod {
			return "katana"
		}
		return "httpx"
	}
	return "generic"
}

// jsonConfidence computes confidence for a JSON importer based on probe shape.
// want is the shape this importer claims (e.g. "httpx").
func jsonConfidence(path string, peek []byte, want string) (float64, bool) {
	shape := jsonProbeShape(peek)
	if shape == "" {
		return 0, false
	}
	if shape != want {
		return 0, false
	}
	// Base confidence for correct shape
	conf := 0.85
	// Extension tie-break: .json adds 0.05, .ndjson too
	extLower := strings.ToLower(filepath.Ext(path))
	if extLower == ".json" || extLower == ".ndjson" || extLower == ".jsonl" {
		conf += 0.05
	}
	if conf > 0.95 {
		conf = 0.95
	}
	return conf, true
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
	// Signature stage: if peek is XML / JSON / gzip, plain importers decline.
	// The XML check is the broad looksLikeXMLPeek (declaration-less fragments
	// too), so tag-laden content never reaches the line-shape classifier.
	if looksLikeXMLPeek(peek) || isJSONStructure(peek) || isGzipped(peek) {
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
