package adapt

// Test support for the v1.7 acceptance golden tests (NEW-56 batch E;
// TODO.md NEW-56 locked decisions D1 and D2).
//
// Materialization (D1): fixtureManifest -> the EXISTING T4 harness seams.
// Nothing here forks the harness: discovery detections/runs become a
// fakeRunner script, dns records a fakeResolver, http responses the
// cannedTransport, urlintel lines the scripted gau runner (gauLines), js
// bodies a loopback httptest server behind the shared rewriteTransport,
// and stage_params the ScanConfig.StageParams seam. Everything else (the
// synthetic detect/priority/secrentel catalogs, the hermetic crawl and
// urllive transports) reuses the package's established T3d/T4 helpers so
// the clean profile exercises byte-identical wiring to the pinned T4 run.
// Unsupported manifest shapes fail loudly here instead of silently
// materializing something else.
//
// Golden rendering (D2): normalizeRunReport / normalizeStageRecord produce
// the normalized, sorted-key JSON documents:
//
//   - the run bracket (StartAt/EndAt) and every StageRecord.Duration are
//     zeroed at the type level before marshal;
//   - timestamp-shaped keys anywhere in the document (DiscoveredAt,
//     Created, StartedAt, EndedAt, At) are masked to "" during the tree
//     walk — with the fixed clock they would be stable anyway, but the
//     mask keeps the goldens independent of the clock seam's concrete
//     instant;
//   - caller-supplied literal substrings (temp/cache/output directories,
//     the loopback server URL) are replaced with stable placeholders, so
//     no machine-local path or port can ever reach a committed golden;
//   - tool/runtime versions cannot appear: no pipeline stage reports them
//     into the RunReport (adapt/report.go keeps the stats channels empty;
//     discovery provenance carries the tool NAME, never its version) — if
//     a future profile leaks one, add its literal to the redaction map
//     deliberately rather than pattern-guessing here;
//   - the document round-trips through the generic encoder so every
//     object key is sorted before the final marshal.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/discovery"
	"github.com/RA000WL/RavenRecon/internal/dns"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/priority"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// fixtureLoopbackFallback is the body served for loopback paths the
// manifest does not script — identical to the T3d/T4 fallback so the
// corpus root/graphql URLs behave exactly as in the pinned runs.
const fixtureLoopbackFallback = "window.ready = true;\n"

// fixtureHarness is one manifest materialized onto the T4 seams.
type fixtureHarness struct {
	m           fixtureManifest
	discovery   *fakeRunner
	gau         *fakeRunner
	resolver    *fakeResolver
	transport   *cannedTransport
	js          *rewriteTransport
	jsRequests  func() int
	loopback    string // the loopback base URL (a golden redaction source)
	secretDB    *patterns.DB
	interesting *priority.Catalog
	risk        *priority.Catalog
	detectReg   *detect.Registry
}

// newFixtureHarness materializes m. Shapes the current seams cannot
// express (path-scoped canned HTTP responses, oversized bodies, dns_poison
// seeding — a messy-profile scenario) fail loudly here instead of
// materializing a silent approximation.
func newFixtureHarness(t *testing.T, m fixtureManifest) *fixtureHarness {
	t.Helper()
	h := &fixtureHarness{m: m}

	// Discovery: detections + runs merged into ONE fakeRunner script keyed
	// by the runner's argv form. Duplicate keys between the two sections
	// are rejected deterministically (sorted order) rather than letting map
	// iteration decide the winner.
	h.discovery = newFakeRunner(make(map[string]func(discovery.Cmd) (discovery.RunResult, error)))
	for _, key := range sortedManifestKeys(m.Detections) {
		res := m.Detections[key]
		h.discovery.script[key] = fixtureScriptEntry(res)
	}
	for _, key := range sortedManifestKeys(m.Runs) {
		if _, clash := m.Detections[key]; clash {
			t.Fatalf("fixture manifest: runs key %q duplicates a detection key", key)
		}
		res := m.Runs[key]
		h.discovery.script[key] = fixtureScriptEntry(res)
	}

	// urlintel: the raw gau output lines for the declared target, exactly
	// the T4/T5 scripting shape.
	h.gau = newFakeRunner(gauLines(m.Target, m.URLIntel...))

	// DNS: canned answers per host; absent record types resolve as the
	// fakeResolver's NODATA default, matching the manifest schema.
	h.resolver = newFakeResolver()
	for _, host := range sortedManifestKeys(m.DNS) {
		recs := m.DNS[host]
		if len(recs.A) > 0 {
			h.resolver.set(host, dns.TypeA, recs.A...)
		}
		if len(recs.AAAA) > 0 {
			h.resolver.set(host, dns.TypeAAAA, recs.AAAA...)
		}
		if len(recs.CNAME) > 0 {
			h.resolver.set(host, dns.TypeCNAME, recs.CNAME...)
		}
	}

	// HTTP probing: the canned transport matches scheme://host, so bare
	// host keys register both schemes (cannedHost) and explicit
	// scheme://host keys register that scheme alone. Path-scoped responses
	// have no canned-transport expression and are rejected.
	if len(m.DNSPoison) > 0 {
		t.Fatal("fixture manifest: dns_poison belongs to the cache-poisoning scenario (messy profile) and is not consumed by this batch")
	}
	h.transport = &cannedTransport{}
	for _, key := range sortedManifestKeys(m.HTTP) {
		resp := m.HTTP[key]
		if resp.BodyOversized {
			t.Fatalf("fixture manifest: http %s: oversized canned responses are not supported by this batch's materializer", key)
		}
		cr := cannedResponse{status: resp.Status, body: resp.Body, headers: resp.Headers}
		if !strings.Contains(key, "://") {
			cannedHost(h.transport, key, cr)
			continue
		}
		scheme, host, ok := splitSchemeHost(key)
		if !ok || strings.Contains(host, "/") {
			t.Fatalf("fixture manifest: http key %q: path-scoped canned responses have no cannedTransport expression", key)
		}
		cannedHostScheme(h.transport, host, scheme, cr)
	}

	// JS intelligence: loopback server serving the manifest bodies by URL
	// path behind the shared rewrite transport (the engine never leaves
	// the loopback).
	bodies := make(map[string]fixtureJSBody, len(m.JS))
	for path, jb := range m.JS {
		if jb.Oversized {
			t.Fatalf("fixture manifest: js %s: oversized bodies are not supported by this batch's materializer", path)
		}
		bodies[path] = jb
	}
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		jb, ok := bodies[r.URL.Path]
		status := 0
		body := fixtureLoopbackFallback
		if ok {
			status = jb.Status
			for k, v := range jb.Headers {
				w.Header().Set(k, v)
			}
			body = jb.Body
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/javascript")
		}
		if status != 0 {
			w.WriteHeader(status)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	h.loopback = srv.URL
	h.js = &rewriteTransport{base: srv.URL}
	h.jsRequests = func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}

	// The shared synthetic catalogs and registries (the T4 fixtures).
	h.secretDB = testSecretDB(t)
	h.interesting, h.risk = priorityCatalogs(t)
	h.detectReg = newDetectRegistry(t, t3dTechListingRule(t))
	return h
}

// stages wires the full twelve-stage pipeline over the materialized
// seams — the exact T4 wiring shape, with the REAL production report
// registry (NewReportStage(nil)) so the builtin reporters (markdown among
// them) commit into OutputDir.
func (h *fixtureHarness) stages() []pipeline.Stage {
	return []pipeline.Stage{
		NewDiscoveryStage(h.discovery, fakeLookup),
		NewDNSStage(h.resolver),
		NewHTTPProbeStage(h.transport),
		NewURLIntelStage(h.gau, fakeLookup),
		NewCrawlStage(newFakeCrawlEmpty()),
		NewTechIntelStage(nil), // production fingerprint database
		NewJSIntelStage(h.js),
		NewSecretIntelStage(h.secretDB),
		NewUrlliveStage(&liveTransport{}),
		NewPriorityStage(h.interesting, h.risk),
		NewDetectStage(h.detectReg),
		NewReportStage(nil), // production default registry: json, csv, markdown, html
	}
}

// scanConfig derives the run config: the full twelve-stage selection with
// the T4-pinned discovery bound, plus the manifest's stage_params passed
// through the ScanConfig.StageParams seam.
func (h *fixtureHarness) scanConfig(t testing.TB) pipeline.ScanConfig {
	t.Helper()
	cfg := pipeline.ScanConfig{
		Target: mustDomain(t, h.m.Target),
		Stages: pipeline.AllStages(),
		StageBounds: map[pipeline.StageName]pipeline.StageConfig{
			pipeline.StageDiscover: {
				MaxConcurrency: 4,
				QueueSize:      8,
				Rate:           0, // pacing disabled: the pool overlap stays genuine
			},
		},
	}
	if len(h.m.StageParams) > 0 {
		cfg.StageParams = make(map[pipeline.StageName]map[string]string, len(h.m.StageParams))
		for name, kv := range h.m.StageParams {
			cfg.StageParams[pipeline.StageName(name)] = kv
		}
	}
	return cfg
}

// fixtureScriptEntry adapts one manifest tool result into a fakeRunner
// script entry (stdout/stderr/exit code; no error injection in the
// manifest schema).
func fixtureScriptEntry(res fixtureToolResult) func(discovery.Cmd) (discovery.RunResult, error) {
	return func(discovery.Cmd) (discovery.RunResult, error) {
		return discovery.RunResult{
			Stdout:   []byte(res.Stdout),
			Stderr:   []byte(res.Stderr),
			ExitCode: res.ExitCode,
		}, nil
	}
}

// splitSchemeHost splits "scheme://host" into its parts.
func splitSchemeHost(key string) (scheme, host string, ok bool) {
	i := strings.Index(key, "://")
	if i <= 0 || i+3 >= len(key) {
		return "", "", false
	}
	return key[:i], key[i+3:], true
}

// cannedHostScheme registers one response for a single scheme of a host
// on the canned transport (cannedHost registers both schemes).
func cannedHostScheme(tr *cannedTransport, host, scheme string, resp cannedResponse) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.byHost == nil {
		tr.byHost = make(map[string]map[string]cannedResponse)
	}
	byScheme, ok := tr.byHost[host]
	if !ok {
		byScheme = make(map[string]cannedResponse)
		tr.byHost[host] = byScheme
	}
	byScheme[scheme] = resp
}

// sortedManifestKeys returns the map's keys in sorted order
// (deterministic materialization order).
func sortedManifestKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- Golden rendering (D2) ---

// timestampMaskKeys are the object keys masked to "" during the golden
// tree walk: every timestamp-shaped field a RunReport can transitively
// carry, in both spellings such a field occurs in — Go field names (the
// pipeline types declare no json tags) and the snake_case json tags of
// the asset, priority, and report-model types (including the report run
// bracket started_at/ended_at and the TLS validity window
// not_before/not_after). Masking is an exact key match applied wherever
// the key appears, so keys absent from a given document are simply never
// hit — entries that do not occur are harmless by design. With the fixed
// clock these values would be stable anyway; the mask keeps the goldens
// independent of the concrete clock instant.
var timestampMaskKeys = map[string]bool{
	// Go-field-name spellings (no json tags on the pipeline types;
	// StartedAt/EndedAt/At pin the report-model bracket and event-envelope
	// spellings of the same shapes).
	"StartAt":      true,
	"EndAt":        true,
	"Duration":     true,
	"StartedAt":    true,
	"EndedAt":      true,
	"At":           true,
	"DiscoveredAt": true,
	"Created":      true,
	"Updated":      true,
	"FirstSeen":    true,
	"LastSeen":     true,
	"LastModified": true,
	"ScoredAt":     true,
	// json-tag spellings (internal/asset, internal/priority, internal/report).
	"discovered_at": true,
	"created":       true,
	"updated":       true,
	"first_seen":    true,
	"last_seen":     true,
	"last_modified": true,
	"scored_at":     true,
	"started_at":    true,
	"ended_at":      true,
	"not_before":    true,
	"not_after":     true,
}

// goldenRedactions collects the machine-local literals one acceptance run
// must never leak into a golden: the run's cache directory, each run's
// output directory, the OS temp root beneath which they all live, and the
// loopback server URL (its port changes every process).
func goldenRedactions(cacheDir string, outputDirs []string, loopback string) map[string]string {
	reds := map[string]string{
		cacheDir:     "<cache-dir>",
		loopback:     "<loopback>",
		os.TempDir(): "<temp>",
	}
	for i, dir := range outputDirs {
		reds[dir] = fmt.Sprintf("<output-dir-%d>", i+1)
	}
	return reds
}

// normalizeRunReport zeroes the run-level wall-clock bracket and every
// stage duration, then renders the canonical golden document.
func normalizeRunReport(t testing.TB, redactions map[string]string, rep pipeline.RunReport) []byte {
	t.Helper()
	rep.StartAt = time.Time{}
	rep.EndAt = time.Time{}
	for i := range rep.Stages {
		rep.Stages[i].Duration = 0
	}
	return canonicalGoldenJSON(t, redactions, rep)
}

// normalizeStageRecord zeroes one stage record's duration and renders the
// canonical golden document (the per-stage golden: the failing subtest IS
// the stage name).
func normalizeStageRecord(t testing.TB, redactions map[string]string, sr pipeline.StageRecord) []byte {
	t.Helper()
	sr.Duration = 0
	return canonicalGoldenJSON(t, redactions, sr)
}

// canonicalGoldenJSON renders v deterministically: marshal, generic
// round-trip (sorted object keys, integer fidelity via UseNumber),
// timestamp masking, literal redactions, final marshal + newline.
func canonicalGoldenJSON(t testing.TB, redactions map[string]string, v any) []byte {
	t.Helper()
	first, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal golden input: %v", err)
	}
	var generic any
	dec := json.NewDecoder(strings.NewReader(string(first)))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		t.Fatalf("re-decode golden input: %v", err)
	}
	obj, ok := generic.(map[string]any)
	if !ok {
		t.Fatalf("golden input must marshal to a JSON object, got %T", generic)
	}
	maskTimestamps(obj)
	scrubRedactions(obj, redactions)
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal golden document: %v", err)
	}
	return append(out, '\n')
}

// maskTimestamps walks the decoded document and masks every
// timestamp-masked key's value to "" (recursively through objects and
// arrays), mutating containers in place.
func maskTimestamps(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			if timestampMaskKeys[k] {
				x[k] = ""
				continue
			}
			x[k] = maskTimestamps(vv)
		}
		return x
	case []any:
		for i := range x {
			x[i] = maskTimestamps(x[i])
		}
		return x
	default:
		return v
	}
}

// scrubSource is one literal redaction with its placeholder.
type scrubSource struct{ from, to string }

// sortedScrubSources flattens the redaction map into a FIXED application
// order, longest source first. The order must never depend on Go's
// randomized map iteration: a document string can carry overlapping
// sources (a cache directory lives inside the OS temp root), and applying
// the shorter source first would rewrite the longer one's occurrence into
// "<temp>/..." instead of the specific placeholder — a per-process coin
// flip that would flap the goldens.
func sortedScrubSources(redactions map[string]string) []scrubSource {
	out := make([]scrubSource, 0, len(redactions))
	for from, to := range redactions {
		if from == "" {
			continue
		}
		out = append(out, scrubSource{from: from, to: to})
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].from) > len(out[j].from) })
	return out
}

// scrubRedactions replaces every literal redaction source with its
// placeholder throughout the document's strings (temp/cache/output
// directories, the loopback URL — anything machine-local). Sources apply
// longest-first (sortedScrubSources): the most specific literal wins over
// its own substrings, deterministically.
func scrubRedactions(v map[string]any, redactions map[string]string) {
	sources := sortedScrubSources(redactions)
	var walk func(node any) any
	walk = func(node any) any {
		switch x := node.(type) {
		case map[string]any:
			for k, vv := range x {
				x[k] = walk(vv)
			}
			return x
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
			return x
		case string:
			for _, s := range sources {
				if strings.Contains(x, s.from) {
					x = strings.ReplaceAll(x, s.from, s.to)
				}
			}
			return x
		default:
			return node
		}
	}
	walk(v)
}
