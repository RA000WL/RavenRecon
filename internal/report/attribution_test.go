package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// attributionTestModel builds a minimal model with one host, one URL, and
// one finding — the importer-producible asset kinds — plus optional
// attribution input.
func attributionTestModel(t *testing.T, attribution map[string]AttributionEntry) *Model {
	t.Helper()
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	host, err := asset.NewHost("api.example.com", asset.Provenance{Source: "subfinder", DiscoveredAt: now})
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	u, err := asset.ParseURL("http://api.example.com/login", asset.Provenance{Source: "manual", DiscoveredAt: now})
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	finding, err := asset.NewFinding(asset.Finding{
		RuleID:     "rule-1",
		RuleName:   "Rule One",
		Category:   "exposure",
		Subject:    host.Identity(),
		Confidence: 0.5,
		Priority:   "info",
		Status:     "open",
		Created:    now,
		Evidence:   []asset.Evidence{mustEvidence(t, host.Identity(), now)},
	})
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	m, err := NewModel(Context{
		Target:      "example.com",
		Hosts:       []asset.Host{host},
		URLs:        []asset.URL{u},
		Findings:    []asset.Finding{finding},
		Attribution: attribution,
	})
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}
	return m
}

func mustEvidence(t *testing.T, subject asset.Identity, at time.Time) asset.Evidence {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodHTML, "test-indicator", "synthetic-value", subject,
		asset.Provenance{Source: "manual", DiscoveredAt: at})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	return ev
}

func sampleAttribution() map[string]AttributionEntry {
	at := time.Date(2026, 8, 21, 9, 30, 0, 0, time.UTC)
	return map[string]AttributionEntry{
		"host:api.example.com": {
			Importer:     "json-httpx",
			OriginalTool: "httpx",
			Filename:     "httpx.json",
			Line:         1,
			ImportedAt:   at,
			Confidence:   0.9,
		},
	}
}

// TestAttributionAbsentKeepsLegacyExports pins the zero-change guarantee:
// without attribution the model carries no origins/attribution fields and the
// JSON export is byte-identical to the legacy shape (no new keys).
func TestAttributionAbsentKeepsLegacyExports(t *testing.T) {
	m := attributionTestModel(t, nil)
	if m.Attribution != nil || m.Origins != nil || m.AttributionTruncated {
		t.Fatalf("absent attribution leaked into the model")
	}
	parts := renderToMem(t, builtin(t, "json"), m)
	var generic map[string]any
	if err := json.Unmarshal(parts[""], &generic); err != nil {
		t.Fatalf("decode json export: %v", err)
	}
	for _, key := range []string{"attribution", "origins", "attribution_truncated"} {
		if _, ok := generic[key]; ok {
			t.Fatalf("legacy export gained %q key", key)
		}
	}
}

// TestAttributionDigestDeterminism covers the digest contract: identical
// content+attribution → identical digest; ±attribution changes the digest;
// absent attribution keeps the legacy digest value.
func TestAttributionDigestDeterminism(t *testing.T) {
	base := attributionTestModel(t, nil)
	with := attributionTestModel(t, sampleAttribution())
	withAgain := attributionTestModel(t, sampleAttribution())

	if with.Digest != withAgain.Digest {
		t.Fatalf("same content+attribution produced different digests: %s vs %s", with.Digest, withAgain.Digest)
	}
	if base.Digest == with.Digest {
		t.Fatalf("adding attribution did not move the digest")
	}

	altered := attributionTestModel(t, func() map[string]AttributionEntry {
		a := sampleAttribution()
		e := a["host:api.example.com"]
		e.Confidence = 0.8
		a["host:api.example.com"] = e
		return a
	}())
	if altered.Digest == with.Digest {
		t.Fatalf("changing an attribution field did not move the digest")
	}

	// ImportedAt participates like content provenance (asset DiscoveredAt),
	// unlike wall-clock run brackets.
	retimed := attributionTestModel(t, func() map[string]AttributionEntry {
		a := sampleAttribution()
		e := a["host:api.example.com"]
		e.ImportedAt = e.ImportedAt.Add(time.Hour)
		a["host:api.example.com"] = e
		return a
	}())
	if retimed.Digest == with.Digest {
		t.Fatalf("changing ImportedAt did not move the digest")
	}
}

// TestOriginOfParity pins the roadmap acceptance criterion: the same host,
// discovered vs imported, keeps IDENTICAL asset fields in both models — only
// origin classification and attribution differ.
func TestOriginOfParity(t *testing.T) {
	discovered := attributionTestModel(t, nil)
	imported := attributionTestModel(t, sampleAttribution())

	dh, ih := discovered.Hosts[0], imported.Hosts[0]
	if dh.Name != ih.Name || dh.Original != ih.Original || dh.Prov.Source != ih.Prov.Source ||
		!dh.Prov.DiscoveredAt.Equal(ih.Prov.DiscoveredAt) || dh.Prov.Confidence != ih.Prov.Confidence {
		t.Fatalf("host fields diverge between runs: %+v vs %+v", dh, ih)
	}
	if discovered.OriginOf(dh.Identity()) != OriginDiscovered {
		t.Fatalf("unattributed host classified %q", discovered.OriginOf(dh.Identity()))
	}
	if imported.OriginOf(ih.Identity()) != OriginImported {
		t.Fatalf("attributed host classified %q", imported.OriginOf(ih.Identity()))
	}
	// The unattributed URL in the same run stays discovered.
	if imported.OriginOf(imported.URLs[0].Identity()) != OriginDiscovered {
		t.Fatalf("unattributed url classified imported")
	}
	// Census reflects the split.
	if imported.Origins[string(OriginImported)] != 1 || imported.Origins[string(OriginDiscovered)] < 2 {
		t.Fatalf("origins census wrong: %v", imported.Origins)
	}
	if !imported.AttributionTruncated && len(imported.Attribution) != 1 {
		t.Fatalf("attribution normalization lost entries: %d", len(imported.Attribution))
	}
}

// TestAttributionValidationRejectsUnknownIdentity pins schema honesty.
func TestAttributionValidationRejectsUnknownIdentity(t *testing.T) {
	at := sampleAttribution()
	at["host:ghost.example.com"] = AttributionEntry{Importer: "plain-domains"}
	_, err := NewModel(Context{
		Target:      "example.com",
		Hosts:       attributionTestModel(t, nil).Hosts,
		Attribution: at,
	})
	if err == nil || !strings.Contains(err.Error(), "ghost.example.com") {
		t.Fatalf("err = %v, want unknown-identity rejection naming ghost.example.com", err)
	}
}

// TestAttributionConfidenceRangeRejected pins the confidence bound.
func TestAttributionConfidenceRangeRejected(t *testing.T) {
	at := sampleAttribution()
	e := at["host:api.example.com"]
	e.Confidence = 1.5
	at["host:api.example.com"] = e
	_, err := NewModel(attributionContextWith(t, at))
	if err == nil || !strings.Contains(err.Error(), "confidence") {
		t.Fatalf("err = %v, want confidence range rejection", err)
	}
}

func attributionContextWith(t *testing.T, at map[string]AttributionEntry) Context {
	t.Helper()
	m := attributionTestModel(t, nil)
	return Context{
		Target:      m.Target,
		Hosts:       []asset.Host{m.Hosts[0]},
		URLs:        []asset.URL{m.URLs[0]},
		Findings:    m.Findings,
		Attribution: at,
	}
}

// TestAttributionOverflowFlagged drives the MaxOutput-style cap: over-bound
// input keeps the sorted-key prefix and flags the cut instead of failing or
// silently truncating.
func TestAttributionOverflowFlagged(t *testing.T) {
	at := map[string]AttributionEntry{}
	for i := 0; i < maxAttributionEntries+1; i++ {
		at[fmt.Sprintf("host:h%07d.example.com", i)] = AttributionEntry{Importer: "plain-hosts"}
	}
	// Make every key known so the cap (not validation) decides retention.
	ctx := attributionContextWith(t, at)
	hosts := make([]asset.Host, 0, maxAttributionEntries+1)
	for i := 0; i < maxAttributionEntries+1; i++ {
		h, err := asset.NewHost(fmt.Sprintf("h%07d.example.com", i), asset.Provenance{})
		if err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
		hosts = append(hosts, h)
	}
	ctx.Hosts = hosts

	m, err := NewModel(ctx)
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}
	if !m.AttributionTruncated {
		t.Fatalf("overflow not flagged")
	}
	if len(m.Attribution) != maxAttributionEntries {
		t.Fatalf("retained %d entries, want exactly the cap", len(m.Attribution))
	}
	// Sorted-key prefix kept: the lexicographically smallest keys survive.
	first := fmt.Sprintf("host:h%07d.example.com", 0)
	if _, ok := m.Attribution[first]; !ok {
		t.Fatalf("sorted-prefix retention broken: %q missing", first)
	}
	last := fmt.Sprintf("host:h%07d.example.com", maxAttributionEntries)
	if _, ok := m.Attribution[last]; ok {
		t.Fatalf("tail entry %q should have been dropped", last)
	}
}

// TestRenderersSurfaceAttribution pins presentation: JSON gains the
// attribution/origins fields, CSV rows carry origin values, Markdown/HTML
// gain the Provenance section — and none of them appear without attribution.
func TestRenderersSurfaceAttribution(t *testing.T) {
	with := attributionTestModel(t, sampleAttribution())
	without := attributionTestModel(t, nil)

	jsonParts := renderToMem(t, builtin(t, "json"), with)
	var generic map[string]any
	if err := json.Unmarshal(jsonParts[""], &generic); err != nil {
		t.Fatalf("decode: %v", err)
	}
	attr, ok := generic["attribution"].(map[string]any)
	if !ok || len(attr) != 1 {
		t.Fatalf("json attribution missing: %v", generic["attribution"])
	}
	entry := attr["host:api.example.com"].(map[string]any)
	if entry["importer"] != "json-httpx" || entry["original_tool"] != "httpx" ||
		entry["filename"] != "httpx.json" || entry["line"] != float64(1) {
		t.Fatalf("attribution entry wrong: %v", entry)
	}
	origins := generic["origins"].(map[string]any)
	if origins["imported"] != float64(1) {
		t.Fatalf("origins census wrong: %v", origins)
	}

	csvParts := renderToMem(t, builtin(t, "csv"), with)
	rows, err := csv.NewReader(bytes.NewReader(csvParts["hosts"])).ReadAll()
	if err != nil {
		t.Fatalf("hosts csv: %v", err)
	}
	if rows[0][1] != "origin" || rows[1][1] != string(OriginImported) {
		t.Fatalf("hosts csv origin column wrong: header=%v row=%v", rows[0], rows[1])
	}
	urlRows, err := csv.NewReader(bytes.NewReader(csvParts["urls"])).ReadAll()
	if err != nil {
		t.Fatalf("urls csv: %v", err)
	}
	if urlRows[0][1] != "origin" || urlRows[1][1] != string(OriginDiscovered) {
		t.Fatalf("urls csv origin column wrong: header=%v row=%v", urlRows[0], urlRows[1])
	}

	md := string(renderToMem(t, builtin(t, "markdown"), with)[""])
	if !strings.Contains(md, "## Provenance") || !strings.Contains(md, "json-httpx") {
		t.Fatalf("markdown provenance section missing")
	}
	html := string(renderToMem(t, builtin(t, "html"), with)[""])
	if !strings.Contains(html, `id="provenance"`) || !strings.Contains(html, "httpx") {
		t.Fatalf("html provenance section missing")
	}

	// Absence: neither renderer gains a Provenance section, and the legacy
	// JSON keeps no attribution key.
	mdPlain := string(renderToMem(t, builtin(t, "markdown"), without)[""])
	htmlPlain := string(renderToMem(t, builtin(t, "html"), without)[""])
	if strings.Contains(mdPlain, "## Provenance") {
		t.Fatalf("markdown renders provenance without attribution")
	}
	if strings.Contains(htmlPlain, `id="provenance"`) {
		t.Fatalf("html renders provenance without attribution")
	}
	plainJSON := renderToMem(t, builtin(t, "json"), without)[""]
	var plainGeneric map[string]any
	if err := json.Unmarshal(plainJSON, &plainGeneric); err != nil {
		t.Fatalf("decode legacy json: %v", err)
	}
	if _, ok := plainGeneric["attribution"]; ok {
		t.Fatalf("legacy json gained attribution key")
	}
}
