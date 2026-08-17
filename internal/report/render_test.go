package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// renderToMem renders one reporter into a memory sink and returns the map
// of part name to bytes.
func renderToMem(t *testing.T, rep Reporter, m *Model) map[string][]byte {
	t.Helper()
	sink := newMemSink()
	if err := rep.Render(context.Background(), m, sink); err != nil {
		t.Fatalf("render %s: %v", rep.ID, err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	out := make(map[string][]byte)
	for part, buf := range sink.parts {
		out[part] = append([]byte(nil), buf.Bytes()...)
	}
	return out
}

// builtin returns one builtin reporter by ID.
func builtin(t *testing.T, id string) Reporter {
	t.Helper()
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("default registry: %v", err)
	}
	rep, ok := reg.Get(id)
	if !ok {
		t.Fatalf("builtin %q missing", id)
	}
	return rep
}

// modelWithSecrets rebuilds the canonical model with extra secret values.
func modelWithSecrets(t *testing.T, values ...string) *Model {
	t.Helper()
	c := testContext(t)
	for _, v := range values {
		sec, err := asset.NewSecretCandidate(asset.SecretTypeGeneric, v, c.JavaScript[0].Identity(), fixedProv("secrentel"))
		if err != nil {
			t.Fatalf("secret fixture %q: %v", v, err)
		}
		c.Secrets = append(c.Secrets, sec)
	}
	m, err := NewModel(c)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	return m
}

func TestRenderJSONDeterministicAndVersioned(t *testing.T) {
	m := testModel(t)
	jsonRep := builtin(t, "json")
	first := renderToMem(t, jsonRep, m)[""]
	second := renderToMem(t, jsonRep, m)[""]
	if !bytes.Equal(first, second) {
		t.Fatalf("two renders of one model differ")
	}
	var doc map[string]any
	if err := json.Unmarshal(first, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v, _ := doc["schema_version"].(float64); int(v) != SchemaVersion {
		t.Fatalf("schema_version = %v, want %d", doc["schema_version"], SchemaVersion)
	}
	for _, key := range []string{"target", "hosts", "urls", "secrets", "findings", "statistics", "summary", "errors", "digest", "recommendations", "attack_paths", "relationships", "evidence", "technologies"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("document missing key %q", key)
		}
	}
}

func TestRenderJSONUnicodePreserved(t *testing.T) {
	m := unicodeModel(t) // carries unicode evidence + error samples
	out := renderToMem(t, builtin(t, "json"), m)[""]
	if !strings.Contains(string(out), "Généré") {
		t.Fatalf("unicode evidence value missing from JSON export")
	}
	if !strings.Contains(string(out), "无效的响应") {
		t.Fatalf("unicode error message missing from JSON export")
	}
}

// unicodeModel builds a model carrying unicode evidence and error text.
func unicodeModel(t *testing.T) *Model {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodHTML, "html:generator", "Généré Par Ünïcode 框架 v1", hostAsset(t, "u.example.com").Identity(), fixedProv("t"))
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	m, err := NewModel(Context{
		Target:    "example.com",
		StartedAt: fixedTime,
		EndedAt:   fixedTime,
		Evidence:  []asset.Evidence{ev},
		Errors:    []ErrorRecord{{Category: CategoryParsing, Stage: "parse", Message: "无效的响应 – retry", Count: 1}},
	})
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	return m
}

func TestRenderCSVPartsHeadersAndRows(t *testing.T) {
	m := testModel(t)
	parts := renderToMem(t, builtin(t, "csv"), m)
	want := map[string]string{
		"hosts":        "www.example.com",
		"urls":         "https://www.example.com/admin?refresh=1",
		"endpoints":    "GET",
		"technologies": "nginx",
		"secrets":      "aws-documented-example-key",
		"findings":     "rule-exposure-1",
	}
	if len(parts) != len(csvParts) {
		t.Fatalf("parts = %d, want %d", len(parts), len(csvParts))
	}
	for part, marker := range want {
		data, ok := parts[part]
		if !ok {
			t.Fatalf("part %q missing", part)
		}
		r := csv.NewReader(bytes.NewReader(data))
		header, err := r.Read()
		if err != nil || len(header) == 0 {
			t.Fatalf("part %q has no header: %v", part, err)
		}
		rows, err := r.ReadAll()
		if err != nil {
			t.Fatalf("part %q does not reparse: %v", part, err)
		}
		if len(rows) == 0 {
			t.Fatalf("part %q has no data rows", part)
		}
		found := false
		for _, row := range rows {
			for _, cell := range row {
				if cell == marker {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("part %q does not contain %q", part, marker)
		}
	}
}

func TestRenderCSVNeutralizesFormulaInjection(t *testing.T) {
	// A value that begins with "=" must be neutralized in the CSV
	// presentation (the JSON export keeps exact bytes).
	m := modelWithSecrets(t, "=1+1", "+SUM(A1:A2)", "@cmd", "-2+3")
	parts := renderToMem(t, builtin(t, "csv"), m)
	r := csv.NewReader(bytes.NewReader(parts["secrets"]))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("secrets csv: %v", err)
	}
	neutralized := 0
	for _, row := range rows {
		for _, cell := range row {
			for _, dangerous := range []string{"=1+1", "+SUM(A1:A2)", "@cmd", "-2+3"} {
				if cell == dangerous {
					t.Fatalf("unneutralized formula cell %q in CSV", cell)
				}
				if cell == "'"+dangerous {
					neutralized++
				}
			}
		}
	}
	if neutralized != 4 {
		t.Fatalf("neutralized cells = %d, want 4", neutralized)
	}
	// JSON keeps the exact bytes.
	jsonOut := string(renderToMem(t, builtin(t, "json"), m)[""])
	if !strings.Contains(jsonOut, `"=1+1"`) {
		t.Fatalf("JSON export mangled the exact value bytes")
	}
}

func TestRenderCSVDeterministic(t *testing.T) {
	m := testModel(t)
	csvRep := builtin(t, "csv")
	a := renderToMem(t, csvRep, m)
	b := renderToMem(t, csvRep, m)
	for part := range a {
		if !bytes.Equal(a[part], b[part]) {
			t.Fatalf("part %q differs between renders", part)
		}
	}
}

func TestRenderMarkdownSections(t *testing.T) {
	m := testModel(t)
	out := string(renderToMem(t, builtin(t, "markdown"), m)[""])
	for _, section := range []string{
		"# RavenRecon Report", "## Summary", "## Interesting Assets",
		"## Technologies", "## Secrets", "## Top Findings",
		"## Attack Surface", "## Recommendations", "## Statistics", "## Errors",
	} {
		if !strings.Contains(out, section) {
			t.Fatalf("markdown missing section %q", section)
		}
	}
	for _, marker := range []string{"example.com", "rule-exposure-1", "lookup timeout for api.example.com", "nginx"} {
		if !strings.Contains(out, marker) {
			t.Fatalf("markdown missing %q", marker)
		}
	}
}

func TestRenderMarkdownHonestCaps(t *testing.T) {
	c := testContext(t)
	for i := 0; i < maxMarkdownListRows+5; i++ {
		tech, err := asset.NewTechnology(fmt.Sprintf("tech-%03d", i), asset.CategoryServer, fixedProv("t"))
		if err != nil {
			t.Fatalf("tech fixture: %v", err)
		}
		c.Technologies = append(c.Technologies, tech)
	}
	m, err := NewModel(c)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	out := string(renderToMem(t, builtin(t, "markdown"), m)[""])
	if !strings.Contains(out, "more technologies") {
		t.Fatalf("markdown cap note missing")
	}
	if !strings.Contains(out, "tech-000") {
		t.Fatalf("markdown cap kept the wrong end of the list")
	}
}

func TestRenderMarkdownDeterministic(t *testing.T) {
	m := testModel(t)
	mdRep := builtin(t, "markdown")
	if !bytes.Equal(renderToMem(t, mdRep, m)[""], renderToMem(t, mdRep, m)[""]) {
		t.Fatalf("markdown differs between renders")
	}
}

func TestRenderMarkdownEscapesCellsExactlyOnce(t *testing.T) {
	// A pipe- and backslash-carrying value must render inside ONE cell:
	// the emitted "\|" must not be re-escaped into a literal backslash
	// plus a live delimiter, which would split the row in GFM.
	m := modelWithSecrets(t, "token|with|pipes", `C:\temp\keys|admin`)
	out := string(renderToMem(t, builtin(t, "markdown"), m)[""])
	if !strings.Contains(out, `token\|with\|pipes`) {
		t.Fatalf("markdown lost the single-escaped pipe cell")
	}
	if strings.Contains(out, `token\\|with`) {
		t.Fatalf("markdown double-escaped the pipe (backslash + live delimiter)")
	}
	if !strings.Contains(out, `C:\temp\keys\|admin`) {
		t.Fatalf("markdown lost the single-escaped backslash+pipe cell")
	}
	if strings.Contains(out, `C:\temp\keys\\|admin`) {
		t.Fatalf("markdown double-escaped the backslash+pipe cell")
	}
	// The header must stay escaped too (framework vocabulary, but the
	// choke point applies to every cell).
	if !strings.Contains(out, "| metric | value |") {
		t.Fatalf("markdown header row malformed")
	}
}

func TestRenderHTMLEscapesEverything(t *testing.T) {
	m := modelWithSecrets(t, `<script>alert("xss")</script>`)
	m.Errors = ErrorSummary{
		Total: 1, Unique: 1,
		Categories: []ErrorCategorySummary{{
			Category: CategoryUnknown, Total: 1, Unique: 1,
			Samples: []ErrorRecord{{
				Category: CategoryUnknown,
				Stage:    `<img src=x onerror=alert(1)>`,
				Message:  `"; drop table --`,
				Count:    1,
			}},
		}},
	}
	out := string(renderToMem(t, builtin(t, "html"), m)[""])
	if strings.Contains(out, "<script>alert") {
		t.Fatalf("unescaped script tag in HTML")
	}
	if strings.Contains(out, "<img src=x") {
		t.Fatalf("unescaped img tag in HTML")
	}
	if strings.Contains(out, `"; drop table --`) {
		t.Fatalf("unescaped message in HTML")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("escaped script tag missing")
	}
	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Fatalf("html document does not start with doctype")
	}
	if !strings.Contains(out, "</html>") {
		t.Fatalf("html document not closed")
	}
	// The document must satisfy its own validator.
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if err := validateHTMLFile(path, false); err != nil {
		t.Fatalf("html failed its own validator: %v", err)
	}
}

func TestRenderHTMLNoExternalResources(t *testing.T) {
	m := testModel(t)
	out := string(renderToMem(t, builtin(t, "html"), m)[""])
	if strings.Contains(out, "<link") {
		t.Fatalf("link element found")
	}
	if strings.Contains(out, "@import") {
		t.Fatalf("css import found")
	}
	if strings.Contains(out, `src="http`) {
		t.Fatalf("external script/image source found")
	}
	if strings.Contains(out, `href="http`) {
		t.Fatalf("external stylesheet href found")
	}
}

func TestRenderHTMLTruncationNote(t *testing.T) {
	c := testContext(t)
	for i := 0; i < maxHTMLTableRows+10; i++ {
		h, err := asset.NewHost(fmt.Sprintf("h%05d.example.com", i), fixedProv("t"))
		if err != nil {
			t.Fatalf("host fixture: %v", err)
		}
		c.Hosts = append(c.Hosts, h)
	}
	m, err := NewModel(c)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	out := string(renderToMem(t, builtin(t, "html"), m)[""])
	if !strings.Contains(out, "Showing first") {
		t.Fatalf("truncation note missing")
	}
}

func TestRenderHTMLDeterministic(t *testing.T) {
	m := testModel(t)
	htmlRep := builtin(t, "html")
	if !bytes.Equal(renderToMem(t, htmlRep, m)[""], renderToMem(t, htmlRep, m)[""]) {
		t.Fatalf("html differs between renders")
	}
}

func TestRenderHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := testModel(t)
	for _, id := range []string{"json", "csv", "markdown", "html"} {
		if err := builtin(t, id).Render(ctx, m, newMemSink()); err == nil {
			t.Fatalf("reporter %q rendered under a cancelled context", id)
		}
	}
}
