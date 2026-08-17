package report

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTemp writes a fixture file and returns its path.
func writeTemp(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestValidateJSONFile(t *testing.T) {
	dir := t.TempDir()
	good := writeTemp(t, dir, "good.json", []byte(`{"schema_version":1,"target":"example.com"}`))
	if err := validateJSONFile(good, false); err != nil {
		t.Fatalf("valid json rejected: %v", err)
	}
	wrongVersion := writeTemp(t, dir, "wrong.json", []byte(`{"schema_version":99}`))
	if err := validateJSONFile(wrongVersion, false); err == nil {
		t.Fatalf("wrong schema version accepted")
	}
	trailing := writeTemp(t, dir, "trailing.json", []byte(`{"schema_version":1} garbage`))
	if err := validateJSONFile(trailing, false); err == nil {
		t.Fatalf("trailing garbage accepted")
	}
	empty := writeTemp(t, dir, "empty.json", nil)
	if err := validateJSONFile(empty, false); err == nil {
		t.Fatalf("empty file accepted")
	}
}

func TestValidateCSVFile(t *testing.T) {
	dir := t.TempDir()
	good := writeTemp(t, dir, "good.csv", []byte("host,source\na.example,test\n"))
	if err := validateCSVFile(good, false); err != nil {
		t.Fatalf("valid csv rejected: %v", err)
	}
	headerOnly := writeTemp(t, dir, "header.csv", []byte("host,source\n"))
	if err := validateCSVFile(headerOnly, false); err != nil {
		t.Fatalf("header-only csv rejected: %v", err)
	}
	ragged := writeTemp(t, dir, "ragged.csv", []byte("host,source\na.example\n"))
	if err := validateCSVFile(ragged, false); err == nil {
		t.Fatalf("ragged row accepted")
	}
	empty := writeTemp(t, dir, "empty.csv", nil)
	if err := validateCSVFile(empty, false); err == nil {
		t.Fatalf("empty csv accepted")
	}
}

func TestValidateMarkdownFile(t *testing.T) {
	dir := t.TempDir()
	good := writeTemp(t, dir, "good.md", []byte("# Report\n\n## Summary\n\n| a |\n| --- |\n| 1 |\n"))
	if err := validateMarkdownFile(good, false); err != nil {
		t.Fatalf("valid markdown rejected: %v", err)
	}
	noHeading := writeTemp(t, dir, "noheading.md", []byte("just text\n"))
	if err := validateMarkdownFile(noHeading, false); err == nil {
		t.Fatalf("heading-less markdown accepted")
	}
	unbalanced := writeTemp(t, dir, "fence.md", []byte("# Report\n```go\nfmt.Println(1)\n"))
	if err := validateMarkdownFile(unbalanced, false); err == nil {
		t.Fatalf("unbalanced fences accepted")
	}
	empty := writeTemp(t, dir, "empty.md", nil)
	if err := validateMarkdownFile(empty, false); err == nil {
		t.Fatalf("empty markdown accepted")
	}
}

func TestValidateHTMLFile(t *testing.T) {
	dir := t.TempDir()
	good := writeTemp(t, dir, "good.html", []byte("<!DOCTYPE html><html><body><details><summary>s</summary>x</details></body></html>"))
	if err := validateHTMLFile(good, false); err != nil {
		t.Fatalf("valid html rejected: %v", err)
	}
	unclosed := writeTemp(t, dir, "unclosed.html", []byte("<!DOCTYPE html><html><body><details><summary>s</summary></body></html>"))
	if err := validateHTMLFile(unclosed, false); err == nil {
		t.Fatalf("unclosed details accepted")
	}
	noClose := writeTemp(t, dir, "noclose.html", []byte("<!DOCTYPE html><html><body>"))
	if err := validateHTMLFile(noClose, false); err == nil {
		t.Fatalf("missing </html> accepted")
	}
}

func TestValidateCompressedFiles(t *testing.T) {
	dir := t.TempDir()
	// Produce genuinely compressed output through the sink.
	final := filepath.Join(dir, "report.json.gz")
	sink, err := newFileSink(dir, true, func(string) string { return final })
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	w, _ := sink.Writer("")
	w.Write([]byte(`{"schema_version":1}`))
	w.Close()
	parts, err := sink.Parts()
	if err != nil {
		t.Fatalf("parts: %v", err)
	}
	// Validation runs on the temp files BEFORE the commit renames them —
	// the engine's actual order.
	if err := validateJSONFile(parts[0].Tmp, true); err != nil {
		t.Fatalf("compressed valid json rejected: %v", err)
	}
	if err := validateJSONFile(parts[0].Tmp, false); err == nil {
		t.Fatalf("compressed json accepted as plain json")
	}
	if err := sink.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestValidateNonEmpty(t *testing.T) {
	dir := t.TempDir()
	nonEmpty := writeTemp(t, dir, "data.bin", []byte("x"))
	if err := validateNonEmpty(nonEmpty, false); err != nil {
		t.Fatalf("non-empty file rejected: %v", err)
	}
	empty := writeTemp(t, dir, "empty.bin", nil)
	if err := validateNonEmpty(empty, false); err == nil {
		t.Fatalf("empty file accepted")
	}
}
