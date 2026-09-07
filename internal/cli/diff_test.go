package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/report"
)

func diffTestHost(t *testing.T, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewHost(%q): %v", name, err)
	}
	return h
}

func diffTestURL(t *testing.T, raw string) asset.URL {
	t.Helper()
	u, err := asset.ParseURL(raw, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u
}

func writeDiffReport(t *testing.T, dir, name string, m *report.Model) string {
	t.Helper()
	m.SchemaVersion = report.SchemaVersion
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestRunDiffEndToEnd(t *testing.T) {
	dir := t.TempDir()
	old := writeDiffReport(t, dir, "old.json", &report.Model{
		Target: "example.com",
		Hosts:  []asset.Host{diffTestHost(t, "a.example.com"), diffTestHost(t, "gone.example.com")},
	})
	cur := writeDiffReport(t, dir, "new.json", &report.Model{
		Target: "example.com",
		Hosts:  []asset.Host{diffTestHost(t, "a.example.com"), diffTestHost(t, "new.example.com")},
		URLs:   []asset.URL{diffTestURL(t, "https://new.example.com/robots.txt")},
	})
	outDir := filepath.Join(dir, "deltas")
	if err := os.Mkdir(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := runDiff(context.Background(), &buf, []string{"--output", outDir, old, cur}); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"example.com", "hosts: +1/-1", "urls: +1/-0"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary lacks %q:\n%s", want, got)
		}
	}
	for _, name := range []string{"delta.json", "delta.md"} {
		raw, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(raw) == 0 {
			t.Errorf("%s is empty", name)
		}
	}
	md, err := os.ReadFile(filepath.Join(outDir, "delta.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"new.example.com", "gone.example.com", "robots.txt"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("delta.md lacks %q", want)
		}
	}
}

func TestRunDiffRejects(t *testing.T) {
	dir := t.TempDir()
	rep := writeDiffReport(t, dir, "r.json", &report.Model{Target: "example.com"})
	other := writeDiffReport(t, dir, "o.json", &report.Model{Target: "other.com"})
	var buf bytes.Buffer
	if err := runDiff(context.Background(), &buf, []string{rep}); err == nil {
		t.Error("one path must be rejected")
	}
	if err := runDiff(context.Background(), &buf, []string{rep, other}); err == nil {
		t.Error("cross-target diff must be rejected")
	}
	if err := runDiff(context.Background(), &buf, []string{rep, filepath.Join(dir, "missing.json")}); err == nil {
		t.Error("missing file must be rejected")
	}
	var help bytes.Buffer
	if err := runDiff(context.Background(), &help, []string{"--help"}); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(help.String(), "ravenrecon diff") {
		t.Errorf("help text wrong:\n%s", help.String())
	}
}

func TestRunDiffEmptyDelta(t *testing.T) {
	dir := t.TempDir()
	m := &report.Model{Target: "example.com", Hosts: []asset.Host{diffTestHost(t, "a.example.com")}}
	a := writeDiffReport(t, dir, "a.json", m)
	b := writeDiffReport(t, dir, "b.json", m)
	var buf bytes.Buffer
	if err := runDiff(context.Background(), &buf, []string{"--output", dir, a, b}); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	if !strings.Contains(buf.String(), "no changes") {
		t.Errorf("empty delta must say no changes:\n%s", buf.String())
	}
}

func TestRunHandoffEndToEnd(t *testing.T) {
	dir := t.TempDir()
	rep := writeDiffReport(t, dir, "report.json", &report.Model{
		Target: "example.com",
		Hosts:  []asset.Host{diffTestHost(t, "www.example.com")},
		URLs:   []asset.URL{diffTestURL(t, "https://www.example.com/")},
	})
	outDir := filepath.Join(dir, "feed")
	if err := os.Mkdir(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := runHandoff(context.Background(), &buf, []string{"--output", outDir, rep}); err != nil {
		t.Fatalf("runHandoff: %v", err)
	}
	if !strings.Contains(buf.String(), "1 targets") {
		t.Errorf("summary wrong:\n%s", buf.String())
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "targets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "https://www.example.com/\n" {
		t.Errorf("targets.txt = %q", raw)
	}
	if _, err := os.Stat(filepath.Join(outDir, "handoff.json")); err != nil {
		t.Errorf("handoff.json missing: %v", err)
	}
	var help bytes.Buffer
	if err := runHandoff(context.Background(), &help, []string{"--help"}); err != nil {
		t.Fatalf("help: %v", err)
	}
	if err := runHandoff(context.Background(), &help, []string{}); err == nil {
		t.Error("zero paths must be rejected")
	}
}

// TestRunDiffNestedOutputWithoutMkdir pins that runDiff creates a nested
// --output directory with parents as needed: the caller must NOT pre-make
// it (regression: the runner's MkdirAll must cover the whole path, not
// just rely on the writer).
func TestRunDiffNestedOutputWithoutMkdir(t *testing.T) {
	dir := t.TempDir()
	old := writeDiffReport(t, dir, "old.json", &report.Model{
		Target: "example.com",
		Hosts:  []asset.Host{diffTestHost(t, "a.example.com")},
	})
	cur := writeDiffReport(t, dir, "new.json", &report.Model{
		Target: "example.com",
		Hosts:  []asset.Host{diffTestHost(t, "a.example.com"), diffTestHost(t, "b.example.com")},
	})
	outDir := filepath.Join(dir, "nested", "deltas")
	var buf bytes.Buffer
	if err := runDiff(context.Background(), &buf, []string{"--output", outDir, old, cur}); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	for _, name := range []string{"delta.json", "delta.md"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("%s missing in created nested output: %v", name, err)
		}
	}
}

// TestRunHandoffNestedOutputWithoutMkdir pins the same contract for
// runHandoff: a nested --output path that does not exist yet is created,
// and both feeder files land there.
func TestRunHandoffNestedOutputWithoutMkdir(t *testing.T) {
	dir := t.TempDir()
	rep := writeDiffReport(t, dir, "report.json", &report.Model{
		Target: "example.com",
		Hosts:  []asset.Host{diffTestHost(t, "www.example.com")},
		URLs:   []asset.URL{diffTestURL(t, "https://www.example.com/")},
	})
	outDir := filepath.Join(dir, "nested", "feed")
	var buf bytes.Buffer
	if err := runHandoff(context.Background(), &buf, []string{"--output", outDir, rep}); err != nil {
		t.Fatalf("runHandoff: %v", err)
	}
	for _, name := range []string{"targets.txt", "handoff.json"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("%s missing in created nested output: %v", name, err)
		}
	}
}
