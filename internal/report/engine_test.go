package report

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/cache"
)

// runReports runs the default registry over the test context.
func runReports(t *testing.T, dir string, mutate func(*EngineConfig)) RunResult {
	t.Helper()
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	cfg := DefaultEngineConfig(reg, dir)
	if mutate != nil {
		mutate(&cfg)
	}
	res, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func TestRunWritesEveryFormat(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	res := runReports(t, dir, nil)
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %q, want completed: %+v", res.Outcome, res.Reports)
	}
	if res.Digest == "" || res.BaseName == "" {
		t.Fatalf("run result missing digest or base name")
	}
	if len(res.Reports) != 4 {
		t.Fatalf("results = %d, want 4", len(res.Reports))
	}
	for i := 1; i < len(res.Reports); i++ {
		if res.Reports[i-1].ReporterID >= res.Reports[i].ReporterID {
			t.Fatalf("results not sorted by reporter id")
		}
	}
	want := map[string]int{
		"ravenrecon-report-example.com.json": 1,
		"ravenrecon-report-example.com.md":   1,
		"ravenrecon-report-example.com.html": 1,
		// CSV: one file per dataset.
		"ravenrecon-report-example.com.hosts.csv":        1,
		"ravenrecon-report-example.com.urls.csv":         1,
		"ravenrecon-report-example.com.endpoints.csv":    1,
		"ravenrecon-report-example.com.technologies.csv": 1,
		"ravenrecon-report-example.com.secrets.csv":      1,
		"ravenrecon-report-example.com.findings.csv":     1,
	}
	got := make(map[string]int)
	for _, rep := range res.Reports {
		if rep.Status != ReportStatusCompleted {
			t.Fatalf("reporter %q: status %q err %v", rep.ReporterID, rep.Status, rep.Err)
		}
		for _, f := range rep.Files {
			got[filepath.Base(f)]++
		}
	}
	for name, n := range want {
		if got[name] != n {
			t.Fatalf("file %q written %d times, want %d (all files: %v)", name, got[name], n, got)
		}
	}
	// Deterministic rerun produces byte-identical files.
	first := readAll(t, dir)
	res2 := runReports(t, dir, nil)
	if res2.Digest != res.Digest {
		t.Fatalf("digest changed between identical runs")
	}
	second := readAll(t, dir)
	for name, data := range first {
		if !equalBytes(second[name], data) {
			t.Fatalf("file %q changed between identical runs", name)
		}
	}
}

func TestRunCustomBaseNameAndSelection(t *testing.T) {
	dir := t.TempDir()
	res := runReports(t, dir, func(c *EngineConfig) {
		c.BaseName = "Scan_2026 Example.COM"
		c.Reports = []string{"json"}
	})
	if len(res.Reports) != 4 {
		t.Fatalf("results = %d, want every registered reporter present", len(res.Reports))
	}
	completed, skipped := 0, 0
	for _, rep := range res.Reports {
		switch rep.Status {
		case ReportStatusCompleted:
			completed++
		case ReportStatusSkipped:
			skipped++
		default:
			t.Fatalf("reporter %q status %q", rep.ReporterID, rep.Status)
		}
	}
	if completed != 1 || skipped != 3 {
		t.Fatalf("completed = %d skipped = %d, want 1/3", completed, skipped)
	}
	if res.BaseName != "scan-2026-example.com" {
		t.Fatalf("base name = %q", res.BaseName)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "scan-2026-example.com.json" {
		t.Fatalf("unexpected output files: %v", entries)
	}
}

func TestRunUnknownReporterRejected(t *testing.T) {
	reg, _ := NewDefaultRegistry()
	_, err := Run(context.Background(), DefaultEngineConfig(reg, t.TempDir()).withReports("bogus"), testContext(t))
	if err == nil || !strings.Contains(err.Error(), "unknown reporter id") {
		t.Fatalf("unknown reporter accepted: %v", err)
	}
}

func TestRunCompressedOutput(t *testing.T) {
	dir := t.TempDir()
	res := runReports(t, dir, func(c *EngineConfig) { c.Compress = true })
	for _, rep := range res.Reports {
		if rep.Status != ReportStatusCompleted {
			t.Fatalf("reporter %q: %q %v", rep.ReporterID, rep.Status, rep.Err)
		}
		if !rep.Compressed {
			t.Fatalf("reporter %q not compressed", rep.ReporterID)
		}
		for _, f := range rep.Files {
			if !strings.HasSuffix(f, ".gz") {
				t.Fatalf("compressed output %q lacks .gz", f)
			}
		}
	}
	// The compressed outputs must validate (validators decompress).
	for _, rep := range res.Reports {
		validate := builtin(t, rep.ReporterID).Validate
		for _, f := range rep.Files {
			if err := validate(f, true); err != nil {
				t.Fatalf("compressed %q failed validation: %v", f, err)
			}
		}
	}
}

func TestRunDisabledReporterSkipped(t *testing.T) {
	reg, _ := NewDefaultRegistry()
	csvRep, _ := reg.Get("csv")
	csvRep.Enabled = false
	reg2 := NewRegistry()
	for _, rep := range reg.Reports() {
		if rep.ID == "csv" {
			rep.Enabled = false
		}
		if err := reg2.Register(rep); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	res, err := Run(context.Background(), DefaultEngineConfig(reg2, t.TempDir()), testContext(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("skipped report forced outcome %q", res.Outcome)
	}
	for _, rep := range res.Reports {
		if rep.ReporterID == "csv" && rep.Status != ReportStatusSkipped {
			t.Fatalf("disabled reporter status = %q", rep.Status)
		}
	}
}

func TestRunFailedRenderLeavesNoFileAndKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	reg := NewRegistry()
	failing := okReporter("failing")
	failing.Format = FormatJSON
	failing.Render = func(ctx context.Context, m *Model, s Sink) error {
		return errors.New("renderer exploded")
	}
	if err := reg.Register(failing); err != nil {
		t.Fatalf("register: %v", err)
	}
	// A previous good report exists.
	previous := filepath.Join(dir, "ravenrecon-report-example.com.json")
	os.WriteFile(previous, []byte("previous-good"), 0o600)

	res, err := Run(context.Background(), DefaultEngineConfig(reg, dir), testContext(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != OutcomeFailed {
		t.Fatalf("outcome = %q, want failed (only reporter failed)", res.Outcome)
	}
	rep := resultFor(t, res, "failing")
	if rep.Status != ReportStatusFailed || rep.Err == nil {
		t.Fatalf("failing reporter status = %q err = %v", rep.Status, rep.Err)
	}
	data, err := os.ReadFile(previous)
	if err != nil || string(data) != "previous-good" {
		t.Fatalf("previous report damaged: %q %v", data, err)
	}
	// No temp files survive.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			t.Fatalf("temp file survived: %s", e.Name())
		}
	}
}

func TestRunInvalidRenderFailsValidation(t *testing.T) {
	dir := t.TempDir()
	reg := NewRegistry()
	bad := okReporter("bad")
	bad.Format = FormatJSON
	bad.Validate = validateJSONFile
	bad.Render = func(ctx context.Context, m *Model, s Sink) error {
		w, err := s.Writer("")
		if err != nil {
			return err
		}
		// Renders, but with the wrong schema version — the validator must
		// catch it before anything is exposed.
		w.Write([]byte(`{"schema_version":999}`))
		return w.Close()
	}
	if err := reg.Register(bad); err != nil {
		t.Fatalf("register: %v", err)
	}
	res, err := Run(context.Background(), DefaultEngineConfig(reg, dir), testContext(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if resultFor(t, res, "bad").Status != ReportStatusFailed {
		t.Fatalf("invalid render status = %q, want failed", resultFor(t, res, "bad").Status)
	}
	if _, err := os.Stat(filepath.Join(dir, "ravenrecon-report-example.com.json")); !os.IsNotExist(err) {
		t.Fatalf("invalid report was exposed on disk")
	}
}

func TestRunCancelledContext(t *testing.T) {
	dir := t.TempDir()
	reg, _ := NewDefaultRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Run(ctx, DefaultEngineConfig(reg, dir), testContext(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != OutcomeCancelled {
		t.Fatalf("outcome = %q, want cancelled", res.Outcome)
	}
	for _, rep := range res.Reports {
		if rep.Status != ReportStatusCancelled {
			t.Fatalf("reporter %q status %q, want cancelled", rep.ReporterID, rep.Status)
		}
		if len(rep.Files) != 0 {
			t.Fatalf("cancelled reporter left files: %v", rep.Files)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("cancelled run left files behind: %v", entries)
	}
}

func TestRunRenderCacheHitAndTamperEviction(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	store, err := cache.Open(cacheDir)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	_ = store

	reg, _ := NewDefaultRegistry()
	cfg := DefaultEngineConfig(reg, dir)
	cfg.Cache = store
	cfg.Reports = []string{"json"}
	res1, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	cold := resultFor(t, res1, "json")
	if cold.Cached {
		t.Fatalf("cold run served from cache")
	}
	firstBytes, err := os.ReadFile(cold.Files[0])
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// Warm run: identical model, cache hit, byte-identical file.
	res2, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if !resultFor(t, res2, "json").Cached {
		t.Fatalf("warm run did not serve from cache")
	}
	secondBytes, err := os.ReadFile(resultFor(t, res2, "json").Files[0])
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Fatalf("cache-served output differs from fresh output")
	}

	// Tamper the stored record: the next run must evict and re-render.
	res3, err := Run(context.Background(), cfg, tamperedInput(t))
	if err != nil {
		t.Fatalf("run 3: %v", err)
	}
	if resultFor(t, res3, "json").Cached {
		t.Fatalf("tampered digest mismatch served from cache")
	}
}

func TestRunPanickingReporterFailsNotCancels(t *testing.T) {
	// A panicking render function is a renderer failure — the engine doc
	// reserves cancelled for run teardown — and the panic must surface in
	// the report's error.
	registerPanicReporter := func(t *testing.T, reg *Registry) {
		t.Helper()
		panicky := okReporter("panicky")
		panicky.Format = FormatJSON
		panicky.Render = func(ctx context.Context, m *Model, s Sink) error {
			panic("renderer blew up")
		}
		if err := reg.Register(panicky); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	writingReporter := func(t *testing.T, reg *Registry, id string) {
		t.Helper()
		rep := okReporter(id)
		rep.Render = func(ctx context.Context, m *Model, s Sink) error {
			w, err := s.Writer("")
			if err != nil {
				return err
			}
			if _, err := w.Write([]byte("{}")); err != nil {
				return err
			}
			return w.Close()
		}
		if err := reg.Register(rep); err != nil {
			t.Fatalf("register: %v", err)
		}
	}

	t.Run("single panicking reporter fails the run", func(t *testing.T) {
		dir := t.TempDir()
		reg := NewRegistry()
		registerPanicReporter(t, reg)
		res, err := Run(context.Background(), DefaultEngineConfig(reg, dir), testContext(t))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if res.Outcome != OutcomeFailed {
			t.Fatalf("outcome = %q, want failed (a panic is not run teardown)", res.Outcome)
		}
		rep := resultFor(t, res, "panicky")
		if rep.Status != ReportStatusFailed {
			t.Fatalf("status = %q, want failed", rep.Status)
		}
		if rep.Err == nil || !strings.Contains(rep.Err.Error(), "panicked") ||
			!strings.Contains(rep.Err.Error(), "renderer blew up") {
			t.Fatalf("panic not surfaced in the error: %v", rep.Err)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Fatalf("panicked render left files behind: %v", entries)
		}
	})

	t.Run("panic alongside a success is incomplete", func(t *testing.T) {
		dir := t.TempDir()
		reg := NewRegistry()
		writingReporter(t, reg, "json")
		registerPanicReporter(t, reg)
		res, err := Run(context.Background(), DefaultEngineConfig(reg, dir), testContext(t))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if res.Outcome != OutcomeIncomplete {
			t.Fatalf("outcome = %q, want incomplete (one completed, one failed)", res.Outcome)
		}
		if rep := resultFor(t, res, "panicky"); rep.Status != ReportStatusFailed {
			t.Fatalf("panicky status = %q, want failed", rep.Status)
		}
		if rep := resultFor(t, res, "json"); rep.Status != ReportStatusCompleted {
			t.Fatalf("json reporter status = %q, want completed", rep.Status)
		}
	})

	t.Run("panicking renderer after writing leaves no temp file", func(t *testing.T) {
		dir := t.TempDir()
		reg := NewRegistry()
		writesThenPanics := okReporter("panicky")
		writesThenPanics.Format = FormatJSON
		writesThenPanics.Render = func(ctx context.Context, m *Model, s Sink) error {
			w, err := s.Writer("")
			if err != nil {
				return err
			}
			if _, err := w.Write([]byte("partial output")); err != nil {
				return err
			}
			panic("renderer blew up mid-write")
		}
		if err := reg.Register(writesThenPanics); err != nil {
			t.Fatalf("register: %v", err)
		}
		res, err := Run(context.Background(), DefaultEngineConfig(reg, dir), testContext(t))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		rep := resultFor(t, res, "panicky")
		if rep.Status != ReportStatusFailed {
			t.Fatalf("status = %q, want failed", rep.Status)
		}
		if rep.Err == nil || !strings.Contains(rep.Err.Error(), "renderer blew up mid-write") {
			t.Fatalf("panic not surfaced in the error: %v", rep.Err)
		}
		// The renderer wrote into a temp file before panicking; the
		// widened recovery must abort it (the still-open part is
		// force-closed and removed).
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Fatalf("panicked render left files behind: %v", entries)
		}
	})
}

func TestRunPanickingValidateFailsNotCancels(t *testing.T) {
	// A panicking output validator is a reporter failure — the engine doc
	// reserves cancelled for run teardown — and the panic must surface in
	// the report's error while the sink aborts (no temp file survives).
	// Regression: the panic used to unwind past processReport into the
	// pool's recovery, installing a cancelled placeholder (a panic
	// surfaced as run teardown), leaking the sink's temp files, and
	// losing the panic message.
	writingReporter := func(t *testing.T, reg *Registry, id string, validate func(path string, compressed bool) error) {
		t.Helper()
		rep := okReporter(id)
		rep.Validate = validate
		rep.Render = func(ctx context.Context, m *Model, s Sink) error {
			w, err := s.Writer("")
			if err != nil {
				return err
			}
			if _, err := w.Write([]byte("{}")); err != nil {
				return err
			}
			return w.Close()
		}
		if err := reg.Register(rep); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	panickyValidator := func(t *testing.T, reg *Registry, id string) {
		t.Helper()
		writingReporter(t, reg, id, func(path string, compressed bool) error {
			panic("validator blew up")
		})
	}
	assertNoTempFiles := func(t *testing.T, dir string) {
		t.Helper()
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), tmpPrefix) {
				t.Fatalf("temp file survived: %s", e.Name())
			}
		}
	}

	t.Run("single panicking validator fails the run", func(t *testing.T) {
		dir := t.TempDir()
		reg := NewRegistry()
		panickyValidator(t, reg, "panicky")
		res, err := Run(context.Background(), DefaultEngineConfig(reg, dir), testContext(t))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if res.Outcome != OutcomeFailed {
			t.Fatalf("outcome = %q, want failed (a panic is not run teardown)", res.Outcome)
		}
		rep := resultFor(t, res, "panicky")
		if rep.Status != ReportStatusFailed {
			t.Fatalf("status = %q, want failed", rep.Status)
		}
		if rep.Err == nil || !strings.Contains(rep.Err.Error(), "panicked") ||
			!strings.Contains(rep.Err.Error(), "validator blew up") {
			t.Fatalf("panic not surfaced in the error: %v", rep.Err)
		}
		// Validation precedes commit: no final file exists and no temp
		// file survived the abort.
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Fatalf("panicked validation left files behind: %v", entries)
		}
	})

	t.Run("panicking validator alongside a success is incomplete", func(t *testing.T) {
		dir := t.TempDir()
		reg := NewRegistry()
		writingReporter(t, reg, "json", func(path string, compressed bool) error {
			return validateNonEmpty(path, compressed)
		})
		panickyValidator(t, reg, "panicky")
		res, err := Run(context.Background(), DefaultEngineConfig(reg, dir), testContext(t))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if res.Outcome != OutcomeIncomplete {
			t.Fatalf("outcome = %q, want incomplete (one completed, one failed)", res.Outcome)
		}
		if rep := resultFor(t, res, "panicky"); rep.Status != ReportStatusFailed {
			t.Fatalf("panicky status = %q, want failed", rep.Status)
		}
		if rep := resultFor(t, res, "json"); rep.Status != ReportStatusCompleted {
			t.Fatalf("json reporter status = %q, want completed", rep.Status)
		}
		assertNoTempFiles(t, dir)
	})

	t.Run("warm cache hit panicking validator fails honestly", func(t *testing.T) {
		// The cache-hit commit streams through the same sink and runs the
		// same validator: a panicking validator on a warm hit must fail
		// (never cancel), surface the panic, and leave no temp file.
		dir := t.TempDir()
		cacheDir := filepath.Join(t.TempDir(), "cache")
		store, err := cache.Open(cacheDir)
		if err != nil {
			t.Fatalf("cache: %v", err)
		}

		// Run 1 populates the cache under the reporter's registered
		// identity (ID, version, format) and the model digest.
		reg1 := NewRegistry()
		writingReporter(t, reg1, "cached", func(path string, compressed bool) error {
			return validateNonEmpty(path, compressed)
		})
		cfg1 := DefaultEngineConfig(reg1, dir)
		cfg1.Cache = store
		cfg1.Reports = []string{"cached"}
		res1, err := Run(context.Background(), cfg1, testContext(t))
		if err != nil {
			t.Fatalf("run 1: %v", err)
		}
		if resultFor(t, res1, "cached").Cached {
			t.Fatalf("cold run served from cache")
		}

		// Run 2: identical reporter identity and model, panicking
		// validator — the stored record must hit and the commit must
		// fail honestly.
		reg2 := NewRegistry()
		panickyValidator(t, reg2, "cached")
		cfg2 := DefaultEngineConfig(reg2, dir)
		cfg2.Cache = store
		cfg2.Reports = []string{"cached"}
		res2, err := Run(context.Background(), cfg2, testContext(t))
		if err != nil {
			t.Fatalf("run 2: %v", err)
		}
		rep := resultFor(t, res2, "cached")
		if rep.Cached {
			t.Fatalf("panicking validator run must not report cached")
		}
		if rep.Status != ReportStatusFailed {
			t.Fatalf("status = %q, want failed", rep.Status)
		}
		if rep.Err == nil || !strings.Contains(rep.Err.Error(), "validator blew up") {
			t.Fatalf("panic not surfaced in the error: %v", rep.Err)
		}
		assertNoTempFiles(t, dir)
	})
}

// tamperedInput returns a context whose model differs (different digest),
// proving key coverage; the direct tamper test rewrites the record below.
func tamperedInput(t *testing.T) Context {
	t.Helper()
	c := testContext(t)
	c.Hosts = append(c.Hosts, hostAsset(t, "tamper.example.com"))
	return c
}

func TestRunCompressedRenderCacheHitAndTamperEviction(t *testing.T) {
	// A compressed warm hit must reproduce the cold render's final file
	// bytes EXACTLY: the cache stores the final file bytes (already
	// gzip-compressed), so the cache-commit path must write them raw —
	// re-compressing them would stack a second gzip layer on disk and
	// every builtin validator (which decompresses exactly once) would
	// fail every warm run with no eviction and no self-heal.
	dir := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	store, err := cache.Open(cacheDir)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}

	reg, _ := NewDefaultRegistry()
	cfg := DefaultEngineConfig(reg, dir)
	cfg.Cache = store
	cfg.Reports = []string{"json"}
	cfg.Compress = true

	// Run 1 (cold): the fresh compressed render commits and its exact
	// final file bytes are stored in the render cache.
	res1, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	cold := resultFor(t, res1, "json")
	if cold.Status != ReportStatusCompleted {
		t.Fatalf("cold run status = %q err %v", cold.Status, cold.Err)
	}
	if cold.Cached {
		t.Fatalf("cold run served from cache")
	}
	coldBytes, err := os.ReadFile(cold.Files[0])
	if err != nil {
		t.Fatalf("read run-1 file: %v", err)
	}

	// Run 2 (warm): served from cache, completed, and byte-identical to
	// the cold render.
	res2, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	warm := resultFor(t, res2, "json")
	if warm.Status != ReportStatusCompleted {
		t.Fatalf("warm run status = %q err %v", warm.Status, warm.Err)
	}
	if !warm.Cached {
		t.Fatalf("warm run did not serve from cache")
	}
	warmBytes, err := os.ReadFile(warm.Files[0])
	if err != nil {
		t.Fatalf("read run-2 file: %v", err)
	}
	if !equalBytes(coldBytes, warmBytes) {
		t.Fatalf("cache-served compressed output differs from the cold render (byte identity violated)")
	}
	// Single-decompression validity: exactly one gzip layer, and that
	// one decompression yields valid JSON with the framework schema.
	gz, err := gzip.NewReader(bytes.NewReader(warmBytes))
	if err != nil {
		t.Fatalf("warm output is not a single gzip stream: %v", err)
	}
	uncompressed, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("warm output does not decompress exactly once: %v", err)
	}
	gz.Close()
	if len(uncompressed) >= 2 && uncompressed[0] == 0x1f && uncompressed[1] == 0x8b {
		t.Fatalf("warm output is double-gzipped (second gzip layer found)")
	}
	var doc struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(uncompressed, &doc); err != nil {
		t.Fatalf("single-decompressed warm output is not valid JSON: %v", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		t.Fatalf("single-decompressed schema version = %d, want %d", doc.SchemaVersion, SchemaVersion)
	}

	// Tamper the stored record (identity mismatch): on the compressed
	// axis too the engine must evict it and re-render in the same run,
	// never serve the tampered record.
	err = filepath.Walk(filepath.Join(cacheDir, "entries"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		return os.WriteFile(path, []byte(`{"schema_version":1,"operation":"report.render","target":"report:x","created_at":"2026-01-01T00:00:00Z","status":"completed","data":{"report_id":"json","version":"9.9.9","format":"json","digest":"deadbeef","parts":[{"part":"","bytes":2,"data":"eHg="}]}}`), 0o600)
	})
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}

	res3, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("run 3: %v", err)
	}
	tampered := resultFor(t, res3, "json")
	if tampered.Status != ReportStatusCompleted {
		t.Fatalf("tampered-cache run failed: %q %v", tampered.Status, tampered.Err)
	}
	if tampered.Cached {
		t.Fatalf("tampered compressed record was served")
	}
	reRendered, err := os.ReadFile(tampered.Files[0])
	if err != nil || len(reRendered) == 0 {
		t.Fatalf("re-rendered output missing: %v", err)
	}
	if !equalBytes(reRendered, coldBytes) {
		t.Fatalf("re-rendered compressed output differs from run-1 bytes")
	}
}

func TestRunRenderCacheZeroBytePartEvictedAndReRendered(t *testing.T) {
	// L-10 regression: a cached render record whose part payload is
	// zero-byte (Bytes 0, Data empty) used to pass decodeRender and then
	// fail validation on EVERY warm run — a permanently failing render
	// with no eviction and no self-heal. The decode boundary must refuse
	// the empty payload, and the engine's decode-failure path must evict
	// the record and recompute the render in the same run.
	dir := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	store, err := cache.Open(cacheDir)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}

	reg, _ := NewDefaultRegistry()
	cfg := DefaultEngineConfig(reg, dir)
	cfg.Cache = store
	cfg.Reports = []string{"json"}

	// Cold run: renders fresh and stores a usable record.
	res1, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("cold run: %v", err)
	}
	cold := resultFor(t, res1, "json")
	if cold.Cached {
		t.Fatalf("cold run served from cache")
	}
	coldBytes, err := os.ReadFile(cold.Files[0])
	if err != nil {
		t.Fatalf("read cold render: %v", err)
	}

	// Plant a zero-byte-part record whose identity fields match the run
	// EXACTLY (report ID, version, format, digest): the empty payload is
	// the record's only defect, so only the decode rejection can catch it.
	rep, _ := reg.Get("json")
	m := testModel(t)
	poisonPayload, err := json.Marshal(renderRecord{
		ReportID: rep.ID, Version: rep.Version, Format: string(rep.Format),
		Digest: m.Digest,
		Parts:  []renderPart{{Part: "", Bytes: 0, Data: []byte{}}},
	})
	if err != nil {
		t.Fatalf("marshal poison record: %v", err)
	}
	raw, err := json.Marshal(cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Operation:     renderOperation,
		Target:        "report:" + m.Digest,
		CreatedAt:     fixedTime,
		Status:        cache.StatusCompleted,
		Data:          poisonPayload,
	})
	if err != nil {
		t.Fatalf("marshal poisoned cache entry: %v", err)
	}
	err = filepath.Walk(filepath.Join(cacheDir, "entries"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		return os.WriteFile(path, raw, 0o600)
	})
	if err != nil {
		t.Fatalf("plant: %v", err)
	}

	// The planted record must be refused at the decode boundary with a
	// descriptive error (lookup treats it as unusable, never a hit).
	key, err := renderCacheKey(m, rep, false)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	out := store.Get(context.Background(), key)
	if !out.IsHit() {
		t.Fatalf("planted record did not surface as a hit: %+v", out.State)
	}
	if parts, derr := decodeRender(out, m, rep, false); derr == nil {
		t.Fatalf("zero-byte part record accepted by decode: %+v", parts)
	} else if !strings.Contains(derr.Error(), "empty payload") {
		t.Fatalf("rejection error not descriptive: %v", derr)
	}

	// Warm run against the poisoned record: it must be evicted and the
	// render recomputed fresh (completed, not cached, byte-identical).
	res2, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("warm run: %v", err)
	}
	warm := resultFor(t, res2, "json")
	if warm.Status != ReportStatusCompleted {
		t.Fatalf("self-healed run failed: %q %v", warm.Status, warm.Err)
	}
	if warm.Cached {
		t.Fatalf("zero-byte part record was served as a hit")
	}
	reRendered, err := os.ReadFile(warm.Files[0])
	if err != nil {
		t.Fatalf("read re-rendered output: %v", err)
	}
	if !equalBytes(coldBytes, reRendered) {
		t.Fatalf("recomputed render differs from the cold render")
	}

	// Self-heal proven: the eviction + fresh store left a USABLE record
	// behind, so the next run is a genuine cache hit.
	out2 := store.Get(context.Background(), key)
	parts, derr := decodeRender(out2, m, rep, false)
	if derr != nil {
		t.Fatalf("stored record after self-heal is unusable: %v", derr)
	}
	if len(parts) != 1 || len(parts[0].Data) == 0 {
		t.Fatalf("stored record after self-heal is not the fresh render: %+v", parts)
	}
	res3, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("third run: %v", err)
	}
	if !resultFor(t, res3, "json").Cached {
		t.Fatalf("third run did not serve the self-healed record from cache")
	}
}

func TestRunRenderCacheTamperedRecordEvicted(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	store, err := cache.Open(cacheDir)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	_ = store
	reg, _ := NewDefaultRegistry()
	cfg := DefaultEngineConfig(reg, dir)
	cfg.Cache = store
	cfg.Reports = []string{"json"}
	if _, err := Run(context.Background(), cfg, testContext(t)); err != nil {
		t.Fatalf("cold run: %v", err)
	}

	// Corrupt every stored record's payload.
	err = filepath.Walk(filepath.Join(cacheDir, "entries"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		return os.WriteFile(path, []byte(`{"schema_version":1,"operation":"report.render","target":"report:x","created_at":"2026-01-01T00:00:00Z","status":"completed","data":{"report_id":"json","version":"9.9.9","format":"json","digest":"deadbeef","parts":[{"part":"","bytes":2,"data":"eHg="}]}}`), 0o600)
	})
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}

	res, err := Run(context.Background(), cfg, testContext(t))
	if err != nil {
		t.Fatalf("warm run: %v", err)
	}
	rep := resultFor(t, res, "json")
	if rep.Status != ReportStatusCompleted {
		t.Fatalf("tampered-cache run failed: %q %v", rep.Status, rep.Err)
	}
	if rep.Cached {
		t.Fatalf("tampered record was served")
	}
	data, err := os.ReadFile(rep.Files[0])
	if err != nil || len(data) == 0 {
		t.Fatalf("re-rendered output missing")
	}
}

func TestRunConcurrentSafe(t *testing.T) {
	// Parallel runs in separate directories sharing one registry: the
	// model is shared read-only across jobs within a run, and registries
	// are read-only at run time.
	reg, _ := NewDefaultRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			dir := filepath.Join(t.TempDir(), "out")
			res, err := Run(context.Background(), DefaultEngineConfig(reg, dir), testContext(t))
			if err != nil {
				t.Errorf("run %d: %v", n, err)
				return
			}
			if res.Outcome != OutcomeCompleted {
				t.Errorf("run %d outcome %q", n, res.Outcome)
			}
		}(i)
	}
	wg.Wait()
}

func TestRunParallelRenderersShareModel(t *testing.T) {
	// All four builtin renderers run concurrently against one model; the
	// run must complete and every output must validate (race detector
	// covers the shared-model contract).
	dir := t.TempDir()
	res := runReports(t, dir, nil)
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %q", res.Outcome)
	}
	for _, rep := range res.Reports {
		validate := builtin(t, rep.ReporterID).Validate
		for _, f := range rep.Files {
			if err := validate(f, false); err != nil {
				t.Fatalf("output %q failed validation: %v", f, err)
			}
		}
	}
}

func TestEngineConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  EngineConfig
		want string
	}{
		{"no registry", EngineConfig{OutputDir: "x"}, "registry"},
		{"no output dir", EngineConfig{Registry: NewRegistry()}, "output directory"},
		{"negative timeout", EngineConfig{Registry: NewRegistry(), OutputDir: "x", Timeout: -time.Second}, "negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Run(context.Background(), tc.cfg, Context{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
	if _, err := Run(nil, DefaultEngineConfig(mustRegistry(t), "x"), Context{}); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("nil context accepted: %v", err)
	}
}

func mustRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

// resultFor returns one reporter's result from a run.
func resultFor(t *testing.T, res RunResult, id string) ReportResult {
	t.Helper()
	for _, rep := range res.Reports {
		if rep.ReporterID == id {
			return rep
		}
	}
	t.Fatalf("reporter %q missing from run result", id)
	return ReportResult{}
}

// readAll snapshots every file in dir as base-name -> content.
func readAll(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[filepath.Base(path)] = data
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// withReports is a small test-only config helper.
func (c EngineConfig) withReports(ids ...string) EngineConfig {
	c.Reports = ids
	return c
}
