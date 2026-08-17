package report

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"
)

// maxRegistryReports bounds the registry (fixed constant): it protects
// engine memory from runaway registration while staying far above any
// realistic format count.
const maxRegistryReports = 64

// Reporter metadata string bounds (fixed constants).
const (
	maxReporterIDBytes          = 32
	maxReporterNameBytes        = 128
	maxReporterDescriptionBytes = 512
	maxReporterVersionBytes     = 32
)

// Format is a report's output format. The framework ships four; future
// formats register through the same Reporter contract.
type Format string

// Output formats.
const (
	FormatJSON     Format = "json"
	FormatCSV      Format = "csv"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

// Valid reports whether f is one of the formats the framework knows.
func (f Format) Valid() bool {
	switch f {
	case FormatJSON, FormatCSV, FormatMarkdown, FormatHTML:
		return true
	}
	return false
}

// extension returns the canonical file extension for the format.
func (f Format) extension() string {
	switch f {
	case FormatJSON:
		return "json"
	case FormatCSV:
		return "csv"
	case FormatMarkdown:
		return "md"
	case FormatHTML:
		return "html"
	}
	return string(f)
}

// Sink is the output seam reporters render into. Part "" is a report's
// default (single) part; a multi-dataset report (the CSV export) names its
// parts ("hosts", "urls", ...). Each part may be opened exactly once and
// must be closed before the engine commits or aborts the sink.
type Sink interface {
	// Writer returns the writer for one named part. An unknown or reopened
	// part is an error.
	Writer(part string) (io.WriteCloser, error)
}

// RenderFunc renders one report from the canonical model into the sink.
// Implementations must:
//
//   - treat the Model as immutable (it is shared across concurrent jobs);
//   - honor ctx cancellation between output units (rows, sections) and
//     return promptly with ctx.Err();
//   - stream output (never buffer the whole report in memory).
type RenderFunc func(ctx context.Context, m *Model, s Sink) error

// Reporter is a registered report: validated, immutable metadata plus the
// render function. Reports register like rules — the registry validates
// every field at registration and rejects duplicates.
type Reporter struct {
	// ID is the canonical report ID (a stable, lowercase identifier, e.g.
	// "json"). It enters filenames when disambiguation is needed and every
	// result.
	ID string

	// Name is the human-readable name.
	Name string

	// Description is a bounded human-readable description.
	Description string

	// Version is the reporter's semantic version. A version bump changes
	// output; the version enters the render-cache key (the documented bump
	// contract, mirroring the detection rules).
	Version string

	// Format is the output format.
	Format Format

	// SupportsCompression reports whether the output remains valid when
	// gzip-compressed (streaming formats do; formats that must stay
	// byte-addressable would not).
	SupportsCompression bool

	// Enabled selects whether the engine runs the reporter. Disabled
	// reporters stay registered and are reported as skipped.
	Enabled bool

	// Render renders the report.
	Render RenderFunc

	// Validate optionally checks one rendered, committed part file. nil
	// means the engine applies the default non-empty check. The function
	// receives the file path and whether the file is gzip-compressed.
	Validate func(path string, compressed bool) error
}

// validateReporter enforces the metadata contract: bounded printable ID,
// name, description, and version; a known format; a non-nil render
// function.
func validateReporter(r Reporter) error {
	if err := validatePrintableASCII(r.ID, "report id", maxReporterIDBytes); err != nil {
		return err
	}
	for i := 0; i < len(r.ID); i++ {
		c := r.ID[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return fmt.Errorf("report: report id %q contains a character outside [a-z0-9.-]", r.ID)
		}
	}
	if err := validatePrintableASCII(r.Name, "report name", maxReporterNameBytes); err != nil {
		return err
	}
	if err := validatePrintableASCII(r.Description, "report description", maxReporterDescriptionBytes); err != nil {
		return err
	}
	if err := validatePrintableASCII(r.Version, "report version", maxReporterVersionBytes); err != nil {
		return err
	}
	if !r.Format.Valid() {
		return fmt.Errorf("report: reporter %q has unknown format %q", r.ID, string(r.Format))
	}
	if r.Render == nil {
		return fmt.Errorf("report: reporter %q has no render function", r.ID)
	}
	return nil
}

// validatePrintableASCII enforces the shared metadata-field contract:
// non-empty, within bound, printable ASCII.
func validatePrintableASCII(s, what string, max int) error {
	if s == "" {
		return fmt.Errorf("report: %s must not be empty", what)
	}
	if len(s) > max {
		return fmt.Errorf("report: %s is over %d bytes", what, max)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return fmt.Errorf("report: %s contains a non-printable character", what)
		}
	}
	return nil
}

// Registry is the report registration point: reporters are validated on
// registration, stored as immutable values, and never mutated afterwards.
// It is safe for concurrent use; the expected pattern is single-writer at
// startup, many readers at run time. Duplicate IDs and duplicate
// (case-insensitive) names are rejected.
type Registry struct {
	mu       sync.RWMutex
	reports  map[string]Reporter
	names    map[string]string // lowercase name -> report ID
	readonly bool
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		reports: make(map[string]Reporter),
		names:   make(map[string]string),
	}
}

// Register validates rep and adds it to the registry. Duplicate report IDs
// and duplicate names (case-insensitive) are rejected.
func (r *Registry) Register(rep Reporter) error {
	if r.readonly {
		return fmt.Errorf("report: registry is sealed")
	}
	if err := validateReporter(rep); err != nil {
		return fmt.Errorf("report: register reporter: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reports) >= maxRegistryReports {
		return fmt.Errorf("report: registry is full (%d reporters)", maxRegistryReports)
	}
	if _, ok := r.reports[rep.ID]; ok {
		return fmt.Errorf("report: duplicate reporter id %q", rep.ID)
	}
	nameKey := lowerASCII(rep.Name)
	if owner, ok := r.names[nameKey]; ok {
		return fmt.Errorf("report: reporter name %q duplicates reporter %q", rep.Name, owner)
	}
	r.reports[rep.ID] = rep
	r.names[nameKey] = rep.ID
	return nil
}

// Get returns the registered reporter with the given ID.
func (r *Registry) Get(id string) (Reporter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rep, ok := r.reports[id]
	return rep, ok
}

// Reports returns every registered reporter sorted by ID — the
// deterministic registry order.
func (r *Registry) Reports() []Reporter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Reporter, 0, len(r.reports))
	for _, rep := range r.reports {
		out = append(out, rep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Len returns the number of registered reporters.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.reports)
}

// Seal freezes the registry: any later Register call fails. Sealing is
// optional; it exists for callers that want registration confined to
// startup.
func (r *Registry) Seal() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readonly = true
}

// BuiltinReporters returns the four built-in exports (JSON, CSV, Markdown,
// HTML) as fresh values a caller registers into its own registry. The
// framework ships the format exporters; future formats plug in through the
// same contract.
func BuiltinReporters() []Reporter {
	return []Reporter{
		{
			ID:                  "json",
			Name:                "JSON export",
			Description:         "Complete structured export of the canonical report model: every dataset, statistics, summaries, errors, and the model digest. Deterministic ordering, stable versioned schema, machine-readable.",
			Version:             "1.0.0",
			Format:              FormatJSON,
			SupportsCompression: true,
			Enabled:             true,
			Render:              renderJSON,
			Validate:            validateJSONFile,
		},
		{
			ID:                  "csv",
			Name:                "CSV export",
			Description:         "One CSV table per dataset (hosts, urls, endpoints, technologies, secrets, findings) with header rows and spreadsheet-formula injection neutralized.",
			Version:             "1.0.0",
			Format:              FormatCSV,
			SupportsCompression: true,
			Enabled:             true,
			Render:              renderCSV,
			Validate:            validateCSVFile,
		},
		{
			ID:                  "markdown",
			Name:                "Markdown report",
			Description:         "Human-readable summary report: target, run summary, interesting assets, technologies, secrets, top findings, attack surface, recommendations, statistics, and errors.",
			Version:             "1.0.0",
			Format:              FormatMarkdown,
			SupportsCompression: true,
			Enabled:             true,
			Render:              renderMarkdown,
			Validate:            validateMarkdownFile,
		},
		{
			ID:                  "html",
			Name:                "HTML report",
			Description:         "Self-contained static HTML report with collapsible sections, search, and category filters (inline CSS and vanilla script only; no frameworks, no external resources).",
			Version:             "1.0.0",
			Format:              FormatHTML,
			SupportsCompression: true,
			Enabled:             true,
			Render:              renderHTML,
			Validate:            validateHTMLFile,
		},
	}
}

// NewDefaultRegistry returns a registry with the four built-in reporters
// registered.
func NewDefaultRegistry() (*Registry, error) {
	reg := NewRegistry()
	for _, rep := range BuiltinReporters() {
		if err := reg.Register(rep); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// lowerASCII lowercases ASCII letters only — the duplicate-name fold.
func lowerASCII(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + ('a' - 'A')
		}
	}
	return string(out)
}
