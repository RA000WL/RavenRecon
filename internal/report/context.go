package report

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
	"github.com/RA000WL/RavenRecon/internal/priority"
)

// SchemaVersion is the report model's schema version. It appears in every
// JSON export, enters every render-cache key, and is validated on decode; a
// build never interprets an export whose schema version it does not support.
const SchemaVersion = 1

// Context is the caller-composed input of one report run: the canonical,
// structured output the earlier phases produced plus the run's own
// statistics. It is NOT untrusted tool output — every entry must already be
// a canonical Phase 2 value (NewModel re-derives every identity through the
// Phase 2 builders and rejects a non-canonical entry with a structured error
// naming it, mirroring the detection framework's snapshot contract).
//
// The zero Context is valid (an empty report); fields are added as the
// caller's run produced them. Nothing in a Context is mutated: NewModel
// copies, merges, and sorts into the Model.
type Context struct {
	// Target is the run's declared target (a canonical domain or host
	// name). It is display metadata and the default report base name; it
	// never reaches a filesystem path unsanitized.
	Target string

	// StartedAt and EndedAt bracket the recon run the report describes.
	// Both are caller-declared inputs (the report engine reads no wall
	// clock, so identical inputs produce identical reports). EndedAt before
	// StartedAt is rejected.
	StartedAt time.Time
	EndedAt   time.Time

	// The canonical Phase 2 corpus.
	Domains         []asset.Domain
	Hosts           []asset.Host
	IPs             []asset.IP
	Ports           []asset.Port
	Services        []asset.Service
	URLs            []asset.URL
	Endpoints       []asset.Endpoint
	JavaScript      []asset.JavaScript
	Parameters      []asset.Parameter
	Technologies    []asset.Technology
	Secrets         []asset.SecretCandidate
	Evidence        []asset.Evidence
	Findings        []asset.Finding
	TLSCertificates []asset.TLSCertificate
	SourceMaps      []asset.SourceMap
	Relationships   []asset.Relationship

	// The priority engine's output (phase 9): scored surfaces, correlated
	// groups, and attack-path hypotheses. All optional; a run that did not
	// score reports zero attack surface.
	Surfaces    []priority.SurfaceAsset
	Groups      []priority.Group
	AttackPaths []priority.AttackPath

	// LiveRecords are the URL liveness observations (urllive). They are
	// presentation-only and never rescanned; the report renders them as a
	// table/list in markdown/html.
	LiveRecords []httpprobe.LiveRecord

	// Attribution is the import-provenance input (v1.8 T13): per-asset
	// records keyed by canonical identity string ("host:api.example.com"),
	// stating where each IMPORTED asset came from. Optional — an absent or
	// empty map leaves every derived value byte-identical to a run without
	// ingestion (digest included). Keys must reference identities present
	// in the corpora above; NewModel rejects unknown keys with a structured
	// error. The map is bounded at maxAttributionEntries (sorted-key
	// prefix kept, overflow flagged on the Model — never silently
	// truncated).
	Attribution map[string]AttributionEntry

	// Errors is the run's error log for the error summary: one record per
	// distinct error observation (identical records merge by summing
	// counts).
	Errors []ErrorRecord

	// Runtime carries the run's worker-pool statistics (callers collect
	// them from their runtime pool subscriptions).
	Runtime RuntimeStats

	// Cache carries the run's cache statistics.
	Cache CacheStats

	// Execution carries the run's rule-execution statistics (the detection
	// framework's metrics).
	Execution ExecStats
}

// ErrorCategory groups errors for the error summary. The vocabulary is
// fixed; ClassifyError derives a category structurally where it can and
// callers pass explicit categories everywhere else.
type ErrorCategory string

// Error categories.
const (
	CategoryDNS          ErrorCategory = "dns"
	CategoryHTTP         ErrorCategory = "http"
	CategoryTLS          ErrorCategory = "tls"
	CategoryParsing      ErrorCategory = "parsing"
	CategoryCache        ErrorCategory = "cache"
	CategoryTimeout      ErrorCategory = "timeout"
	CategoryCancellation ErrorCategory = "cancellation"
	CategoryToolFailure  ErrorCategory = "tool_failure"
	CategoryPermission   ErrorCategory = "permission"
	CategoryUnknown      ErrorCategory = "unknown"
)

// Valid reports whether c is one of the known error categories.
func (c ErrorCategory) Valid() bool {
	switch c {
	case CategoryDNS, CategoryHTTP, CategoryTLS, CategoryParsing, CategoryCache,
		CategoryTimeout, CategoryCancellation, CategoryToolFailure,
		CategoryPermission, CategoryUnknown:
		return true
	}
	return false
}

// KnownErrorCategories returns every error category in canonical sorted
// order. The returned slice is a fresh copy.
func KnownErrorCategories() []ErrorCategory {
	return []ErrorCategory{
		CategoryCache, CategoryCancellation, CategoryDNS, CategoryHTTP,
		CategoryParsing, CategoryPermission, CategoryTimeout, CategoryTLS,
		CategoryToolFailure, CategoryUnknown,
	}
}

// ClassifyError derives an error's category from its structure. It checks
// context cancellation, deadlines, DNS errors, URL parse errors, permission
// errors, and net-level timeouts; anything else classifies as unknown.
// Structural classification is deliberately conservative — it never guesses
// from message text. Callers that know an error's stage should record an
// explicit category instead.
func ClassifyError(err error) ErrorCategory {
	if err == nil {
		return CategoryUnknown
	}
	switch {
	case errors.Is(err, context.Canceled):
		return CategoryCancellation
	case errors.Is(err, context.DeadlineExceeded):
		return CategoryTimeout
	case errors.Is(err, os.ErrPermission):
		return CategoryPermission
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return CategoryDNS
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return CategoryTimeout
		}
		return CategoryHTTP
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return CategoryTimeout
	}
	return CategoryUnknown
}

// Bounds applied to error records (fixed constants).
const (
	// maxErrorStageBytes bounds one error's stage label.
	maxErrorStageBytes = 64
	// maxErrorMessageBytes bounds one error's message.
	maxErrorMessageBytes = 512
	// errorTruncationMarker marks a truncated stage or message.
	errorTruncationMarker = "…"
)

// ErrorRecord is one bounded error observation for the error summary.
// Records with the same (category, stage, message) merge by summing counts.
type ErrorRecord struct {
	// Category groups the error (see ErrorCategory).
	Category ErrorCategory `json:"category"`

	// Stage names the pipeline stage that observed the error (a bounded,
	// free-form label, e.g. "dns" or "http.probe").
	Stage string `json:"stage"`

	// Message is the bounded error message. Messages are truncated to
	// maxErrorMessageBytes with an explicit marker; error text must never
	// carry secrets (the caller is responsible for what it records).
	Message string `json:"message"`

	// Count is how many times this exact error was observed (<= 0
	// normalizes to 1).
	Count int `json:"count"`
}

// maxAttributionBytes bounds one attribution entry's string fields (fixed
// constant, mirroring the error-record bounds).
const maxAttributionBytes = 512

// maxAttributionEntries bounds the attribution map (the MaxOutput-style cap):
// over-bound input keeps the first entries in sorted-key order and the Model
// flags the overflow with AttributionTruncated — never a silent truncation.
const maxAttributionEntries = 100_000

// AttributionEntry is one imported asset's provenance for the report: which
// importer ingested it, which original tool produced the data, from which
// file, at what time, with what confidence. Line is the record's in-file
// position when known (0 otherwise; today's importer sidecar carries position
// info via the asset provenance Reference — a "filename:line" string for
// line-oriented formats, but an element ordinal for array/NDJSON framing, so
// populating Line from it reliably is the CLI wiring task's concern, not the
// report model's).
type AttributionEntry struct {
	// Importer is the internal/importer engine name ("plain-urls",
	// "json-httpx", ...).
	Importer string `json:"importer,omitempty"`

	// OriginalTool is the tool whose output format was ingested ("httpx",
	// "burpsuite", ... — the importer package's provenance mapping).
	OriginalTool string `json:"original_tool,omitempty"`

	// Filename is the base name of the ingested file.
	Filename string `json:"filename,omitempty"`

	// Line is the 1-based record line when known; 0 means unknown.
	Line int `json:"line,omitempty"`

	// ImportedAt is when the file was ingested (content provenance, not
	// wall-clock timing metadata — it participates in the digest exactly
	// like asset DiscoveredAt). No omitempty: omitempty never fires on a
	// struct, so the tag would only mislead readers — the field always
	// serializes.
	ImportedAt time.Time `json:"imported_at"`

	// Confidence is the observation confidence in [0,1].
	Confidence float64 `json:"confidence,omitempty"`
}

// RuntimeStats carries the run's worker-pool statistics. Callers collect
// them from their runtime.Pool event subscriptions; the report framework
// only presents them.
type RuntimeStats struct {
	// Workers is the pool's configured worker count.
	Workers int `json:"workers,omitempty"`

	// Jobs is the total number of jobs the run submitted.
	Jobs int `json:"jobs,omitempty"`

	// JobsCompleted, JobsFailed, JobsCancelled, and JobsTimedOut count the
	// terminal job outcomes.
	JobsCompleted int `json:"jobs_completed,omitempty"`
	JobsFailed    int `json:"jobs_failed,omitempty"`
	JobsCancelled int `json:"jobs_cancelled,omitempty"`
	JobsTimedOut  int `json:"jobs_timed_out,omitempty"`

	// WorkerTime is the cumulative time workers spent executing jobs
	// (completed + failed), derived from the pool events' started/terminal
	// timestamps (convert with Ms).
	WorkerTime Milliseconds `json:"worker_time_ms,omitempty"`
}

// CacheStats carries the run's cache statistics.
type CacheStats struct {
	// Hits and Misses count the run's cache lookups.
	Hits   int `json:"hits,omitempty"`
	Misses int `json:"misses,omitempty"`

	// Reads and Stores count raw cache operations when the caller tracked
	// them separately.
	Reads  int `json:"reads,omitempty"`
	Stores int `json:"stores,omitempty"`

	// Evictions counts entries removed by strict decode re-validation.
	Evictions int `json:"evictions,omitempty"`
}

// ExecStats carries the run's rule-execution statistics (the phase 10
// detection framework's metrics shape).
type ExecStats struct {
	// Rules is the number of rules registered for the run.
	Rules int `json:"rules,omitempty"`

	// Executions counts fresh detector executions.
	Executions int `json:"executions,omitempty"`

	// Errors, Timeouts, and Panics count the failure classes.
	Errors   int `json:"errors,omitempty"`
	Timeouts int `json:"timeouts,omitempty"`
	Panics   int `json:"panics,omitempty"`

	// CacheHits and CacheMisses count the rule cache outcomes.
	CacheHits   int `json:"cache_hits,omitempty"`
	CacheMisses int `json:"cache_misses,omitempty"`
}

// NewStageErrorRecord builds the ErrorRecord for one failed pipeline stage
// (NEW-90): the category derives structurally from the error
// (ClassifyError — deadline-exceeded classifies as timeout, cancellation as
// cancellation), and the message is prefixed with the stage name so even
// flattened views attribute the failure. The returned record passes through
// NewModel's normal bounds (maxErrorStageBytes / maxErrorMessageBytes) and
// dedup (records merge by category+stage+message).
func NewStageErrorRecord(stage string, err error) ErrorRecord {
	var msg string
	if err != nil {
		msg = err.Error()
	}
	if stage != "" {
		msg = "stage " + stage + ": " + msg
	}
	return ErrorRecord{
		Category: ClassifyError(err),
		Stage:    stage,
		Message:  msg,
		Count:    1,
	}
}

// normalizeErrorRecord validates, bounds, and canonicalizes one error
// record: an invalid category is rejected, over-bound stages and messages
// are truncated rune-safely with the marker, and a non-positive count
// becomes 1.
func normalizeErrorRecord(r ErrorRecord) (ErrorRecord, error) {
	if !r.Category.Valid() {
		return ErrorRecord{}, fmt.Errorf("report: error record has invalid category %q", string(r.Category))
	}
	if r.Count <= 0 {
		r.Count = 1
	}
	r.Stage = truncateRunes(r.Stage, maxErrorStageBytes)
	r.Message = truncateRunes(r.Message, maxErrorMessageBytes)
	return r, nil
}
