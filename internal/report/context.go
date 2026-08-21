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
