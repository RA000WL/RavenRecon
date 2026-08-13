package cache

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Status records whether the work behind a cache entry finished successfully.
// Only completed entries are ever returned as usable cache hits.
type Status string

const (
	// StatusCompleted marks work that finished and produced a trustworthy
	// result. Only completed entries are returned as usable hits.
	StatusCompleted Status = "completed"

	// StatusFailed marks work that ran and failed. The entry is not a usable
	// result; Data may hold diagnostics.
	StatusFailed Status = "failed"

	// StatusCancelled marks work that was interrupted and cancelled before
	// finishing. Not usable as a result.
	StatusCancelled Status = "cancelled"

	// StatusIncomplete marks work that finished with partial results only.
	// Not usable as a successful result; Data may hold the partial results so
	// a later run can resume without repeating finished sub-work.
	StatusIncomplete Status = "incomplete"
)

func validStatus(s Status) bool {
	switch s {
	case StatusCompleted, StatusFailed, StatusCancelled, StatusIncomplete:
		return true
	}
	return false
}

// Record is a structured, self-describing cache entry. It is versioned, so a
// build never interprets a record layout it does not support, and it is not
// coupled to any single external tool.
//
// Cache keys are the index; the Record is the self-describing value. Keys are
// derived from the same identity information (operation, normalized target,
// configuration, tool) so a future runtime derives the key from the parts it
// also stores in the record.
type Record struct {
	// SchemaVersion is the record layout version. It must equal the package
	// SchemaVersion; Put rejects and Get reports records with other versions.
	SchemaVersion int `json:"schema_version"`

	// Operation is the stable capability name that produced this entry.
	Operation string `json:"operation"`

	// Target is the canonical asset identity this entry belongs to.
	Target string `json:"target"`

	// Tool optionally records which external tool produced the entry.
	Tool ToolInfo `json:"tool,omitempty"`

	// CreatedAt is when the work behind the entry was started (UTC). TTL is
	// measured from it.
	CreatedAt time.Time `json:"created_at"`

	// Status distinguishes completed, failed, cancelled, and incomplete work.
	Status Status `json:"status"`

	// Data is the structured result payload (arbitrary JSON). It is never
	// terminal output; stages store their own structured result models.
	Data json.RawMessage `json:"data,omitempty"`

	// Meta carries small annotations (run identifiers, counters, ...).
	Meta map[string]string `json:"meta,omitempty"`
}

// validate checks the schema version and, on success, the record content.
func (r Record) validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema version %d (want %d)", r.SchemaVersion, SchemaVersion)
	}
	return r.validateContent()
}

// validateContent checks fields that must hold regardless of the enclosing
// schema version. It is used both by Put (before writing) and by Get (after
// reading) to decide whether a decoded record can be trusted.
func (r Record) validateContent() error {
	if strings.TrimSpace(r.Operation) == "" {
		return fmt.Errorf("record operation must not be empty")
	}
	if strings.TrimSpace(r.Target) == "" {
		return fmt.Errorf("record target must not be empty")
	}
	if !validStatus(r.Status) {
		return fmt.Errorf("record has invalid status %q", truncateForError(string(r.Status)))
	}
	if r.CreatedAt.IsZero() {
		return fmt.Errorf("record created_at must not be zero")
	}
	return nil
}

// maxErrorFieldLen bounds how many bytes of an unbounded record field value
// (Status, Operation, Target) may be echoed into a validation error. Field
// values are caller- or on-disk-supplied and potentially hostile;
// interpolating them verbatim could bloat error strings and logs unboundedly.
const maxErrorFieldLen = 200

// truncationMarker marks the tail of a field value truncated for error
// messages.
const truncationMarker = "...(truncated)"

// truncateForError limits a record field value to maxErrorFieldLen bytes for
// inclusion in an error message, appending truncationMarker when it was cut.
// Values within the limit are returned unchanged.
func truncateForError(s string) string {
	if len(s) <= maxErrorFieldLen {
		return s
	}
	return s[:maxErrorFieldLen] + truncationMarker
}
