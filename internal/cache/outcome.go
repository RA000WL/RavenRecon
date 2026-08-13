package cache

import "fmt"

// OutcomeState is the precise result of a Get. Distinct states are exposed so
// callers never lose diagnostic information: a corrupt entry, an expired
// entry, and a schema-incompatible entry are all "no valid cached result",
// but they are meaningfully different situations.
type OutcomeState int

const (
	// StateHit: a completed, unexpired record exists for the key and is
	// returned as the valid result.
	StateHit OutcomeState = iota

	// StateMiss: no entry exists for the key.
	StateMiss

	// StateExpired: an entry exists but its TTL has elapsed. It is not a
	// valid result; the record is attached to the outcome for diagnostics.
	// TTL expiration is evaluated before status: an expired record reports
	// StateExpired even when its status is not completed, so the attached
	// record (and any resume data it carries) remains reachable.
	StateExpired

	// StateCorrupt: an entry exists but could not be parsed, failed content
	// validation, exceeds the size limit, or is not a regular file (for
	// example a planted directory, FIFO, socket, or symlink). It has been
	// removed (self-healing). Not a valid result.
	StateCorrupt

	// StateSchemaIncompatible: an entry exists but carries a schema version
	// this build cannot interpret. It has been removed. Not a valid result.
	StateSchemaIncompatible

	// StateIncomplete: an entry exists and is well-formed, but it does not
	// represent successful completion (its Status is failed, cancelled, or
	// incomplete). Only unexpired non-completed records report this state;
	// an expired one is StateExpired instead (see StateExpired). The record
	// is attached so a caller can inspect Record.Status and any partial
	// Data. Not a valid result.
	StateIncomplete

	// StateError: the outcome could not be determined because of a
	// filesystem-level failure; Err carries the cause.
	StateError
)

func (s OutcomeState) String() string {
	switch s {
	case StateHit:
		return "hit"
	case StateMiss:
		return "miss"
	case StateExpired:
		return "expired"
	case StateCorrupt:
		return "corrupt"
	case StateSchemaIncompatible:
		return "schema-incompatible"
	case StateIncomplete:
		return "incomplete"
	case StateError:
		return "error"
	default:
		return fmt.Sprintf("outcome-state(%d)", int(s))
	}
}

// Outcome is the full result of a Get.
type Outcome struct {
	// State is the precise outcome (see OutcomeState).
	State OutcomeState

	// Record is non-nil for StateHit, StateExpired, and StateIncomplete. It
	// is never returned for corrupted, schema-incompatible, or missing
	// entries.
	Record *Record

	// Err is non-nil for StateError and carries the cause for StateCorrupt
	// and StateSchemaIncompatible (diagnostics). It never contains cache
	// record content.
	Err error
}

// IsHit reports whether the outcome is a valid completed result that can be
// used without re-executing work.
func (o Outcome) IsHit() bool { return o.State == StateHit }

// IsUsable is an alias for IsHit; a usable outcome is one whose record may be
// trusted as a completed result.
func (o Outcome) IsUsable() bool { return o.State == StateHit }

// IsMiss reports that no valid cached result exists, so the caller must
// execute the work. Miss, expired, corrupt, schema-incompatible, incomplete,
// and error outcomes are all misses; State distinguishes them. For
// StateError the caller should inspect Err before deciding how to proceed.
func (o Outcome) IsMiss() bool { return o.State != StateHit }

// ValidResult returns the record together with true when the outcome is a
// usable hit, and (nil, false) otherwise.
func (o Outcome) ValidResult() (*Record, bool) {
	if !o.IsUsable() {
		return nil, false
	}
	return o.Record, true
}
