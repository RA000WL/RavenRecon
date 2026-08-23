package report

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestNewStageErrorRecordClassification pins the stage-failure record
// constructor (NEW-90): structural category derivation, the stage-prefixed
// message, and the defensive zero-error shape.
func TestNewStageErrorRecordClassification(t *testing.T) {
	timeout := NewStageErrorRecord("crawl", context.DeadlineExceeded)
	if timeout.Category != CategoryTimeout {
		t.Errorf("deadline-exceeded category = %q, want %q", timeout.Category, CategoryTimeout)
	}
	if !strings.HasPrefix(timeout.Message, "stage crawl: ") {
		t.Errorf("message = %q, want the stage-prefixed text", timeout.Message)
	}

	cancel := NewStageErrorRecord("dns", context.Canceled)
	if cancel.Category != CategoryCancellation {
		t.Errorf("canceled category = %q, want %q", cancel.Category, CategoryCancellation)
	}

	generic := NewStageErrorRecord("discover", errors.New("boom"))
	if generic.Category != CategoryUnknown {
		t.Errorf("plain error category = %q, want %q", generic.Category, CategoryUnknown)
	}
	if generic.Message != "stage discover: boom" || generic.Count != 1 || generic.Stage != "discover" {
		t.Errorf("record = %+v, want prefixed message/count 1/stage label", generic)
	}

	defensive := NewStageErrorRecord("s", nil)
	if defensive.Category != CategoryUnknown || defensive.Message != "stage s: " {
		t.Errorf("nil-error record = %+v, want unknown category and empty detail", defensive)
	}
}
