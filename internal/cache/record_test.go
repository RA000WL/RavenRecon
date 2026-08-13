package cache

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRecordValidate(t *testing.T) {
	good := Record{
		SchemaVersion: SchemaVersion,
		Operation:     "dns.resolve",
		Target:        "host:example.com",
		CreatedAt:     time.Unix(1_000_000_000, 0).UTC(),
		Status:        StatusCompleted,
	}
	if err := good.validate(); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Record)
	}{
		{"wrong schema", func(r *Record) { r.SchemaVersion = SchemaVersion + 1 }},
		{"empty operation", func(r *Record) { r.Operation = "" }},
		{"blank operation", func(r *Record) { r.Operation = "  " }},
		{"empty target", func(r *Record) { r.Target = "" }},
		{"empty status", func(r *Record) { r.Status = "" }},
		{"bad status", func(r *Record) { r.Status = "in-progress" }},
		{"zero created at", func(r *Record) { r.CreatedAt = time.Time{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := good
			tt.mutate(&r)
			if err := r.validate(); err == nil {
				t.Fatalf("expected validation error for %s", tt.name)
			}
		})
	}
}

func TestRecordRoundTrip(t *testing.T) {
	rec := Record{
		SchemaVersion: SchemaVersion,
		Operation:     "http.probe",
		Target:        "url:https://example.com/",
		Tool:          ToolInfo{Name: "httpx", Version: "1.6.0"},
		CreatedAt:     time.Unix(1_600_000_000, 0).UTC(),
		Status:        StatusCompleted,
		Data:          json.RawMessage(`{"status_code":200,"title":"Example"}`),
		Meta:          map[string]string{"run": "abc123"},
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Record
	if err := json.Unmarshal(buf, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.SchemaVersion != rec.SchemaVersion ||
		back.Operation != rec.Operation ||
		back.Target != rec.Target ||
		back.Tool != rec.Tool ||
		!back.CreatedAt.Equal(rec.CreatedAt) ||
		back.Status != rec.Status ||
		string(back.Data) != string(rec.Data) ||
		back.Meta["run"] != "abc123" {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", back, rec)
	}
}

func TestRecordStatusesDistinct(t *testing.T) {
	// The four statuses must be pairwise distinct strings so partial, failed,
	// cancelled, and completed work can never be confused.
	want := map[Status]bool{
		StatusCompleted:  true,
		StatusFailed:     true,
		StatusCancelled:  true,
		StatusIncomplete: true,
	}
	if len(want) != 4 {
		t.Fatal("status constants are not pairwise distinct")
	}
}

// TestRecordValidationErrorBounded verifies that validation errors never
// interpolate unbounded field values verbatim: an oversized Status value must
// produce an error far smaller than the field itself, with an explicit
// truncation marker.
func TestRecordValidationErrorBounded(t *testing.T) {
	bigStatus := strings.Repeat("x", 1<<20) // 1 MiB
	rec := Record{
		SchemaVersion: SchemaVersion,
		Operation:     "op",
		Target:        "host:example.com",
		CreatedAt:     time.Unix(1_000_000_000, 0).UTC(),
		Status:        Status(bigStatus),
	}
	err := rec.validate()
	if err == nil {
		t.Fatal("expected validation error for invalid status")
	}
	msg := err.Error()
	if len(msg) > 1<<10 {
		t.Fatalf("validation error is %d bytes, not bounded (field was %d bytes)", len(msg), len(bigStatus))
	}
	if !strings.Contains(msg, truncationMarker) {
		t.Fatalf("expected truncation marker in error %q", msg)
	}
}
