package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/cache"
)

// TestDecodeRenderRejectsTraversalPartNames pins the cache-boundary half of
// the part-name defense: a record whose identity fields all match the
// current run but whose part name would traverse a path is rejected and
// (by the engine contract) evicted, never served.
func TestDecodeRenderRejectsTraversalPartNames(t *testing.T) {
	m := testModel(t)
	rep := Reporter{ID: "json", Version: "1.0.0", Format: FormatJSON}
	for _, part := range []string{"../../evil", "a/b", "UPPER"} {
		payload, err := json.Marshal(renderRecord{
			ReportID: rep.ID, Version: rep.Version, Format: string(rep.Format),
			Digest: m.Digest,
			Parts:  []renderPart{{Part: part, Bytes: 2, Data: []byte("xx")}},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		outcome := cache.Outcome{State: cache.StateHit, Record: &cache.Record{
			SchemaVersion: cache.SchemaVersion,
			Status:        cache.StatusCompleted,
			Data:          payload,
		}}
		if parts, err := decodeRender(outcome, m, rep, false); err == nil {
			t.Fatalf("record with part name %q accepted: %+v", part, parts)
		}
	}
}

// TestDecodeRenderAcceptsHonestRecord pins that a well-formed record with
// the exact identity fields still decodes.
func TestDecodeRenderAcceptsHonestRecord(t *testing.T) {
	m := testModel(t)
	rep := Reporter{ID: "json", Version: "1.0.0", Format: FormatJSON}
	payload, err := json.Marshal(renderRecord{
		ReportID: rep.ID, Version: rep.Version, Format: string(rep.Format),
		Digest: m.Digest,
		Parts:  []renderPart{{Part: "", Bytes: 7, Data: []byte(`{"a":1}`)}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	outcome := cache.Outcome{State: cache.StateHit, Record: &cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Status:        cache.StatusCompleted,
		Data:          payload,
	}}
	parts, err := decodeRender(outcome, m, rep, false)
	if err != nil || len(parts) != 1 || parts[0].Part != "" || string(parts[0].Data) != `{"a":1}` {
		t.Fatalf("honest record rejected: %+v %v", parts, err)
	}
}

// TestDecodeRenderRejectsEmptyPartPayload pins the L-10 regression: a
// record whose identity fields all match the current run but whose part
// carries a zero-byte payload is refused with a descriptive error, so the
// engine's decode-failure path evicts it and re-renders fresh instead of
// serving a render that fails validation forever.
func TestDecodeRenderRejectsEmptyPartPayload(t *testing.T) {
	m := testModel(t)
	rep := Reporter{ID: "json", Version: "1.0.0", Format: FormatJSON}

	// Genuinely zero-byte payloads (the L-10 defect) must be rejected with
	// a descriptive "empty payload" error, regardless of the declared byte
	// count: the empty default part and the empty named part.
	for _, part := range []renderPart{
		{Part: "", Bytes: 0, Data: []byte{}},
		{Part: "", Bytes: 1, Data: []byte{}},
		{Part: "hosts", Bytes: 0, Data: nil},
	} {
		payload, err := json.Marshal(renderRecord{
			ReportID: rep.ID, Version: rep.Version, Format: string(rep.Format),
			Digest: m.Digest,
			Parts:  []renderPart{part},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		outcome := cache.Outcome{State: cache.StateHit, Record: &cache.Record{
			SchemaVersion: cache.SchemaVersion,
			Status:        cache.StatusCompleted,
			Data:          payload,
		}}
		if parts, err := decodeRender(outcome, m, rep, false); err == nil {
			t.Fatalf("record with empty part payload accepted: %+v", parts)
		} else if !strings.Contains(err.Error(), "empty payload") {
			t.Fatalf("rejection error not descriptive (want 'empty payload'): %v", err)
		}
	}

	// A payload that contradicts its declared byte count is rejected too
	// (the declared-size check); it is a different defect, so only the
	// rejection itself is pinned here.
	payload, err := json.Marshal(renderRecord{
		ReportID: rep.ID, Version: rep.Version, Format: string(rep.Format),
		Digest: m.Digest,
		Parts:  []renderPart{{Part: "", Bytes: 0, Data: []byte("x")}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	outcome := cache.Outcome{State: cache.StateHit, Record: &cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Status:        cache.StatusCompleted,
		Data:          payload,
	}}
	if parts, err := decodeRender(outcome, m, rep, false); err == nil {
		t.Fatalf("record with contradictory byte count accepted: %+v", parts)
	}
}
