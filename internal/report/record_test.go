package report

import (
	"encoding/json"
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
		if parts, ok := decodeRender(outcome, m, rep, false); ok {
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
	parts, ok := decodeRender(outcome, m, rep, false)
	if !ok || len(parts) != 1 || parts[0].Part != "" || string(parts[0].Data) != `{"a":1}` {
		t.Fatalf("honest record rejected: %+v %v", parts, ok)
	}
}
