package priority

import (
	"encoding/json"
	"testing"
)

// TestSurfaceMemoryFootprint measures the average serialized surface size
// over the 100k benchmark signal corpus (input for the memory math; not a
// behavioral pin).
func TestSurfaceMemoryFootprint(t *testing.T) {
	sigs := synthSignals(100_000)
	ic, rc := mustCatalogs(t)
	var total int
	for i := 0; i < len(sigs); i += 97 { // ~1031-sample deterministic sweep
		s := sigs[i]
		s.ScoredAt = fixedTime(1)
		surface, err := ScoreSurface(s, ic, rc)
		if err != nil {
			t.Fatal(err)
		}
		buf, err := json.Marshal(surface)
		if err != nil {
			t.Fatal(err)
		}
		total += len(buf)
	}
	n := (len(sigs) + 96) / 97
	t.Logf("avg serialized surface: %d bytes over %d samples", total/n, n)
}
