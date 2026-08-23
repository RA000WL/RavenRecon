package pipeline

import (
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/importer"
)

// TestMergeProvenanceDedupAndCap pins the runner-side import-provenance
// sidecar merge (v1.8 T11): first-seen dedup on the identity|filename|
// importer triple, and the MaxOutput cap reporting its cut so the caller can
// flag import_provenance_truncated.
func TestMergeProvenanceDedupAndCap(t *testing.T) {
	rec := func(id, file string) importer.ProvenanceRecord {
		return importer.ProvenanceRecord{Identity: id, Filename: file, Importer: "plain-urls"}
	}
	seen := map[string]struct{}{}
	got, cut := mergeProvenance(nil, []importer.ProvenanceRecord{rec("url:a", "f1")}, seen, 10)
	if cut || len(got) != 1 {
		t.Fatalf("first merge: %d records cut=%v, want 1/not-cut", len(got), cut)
	}
	// Same identity+file+importer again → deduplicated (a re-served cache
	// hit of the same file must not duplicate records).
	got, _ = mergeProvenance(got, []importer.ProvenanceRecord{rec("url:a", "f1")}, seen, 10)
	if len(got) != 1 {
		t.Fatalf("dedup failed: %d records, want 1", len(got))
	}
	// Same identity from another file → kept (both records legitimate).
	got, _ = mergeProvenance(got, []importer.ProvenanceRecord{rec("url:a", "f2")}, seen, 10)
	if len(got) != 2 {
		t.Fatalf("cross-file record dropped: %d records, want 2", len(got))
	}
	// Cap: adding two more against cap 3 cuts one tail record.
	got, cut = mergeProvenance(got, []importer.ProvenanceRecord{rec("url:b", "f1"), rec("url:c", "f1")}, seen, 3)
	if !cut || len(got) != 3 {
		t.Fatalf("cap merge: %d records cut=%v, want 3/cut", len(got), cut)
	}
}

// TestValidStageIngestVocabulary pins the v1.8 vocabulary decision: "ingest"
// is a valid stage selection, but AllStages stays the fixed twelve-stage
// production order.
func TestValidStageIngestVocabulary(t *testing.T) {
	if !ValidStage(StageIngest) {
		t.Fatalf("StageIngest not valid")
	}
	if got := AllStages(); len(got) != 12 {
		t.Fatalf("AllStages = %d entries, want 12 (production order unchanged)", len(got))
	}
	for _, s := range AllStages() {
		if s == StageIngest {
			t.Fatalf("ingest leaked into AllStages production order")
		}
	}
	cfg := ScanConfig{
		Target: mustDomainIngest(t),
		Stages: []StageName{StageIngest, StageDiscover},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("[ingest discover] rejected: %v", err)
	}
	bad := ScanConfig{Target: mustDomainIngest(t), Stages: []StageName{"nope"}}
	err := bad.Validate()
	if err == nil || !strings.Contains(err.Error(), "known stages") || !strings.Contains(err.Error(), "ingest") {
		t.Fatalf("unknown-stage error should list ingest in the vocabulary, got: %v", err)
	}
}

func mustDomainIngest(t *testing.T) asset.Domain {
	t.Helper()
	d, err := asset.NewDomain("example.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("domain: %v", err)
	}
	return d
}
