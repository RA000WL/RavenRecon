package techintel

import (
	"context"
	"fmt"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// deriveTerminal builds the task_completed terminal event the Deriving
// bridge hands to Derive alongside the raw job result.
func deriveTerminal(at interface{ String() string }) event.Event {
	panic("unused")
}

// mustTech builds one detected technology result for Derive unit tests.
func mustTech(t *testing.T, name string, score float64) TechnologyResult {
	t.Helper()
	tech, err := asset.NewTechnology(name, asset.CategoryServer, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	return TechnologyResult{Technology: tech, Score: score, Level: LevelHigh}
}

func TestDeriverDerivesTechnologiesEvidenceAndEdges(t *testing.T) {
	url := mustURL(t, "https://ok.example/")
	tech := mustTech(t, "nginx", 0.9)
	evi, err := asset.NewEvidence(asset.MethodHeader, "header:server", "nginx/1.25.3", url.Identity(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	rel, err := asset.NewRelationship(url.Identity(), asset.RelationshipURLToTechnology, tech.Technology.Identity())
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	entry := ReportEntry{
		ID:            url.Identity(),
		URL:           url,
		Status:        StatusCompleted,
		Technologies:  []TechnologyResult{tech},
		Evidence:      []asset.Evidence{evi},
		Relationships: []asset.Relationship{rel},
	}

	at := fixedTime
	term := event.New(event.KindTaskCompleted, at, event.NewTaskCompleted(event.NewTaskTerminal(7, 2, at, "", ""), entry))
	got := Deriver{}.Derive(term, entry)
	if len(got) != 3 {
		t.Fatalf("derived = %d events, want 3 (technology + evidence + edge)", len(got))
	}
	if got[0].Kind != event.KindAssetDiscovered || got[1].Kind != event.KindEvidenceCreated || got[2].Kind != event.KindRelationshipCreated {
		t.Fatalf("derived kinds = %q %q %q, want asset_discovered evidence_created relationship_created", got[0].Kind, got[1].Kind, got[2].Kind)
	}
	ad, ok := got[0].Payload.(event.AssetDiscovered)
	if !ok {
		t.Fatalf("event 0 payload = %T, want AssetDiscovered", got[0].Payload)
	}
	if ad.Identity != tech.Technology.Identity().String() || ad.Kind != string(asset.KindTechnology) || ad.Confidence != 0.9 {
		t.Errorf("asset payload = %+v, want technology identity/kind/confidence 0.9", ad)
	}
	ec, ok := got[1].Payload.(event.EvidenceCreated)
	if !ok {
		t.Fatalf("event 1 payload = %T, want EvidenceCreated", got[1].Payload)
	}
	if ec.Identity != evi.Identity().String() || ec.Source != url.Identity().String() || ec.Method != string(asset.MethodHeader) {
		t.Errorf("evidence payload = %+v", ec)
	}
	rc, ok := got[2].Payload.(event.RelationshipCreated)
	if !ok {
		t.Fatalf("event 2 payload = %T, want RelationshipCreated", got[2].Payload)
	}
	if rc.From != url.Identity().String() || rc.To != tech.Technology.Identity().String() || rc.Kind != string(asset.RelationshipURLToTechnology) {
		t.Errorf("relationship payload = %+v", rc)
	}
	for i, ev := range got {
		if !ev.At.Equal(at) {
			t.Errorf("event %d At = %v, want terminal time %v", i, ev.At, at)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("event %d invalid: %v (%+v)", i, err, ev)
		}
	}

	// Pointer results derive identically (the bridge hands over whatever
	// the job returned; both shapes are recognized).
	gotPtr := Deriver{}.Derive(term, &entry)
	if len(gotPtr) != 3 {
		t.Errorf("pointer derive = %d events, want 3", len(gotPtr))
	}
}

func TestDeriverIgnoresUnrecognizedResults(t *testing.T) {
	at := fixedTime
	term := event.New(event.KindTaskCompleted, at, event.NewTaskCompleted(event.NewTaskTerminal(1, 0, at, "", ""), nil))
	for name, result := range map[string]any{
		"nil":             nil,
		"string":          "host:example.com",
		"int":             42,
		"nil entry":       (*ReportEntry)(nil),
		"failed":          ReportEntry{Status: StatusFailed},
		"cancelled":       ReportEntry{Status: StatusCancelled},
		"empty completed": ReportEntry{Status: StatusCompleted},
	} {
		got := Deriver{}.Derive(term, result)
		if got != nil {
			t.Errorf("%s: derived %d events, want nil", name, len(got))
		}
	}
}

func TestDeriverCapsAtMaxDerivedPerJob(t *testing.T) {
	techs := make([]TechnologyResult, 0, 600)
	for i := 0; i < 600; i++ {
		techs = append(techs, mustTech(t, fmt.Sprintf("tech%03d", i), 0.5))
	}
	entry := ReportEntry{Status: StatusCompleted, Technologies: techs}
	at := fixedTime
	term := event.New(event.KindTaskCompleted, at, event.NewTaskCompleted(event.NewTaskTerminal(1, 0, at, "", ""), entry))
	got := Deriver{}.Derive(term, entry)
	if len(got) != maxDerivedPerJob {
		t.Fatalf("derived = %d events, want cap %d", len(got), maxDerivedPerJob)
	}
	for i, ev := range got {
		if ev.Kind != event.KindAssetDiscovered {
			t.Fatalf("event %d kind = %s, want asset_discovered (entry order preserved, head retained)", i, ev.Kind)
		}
		if err := ev.Validate(); err != nil {
			t.Fatalf("event %d invalid: %v", i, err)
		}
	}
}

// TestDeriveArrivalHermetic pins the boundary wiring end to end: a run
// with a recording observer carries the derived technology events after
// each task_completed, and every recorded event validates.
func TestDeriveArrivalHermetic(t *testing.T) {
	var evs []event.Event
	mustFinish(t, "observed ingest", func() {
		rec := &observerRecorder{}
		cfg := testConfig(t)
		cfg.Observer = rec

		obs := newObs(t, "https://ok.example/")
		obs.Headers = []HeaderEntry{{Name: "Server", Value: "nginx/1.25.3"}}
		obs.Body = "It works!"
		src := SliceObservationSource{obs}

		rep, err := Ingest(context.Background(), cfg, &src)
		if err != nil {
			t.Errorf("Ingest: %v", err)
			return
		}
		if rep.Observations.Completed != 1 {
			t.Errorf("completed = %d, want 1", rep.Observations.Completed)
			return
		}
		if len(rep.Technologies) == 0 {
			t.Error("no technologies detected; the arrival probe needs a firing indicator")
			return
		}
		evs = rec.snapshot()
	})
	if len(evs) == 0 {
		t.Fatal("observer recorded no events")
	}
	for _, ev := range evs {
		if err := ev.Validate(); err != nil {
			t.Errorf("invalid event %+v: %v", ev, err)
		}
	}
	if got := countKind(evs, event.KindTaskCompleted); got != 1 {
		t.Errorf("task_completed events = %d, want 1", got)
	}
	if got := countKind(evs, event.KindAssetDiscovered); got == 0 {
		t.Error("no asset_discovered events derived from a completed detection")
	}
	if got := countKind(evs, event.KindEvidenceCreated); got == 0 {
		t.Error("no evidence_created events derived from a completed detection")
	}
	if got := countKind(evs, event.KindRelationshipCreated); got == 0 {
		t.Error("no relationship_created events derived from a completed detection")
	}
}
