package adapt

import (
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

func TestIngestDeriver(t *testing.T) {
	at := time.Now().UTC()
	term := event.New(event.KindTaskCompleted, at, event.NewTaskCompleted(event.NewTaskTerminal(1, 0, at, "", ""), nil))
	gotUnknown := ingestDeriver{}.Derive(term, "nope")
	if gotUnknown != nil {
		t.Fatalf("unknown result derived %d events, want nil", len(gotUnknown))
	}
	gotSinkless := ingestDeriver{}.Derive(term, ingestFileOutcome{status: ingestCancelled})
	if gotSinkless != nil {
		t.Fatalf("sinkless outcome derived %d events, want nil", len(gotSinkless))
	}
	host, err := asset.NewHost("www.example.com", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := asset.ParseURL("https://www.example.com/robots.txt", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := asset.NewEvidence(asset.MethodDetection, "tri", "sig", u.Identity(), asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	finding, err := asset.NewFinding(asset.Finding{
		RuleID: "tri.x", RuleName: "Tri", Category: "information",
		Subject: u.Identity(), Confidence: 0.7, Evidence: []asset.Evidence{ev},
		Priority: "medium", Status: "open", Created: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := ingestDeriver{}.Derive(term, ingestFileOutcome{
		sink: &ingestSinkData{
			Hosts:    []asset.Host{host},
			URLs:     []asset.URL{u},
			Findings: []asset.Finding{finding},
		},
	})
	if len(got) != 3 {
		t.Fatalf("derived = %d events, want 3 (host, url, finding)", len(got))
	}
	kinds := map[event.Kind]int{}
	for i, e := range got {
		kinds[e.Kind]++
		if err := e.Validate(); err != nil {
			t.Fatalf("event %d invalid: %v", i, err)
		}
	}
	if kinds[event.KindAssetDiscovered] != 2 || kinds[event.KindFindingCreated] != 1 {
		t.Fatalf("kinds = %v, want 2 assets + 1 finding", kinds)
	}
}
