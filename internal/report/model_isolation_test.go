package report

import (
	"context"
	"sync/atomic"
	"testing"
)

// TestModelIsolation verifies per-render Model isolation: a reporter that
// mutates the Model (Domains[0], Attribution map) must not affect a peer
// reporter rendering concurrently from the same Model. Before OPT-P1-2 the
// shared *Model pointer caused observer to see mutated values.
func TestModelIsolation(t *testing.T) {
	base := testContext(t)
	origModel, err := NewModel(base)
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}
	// Ensure we have at least one domain and attribution entry to mutate.
	// testContext has one domain; add attribution for clone map check.
	base2 := base
	if base2.Attribution == nil {
		base2.Attribution = map[string]AttributionEntry{}
	}
	// Use a known identity from the model.
	if len(origModel.Domains) == 0 {
		t.Fatalf("model has no domains")
	}
	origDomain := origModel.Domains[0]
	origAttributionKey := origModel.Domains[0].Identity().String()
	base2.Attribution[origAttributionKey] = AttributionEntry{Importer: "original", OriginalTool: "tool", Filename: "orig.txt"}
	mutModel, err := NewModel(base2)
	if err != nil {
		t.Fatalf("NewModel with attribution: %v", err)
	}
	origLen := len(mutModel.Domains)

	mutatedCh := make(chan struct{})
	observedCh := make(chan struct{})
	var seenMutated atomic.Bool
	var reason atomic.Value

	mutID := "mutator"
	obsID := "observer"

	mutReporter := Reporter{
		ID:          mutID,
		Name:        "Mutator",
		Description: "mutator",
		Version:     "1.0.0",
		Format:      FormatJSON,
		Enabled:     true,
		Render: func(ctx context.Context, m *Model, s Sink) error {
			if len(m.Domains) > 0 {
				m.Domains[0] = origDomain // placeholder to ensure same type; mutate to evil
				m.Domains[0].Name = "evil.example.com"
			}
			if m.Attribution != nil {
				m.Attribution[origAttributionKey] = AttributionEntry{Importer: "evil", Filename: "evil.txt"}
				m.Attribution["injected"] = AttributionEntry{Importer: "evil"}
			}
			m.Domains = append(m.Domains, origDomain)
			close(mutatedCh)
			<-observedCh
			w, _ := s.Writer("")
			if w != nil {
				w.Write([]byte("{}"))
				w.Close()
			}
			return nil
		},
	}
	obsReporter := Reporter{
		ID:          obsID,
		Name:        "Observer",
		Description: "observer",
		Version:     "1.0.0",
		Format:      FormatJSON,
		Enabled:     true,
		Render: func(ctx context.Context, m *Model, s Sink) error {
			<-mutatedCh
			if len(m.Domains) > 0 && m.Domains[0].Name == "evil.example.com" {
				seenMutated.Store(true)
				reason.Store("Domains[0] mutated visible")
			}
			if m.Attribution != nil {
				if ent, ok := m.Attribution[origAttributionKey]; ok && ent.Importer == "evil" {
					seenMutated.Store(true)
					reason.Store("Attribution mutated visible")
				}
				if _, ok := m.Attribution["injected"]; ok {
					seenMutated.Store(true)
					reason.Store("Attribution injected visible")
				}
			}
			if len(m.Domains) != origLen {
				if len(m.Domains) > origLen {
					seenMutated.Store(true)
					reason.Store("Domains slice appended visible")
				}
			}
			close(observedCh)
			w, _ := s.Writer("")
			if w != nil {
				w.Write([]byte("{}"))
				w.Close()
			}
			return nil
		},
	}

	reg := NewRegistry()
	if err := reg.Register(mutReporter); err != nil {
		t.Fatalf("register mutator: %v", err)
	}
	if err := reg.Register(obsReporter); err != nil {
		t.Fatalf("register observer: %v", err)
	}
	dir := t.TempDir()
	cfg := DefaultEngineConfig(reg, dir)
	cfg.Concurrency = 2
	cfg.Reports = []string{mutID, obsID}

	// Use the context that produces mutModel; Run will build its own model
	// internally, but we want to test the engine's per-render isolation, which
	// clones the Model inside processReport. The mutation detection above
	// checks the peer's view of that cloned Model.
	_, err = Run(context.Background(), cfg, base2)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if seenMutated.Load() {
		r, _ := reason.Load().(string)
		t.Fatalf("model isolation violated: %s (peer saw mutator's writes; cloneModel missing or not used)", r)
	}
}
