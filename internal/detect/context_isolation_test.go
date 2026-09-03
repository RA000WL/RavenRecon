package detect

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// TestContextIsolation verifies per-rule Context isolation: a rule that
// mutates Assets[0] and Config must not affect a peer rule running in
// parallel on the same level. Before OPT-P1-2 the shared *Context caused the
// observer to see the mutated values; after the fix each rule receives a
// cloned Context.
func TestContextIsolation(t *testing.T) {
	snap := testSnapshot(t)

	// Ensure the snapshot's normalized assets are sorted and known.
	corpus, err := normalizeSnapshot(snap)
	if err != nil {
		t.Fatalf("normalizeSnapshot: %v", err)
	}
	originalAsset := corpus.context.Assets[0]
	if originalAsset.IsZero() {
		t.Fatalf("original asset is zero")
	}

	mutatedCh := make(chan struct{})
	observedCh := make(chan struct{})
	var seenMutated atomic.Bool
	var reason atomic.Value

	mutator := makeRule(t, "mutator.x", &ruleOptions{
		detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
			if len(dctx.Assets) > 0 {
				dctx.Assets[0] = asset.Identity{Kind: asset.KindHost, Value: "evil.example.com"}
			}
			if dctx.Config != nil {
				dctx.Config["threshold"] = "evil"
				dctx.Config["injected"] = "evil"
			}
			// Append to test slice-header isolation: must not grow peer's view.
			dctx.Assets = append(dctx.Assets, asset.Identity{Kind: asset.KindHost, Value: "appended.example.com"})
			// SDK v2: PriorFindings and GraphView handle isolation.
			if len(dctx.PriorFindings) == 0 {
				// PriorFindings is empty for level-0 parallel rules; mutate the slice header via append.
				ev, _ := asset.NewEvidence(asset.MethodDetection, "mutator.x", "evil", dctx.Assets[0], asset.Provenance{Source: "test"})
				f, _ := asset.NewFinding(asset.Finding{RuleID: "mutator.x", RuleName: "Mutator", Category: "information", Subject: dctx.Assets[0], Confidence: 0.5, Evidence: []asset.Evidence{ev}, Priority: "info", Status: "open", Created: time.Now().UTC()})
				dctx.PriorFindings = append(dctx.PriorFindings, f)
			} else {
				dctx.PriorFindings[0].Category = "mutated"
			}
			// GraphView is read-only; replace handle in mutator's copy — must not affect peer's view.
			dctx.GraphView = newGraphView(nil, nil)
			close(mutatedCh)
			<-observedCh
			return nil, nil
		},
	})
	observer := makeRule(t, "observer.x", &ruleOptions{
		detector: func(ctx context.Context, dctx *Context) ([]asset.Finding, error) {
			<-mutatedCh
			if len(dctx.Assets) > 0 && dctx.Assets[0].Value == "evil.example.com" {
				seenMutated.Store(true)
				reason.Store("Assets[0] mutated visible to peer")
			}
			if dctx.Config["threshold"] == "evil" {
				seenMutated.Store(true)
				reason.Store("Config threshold mutated visible")
			}
			if _, ok := dctx.Config["injected"]; ok {
				seenMutated.Store(true)
				reason.Store("Config injected key visible")
			}
			// If slice was shared and appended beyond original length, observer
			// might see appended element. Check length growth.
			if len(dctx.Assets) != len(originalAssetStringSlice(t, corpus)) {
				// original length is len(corpus.context.Assets); any growth is suspicious.
				// Allow if observer sees original length unchanged.
				if len(dctx.Assets) > len(corpus.context.Assets) {
					seenMutated.Store(true)
					reason.Store("Assets slice appended visible")
				}
			}
			if len(dctx.PriorFindings) != 0 {
				seenMutated.Store(true)
				reason.Store("PriorFindings mutated visible to peer (empty level-0 slice should stay empty)")
			}
			if dctx.GraphView == nil {
				seenMutated.Store(true)
				reason.Store("GraphView nil on peer (handle isolation broke)")
			} else {
				// The snapshot's corpus in this test has 2 assets and a host→IP style? Actually testSnapshot has host+url.
				// GraphView should be non-nil and Neighbors for a valid host should not be poisoned by mutator's nil handle.
				// We check that GraphView still has at least the observed nodes.
				if len(dctx.Assets) > 0 {
					// At least one asset should be in the graph nodes set — Path self should exist.
					if path := dctx.GraphView.Path(dctx.Assets[0], dctx.Assets[0]); len(path) == 0 {
						seenMutated.Store(true)
						reason.Store("GraphView handle mutated visible to peer")
					}
				}
			}
			close(observedCh)
			return nil, nil
		},
	})

	reg := newTestRegistry(t, mutator, observer)
	cfg := DefaultEngineConfig(reg)
	cfg.Concurrency = 2
	cfg.Config = map[string]string{"threshold": "0.5"}

	if _, err := Run(context.Background(), cfg, snap); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if seenMutated.Load() {
		r, _ := reason.Load().(string)
		t.Fatalf("context isolation violated: %s (peer saw mutator's writes; cloneContextForRule missing or not used)", r)
	}
	// Also verify the original corpus was not mutated via the shared *Context
	// pointer (engine must not have mutated its own env).
	if len(corpus.context.Assets) > 0 && corpus.context.Assets[0] == (asset.Identity{Kind: asset.KindHost, Value: "evil.example.com"}) {
		t.Fatalf("original corpus mutated")
	}
}

func originalAssetStringSlice(t *testing.T, corpus *corpus) []asset.Identity {
	t.Helper()
	return corpus.context.Assets
}

// TestCloneContextForRuleDepth pins the exact depth contract documented on
// cloneContextForRule (NEW-108): the clone owns fresh backing arrays for
// every corpus slice and a fresh Config map, and — because every slice
// element type is an immutable-by-value struct with no interior
// slices/maps/pointers — mutating a cloned Context through ANY of its
// fields (element mutation, append, map write) must never be observable by
// a sibling clone or by src itself. TestContextIsolation covers the
// end-to-end engine path (Assets + Config); this test covers the remaining
// corpus fields directly.
//
// SDK v2 extends the contract: PriorFindings (the inter-rule view) is
// cloned via slices.Clone plus a per-element Metadata maps.Clone, and
// GraphView (the read-only index) is shared immutably — a per-rule clone
// copies the handle, not the index — and JavaScript is now also covered.
func TestCloneContextForRuleDepth(t *testing.T) {
	// Build a single finding for PriorFindings (observed corpus hit).
	fixedTimeVal := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	findingForPrior := func() asset.Finding {
		subj := asset.Identity{Kind: asset.KindHost, Value: "www.example.com"}
		ev, err := asset.NewEvidence(asset.MethodDetection, "test.rule", "signal", subj, asset.Provenance{Source: "test"})
		if err != nil {
			t.Fatalf("NewEvidence: %v", err)
		}
		f, err := asset.NewFinding(asset.Finding{
			RuleID:     "test.rule",
			RuleName:   "Test Rule",
			Category:   "information",
			Subject:    subj,
			Confidence: 0.5,
			Evidence:   []asset.Evidence{ev},
			Priority:   "info",
			Status:     "open",
			Created:    fixedTimeVal,
			Metadata:   map[string]string{"role": "original"},
		})
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		return f
	}
	src := &Context{
		Assets:        []asset.Identity{{Kind: asset.KindHost, Value: "www.example.com"}},
		Relationships: []asset.Relationship{mustTestRelationship(t)},
		Evidence:      []asset.Evidence{mustTestEvidence(t)},
		Technologies:  []asset.Technology{mustTestTechnology(t)},
		Secrets:       []asset.SecretCandidate{mustTestSecret(t)},
		JavaScript:    []asset.JavaScript{mustTestJavaScript(t)},
		Endpoints:     []asset.Endpoint{mustTestEndpoint(t)},
		PriorFindings: []asset.Finding{findingForPrior()},
		GraphView:     newGraphView([]asset.Identity{{Kind: asset.KindHost, Value: "www.example.com"}}, []asset.Relationship{mustTestRelationship(t)}),
		Config:        map[string]string{"threshold": "0.5"},
	}

	a := cloneContextForRule(src)
	b := cloneContextForRule(src)
	if a == src || b == src || a == b {
		t.Fatal("cloneContextForRule returned an aliased pointer")
	}

	// Mutate EVERYTHING reachable from clone a: in-place element writes,
	// appends that may or may not reallocate, and the Config map.
	a.Assets[0] = asset.Identity{Kind: asset.KindHost, Value: "evil.example.com"}
	a.Relationships[0] = asset.Relationship{}
	a.Evidence[0].Value = "mutated"
	a.Evidence = append(a.Evidence, mustTestEvidence(t))
	a.Technologies[0].Name = "mutated"
	a.Secrets[0].Value = "mutated"
	a.JavaScript[0].ContentType = "mutated"
	a.Endpoints[0].Method = "POST"
	a.PriorFindings[0].Category = "mutated"
	a.PriorFindings[0].Metadata["role"] = "mutated"
	a.PriorFindings[0].Metadata["injected"] = "true"
	a.PriorFindings = append(a.PriorFindings, findingForPrior())
	a.Config["threshold"] = "0.99"
	a.Config["injected"] = "true"
	// GraphView is a read-only handle: the clone shares it immutably.
	// A buggy rule cannot mutate the index — the handle itself is copied,
	// not the map. We verify the handle is shared (not deep-copied into a
	// new index whose addr differs) by checking Neighbors still works,
	// and that mutating the Context's GraphView handle in a does not affect
	// peers (replace handle, not index).
	a.GraphView = newGraphView(nil, nil)

	for _, peer := range []*Context{b, src} {
		if peer.Assets[0].Value != "www.example.com" {
			t.Errorf("Assets leaked through the clone: %q", peer.Assets[0].Value)
		}
		if peer.Relationships[0] == (asset.Relationship{}) {
			t.Error("Relationships leaked through the clone")
		}
		if peer.Evidence[0].Value == "mutated" || len(peer.Evidence) != 1 {
			t.Errorf("Evidence leaked through the clone: value=%q len=%d", peer.Evidence[0].Value, len(peer.Evidence))
		}
		if peer.Technologies[0].Name == "mutated" {
			t.Error("Technologies leaked through the clone")
		}
		if peer.Secrets[0].Value == "mutated" {
			t.Error("Secrets leaked through the clone")
		}
		if peer.JavaScript[0].ContentType == "mutated" {
			t.Error("JavaScript leaked through the clone")
		}
		if peer.Endpoints[0].Method == "POST" {
			t.Error("Endpoints leaked through the clone")
		}
		if len(peer.PriorFindings) != 1 || peer.PriorFindings[0].Category == "mutated" {
			t.Errorf("PriorFindings leaked through the clone: len=%d category=%q", len(peer.PriorFindings), peer.PriorFindings[0].Category)
		}
		if got := peer.PriorFindings[0].Metadata; len(got) != 1 || got["role"] != "original" {
			t.Errorf("PriorFindings Metadata map leaked through the clone: %v", got)
		}
		if peer.GraphView == nil {
			t.Error("GraphView nil on peer (handle not shared immutably)")
		} else if len(peer.GraphView.Neighbors(asset.Identity{Kind: asset.KindHost, Value: "www.example.com"})) == 0 {
			t.Error("GraphView.Neighbors empty on peer — index not shared")
		}
		if peer.Config["threshold"] != "0.5" || len(peer.Config) != 1 {
			t.Errorf("Config leaked through the clone: %v", peer.Config)
		}
	}

	// Nil receiver stays nil (the engine never passes one, but the helper's
	// contract says so).
	if cloneContextForRule(nil) != nil {
		t.Error("cloneContextForRule(nil) != nil")
	}
}

// --- minimal valid corpus elements for TestCloneContextForRuleDepth ---

func mustTestRelationship(t *testing.T) asset.Relationship {
	t.Helper()
	from := asset.Identity{Kind: asset.KindHost, Value: "www.example.com"}
	to := asset.Identity{Kind: asset.KindURL, Value: "http://www.example.com/"}
	rel, err := asset.NewRelationship(from, asset.RelationshipHostToURL, to)
	if err != nil {
		t.Fatalf("NewRelationship: %v", err)
	}
	return rel
}

func mustTestEvidence(t *testing.T) asset.Evidence {
	t.Helper()
	ev, err := asset.NewEvidence(asset.MethodHeader, "header:server", "nginx",
		asset.Identity{Kind: asset.KindHost, Value: "www.example.com"}, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	return ev
}

func mustTestTechnology(t *testing.T) asset.Technology {
	t.Helper()
	tech, err := asset.NewTechnology("nginx", asset.CategoryServer, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewTechnology: %v", err)
	}
	return tech
}

func mustTestSecret(t *testing.T) asset.SecretCandidate {
	t.Helper()
	sec, err := asset.NewSecretCandidate(asset.SecretTypeAWS, "AKIASYNTHETICEXAMPLE",
		asset.Identity{Kind: asset.KindURL, Value: "http://www.example.com/app.js"}, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewSecretCandidate: %v", err)
	}
	return sec
}

func mustTestEndpoint(t *testing.T) asset.Endpoint {
	t.Helper()
	ep, err := asset.NewEndpoint("GET", "http://www.example.com/", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return ep
}

func mustTestJavaScript(t *testing.T) asset.JavaScript {
	t.Helper()
	js, err := asset.NewJavaScript("https://www.example.com/app.js", asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewJavaScript: %v", err)
	}
	return js
}
