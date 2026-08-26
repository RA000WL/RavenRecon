package detect

import (
	"context"
	"sync/atomic"
	"testing"

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
func TestCloneContextForRuleDepth(t *testing.T) {
	src := &Context{
		Assets:        []asset.Identity{{Kind: asset.KindHost, Value: "www.example.com"}},
		Relationships: []asset.Relationship{mustTestRelationship(t)},
		Evidence:      []asset.Evidence{mustTestEvidence(t)},
		Technologies:  []asset.Technology{mustTestTechnology(t)},
		Secrets:       []asset.SecretCandidate{mustTestSecret(t)},
		Endpoints:     []asset.Endpoint{mustTestEndpoint(t)},
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
	a.Endpoints[0].Method = "POST"
	a.Config["threshold"] = "0.99"
	a.Config["injected"] = "true"

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
		if peer.Endpoints[0].Method == "POST" {
			t.Error("Endpoints leaked through the clone")
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
