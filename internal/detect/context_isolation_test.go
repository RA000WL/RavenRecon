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
