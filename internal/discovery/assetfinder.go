package discovery

import (
	"context"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// assetfinder is the assetfinder adapter.
//
// Invocation:
//
//	assetfinder <domain>
//
// The target is a positional argument; assetfinder is passive by nature and
// takes no mode flags. It has no reliable version flag, so detection uses
// capability execution: running -h and observing usage output proves the
// binary runs, and the version is reported as unknown — never as missing.
type assetfinder struct{ env toolEnv }

// Name implements Source.
func (a assetfinder) Name() string { return "assetfinder" }

// Detect implements Source.
func (a assetfinder) Detect(ctx context.Context) Detection {
	return detectCapability(ctx, a.env, "-h")
}

// Discover implements Source.
func (a assetfinder) Discover(ctx context.Context, target asset.Domain) (DiscoverResult, error) {
	return runAndParse(ctx, a.env, a.Name(), []string{target.Name})
}
