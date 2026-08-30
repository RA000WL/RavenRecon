package discovery

import (
	"context"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// asnmap is the asnmap adapter (ProjectDiscovery).
//
// Invocation (passive only):
//
//	asnmap -d <domain> -silent
//
// -d selects the target; -silent suppresses banners so stdout is one
// discovered host per line. No active options are ever passed. Version
// detection uses -version.
type asnmap struct{ env toolEnv }

// Name implements Source.
func (a asnmap) Name() string { return "asnmap" }

// Detect implements Source.
func (a asnmap) Detect(ctx context.Context) Detection {
	return detectVersioned(ctx, a.env, "-version")
}

// Discover implements Source.
func (a asnmap) Discover(ctx context.Context, target asset.Domain) (DiscoverResult, error) {
	return runAndParse(ctx, a.env, a.Name(), []string{"-d", target.Name, "-silent"})
}
