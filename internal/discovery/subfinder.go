package discovery

import (
	"context"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// subfinder is the subfinder adapter.
//
// Invocation (passive only):
//
//	subfinder -d <domain> -silent
//
// -d selects the target; -silent suppresses banners so stdout is one
// discovered host per line. No active or enumeration options are ever passed.
// Version detection uses -version.
type subfinder struct{ env toolEnv }

// Name implements Source.
func (s subfinder) Name() string { return "subfinder" }

// Detect implements Source.
func (s subfinder) Detect(ctx context.Context) Detection {
	return detectVersioned(ctx, s.env, "-version")
}

// Discover implements Source.
func (s subfinder) Discover(ctx context.Context, target asset.Domain) (DiscoverResult, error) {
	return runAndParse(ctx, s.env, s.Name(), []string{"-d", target.Name, "-silent"})
}
