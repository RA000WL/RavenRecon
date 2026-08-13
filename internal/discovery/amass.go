package discovery

import (
	"context"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// amass is the amass adapter.
//
// Invocation (passive enumeration only):
//
//	amass enum -passive -d <domain>
//
// The -passive flag restricts enumeration to passive sources; amass's default
// active enumeration, its intel mode, and its brute-force mode are never
// used. The parser tolerates both the modern one-name-per-line format and the
// historical "name (FQDN) --> 1.2.3.4" format (only the first field of each
// line is parsed). Version detection uses -version.
type amass struct{ env toolEnv }

// Name implements Source.
func (a amass) Name() string { return "amass" }

// Detect implements Source.
func (a amass) Detect(ctx context.Context) Detection {
	return detectVersioned(ctx, a.env, "-version")
}

// Discover implements Source.
func (a amass) Discover(ctx context.Context, target asset.Domain) (DiscoverResult, error) {
	return runAndParse(ctx, a.env, a.Name(), []string{"enum", "-passive", "-d", target.Name})
}
