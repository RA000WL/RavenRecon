package dns

import (
	"fmt"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// validateScope re-validates the declared target domain at the pipeline
// boundary. Resolve receives an asset.Domain that is normally produced by
// asset.NewDomain, but a hand-built struct literal could bypass normalization
// and reach validation or cache keys; this check refuses such values up front.
// Defense-in-depth: the caller is expected to normalize before calling.
func validateScope(domain asset.Domain) error {
	got, err := asset.NewDomain(domain.Name, asset.Provenance{})
	if err != nil {
		return fmt.Errorf("dns: invalid target domain %q: %w", domain.Name, err)
	}
	if got.Name != domain.Name {
		return fmt.Errorf("dns: target domain %q is not in canonical form (normalized %q)", domain.Name, got.Name)
	}
	return nil
}

// validateInputHost re-validates one input host: it must be a canonical Phase
// 2 host (asset.NewHost must accept it and its Name must already be the
// canonical form — raw user input, uppercase, trailing dots, IP literals, and
// hand-built struct literals are all rejected) and it must be the target
// domain itself or a subdomain of it. This is the resolution boundary: the
// package resolves exactly the validated in-scope inputs, never arbitrary
// host lists.
func validateInputHost(h asset.Host, domain asset.Domain) error {
	got, err := asset.NewHost(h.Name, h.Prov)
	if err != nil {
		return fmt.Errorf("dns: invalid host %q: %w", h.Name, err)
	}
	if got.Name != h.Name {
		return fmt.Errorf("dns: host %q is not in canonical form (normalized %q)", h.Name, got.Name)
	}
	if got.Name != domain.Name && !strings.HasSuffix(got.Name, "."+domain.Name) {
		return fmt.Errorf("dns: host %q is outside target domain %q", got.Name, domain.Name)
	}
	return nil
}

// inDomain reports whether name is the domain itself or a subdomain of it.
// Both arguments must already be canonical.
func inDomain(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}
