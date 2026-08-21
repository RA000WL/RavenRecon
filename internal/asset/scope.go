package asset

import "strings"

// InDomain reports whether name is the domain itself or a subdomain of it.
// Both arguments must already be canonical (produced by NewDomain/NewHost);
// InDomain performs no normalization of its own. An empty name or domain is
// never in-domain, matching the guarded copies this function replaces.
// This is the single domain-scope membership check: packages must not keep
// private copies.
func InDomain(name, domain string) bool {
	if name == "" || domain == "" {
		return false
	}
	return name == domain || strings.HasSuffix(name, "."+domain)
}
