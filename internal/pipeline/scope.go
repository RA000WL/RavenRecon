package pipeline

import (
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// InDomain reports whether host is the declared domain itself or a
// subdomain of it.
//
// The check is label-aware (a host matches only when it equals the
// declared name or ends with "." + declared.Name, so "evil-example.com"
// never matches "example.com") and operates ONLY on the canonical names
// asset's builders produce (Host.Name / Domain.Name: lowercase, no
// trailing dot, built by asset.NewHost / asset.NewDomain). No
// normalization happens here — raw strings never enter; this is
// comparison over canonical forms, never a second normalizer.
//
// A host that equals the declared domain (a bare host) is in-domain. An
// empty declared domain or host never matches.
func InDomain(declared asset.Domain, host asset.Host) bool {
	d := declared.Name
	h := host.Name
	if d == "" || h == "" {
		return false
	}
	if h == d {
		return true
	}
	return strings.HasSuffix(h, "."+d)
}

// FilterHosts returns the hosts in hosts that are in-domain, in input
// order (stable, deterministic).
//
// Purpose: the DNS stage can emit out-of-domain CNAME targets, and the
// HTTP probing stage rejects the whole host list on any out-of-domain
// host — the pipeline filters at stage boundaries, before a downstream
// stage sees the corpus.
func FilterHosts(declared asset.Domain, hosts []asset.Host) []asset.Host {
	out := make([]asset.Host, 0, len(hosts))
	for _, h := range hosts {
		if InDomain(declared, h) {
			out = append(out, h)
		}
	}
	return out
}
