package httpprobe

import (
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// maxSANProbeTargets caps the SAN-derived probe hosts synthesized for one
// run (NEW-136): worst case twice that many root probes, inside the
// pool/queue budgets, with the per-job deadline bounding slow ones
// honestly. Hosts beyond the cap are cut (sorted head kept) and the cut
// sets the adapter's httpprobe_san_targets_truncated flag — never silent.
// The value mirrors maxProbePortsPerHost's budget class (16 ports mean 32
// probes per host job); 16 SAN hosts mean 32 extra root probes per run.
const maxSANProbeTargets = 16

// SANProvenance is the single shared provenance source marking hosts
// synthesized from certificate SAN names — the same provenance the
// pipeline's passive tls-san expansion carries, so a SAN host probed here
// and a SAN host expanded there never disagree on origin. Both call sites
// reference this constant (pinned by the adapt-layer equality test); the
// literal value is part of the persisted provenance contract.
const SANProvenance = "tls-san"

// sanProvenance aliases SANProvenance for the in-package call sites.
const sanProvenance = SANProvenance

// SANProbeOutcome is what one SAN→target synthesis produced: the probe
// hosts plus the honest counters behind them. Every dropped name is
// counted by cause; the caller probes Hosts and only Hosts.
type SANProbeOutcome struct {
	// Hosts are the synthesized probe hosts: canonical, in-domain,
	// deduplicated against the known corpus and each other, sorted by
	// canonical name, capped at maxSANProbeTargets.
	Hosts []asset.Host
	// WildcardsSkipped counts SAN entries dropped for carrying a wildcard
	// ("*.example.com" and any other "*" holder). Wildcards are skipped,
	// never expanded: synthesizing an apex or an arbitrary name from a
	// wildcard would be guessing a target the certificate never named,
	// and the scope wall forbids probing guessed names.
	WildcardsSkipped int
	// InvalidSkipped counts SAN entries that are not Host assets at all
	// (IP literals, non-hostname strings): they belong to other asset
	// classes, never to the probe host list.
	InvalidSkipped int
	// OutOfScopeDropped counts valid canonical hosts outside the declared
	// domain: dropped, never probed — the scope wall is absolute.
	OutOfScopeDropped int
	// DuplicatesDropped counts valid in-domain hosts already known (in
	// the corpus or already synthesized): never probed twice.
	DuplicatesDropped int
	// Truncated reports that the synthesized list exceeded
	// maxSANProbeTargets and only the sorted head was kept.
	Truncated bool
}

// SynthesizeSANProbeTargets derives probe hosts from the SAN DNS names of
// observed leaf certificates (NEW-136): the feedback that lets cert-only
// hosts — named on a certificate but never in the discovery corpus —
// become probe targets.
//
// It is a pure function over observations: no network, no cache, no pool.
// A name qualifies when it carries no wildcard, parses as a canonical Host
// asset through asset.NewHost (the single normalization point — IP
// literals and non-hostname strings fail there), is in-domain via
// asset.InDomain (the single scope check), and is not already known. The
// output is sorted by canonical name for determinism and capped at
// maxSANProbeTargets (sorted head; Truncated marks the cut). The input
// slices are read-only; the result aliases nothing.
func SynthesizeSANProbeTargets(domain asset.Domain, certs []asset.TLSCertificate, known []asset.Host) SANProbeOutcome {
	var out SANProbeOutcome
	if len(certs) == 0 {
		return out
	}
	seen := make(map[string]bool, len(known))
	for _, h := range known {
		seen[h.Name] = true
	}
	var hosts []asset.Host
	for _, c := range certs {
		for _, n := range c.DNSNames {
			if strings.Contains(n, "*") {
				// Wildcard: skipped and counted, never expanded to an
				// apex or any other guessed name (see the field
				// documentation).
				out.WildcardsSkipped++
				continue
			}
			h, err := asset.NewHost(n, asset.Provenance{Source: sanProvenance})
			if err != nil {
				out.InvalidSkipped++
				continue
			}
			if !asset.InDomain(h.Name, domain.Name) {
				out.OutOfScopeDropped++
				continue
			}
			if seen[h.Name] {
				out.DuplicatesDropped++
				continue
			}
			seen[h.Name] = true
			hosts = append(hosts, h)
		}
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	if len(hosts) > maxSANProbeTargets {
		hosts = hosts[:maxSANProbeTargets]
		out.Truncated = true
	}
	out.Hosts = hosts
	return out
}
