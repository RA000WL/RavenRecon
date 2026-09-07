package dns

import (
	"fmt"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Status classifies one host's overall resolution outcome. The labels mirror
// the Phase 4 / Phase 3 conventions (completed / incomplete / failed /
// cancelled).
type Status string

const (
	// StatusCompleted: every queried record type finished with a trustworthy
	// result. Positive answers, legitimate empty answers (NODATA-style), and
	// NXDOMAIN observations all count as completed.
	StatusCompleted Status = "completed"
	// StatusIncomplete: partial results only — at least one type finished
	// successfully while another failed or timed out, or an answer set hit
	// the retention cap. The successful parts are retained.
	StatusIncomplete Status = "incomplete"
	// StatusFailed: no usable observations (every attempted type failed).
	StatusFailed Status = "failed"
	// StatusCancelled: the run was cancelled (or the job timed out as a
	// whole) before resolution finished. Whatever was observed is retained.
	StatusCancelled Status = "cancelled"
)

// String returns the stable status label.
func (s Status) String() string { return string(s) }

// TypeStatus classifies one single (queried host, record type) query.
// Timeout and cancellation are distinct because they map to different host
// outcomes: a timed-out type makes the host incomplete (other types may have
// completed), while a cancelled type means the run is being torn down.
type TypeStatus string

const (
	// TypeCompleted: the query produced a trustworthy result (positive
	// answers, a legitimate empty answer, or an NXDOMAIN observation).
	TypeCompleted TypeStatus = "completed"
	// TypeFailed: the query failed (for example SERVFAIL-classified by the
	// resolver as a non-temporary failure). No observation.
	TypeFailed TypeStatus = "failed"
	// TypeTimedOut: the resolver reported a timeout. No observation.
	TypeTimedOut TypeStatus = "timed-out"
	// TypeCancelled: the query was cancelled — either because it was in
	// flight when the job context fired, or because an earlier query's
	// cancellation stopped the job before this type was attempted.
	TypeCancelled TypeStatus = "cancelled"
)

// String returns the stable type-status label.
func (s TypeStatus) String() string { return string(s) }

// TypeResult is the outcome of one (queried host, record type) query. The
// queried host is either an input host or — for the depth-1 address closure —
// a direct host-target observation (CNAME/MX/NS/SRV target); TypeResult.Host
// always names the host the query was issued for.
type TypeResult struct {
	// Host is the canonical host asset the query was issued for (an input
	// host, or the direct CNAME target at depth 1).
	Host asset.Host

	// Type is the queried record type.
	Type RecordType

	// Status classifies the query outcome.
	Status TypeStatus

	// Cached reports that the result was served from a completed cache
	// record without issuing any DNS request.
	Cached bool

	// NXDOMAIN marks a completed query whose name does not exist
	// (NXDOMAIN-equivalent). It is a legitimate observation, stored and
	// reported as completed, never as a failure. Only set with
	// Status == TypeCompleted.
	NXDOMAIN bool

	// Truncated reports that the resolver returned more distinct answers
	// than MaxAnswersPerType and the retained set was capped. A truncated
	// result is incomplete by definition and is never stored as a completed
	// cache entry.
	Truncated bool

	// IPs are the typed address answers (A/AAAA), normalized through
	// asset.NewIP, deduplicated by Phase 2 identity, sorted by canonical
	// address, and capped at MaxAnswersPerType. Empty for other types.
	IPs []asset.IP

	// Hosts are the typed host-target answers (CNAME/MX/NS/SRV), normalized
	// through asset.NewHost (self-targets dropped), deduplicated by Phase 2
	// identity, sorted by canonical name, and capped at MaxAnswersPerType.
	// Empty for A/AAAA/TXT.
	Hosts []asset.Host

	// Strings are the TXT answers: opaque record strings, deduplicated
	// exactly, sorted lexicographically, each within MaxTXTStringBytes, and
	// capped at MaxAnswersPerType. Empty for other types. TXT strings are
	// never assets — the pipeline adapter publishes each retained string as
	// dns:txt Evidence sourced at the queried host (NEW-126 T2).
	Strings []string

	// Ports parallels Hosts for SRV answers: Ports[i] is the service port
	// of Hosts[i] (u16 range check only — ports are service data carried
	// alongside the target, never asset-normalized). Empty for other types,
	// always the same length as Hosts for SRV. The pipeline adapter
	// publishes each retained (target, port) pair as dns:srv Evidence
	// sourced at the queried host with value "target:port" (NEW-126 T2);
	// the SRV edge itself is per distinct target host, never per port.
	Ports []uint16

	// Malformed counts raw answers that failed Phase 2 normalization and
	// were dropped; they can never become observations.
	Malformed int

	// Err carries the classification cause for failed, timed-out, and
	// cancelled types, plus any non-fatal diagnostics (for example cache
	// read warnings) joined for completed types.
	Err error
}

// HostResult is the full outcome of resolving one input host.
type HostResult struct {
	// Host is the canonical input host.
	Host asset.Host

	// Status classifies the overall host outcome (see Status).
	Status Status

	// Types holds one entry per (queried host, record type) pair in stable
	// query order: the input host's A, AAAA, CNAME, MX, TXT, NS, and SRV,
	// followed — when a host-target query completed with a target — by each
	// distinct direct target's A and AAAA (depth 1).
	Types []TypeResult

	// IPs are every address asset observed for the host and its direct
	// CNAME target, deduplicated by Phase 2 identity with earliest
	// provenance retained (asset.MergeIPs), sorted by canonical address.
	IPs []asset.IP

	// Targets are the host-target assets (CNAME/MX/NS/SRV, depth 1),
	// deduplicated by Phase 2 identity with earliest provenance retained
	// (asset.MergeHosts), sorted by canonical name. SRV targets dedupe by
	// host identity (one entry per distinct target host even when observed
	// on several ports — ports ride adapter Evidence, not this list).
	Targets []asset.Host

	// Relationships are the typed edges derived from the observations:
	// host->address via RelationshipHostToIP, host->CNAME-target via
	// RelationshipHostToCNAME, host->MX-exchanger via RelationshipHostToMX,
	// host->nameserver via RelationshipHostToNS, and host->SRV-target via
	// RelationshipHostToSRV (one edge per distinct target host). Edges are
	// deduplicated by relationship identity and sorted deterministically.
	Relationships []asset.Relationship

	// Err carries the cause for hosts that were never submitted or could
	// not be resolved (run cancellation, pool errors, and joined run-level
	// diagnostics). It is nil for hosts whose job executed.
	Err error
}

// Report is the complete outcome of one resolution run.
type Report struct {
	// Target is the declared scope domain.
	Target asset.Domain

	// Results holds one entry per input host, sorted by canonical name.
	// It is safe to read after Resolve returns; Resolve's pool shutdown is
	// the join point.
	Results []HostResult
}

// AllHosts merges every host asset across the report: the input hosts plus
// the host-target assets (CNAME/MX/NS/SRV). Hosts sharing a Phase 2 identity
// are merged with asset.MergeHosts semantics (earliest provenance wins). The
// result is sorted by canonical name.
func (r Report) AllHosts() []asset.Host {
	hosts := make([]asset.Host, 0, len(r.Results))
	for _, hr := range r.Results {
		hosts = append(hosts, hr.Host)
		hosts = append(hosts, hr.Targets...)
	}
	return mergeHosts(hosts)
}

// AllIPs merges every IP asset across the report with asset.MergeIPs
// semantics (earliest provenance wins). The result is sorted by canonical
// address.
func (r Report) AllIPs() []asset.IP {
	var ips []asset.IP
	for _, hr := range r.Results {
		ips = append(ips, hr.IPs...)
	}
	return mergeIPs(ips)
}

// AllRelationships merges every relationship across the report,
// deduplicated by edge identity and sorted deterministically. Shared
// host-target observations emit one target->address edge no matter how many
// input hosts pointed at them (NEW-121: the pipeline adapter publishes these
// edges so later stages can attribute observations to hosts; NEW-126 T2
// extends the edge family to MX/NS/SRV).
func (r Report) AllRelationships() []asset.Relationship {
	seen := make(map[string]struct{})
	var rels []asset.Relationship
	for _, hr := range r.Results {
		for _, rel := range hr.Relationships {
			if _, ok := seen[rel.ID()]; ok {
				continue
			}
			seen[rel.ID()] = struct{}{}
			rels = append(rels, rel)
		}
	}
	return sortRelationships(rels)
}

// mergeHosts deduplicates hosts by Phase 2 identity using asset.MergeHosts.
func mergeHosts(hosts []asset.Host) []asset.Host {
	byID := make(map[asset.Identity]int)
	var out []asset.Host
	for _, h := range hosts {
		if idx, ok := byID[h.Identity()]; ok {
			if m, err := asset.MergeHosts(out[idx], h); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[h.Identity()] = len(out)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// mergeIPs deduplicates addresses by Phase 2 identity using asset.MergeIPs.
func mergeIPs(ips []asset.IP) []asset.IP {
	byID := make(map[asset.Identity]int)
	var out []asset.IP
	for _, ip := range ips {
		if idx, ok := byID[ip.Identity()]; ok {
			if m, err := asset.MergeIPs(out[idx], ip); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[ip.Identity()] = len(out)
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.String() < out[j].Addr.String() })
	return out
}

// sortRelationships orders relationships deterministically by identity.
func sortRelationships(rs []asset.Relationship) []asset.Relationship {
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID() < rs[j].ID() })
	return rs
}

// fmtHostResult is a small identity helper used in error messages.
func fmtHostResult(hr HostResult) string {
	return fmt.Sprintf("host %s (%s)", hr.Host.Name, hr.Status)
}
