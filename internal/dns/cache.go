package dns

import (
	"encoding/json"
	"fmt"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Operation is the stable cache operation name for the DNS pipeline. It is
// part of the Phase 3 cache key payload; changing it invalidates every
// previously stored DNS record by construction.
const Operation = "dns.resolve"

// typeKey derives the Phase 3 cache key for one (host, record type) pair.
//
// The key contains every input that materially changes the result: the
// operation ("dns.resolve"), the canonical Phase 2 host identity
// ("host:example.com" — raw input never reaches a key), and the record type,
// so each type is a distinct key: partial results are per-type (an A hit with
// a fresh AAAA miss is natural, never all-or-nothing) and a failed, cancelled,
// or incomplete type can never be served as a successful entry for a
// different type. No external tool participates, so no tool identity is
// hashed.
//
// Timings, timeouts, concurrency, and rate limits never enter the key. The
// per-type answer cap is a fixed constant, not configuration (see
// MaxAnswersPerType), so it must never be hashed either: a completed entry
// written under the current cap stays valid under any future cap that only
// retains more answers, and truncated entries are stored incomplete (never
// served) under every cap.
func typeKey(host asset.Host, rt RecordType) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    host.Identity().String(),
		Config:    map[string]string{"record_type": string(rt)},
	})
}

// storedType is the structured Data payload of one (host, record type) cache
// record. It is never terminal output: answers are stored as the typed Phase
// 2 assets (with provenance) exactly as they will be served back.
type storedType struct {
	// Target is the canonical host identity the query was issued for.
	Target string `json:"target"`
	// Type is the queried record type.
	Type RecordType `json:"type"`
	// NXDOMAIN marks a completed negative observation (name does not exist).
	NXDOMAIN bool `json:"nxdomain,omitempty"`
	// Truncated marks a retained answer set that hit the cap; such records
	// are stored StatusIncomplete and never served as hits.
	Truncated bool `json:"truncated,omitempty"`
	// IPs are the typed A/AAAA answers (canonical, sorted, deduplicated).
	IPs []asset.IP `json:"ips,omitempty"`
	// Hosts are the typed host-target answers (CNAME/MX/NS/SRV: canonical,
	// sorted, deduplicated).
	Hosts []asset.Host `json:"hosts,omitempty"`
	// Strings are the TXT answers (deduplicated, sorted, each within
	// MaxTXTStringBytes). Only ever set for TXT.
	Strings []string `json:"strings,omitempty"`
	// Ports parallels Hosts for SRV answers: Ports[i] is the service port
	// of Hosts[i] (u16 range only — ports are service data, never
	// asset-normalized). Only ever set for SRV, always the same length as
	// Hosts.
	Ports []uint16 `json:"ports,omitempty"`
	// Malformed counts raw answers dropped at normalization time
	// (diagnostics).
	Malformed int `json:"malformed,omitempty"`
}

// decodeStoredType validates and decodes a stored per-type payload before it
// may be served as a hit. It re-validates every answer through the Phase 2
// asset model (canonical form required) and the TXT/SRV rules (byte cap,
// port/target alignment), refuses payloads whose target does not match the
// queried host, whose record type does not match the query, whose answers
// carry the wrong kind for the type (addresses iff A/AAAA, hostnames iff
// CNAME/MX/NS/SRV, strings iff TXT, ports iff SRV and aligned with the
// targets), and whose NXDOMAIN flag contradicts non-empty answers — so a
// corrupt, tampered, or legacy completed record can never produce bogus
// assets. On any error the caller deletes the record and falls through to a
// fresh resolution (self-healing), never serving it as a hit.
func decodeStoredType(raw json.RawMessage, host asset.Host, rt RecordType) (storedType, error) {
	var s storedType
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("parse stored result: %w", err)
	}
	if s.Target != host.Identity().String() {
		return s, fmt.Errorf("stored result target %q does not match %q", s.Target, host.Identity().String())
	}
	if s.Type != rt {
		return s, fmt.Errorf("stored result type %q does not match queried type %q", s.Type, rt)
	}
	// Kind gates: each payload field is served only for its own record
	// family — hostnames iff CNAME/MX/NS/SRV, strings iff TXT, addresses
	// iff A/AAAA, ports iff SRV. Pre-T1 payloads carry only IPs/Hosts (and
	// Hosts only under CNAME), so they pass these gates unchanged.
	if len(s.Hosts) > 0 && !isHostTargetType(rt) {
		return s, fmt.Errorf("stored %s result contains hostname answers", rt)
	}
	if len(s.IPs) > 0 && rt != TypeA && rt != TypeAAAA {
		return s, fmt.Errorf("stored %s result contains address answers", rt)
	}
	if len(s.Strings) > 0 && rt != TypeTXT {
		return s, fmt.Errorf("stored %s result contains text answers", rt)
	}
	if len(s.Ports) > 0 && rt != TypeSRV {
		return s, fmt.Errorf("stored %s result contains port answers", rt)
	}
	if rt == TypeSRV && len(s.Ports) != len(s.Hosts) {
		return s, fmt.Errorf("stored SRV result has %d ports for %d targets: parallel arrays misaligned", len(s.Ports), len(s.Hosts))
	}
	if s.NXDOMAIN && (len(s.IPs) > 0 || len(s.Hosts) > 0 || len(s.Strings) > 0) {
		return s, fmt.Errorf("stored result is both NXDOMAIN and answer-bearing")
	}
	if s.Truncated {
		// A truncated payload can only have been stored as StatusIncomplete,
		// which the cache never serves as a hit; reaching decode on a
		// completed record means the record was tampered with. Refuse it.
		return s, fmt.Errorf("stored result is marked truncated")
	}
	for _, ip := range s.IPs {
		nip, err := asset.NewIP(ip.Addr.String(), ip.Prov)
		if err != nil {
			return s, fmt.Errorf("stored result contains invalid IP %q: %w", ip.Addr, err)
		}
		if nip.Addr.String() != ip.Addr.String() {
			return s, fmt.Errorf("stored result IP %q is not in canonical form (normalized %q)", ip.Addr, nip.Addr)
		}
	}
	for _, h := range s.Hosts {
		nh, err := asset.NewHost(h.Name, h.Prov)
		if err != nil {
			return s, fmt.Errorf("stored result contains invalid host %q: %w", h.Name, err)
		}
		// Canonical-form check mirrors validateInputHost: a raw name that
		// differs from its normalization would break dedup and formatting.
		if nh.Name != h.Name {
			return s, fmt.Errorf("stored result host %q is not in canonical form (normalized %q)", h.Name, nh.Name)
		}
	}
	for _, str := range s.Strings {
		// The TXT byte cap is re-checked so a tampered record cannot smuggle
		// an unbounded string into a served hit (normalizeAnswers would
		// never have retained it).
		if len(str) > MaxTXTStringBytes {
			return s, fmt.Errorf("stored TXT result contains over-long string (%d bytes)", len(str))
		}
	}
	return s, nil
}

// typeStatusToCache maps a per-type outcome to the Phase 3 record status,
// mirroring the Phase 4 conventions:
//
//   - completed (positive, legitimate empty, or NXDOMAIN) -> StatusCompleted
//   - truncated retention -> StatusIncomplete (the captured set is
//     incomplete by definition, exactly like Phase 4's truncated capture)
//   - resolver failure -> StatusFailed
//   - timeout or cancellation -> StatusCancelled
//
// A failed, cancelled, or incomplete type is never stored as completed, so no
// later run can ever be served a partial or failed type as success.
func typeStatusToCache(ts TypeStatus, truncated bool) cache.Status {
	if truncated {
		return cache.StatusIncomplete
	}
	switch ts {
	case TypeCompleted:
		return cache.StatusCompleted
	case TypeFailed:
		return cache.StatusFailed
	default: // TypeTimedOut, TypeCancelled
		return cache.StatusCancelled
	}
}

// typeResultFromStored rebuilds a completed TypeResult from a validated
// stored payload (always plus typeStatusToCache-completed semantics: only
// completed records are ever served as hits, and decodeStoredType guarantees
// the payload is answer-bearing but not truncated or NXDOMAIN-answer-bearing).
func typeResultFromStored(s storedType, host asset.Host, rt RecordType) TypeResult {
	return TypeResult{
		Host:      host,
		Type:      rt,
		Status:    TypeCompleted,
		Cached:    true,
		NXDOMAIN:  s.NXDOMAIN,
		IPs:       s.IPs,
		Hosts:     s.Hosts,
		Strings:   s.Strings,
		Ports:     s.Ports,
		Malformed: s.Malformed,
	}
}
