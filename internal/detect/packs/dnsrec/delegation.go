package dnsrec

import (
	"context"
	"fmt"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// nsDanglingDetector observes the dangling-delegation shape: a host_to_ns
// edge whose nameserver target has no host_to_ip (no A/AAAA observed for
// the target at depth 1).
//
// Shape note: unlike takeover.cname.unclaimed there is NO curated
// provider-suffix list for nameservers — delegation targets are
// operator-run infrastructure with no unclaimed-provider fingerprint
// universe, so the orphan shape alone (edge without target addresses) is
// the signal. The finding is a per-source-host informational observation;
// it never claims the delegation is unclaimed, expired, or exploitable.
func nsDanglingDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleNSDangling+".disabled"] == "true" {
		return nil, nil
	}
	hostsIP := hostsWithIP(dctx)
	observed := hostAssetSet(dctx)
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	metaFor := make(map[asset.Identity]map[string]string)
	for _, rel := range dctx.Relationships {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rel.Kind != asset.RelationshipHostToNS {
			continue
		}
		src := rel.From
		tgt := rel.To
		if src.Kind != asset.KindHost || tgt.Kind != asset.KindHost {
			continue
		}
		// Subjects must be census hosts so findings always cite observed
		// assets (fail-open: edges pointing from unobserved sources are
		// skipped, never fabricated into findings).
		if _, ok := observed[src]; !ok {
			continue
		}
		if _, hasIP := hostsIP[tgt]; hasIP {
			continue
		}
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		subjects = append(subjects, src)
		metaFor[src] = map[string]string{
			"signal":    "dnsrec_ns_dangling_delegation",
			"ns_target": tgt.Value,
			"category":  "dangling_delegation",
		}
	}
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := metaFor[s]
		m := make(map[string]string, len(meta)+2)
		for k, v := range meta {
			m[k] = v
		}
		if dropped > 0 {
			m["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			m["truncated"] = "true"
		}
		f, err := dnsrecFinding(dctx, ruleNSDangling, "DNSRec NS Dangling Delegation", s, m)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleNSDangling, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleNSDangling)
	return out, nil
}

// mxDanglingDetector observes the dangling-MX shape: a host_to_mx edge whose
// exchanger target has no host_to_ip (no A/AAAA observed for the target at
// depth 1). It mirrors the dangling-CNAME signal exactly — edge without
// target addresses — applied to the mail topology channel. The finding is a
// per-source-host informational observation; it never claims the exchanger
// is unclaimed or that mail is undeliverable.
func mxDanglingDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleMXDangling+".disabled"] == "true" {
		return nil, nil
	}
	hostsIP := hostsWithIP(dctx)
	observed := hostAssetSet(dctx)
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	metaFor := make(map[asset.Identity]map[string]string)
	for _, rel := range dctx.Relationships {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rel.Kind != asset.RelationshipHostToMX {
			continue
		}
		src := rel.From
		tgt := rel.To
		if src.Kind != asset.KindHost || tgt.Kind != asset.KindHost {
			continue
		}
		// Subjects must be census hosts so findings always cite observed
		// assets (fail-open: edges pointing from unobserved sources are
		// skipped, never fabricated into findings).
		if _, ok := observed[src]; !ok {
			continue
		}
		if _, hasIP := hostsIP[tgt]; hasIP {
			continue
		}
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		subjects = append(subjects, src)
		metaFor[src] = map[string]string{
			"signal":    "dnsrec_mx_dangling",
			"mx_target": tgt.Value,
			"category":  "dangling_mx",
		}
	}
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := metaFor[s]
		m := make(map[string]string, len(meta)+2)
		for k, v := range meta {
			m[k] = v
		}
		if dropped > 0 {
			m["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			m["truncated"] = "true"
		}
		f, err := dnsrecFinding(dctx, ruleMXDangling, "DNSRec MX Dangling", s, m)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleMXDangling, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleMXDangling)
	return out, nil
}
