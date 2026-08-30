package takeover

import (
	"context"
	"fmt"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func cnameUnclaimedDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleCNAMEUnclaimed+".disabled"] == "true" {
		return nil, nil
	}
	hostsIP := hostsWithIP(dctx)
	// Collect candidate subjects: hosts with CNAME to unclaimed provider and no IP for target.
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	metaFor := make(map[asset.Identity]map[string]string)
	for _, rel := range dctx.Relationships {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rel.Kind != asset.RelationshipHostToCNAME {
			continue
		}
		src := rel.From
		tgt := rel.To
		// Target host name is tgt.Value (host kind).
		tgtHost := tgt.Value
		provider := providerForHost(tgtHost)
		if provider == "" {
			continue
		}
		if _, hasIP := hostsIP[tgt]; hasIP {
			continue
		}
		// Additionally, if target host has an A/AAAA, that would be a host->IP for target.
		// No IP means dangling (NXDOMAIN or unclaimed).
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		subjects = append(subjects, src)
		metaFor[src] = map[string]string{
			"signal":       "takeover_cname_unclaimed",
			"cname_target": tgtHost,
			"provider":     provider,
			"category":     "unclaimed_provider",
		}
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].String() < subjects[j].String() })
	dropped := 0
	if len(subjects) > 256 {
		dropped = len(subjects) - 256
		subjects = subjects[:256]
	}
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := metaFor[s]
		// Copy to avoid aliasing.
		m := make(map[string]string, len(meta)+2)
		for k, v := range meta {
			m[k] = v
		}
		if dropped > 0 {
			m["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			m["truncated"] = "true"
		}
		f, err := takeoverFinding(dctx, ruleCNAMEUnclaimed, "Takeover CNAME Unclaimed", s, m)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleCNAMEUnclaimed, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleCNAMEUnclaimed)
	return out, nil
}

func cnameDanglingDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleCNAMEDangling+".disabled"] == "true" {
		return nil, nil
	}
	hostsIP := hostsWithIP(dctx)
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	metaFor := make(map[asset.Identity]map[string]string)
	for _, rel := range dctx.Relationships {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rel.Kind != asset.RelationshipHostToCNAME {
			continue
		}
		src := rel.From
		tgt := rel.To
		tgtHost := tgt.Value
		// Exclude provider-matched hosts — those are handled by unclaimed rule to keep sets disjoint.
		if isUnclaimedProvider(tgtHost) {
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
			"signal":       "takeover_cname_dangling",
			"cname_target": tgtHost,
			"category":     "dangling_cname",
		}
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].String() < subjects[j].String() })
	dropped := 0
	if len(subjects) > 256 {
		dropped = len(subjects) - 256
		subjects = subjects[:256]
	}
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
		f, err := takeoverFinding(dctx, ruleCNAMEDangling, "Takeover CNAME Dangling", s, m)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleCNAMEDangling, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleCNAMEDangling)
	return out, nil
}
