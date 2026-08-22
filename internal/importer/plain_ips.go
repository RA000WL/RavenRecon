package importer

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// PlainIPsImporter consumes a plain-text file where each line is an IP address.
type PlainIPsImporter struct{ importerBase }

func NewPlainIPsImporter() *PlainIPsImporter {
	return &PlainIPsImporter{importerBase{name: "plain-ips", version: "1.0.0", tool: "plain-ips"}}
}

func (p *PlainIPsImporter) CanImport(path string, peek []byte) (float64, bool) {
	return plainConfidence(path, peek, ShapeIP, []string{"txt", "ips"})
}

func (p *PlainIPsImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	maxOut := env.Bounds.effectiveMaxOutput()
	filename := filepath.Base(path)
	now := env.now()
	stats := ImportStats{StickyFlags: make(map[string]bool)}
	processed, failed, truncatedSig, err := readLines(ctx, env, path, func(line, raw string) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		// Reject CIDR (contains slash) — that belongs to cidrs importer
		if strings.Contains(line, "/") {
			return &importValidationError{msg: "is CIDR, not IP"}
		}
		// Validate via NewIP only
		prov, rec := buildProvenance(env, p.Name(), filename, raw, now)
		ip, err := asset.NewIP(line, prov)
		if err != nil {
			return err
		}
		key := ip.Identity().String()
		if _, dup := out.seen[key]; dup {
			return errDuplicate
		}
		if len(out.Domains)+len(out.Hosts)+len(out.URLs)+len(out.IPs)+len(out.JS)+len(out.CIDRs) >= maxOut {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
			out.truncated = true
			return errOutputTruncated
		}
		out.seen[key] = struct{}{}
		out.IPs = append(out.IPs, ip)
		rec.Identity = key
		out.ProvenanceRecords = append(out.ProvenanceRecords, rec)
		return nil
	})
	if err != nil {
		stats.ItemsProcessed = processed
		stats.ItemsFailed = failed
		if truncatedSig {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
		}
		if ctx.Err() != nil {
			stats.StickyFlags = normalizeSticky(stats.StickyFlags)
			return stats, ctx.Err()
		}
		return stats, err
	}
	stats.ItemsProcessed = processed
	stats.ItemsFailed = failed
	if truncatedSig {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	if out.truncated {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	stats.StickyFlags = normalizeSticky(stats.StickyFlags)
	return stats, nil
}

// PlainCIDRsImporter consumes a plain-text file where each line is a CIDR prefix.
type PlainCIDRsImporter struct{ importerBase }

func NewPlainCIDRsImporter() *PlainCIDRsImporter {
	return &PlainCIDRsImporter{importerBase{name: "plain-cidrs", version: "1.0.0", tool: "plain-cidrs"}}
}

func (p *PlainCIDRsImporter) CanImport(path string, peek []byte) (float64, bool) {
	return plainConfidence(path, peek, ShapeCIDR, []string{"txt", "cidrs", "cidr"})
}

func (p *PlainCIDRsImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	maxOut := env.Bounds.effectiveMaxOutput()
	filename := filepath.Base(path)
	now := env.now()
	stats := ImportStats{StickyFlags: make(map[string]bool)}
	processed, failed, truncatedSig, err := readLines(ctx, env, path, func(line, raw string) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		// Normalize via netip.ParsePrefix (single point for CIDR validation)
		prefix, err := netip.ParsePrefix(strings.TrimSpace(line))
		if err != nil {
			return err
		}
		// Canonicalize: prefix.String() is already canonical (lowercase, no extra)
		canon := prefix.String()
		// Dedup by canonical string
		if _, dup := out.seenCIDR[canon]; dup {
			return errDuplicate
		}
		// Also dedup via seen map namespaced
		key := "cidr:" + canon
		if _, dup := out.seen[key]; dup {
			return errDuplicate
		}
		if len(out.Domains)+len(out.Hosts)+len(out.URLs)+len(out.IPs)+len(out.JS)+len(out.CIDRs) >= maxOut {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
			out.truncated = true
			return errOutputTruncated
		}
		prov, rec := buildProvenance(env, p.Name(), filename, raw, now)
		_ = prov // provenance preserved in sidecar; CIDR not an asset with Prov field
		out.seen[key] = struct{}{}
		out.seenCIDR[canon] = struct{}{}
		out.CIDRs = append(out.CIDRs, canon)
		rec.Identity = key
		rec.Confidence = prov.Confidence
		out.ProvenanceRecords = append(out.ProvenanceRecords, rec)
		// Keep import time consistent
		_ = now
		return nil
	})
	if err != nil {
		stats.ItemsProcessed = processed
		stats.ItemsFailed = failed
		if truncatedSig {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
		}
		if ctx.Err() != nil {
			stats.StickyFlags = normalizeSticky(stats.StickyFlags)
			return stats, ctx.Err()
		}
		return stats, err
	}
	stats.ItemsProcessed = processed
	stats.ItemsFailed = failed
	if truncatedSig {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	if out.truncated {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	stats.StickyFlags = normalizeSticky(stats.StickyFlags)
	return stats, nil
}
