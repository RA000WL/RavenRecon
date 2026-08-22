package importer

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// PlainDomainsImporter consumes a plain-text file where each line is a domain.
type PlainDomainsImporter struct{ importerBase }

func NewPlainDomainsImporter() *PlainDomainsImporter {
	return &PlainDomainsImporter{importerBase{name: "plain-domains", version: "1.0.0", tool: "plain-domains"}}
}

func (p *PlainDomainsImporter) CanImport(path string, peek []byte) (float64, bool) {
	// Domains are host-like but we claim when lines are mostly host-shaped
	// and not URL/IP/CIDR/JS. Use host shape but expect domain-like names.
	return plainConfidence(path, peek, ShapeHost, []string{"txt", "domains"})
}

func (p *PlainDomainsImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
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
		// Explicit IP check — domains must not be IPs (asset.NewDomain rejects them, but we count cleanly)
		if _, err := netip.ParseAddr(strings.TrimSpace(line)); err == nil {
			return &importValidationError{msg: "is IP, not domain"}
		}
		prov, rec := buildProvenance(env, p.Name(), filename, raw, now)
		d, err := asset.NewDomain(line, prov)
		if err != nil {
			return err
		}
		key := d.Identity().String()
		if _, dup := out.seen[key]; dup {
			return errDuplicate
		}
		// Truncation (MaxOutput) — tail-drop, sticky flag
		if len(out.Domains)+len(out.Hosts)+len(out.URLs)+len(out.IPs)+len(out.JS)+len(out.CIDRs) >= maxOut {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
			out.truncated = true
			return errOutputTruncated
		}
		out.seen[key] = struct{}{}
		out.Domains = append(out.Domains, d)
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
		// Normalize context cancellation: return partial stats + cancelled error
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

type importValidationError struct{ msg string }

func (e *importValidationError) Error() string { return e.msg }

// PlainSubdomainsImporter consumes a plain-text file where each line is a subdomain/host.
type PlainSubdomainsImporter struct{ importerBase }

func NewPlainSubdomainsImporter() *PlainSubdomainsImporter {
	return &PlainSubdomainsImporter{importerBase{name: "plain-subdomains", version: "1.0.0", tool: "plain-subdomains"}}
}

func (p *PlainSubdomainsImporter) CanImport(path string, peek []byte) (float64, bool) {
	return plainConfidence(path, peek, ShapeHost, []string{"txt", "subdomains", "hosts"})
}

func (p *PlainSubdomainsImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
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
		if _, err := netip.ParseAddr(strings.TrimSpace(line)); err == nil {
			return &importValidationError{msg: "is IP, not host"}
		}
		if isURLLike(line) {
			return &importValidationError{msg: "is URL, not host"}
		}
		prov, rec := buildProvenance(env, p.Name(), filename, raw, now)
		h, err := asset.NewHost(line, prov)
		if err != nil {
			return err
		}
		key := h.Identity().String()
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
		out.Hosts = append(out.Hosts, h)
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

func normalizeSticky(m map[string]bool) map[string]bool {
	if len(m) == 0 {
		return nil
	}
	return m
}
