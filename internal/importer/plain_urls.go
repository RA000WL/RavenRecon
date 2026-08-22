package importer

import (
	"context"
	"path/filepath"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// PlainURLsImporter consumes a plain-text file where each line is a URL.
type PlainURLsImporter struct{ importerBase }

func NewPlainURLsImporter() *PlainURLsImporter {
	return &PlainURLsImporter{importerBase{name: "plain-urls", version: "1.0.0", tool: "plain-urls"}}
}

func (p *PlainURLsImporter) CanImport(path string, peek []byte) (float64, bool) {
	return plainConfidence(path, peek, ShapeURL, []string{"txt", "urls"})
}

func (p *PlainURLsImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
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
		prov, rec := buildProvenance(env, p.Name(), filename, raw, now)
		u, err := asset.ParseURL(line, prov)
		if err != nil {
			return err
		}
		key := u.Identity().String()
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
		out.URLs = append(out.URLs, u)
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

// PlainAliveImporter consumes alive.txt-style files (hosts or URLs that are alive).
// Each line may be a host or a URL; we accept either and normalize accordingly.
type PlainAliveImporter struct{ importerBase }

func NewPlainAliveImporter() *PlainAliveImporter {
	return &PlainAliveImporter{importerBase{name: "plain-alive", version: "1.0.0", tool: "plain-alive"}}
}

func (p *PlainAliveImporter) CanImport(path string, peek []byte) (float64, bool) {
	// alive files are dominantly hosts but may contain URLs; claim if host or URL ratio high
	// Reduce confidence by 0.15 so specific importers (domains/urls) outrank alive on pure files.
	c1, ok1 := plainConfidence(path, peek, ShapeHost, []string{"txt", "alive"})
	c2, ok2 := plainConfidence(path, peek, ShapeURL, []string{"txt", "alive"})
	adjust := func(c float64) float64 {
		c -= 0.15
		if c < 0.1 {
			c = 0.1
		}
		return c
	}
	if ok1 && ok2 {
		if c1 > c2 {
			return adjust(c1), true
		}
		return adjust(c2), true
	}
	if ok1 {
		return adjust(c1), true
	}
	if ok2 {
		return adjust(c2), true
	}
	return 0, false
}

func (p *PlainAliveImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
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
		// Try URL first, then host
		prov, rec := buildProvenance(env, p.Name(), filename, raw, now)
		if isURLLike(line) {
			if u, err := asset.ParseURL(line, prov); err == nil {
				key := u.Identity().String()
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
				out.URLs = append(out.URLs, u)
				rec.Identity = key
				out.ProvenanceRecords = append(out.ProvenanceRecords, rec)
				return nil
			}
		}
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
