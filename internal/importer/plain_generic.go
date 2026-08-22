package importer

import (
	"context"
	"path/filepath"
)

func NewPlainGenericImporter() *PlainGenericImporter {
	return &PlainGenericImporter{importerBase{name: "plain-generic", version: "1.0.0", tool: "plain-generic"}}
}

// PlainGenericImporter is the fallback for plain-text family files that do
// not strongly match any specific plain importer. It is sorted last in
// Detect regardless of confidence (see registry.Detect). It claims any
// non-empty peek with low confidence and streams lines accepting any shape (host preferred).
type PlainGenericImporter struct{ importerBase }

func (p *PlainGenericImporter) CanImport(path string, peek []byte) (float64, bool) {
	if len(bytesTrimSpace(peek)) == 0 {
		return 0, false
	}
	// Generic claims any plain text with low confidence 0.1 — even for xml/json/gzip
	// so there is always a fallback. Specific importers decline those signatures.
	return 0.1, true
}

func (p *PlainGenericImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	filename := filepath.Base(path)
	now := env.now()
	stats := ImportStats{StickyFlags: make(map[string]bool)}
	maxOut := env.Bounds.effectiveMaxOutput()
	processed, failed, truncatedSig, err := readLines(ctx, env, path, func(line, raw string) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		prov, rec := buildProvenance(env, p.Name(), filename, raw, now)
		shape := classifyLine(line)
		switch shape {
		case ShapeURL:
			if u, err := assetParseURL(line, prov); err == nil {
				key := u.Identity().String()
				if _, dup := out.seen[key]; dup {
					return errDuplicate
				}
				if totalAssets(out) >= maxOut {
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
		case ShapeIP:
			if ip, err := assetNewIP(line, prov); err == nil {
				key := ip.Identity().String()
				if _, dup := out.seen[key]; dup {
					return errDuplicate
				}
				if totalAssets(out) >= maxOut {
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
			}
		case ShapeCIDR:
			if canon, ok := parseCIDR(line); ok {
				key := "cidr:" + canon
				if _, dup := out.seen[key]; dup {
					return errDuplicate
				}
				if _, dup := out.seenCIDR[canon]; dup {
					return errDuplicate
				}
				if totalAssets(out) >= maxOut {
					stats.Truncated = true
					stats.StickyFlags["import_truncated"] = true
					out.truncated = true
					return errOutputTruncated
				}
				out.seen[key] = struct{}{}
				out.seenCIDR[canon] = struct{}{}
				out.CIDRs = append(out.CIDRs, canon)
				rec.Identity = key
				out.ProvenanceRecords = append(out.ProvenanceRecords, rec)
				return nil
			}
		case ShapeJS:
			if j, err := assetNewJS(line, prov); err == nil {
				key := j.Identity().String()
				if _, dup := out.seen[key]; dup {
					return errDuplicate
				}
				if totalAssets(out) >= maxOut {
					stats.Truncated = true
					stats.StickyFlags["import_truncated"] = true
					out.truncated = true
					return errOutputTruncated
				}
				out.seen[key] = struct{}{}
				out.JS = append(out.JS, j)
				rec.Identity = key
				out.ProvenanceRecords = append(out.ProvenanceRecords, rec)
				return nil
			}
		}
		if h, err := assetNewHost(line, prov); err == nil {
			key := h.Identity().String()
			if _, dup := out.seen[key]; dup {
				return errDuplicate
			}
			if totalAssets(out) >= maxOut {
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
		}
		return &importValidationError{msg: "unknown shape"}
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

func bytesTrimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}

func totalAssets(s *Sink) int {
	return len(s.Domains) + len(s.Hosts) + len(s.URLs) + len(s.IPs) + len(s.JS) + len(s.CIDRs)
}
