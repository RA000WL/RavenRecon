package importer

import (
	"context"
	"path/filepath"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// PlainJSImporter consumes js.txt-style files — each line is a JS URL or path.
// We normalize via asset.NewJavaScript (which delegates to ParseURL) and
// fallback to path-like JS detection.
type PlainJSImporter struct{ importerBase }

func NewPlainJSImporter() *PlainJSImporter {
	return &PlainJSImporter{importerBase{name: "plain-js", version: "1.0.0", tool: "plain-js"}}
}

func (p *PlainJSImporter) CanImport(path string, peek []byte) (float64, bool) {
	// Extension hint for js files is strong
	c, ok := plainConfidence(path, peek, ShapeJS, []string{"txt", "js"})
	if ok {
		// bump if path contains js
		if filepath.Ext(path) == ".js" {
			if c+0.05 <= 0.95 {
				c += 0.05
			}
		}
		return c, true
	}
	// Fallback: if line shapes are URLs with .js, also claim as urls, but js importer should still claim
	// Check raw histogram for JS ratio without strict 0.5 gate
	return 0, false
}

func (p *PlainJSImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
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
		// Try as JavaScript URL first
		if j, err := asset.NewJavaScript(line, prov); err == nil {
			key := j.Identity().String()
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
			out.JS = append(out.JS, j)
			rec.Identity = key
			out.ProvenanceRecords = append(out.ProvenanceRecords, rec)
			return nil
		}
		// Bare path fallback: if looks like JS path, synthesize a URL for dedup
		// We treat it as JS asset with placeholder host; but to keep canonical
		// we require it to be a valid URL — otherwise count as failed.
		return &importValidationError{msg: "not a valid JS URL"}
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
