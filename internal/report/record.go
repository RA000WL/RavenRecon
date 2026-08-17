package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/RA000WL/RavenRecon/internal/cache"
)

// renderOperation is the cache operation name for report renders.
const renderOperation = "report.render"

// maxCacheableRenderBytes bounds the total rendered bytes one run may store
// in a render-cache record (fixed constant). The cache's own
// MaxRecordSize (16 MiB) bounds the encoded record; rendered bytes are
// stored base64-encoded (4/3 inflation) inside a JSON envelope, so the
// render-side guard sits comfortably below it. Larger renders are NEVER
// cached — they always render fresh (an honest, documented cap; no report
// is ever truncated to fit a cache record).
const maxCacheableRenderBytes = 11 << 20

// renderPart is one rendered part inside a render-cache record.
type renderPart struct {
	// Part is the sink part name ("" for single-part reports).
	Part string `json:"part"`
	// Bytes is the exact file bytes (as stored on disk; for gzip renders
	// the compressed size — the same count Data carries, and the count
	// both the store and the decode-revalidation compare).
	Bytes int64 `json:"bytes"`
	// Data is the exact rendered bytes ([]byte marshals base64).
	Data []byte `json:"data"`
}

// renderRecord is the payload of a `report.render` cache record: the exact
// bytes of every part of one rendered report, plus the identity fields the
// decode path re-validates against the current run (report ID, reporter
// version, format, and model digest) — a record that disagrees with the
// run it is being served for is evicted and the render re-executes, never
// served.
type renderRecord struct {
	ReportID string       `json:"report_id"`
	Version  string       `json:"version"`
	Format   string       `json:"format"`
	Digest   string       `json:"digest"`
	Parts    []renderPart `json:"parts"`
}

// renderCacheKey derives the deterministic render-cache key for one
// reporter against one model. The key covers the operation, the model
// digest (the target), and every result-relevant option: the reporter ID,
// its declared version (the documented bump contract), the output format,
// and whether the output is compressed. Timings, concurrency, and the
// output directory never enter the key.
func renderCacheKey(m *Model, rep Reporter, compress bool) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: renderOperation,
		Target:    "report:" + m.Digest,
		Config: map[string]string{
			"report":     rep.ID,
			"version":    rep.Version,
			"format":     string(rep.Format),
			"schema":     fmt.Sprintf("%d", SchemaVersion),
			"compressed": fmt.Sprintf("%t", compress),
		},
	})
}

// storeRender reads the committed part files and stores them as a
// completed render-cache record. Oversized renders are honestly skipped:
// nothing is truncated, nothing is stored, and the fresh render is still
// served.
func storeRender(ctx context.Context, c cache.Cache, key cache.Key, m *Model, rep Reporter, compress bool, parts []sinkPartInfo, now time.Time) error {
	record := renderRecord{
		ReportID: rep.ID,
		Version:  rep.Version,
		Format:   string(rep.Format),
		Digest:   m.Digest,
		Parts:    make([]renderPart, 0, len(parts)),
	}
	// Size-guard BEFORE reading: an oversized render (over the cacheable
	// bound) is honestly skipped without ever being materialized in
	// memory, and nothing is ever truncated to fit a cache record.
	total := int64(0)
	for _, info := range parts {
		fi, err := os.Stat(info.Final)
		if err != nil {
			return fmt.Errorf("report: cache store: stat part %q: %w", info.Part, err)
		}
		total += fi.Size()
	}
	if total > maxCacheableRenderBytes {
		return nil
	}
	for _, info := range parts {
		data, err := os.ReadFile(info.Final)
		if err != nil {
			return fmt.Errorf("report: cache store: read part %q: %w", info.Part, err)
		}
		record.Parts = append(record.Parts, renderPart{Part: info.Part, Bytes: int64(len(data)), Data: data})
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("report: cache store: marshal record: %w", err)
	}
	return c.Put(ctx, key, cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Operation:     renderOperation,
		Target:        "report:" + m.Digest,
		CreatedAt:     now.UTC(),
		Status:        cache.StatusCompleted,
		Data:          payload,
	})
}

// decodeRender validates a cached render record against the current run
// (exact identity match on report ID, version, format, and model digest;
// non-empty parts whose declared sizes match their bytes; total within the
// cacheable bound) and returns its parts. A record failing any check is
// unusable — the caller evicts it and renders fresh.
func decodeRender(outcome cache.Outcome, m *Model, rep Reporter, compress bool) ([]renderPart, bool) {
	rec, ok := outcome.ValidResult()
	if !ok || rec.Status != cache.StatusCompleted {
		return nil, false
	}
	var record renderRecord
	dec := json.NewDecoder(bytes.NewReader(rec.Data))
	if err := dec.Decode(&record); err != nil {
		return nil, false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, false
	}
	if record.ReportID != rep.ID || record.Version != rep.Version ||
		record.Format != string(rep.Format) || record.Digest != m.Digest {
		return nil, false
	}
	if len(record.Parts) == 0 {
		return nil, false
	}
	total := int64(0)
	for _, part := range record.Parts {
		if !validPartName(part.Part) {
			return nil, false // part names enter filenames: reject outright
		}
		if part.Part == "" && len(record.Parts) > 1 {
			return nil, false // the default part only exists alone
		}
		if part.Bytes != int64(len(part.Data)) {
			return nil, false
		}
		total += part.Bytes
		if total > maxCacheableRenderBytes {
			return nil, false
		}
	}
	return record.Parts, true
}
