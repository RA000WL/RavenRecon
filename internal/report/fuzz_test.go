package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// FuzzRenderCSV drives renderCSV/writeCSVTable — the pure CSV presentation
// boundary — with hand-built Models carrying hostile strings in every
// rendered field (CSV metacharacters, formula-injection prefixes, multibyte
// sequences). The Model bypasses the asset builders deliberately: the
// renderer must cope with ANY Model it is handed. Invariants:
//
//   - no panic and no render error for any input;
//   - every part's output round-trips as valid, rectangular CSV through
//     encoding/csv's strict reader with exactly 1 header row + N data rows;
//   - rendering is deterministic: two renders of one immutable Model are
//     byte-identical.
func FuzzRenderCSV(f *testing.F) {
	f.Add("host.example", "src", "/p", "q=1", "GET", "1.2.3", "value", "rule-1", "boom", uint8(0))
	f.Add("a,b\nc\"d", "src,\"\r\nx", "/pa th?q=,\"", "x=1,y=2", "POST", "", "=cmd|' /C calc'!A0", "+1-1\n@x", "\t=SUM(A1)", uint8(1))
	f.Add("h", "@source", "/", "", "-GET-", "-", "--version--", "'lead", "msg\r\nwith\rnewlines", uint8(2))
	f.Add("\xf0\x9f\x8c\x8d.example", "s\u00e9curit\u00e9", "/\u4e2d\u6587", "\u2028q", "get", "\u00fc", "\U0001F600val", "r\u00e8gle", "\u65e5\u672c\u8a9e", uint8(3))
	f.Add("x", "", "", "", "", "", "", "", "", uint8(0))
	f.Add("long-host-name-value.example", "s", "/", "q", "M", "v", "sec", "r", "m", uint8(3))
	f.Add("nul\x00byte.example", "s\x00r", "/p\x00", "q\x00", "G\x00", "v\x00", "sec\x00", "r\x00", "m\x00sg", uint8(1))
	f.Add("quote\"host", "src", "/\"path\"", "\"q\"", "PATCH", "1\".2", "\"sec", "\"rule\"", "\"msg\"", uint8(2))

	f.Fuzz(func(t *testing.T, host, source, path, query, method, version, secretVal, ruleID, msg string, n uint8) {
		now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
		rows := int(n) % 4
		m := &Model{}
		for i := 0; i < rows; i++ {
			u := asset.URL{
				Scheme:   "https",
				HostPort: host,
				Path:     path,
				Query:    query,
				Prov:     asset.Provenance{Source: source, DiscoveredAt: now},
			}
			m.Hosts = append(m.Hosts, asset.Host{Name: host, Prov: u.Prov})
			m.URLs = append(m.URLs, u)
			m.Endpoints = append(m.Endpoints, asset.Endpoint{Method: method, URL: u, Prov: u.Prov})
			m.Technologies = append(m.Technologies, asset.Technology{
				Name:     version,
				Category: asset.CategoryCDN,
				Version:  version,
				Prov:     u.Prov,
			})
			m.Secrets = append(m.Secrets, asset.SecretCandidate{
				Type:   asset.SecretTypeJWT,
				Value:  secretVal,
				Source: asset.Identity{Kind: "js", Value: path},
				Prov:   u.Prov,
			})
			m.Findings = append(m.Findings, asset.Finding{
				RuleID:     ruleID,
				RuleName:   msg,
				Category:   source,
				Subject:    asset.Identity{Kind: "url", Value: path},
				Confidence: 0.5,
				Priority:   msg,
				Status:     source,
				Created:    now,
			})
		}

		ctx := context.Background()
		sink := newMemSink()
		if err := renderCSV(ctx, m, sink); err != nil {
			t.Fatalf("renderCSV: %v", err)
		}

		wantCols := map[string]int{
			"hosts": 4, "urls": 8, "endpoints": 4,
			"technologies": 6, "secrets": 5, "findings": 10,
		}
		for part, cols := range wantCols {
			bufBytes, ok := sink.parts[part]
			if !ok {
				t.Fatalf("part %q was not rendered", part)
			}
			recs, rerr := csv.NewReader(bytes.NewReader(bufBytes.Bytes())).ReadAll()
			if rerr != nil {
				t.Fatalf("part %q output is not valid CSV: %v", part, rerr)
			}
			if len(recs) != 1+rows {
				t.Fatalf("part %q has %d records, want %d (header + %d rows)", part, len(recs), 1+rows, rows)
			}
			for ri, rec := range recs {
				if len(rec) != cols {
					t.Fatalf("part %q record %d has %d fields, want %d (ragged table)", part, ri, len(rec), cols)
				}
			}
		}

		again := newMemSink()
		if err := renderCSV(ctx, m, again); err != nil {
			t.Fatalf("re-render: %v", err)
		}
		for part := range wantCols {
			if !bytes.Equal(sink.parts[part].Bytes(), again.parts[part].Bytes()) {
				t.Fatalf("non-deterministic render of part %q", part)
			}
		}
	})
}

// FuzzErrorContext drives ClassifyError and normalizeErrorRecord — the
// pure error-context boundary that turns arbitrary caller-supplied error
// text into report summary fields. Invariants:
//
//   - ClassifyError never panics and always returns a category from the
//     fixed vocabulary;
//   - normalizeErrorRecord rejects exactly the invalid categories, and on
//     success returns a valid category, a positive count, and stage/message
//     within their byte bounds.
func FuzzErrorContext(f *testing.F) {
	f.Add("dial tcp: lookup failed", "dns", "dns", 3, uint8(0))
	f.Add("", "", "", 0, uint8(0))
	f.Add("boom\r\nwith\tcontrols\x00", "st\age", "not-a-category", -7, uint8(1))
	f.Add(string(bytes.Repeat([]byte("m"), 4096)), string(bytes.Repeat([]byte("s"), 200)), "http", 1<<20, uint8(2))
	f.Add("context canceled mid-run", "scan", "cancellation", 12, uint8(3))
	f.Add("i/o timeout", "probe", "timeout", 2, uint8(4))
	f.Add("https://example.test/x", "fetch", "http", 1, uint8(5))
	f.Add("permission denied", "cache", "cache", 1000000, uint8(6))
	f.Add("\u00e9\u4e2d\u6587 \U0001F600", "\u30b9\u30c6\u30fc\u30b8", "unknown", -1, uint8(7))

	f.Fuzz(func(t *testing.T, msg, stage, category string, count int, wrapper uint8) {
		base := errors.New(msg)
		var err error
		switch wrapper % 8 {
		case 0:
			err = base
		case 1:
			err = fmt.Errorf("stage failed: %w", base)
		case 2:
			err = fmt.Errorf("%w", context.Canceled)
		case 3:
			err = errors.Join(base, context.DeadlineExceeded)
		case 4:
			err = &net.DNSError{Err: msg, Name: "example.test", IsTimeout: wrapper%16 >= 8}
		case 5:
			err = &url.Error{Op: "Get", URL: msg, Err: base}
		case 6:
			err = fmt.Errorf("wrap: %w", os.ErrPermission)
		case 7:
			err = fmt.Errorf("double: %w", fmt.Errorf("inner: %w", base))
		}

		if got := ClassifyError(err); !got.Valid() {
			t.Fatalf("ClassifyError returned invalid category %q", got)
		}

		rec, nerr := normalizeErrorRecord(ErrorRecord{
			Category: ErrorCategory(category),
			Stage:    stage,
			Message:  msg,
			Count:    count,
		})
		if nerr != nil {
			if ErrorCategory(category).Valid() {
				t.Fatalf("normalize rejected a valid category %q: %v", category, nerr)
			}
			return
		}
		if !rec.Category.Valid() {
			t.Fatalf("normalized record kept invalid category %q", rec.Category)
		}
		if rec.Count <= 0 {
			t.Fatalf("count not normalized: %d", rec.Count)
		}
		if len(rec.Stage) > maxErrorStageBytes || len(rec.Message) > maxErrorMessageBytes {
			t.Fatalf("bounds violated: stage=%d bytes, message=%d bytes", len(rec.Stage), len(rec.Message))
		}
	})
}
