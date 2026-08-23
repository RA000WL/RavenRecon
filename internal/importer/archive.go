package importer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Archive-source importers (ROADMAP v1.8 row "Archive sources: wayback
// (Common Crawl future)"): wayback CDX line exports and WARC record files.
// Both are LOCAL-FILE importers only — remote Common Crawl / Wayback API
// ingestion is explicitly out of scope for this milestone.
//
// Detection lives in CanImport as content-shape probes over the peek slice,
// ordered after the json/xml probes in the waterfall (see detect.go): when
// the peek is gzipped it is inflated in memory up to PeekSize bytes and the
// inner content is probed instead, so renamed archives are still detected by
// content while extension matches only nudge confidence.

const (
	cdxSampleLines = 50 // parity with lineShapeHistogram sampling
	inflateCap     = PeekSize
)

// inflatePeek inflates at most limit bytes of a gzipped peek for in-memory
// probing. It never opens files and never allocates more than limit bytes.
// A nil return means "cannot probe honestly" (corrupt or unreadable gzip).
func inflatePeek(peek []byte, limit int) []byte {
	zr, err := gzip.NewReader(bytes.NewReader(peek))
	if err != nil {
		return nil
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, int64(limit)))
	if err != nil && len(out) == 0 {
		return nil
	}
	return out
}

// isHTTPURLValue reports whether s parses through the single normalization
// point as an HTTP(S) URL.
func isHTTPURLValue(s string) bool {
	if !strings.Contains(s, "://") {
		return false
	}
	_, err := asset.ParseURL(s, asset.Provenance{})
	return err == nil
}

// looksLikeCDXTimestamp reports whether s is a classic CDX 14-digit compact
// timestamp (YYYYMMDDhhmmss) or an ISO-8601-ish variant (YYYY-MM-DDThh...).
func looksLikeCDXTimestamp(s string) bool {
	if len(s) == 14 {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return isISOishTimestamp(s)
			}
		}
		return true
	}
	return isISOishTimestamp(s)
}

func isISOishTimestamp(s string) bool {
	// YYYY-MM-DD prefix with either 'T' separator or longer tail.
	if len(s) >= 16 && s[4] == '-' && s[7] == '-' && (s[10] == 'T' || s[10] == ' ') {
		for _, i := range []int{0, 1, 2, 3, 5, 6, 8, 9} {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// isSURTKey reports whether s looks like a SURT (Sort-friendly URI
// Re-ordering Transformer) key such as "com,example)/path" — the canonical
// first column of CDX lines.
func isSURTKey(s string) bool {
	return strings.Contains(s, "),") || strings.Contains(s, ")/") || strings.HasPrefix(s, "com,")
}

// isCDXLine reports whether one whitespace-separated line has the CDX shape:
//
//	SURT timestamp original mimetype status digest length   (classic)
//	original timestamp mimetype status digest length        (surtless export)
//
// The original URL candidate (field 2, falling back to field 0 for surtless
// lines) must parse through asset.ParseURL, and either field 1 must look like
// a CDX timestamp in a ≥6-field line, or field 0 must look like a SURT key.
func isCDXLine(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return false
	}
	// Classic rows carry the original URL at field 2; surtless exports lead
	// with it. Either way some field must parse through ParseURL.
	hasURL := isHTTPURLValue(fields[2]) || isHTTPURLValue(fields[0])
	if !hasURL {
		return false
	}
	if len(fields) >= 6 && looksLikeCDXTimestamp(fields[1]) {
		return true
	}
	return isSURTKey(fields[0])
}

// cdxLineStats samples at most maxSample non-empty lines of peek and returns
// (matched, sampled, ratio) of CDX-shaped lines.
func cdxLineStats(peek []byte, maxSample int) (matched, sampled int, ratio float64) {
	for _, l := range bytes.Split(peek, []byte{'\n'}) {
		if sampled >= maxSample {
			break
		}
		s := strings.TrimSpace(string(l))
		if s == "" {
			continue
		}
		sampled++
		if isCDXLine(s) {
			matched++
		}
	}
	if sampled == 0 {
		return 0, 0, 0
	}
	return matched, sampled, float64(matched) / float64(sampled)
}

// warcMagicInPeek reports whether the first non-empty line of data starts
// with a WARC version marker ("WARC/<digit>...").
func warcMagicInPeek(data []byte) bool {
	for _, l := range bytes.Split(data, []byte{'\n'}) {
		s := strings.TrimRight(string(l), "\r")
		if strings.TrimSpace(s) == "" {
			continue
		}
		return isWARCVersionLine(s)
	}
	return false
}

func isWARCVersionLine(s string) bool {
	if !strings.HasPrefix(s, "WARC/") || len(s) <= len("WARC/") {
		return false
	}
	c := s[len("WARC/")]
	return c >= '0' && c <= '9'
}

func extHasSuffix(path string, suffixes ...string) bool {
	lp := strings.ToLower(path)
	for _, s := range suffixes {
		if strings.HasSuffix(lp, s) {
			return true
		}
	}
	return false
}

// ArchiveCDXImporter consumes local wayback CDX exports (.cdx / .cdx.gz):
// whitespace-separated SURT-key/timestamp/original-URL rows. Only the
// original URL column becomes an asset.URL via ParseURL; timestamp, mimetype,
// status, and length ride provenance metadata. Remote index ingestion
// (Common Crawl) is out of scope.
type ArchiveCDXImporter struct{ importerBase }

func NewArchiveCDXImporter() *ArchiveCDXImporter {
	return &ArchiveCDXImporter{importerBase{name: "archive-cdx", version: "1.0.1", tool: "wayback-cdx"}}
}

func (p *ArchiveCDXImporter) CanImport(path string, peek []byte) (float64, bool) {
	data := peek
	if isGzipped(data) {
		data = inflatePeek(data, inflateCap)
		if data == nil {
			return 0, false
		}
	} else if looksLikeXMLPeek(peek) || isJSONStructure(peek) {
		// Signature stage: XML/JSON content belongs to those families.
		return 0, false
	}
	matched, sampled, ratio := cdxLineStats(data, cdxSampleLines)
	// Require a majority of sampled lines to carry the CDX shape so plain
	// URL lists with one stray CDX-like line stay owned by the plain family.
	if sampled == 0 || matched == 0 || matched*2 < sampled {
		return 0, false
	}
	// Base 0.90 keeps genuine CDX files above plain-urls even when the file
	// is renamed: the plain classifier's ParseURL probe tolerates space-
	// padded lines, so every CDX row also classifies as ShapeURL and a
	// surtless export would otherwise tie or outrank this importer. The
	// majority-of-sample requirement above is what prevents this from
	// stealing one-URL-per-line lists.
	conf := 0.90 + 0.05*ratio
	if extHasSuffix(path, ".cdx", ".cdx.gz") {
		conf += 0.05
	}
	if conf > 0.95 {
		conf = 0.95
	}
	return conf, true
}

// capMetaVal bounds a provenance metadata value to keep sidecar entries small.
func capMetaVal(s string) string {
	if len(s) > 128 {
		return s[:128]
	}
	return s
}

// cdxColumns maps CDX metadata concepts to whitespace-field offsets.
// Timestamp is always field 1; the rest depend on whether a leading SURT
// key pushes every column one slot later (classic) or the row is surtless:
//
//	SURT ts original mime status digest length   → classic  (mime=3 status=4 length=6)
//	original ts mime status digest length        → surtless (mime=2 status=3 length=5)
type cdxColumns struct {
	mime   int
	status int
	length int
}

var (
	cdxClassicColumns  = cdxColumns{mime: 3, status: 4, length: 6}
	cdxSurtlessColumns = cdxColumns{mime: 2, status: 3, length: 5}
)

// cdxColumnsFor picks the offset map by which field supplied the original
// URL: classic rows carry it at field 2 (field 0 is the SURT key), surtless
// exports lead with it. Mirrors the original-URL selection in Import so the
// metadata offsets always describe the same row layout.
func cdxColumnsFor(fields []string) cdxColumns {
	if len(fields) > 2 && !isHTTPURLValue(fields[2]) {
		return cdxSurtlessColumns
	}
	return cdxClassicColumns
}

func (p *ArchiveCDXImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
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
		if !isCDXLine(line) {
			return errors.New("cdx: expected SURT/timestamp/original-URL row")
		}
		fields := strings.Fields(line)
		original := fields[2]
		if !isHTTPURLValue(original) {
			original = fields[0] // surtless variant
		}
		cols := cdxColumnsFor(fields)
		prov, rec := buildProvenance(env, p.Name(), filename, raw, now)
		u, err := asset.ParseURL(original, prov)
		if err != nil {
			return err
		}
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
		meta := map[string]string{
			"timestamp": capMetaVal(fields[1]),
		}
		if len(fields) > cols.mime {
			meta["mimetype"] = capMetaVal(fields[cols.mime])
		}
		if len(fields) > cols.status {
			meta["status"] = capMetaVal(fields[cols.status])
		}
		if len(fields) > cols.length {
			meta["length"] = capMetaVal(fields[cols.length])
		}
		rec.Metadata = meta
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

// ArchiveWARCImporter consumes local WARC 0.x/1.x files (.warc / .warc.gz).
// It extracts the WARC-Target-URI header of every record as an asset.URL and
// streams payloads to discard — bodies are never retained in memory beyond
// bounded 8 KiB chunks, honoring honest truncation when the file ends mid
// payload or the decompressed-byte cap trips.
type ArchiveWARCImporter struct{ importerBase }

func NewArchiveWARCImporter() *ArchiveWARCImporter {
	return &ArchiveWARCImporter{importerBase{name: "archive-warc", version: "1.0.0", tool: "warc"}}
}

func (p *ArchiveWARCImporter) CanImport(path string, peek []byte) (float64, bool) {
	data := peek
	if isGzipped(data) {
		data = inflatePeek(data, inflateCap)
		if data == nil {
			return 0, false
		}
	} else if looksLikeXMLPeek(peek) || isJSONStructure(peek) {
		return 0, false
	}
	if !warcMagicInPeek(data) {
		return 0, false
	}
	conf := 0.90
	if extHasSuffix(path, ".warc", ".warc.gz") {
		conf += 0.05
	}
	if conf > 0.95 {
		conf = 0.95
	}
	return conf, true
}

func (p *ArchiveWARCImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
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
	processed, failed, truncatedSig, serr := streamWARC(ctx, env, path, func(targetURI, headerBlock, warcType string) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		prov, rec := buildProvenance(env, p.Name(), filename, headerBlock, now)
		u, err := asset.ParseURL(strings.TrimSpace(targetURI), prov)
		if err != nil {
			return err
		}
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
		if warcType != "" {
			rec.Metadata = map[string]string{"warc_type": capMetaVal(warcType)}
		}
		out.seen[key] = struct{}{}
		out.URLs = append(out.URLs, u)
		rec.Identity = key
		out.ProvenanceRecords = append(out.ProvenanceRecords, rec)
		return nil
	})
	if serr != nil {
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
		return stats, serr
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

// splitHeaderField splits "Name: value" at the first colon.
func splitHeaderField(line string) (string, string, bool) {
	i := strings.Index(line, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// readBoundedLine reads one logical '\n'-terminated line without ever
// allocating more than limit+fragment bytes. account receives every fragment
// length (decompressed-byte accounting, gzip-bomb guard parity with
// readLines); when account returns false the caller treats the stream as
// truncated. eof is true only for a clean EOF with no pending data; an
// unterminated final line is returned normally with eof=false.
func readBoundedLine(br *bufio.Reader, limit int, account func(int) bool) (line []byte, oversized bool, eof bool, err error) {
	var buf []byte
	for {
		frag, rerr := br.ReadSlice('\n')
		if rerr != nil && rerr != io.EOF && rerr != bufio.ErrBufferFull {
			return nil, false, false, rerr
		}
		isEOF := rerr == io.EOF
		fragLen := len(frag)
		if fragLen > 0 && !account(fragLen) {
			return buf, oversized, isEOF && fragLen == 0, errCapTripped
		}
		if !oversized {
			if len(buf)+fragLen > limit {
				oversized = true
				if keep := limit - len(buf); keep > 0 {
					buf = append(buf, frag[:keep]...)
				}
			} else {
				buf = append(buf, frag...)
			}
		}
		if isEOF {
			if fragLen == 0 && len(buf) == 0 && !oversized {
				return nil, false, true, nil
			}
			return buf, oversized, false, nil
		}
		if fragLen > 0 && frag[fragLen-1] == '\n' {
			return buf, oversized, false, nil
		}
		// ErrBufferFull without newline: continue assembling the same line.
	}
}

// errCapTripped signals that MaxDecompressedBytes tripped inside
// readBoundedLine; streamWARC converts it into honest truncation.
var errCapTripped = errors.New("decompressed byte cap exceeded")

// streamWARC streams a WARC file record-by-record with bounded memory:
// header blocks accumulate up to effectiveMaxLine() bytes, payloads are
// discarded in 8 KiB chunks under the decompressed-byte cap, ctx is checked
// per record and per chunk, and progress is emitted once per completed
// record. handle receives (target URI, verbatim header block, WARC-Type).
// Stray garbage between records counts each offending line as failed; a
// first line that is not a WARC version marker fails structurally.
func streamWARC(ctx context.Context, env ImportEnv, path string, handle func(targetURI, headerBlock, warcType string) error) (processed, failed int, truncatedSig bool, err error) {
	maxLine := env.Bounds.effectiveMaxLine()
	maxDecomp := env.Bounds.effectiveMaxDecompressed()
	base := filepath.Base(path)
	rc, openErr := openStream(path)
	if openErr != nil {
		return 0, 0, false, newImportError(base, path, "open", openErr)
	}
	defer rc.Close()

	br := bufio.NewReaderSize(rc, 8192)
	progress := newProgressEmitter(env.Observer, env.now, "import")
	var bytesRead int
	account := func(n int) bool {
		bytesRead += n
		return bytesRead <= maxDecomp
	}
	failTruncated := func() (int, int, bool, error) {
		progress.flush()
		return processed, failed, true, nil
	}

	firstRecord := true
	for {
		if cerr := checkCtx(ctx); cerr != nil {
			progress.flush()
			return processed, failed, truncatedSig, cerr
		}
		versionRaw, oversized, eof, lerr := readBoundedLine(br, maxLine, account)
		if lerr != nil {
			if errors.Is(lerr, errCapTripped) {
				return failTruncated()
			}
			progress.flush()
			return processed, failed, truncatedSig, newImportError(base, path, "read", lerr)
		}
		if eof && len(versionRaw) == 0 && !oversized {
			break // clean EOF
		}
		version := strings.TrimRight(string(versionRaw), "\r\n")
		if firstRecord && !strings.HasPrefix(version, "WARC/") {
			progress.flush()
			return processed, failed, truncatedSig, newImportError(base, path, "format",
				errors.New("not a WARC file: missing WARC/ version magic"))
		}
		firstRecord = false
		if oversized || !isWARCVersionLine(version) {
			// Stray bytes between records (or an oversized version line):
			// count and resync by scanning forward.
			failed++
			continue
		}

		// Header block: parse until the blank terminator, retaining at most
		// maxLine bytes verbatim for provenance OriginalRecord.
		block := make([]byte, 0, 512)
		appendHeader := func(b []byte) {
			if len(block)+len(b) <= maxLine {
				block = append(block, b...)
			}
		}
		appendHeader(versionRaw)
		var target, warcType string
		var contentLen int64 = -1
		headerOversized := oversized
		for {
			hl, hOver, hEOF, hlerr := readBoundedLine(br, maxLine, account)
			if hlerr != nil {
				if errors.Is(hlerr, errCapTripped) {
					return failTruncated()
				}
				progress.flush()
				return processed, failed, truncatedSig, newImportError(base, path, "read", hlerr)
			}
			if hOver {
				headerOversized = true
			} else {
				appendHeader(hl)
			}
			trimmed := strings.TrimRight(string(hl), "\r\n")
			if trimmed != "" {
				if k, v, ok := splitHeaderField(trimmed); ok {
					switch strings.ToLower(k) {
					case "warc-target-uri":
						target = v
					case "content-length":
						if n, perr := strconv.ParseInt(v, 10, 64); perr == nil && n >= 0 {
							contentLen = n
						}
					case "warc-type":
						warcType = v
					}
				}
			}
			if trimmed == "" || hEOF {
				break // blank terminator, or clean EOF before one
			}
		}

		recordBytes := len(block)
		switch {
		case headerOversized:
			// Untrusted header block; do not import its target even if one
			// parsed. The payload skip below still applies whenever
			// Content-Length was parsed (header parsing continues past an
			// overflowing line until the blank terminator).
			failed++
			truncatedSig = true
		case target != "":
			herr := handle(target, string(block), warcType)
			switch {
			case herr == nil:
				processed++
			case errors.Is(herr, errDuplicate):
				// neither processed nor failed
			case errors.Is(herr, errOutputTruncated):
				truncatedSig = true
			case errors.Is(herr, context.Canceled), errors.Is(herr, context.DeadlineExceeded):
				progress.flush()
				return processed, failed, truncatedSig, herr
			default:
				failed++
			}
		default:
			failed++ // record without WARC-Target-URI
		}

		// Skip the payload (never retained) under the decompressed cap.
		if contentLen > 0 {
			buf := make([]byte, 8192)
			remaining := contentLen
			var skipped int
			for remaining > 0 {
				if cerr := checkCtx(ctx); cerr != nil {
					progress.flush()
					return processed, failed, truncatedSig, cerr
				}
				chunk := buf
				if int64(len(chunk)) > remaining {
					chunk = buf[:remaining]
				}
				n, rerr := io.ReadFull(br, chunk)
				skipped += n
				remaining -= int64(n)
				if n > 0 && !account(n) {
					progress.add(recordBytes + skipped)
					return failTruncated()
				}
				if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
					progress.add(recordBytes + skipped)
					// File ended mid-payload: honest tail truncation.
					return failTruncated()
				}
				if rerr != nil {
					progress.flush()
					return processed, failed, truncatedSig, newImportError(base, path, "read", rerr)
				}
			}
			recordBytes += skipped
		}
		// Consume this record's trailing CRLFCRLF separator (present even
		// for zero-length payloads), lenient about CR/LF mix; any other
		// byte is unread for the next record scan.
		for i := 0; i < 4; i++ {
			b, berr := br.ReadByte()
			if berr == io.EOF {
				break
			}
			if berr != nil {
				progress.flush()
				return processed, failed, truncatedSig, newImportError(base, path, "read", berr)
			}
			if b == '\r' || b == '\n' {
				continue
			}
			_ = br.UnreadByte()
			break
		}
		progress.add(recordBytes)
	}
	progress.flush()
	return processed, failed, truncatedSig, nil
}
