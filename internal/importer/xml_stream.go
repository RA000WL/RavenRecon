package importer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// XML shape labels used by the detection waterfall and CanImport claims.
const (
	xmlShapeBurp = "burp"
	xmlShapeZap  = "zap"
)

// looksLikeXMLPeek reports whether the trimmed peek starts with either the
// <?xml declaration or a '<' tag opening followed by a name character — the
// two forms tool exports take in the wild (declaration-less fragments still
// detect). UTF-8 BOM tolerated, mirroring the JSON probe.
func looksLikeXMLPeek(peek []byte) bool {
	trim := bytesTrimSpace(peek)
	trim = bytes.TrimPrefix(trim, []byte{0xef, 0xbb, 0xbf})
	if len(trim) == 0 {
		return false
	}
	if bytes.HasPrefix(trim, []byte("<?xml")) {
		return true
	}
	if trim[0] != '<' {
		return false
	}
	for i := 1; i < len(trim); i++ {
		c := trim[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	return false
}

// xmlProbeShape classifies the XML peek by its root element name, bounded to
// the peek slice (never opens the file). It mirrors jsonProbeShape: returns
// one of the XML importer shapes (xmlShapeBurp / xmlShapeZap) or "" when the
// content is not XML or the root element belongs to no known importer shape.
//
// Root names match case-insensitively: Burp Suite exports <items> (sitemap)
// and <issues>; OWASP ZAP and zaproxy-cli export <OWASPZAPReport>. Unknown
// XML roots yield "" so no importer mis-claims them — generic XML fallback is
// deliberately out of T7 scope (leave undetected rather than mis-claiming;
// plain-generic's low-confidence catch-all still covers downstream use).
func xmlProbeShape(peek []byte) string {
	if !looksLikeXMLPeek(peek) {
		return ""
	}
	root, ok := xmlProbeRootName(peek)
	if !ok {
		return ""
	}
	switch {
	case strings.EqualFold(root, "items"), strings.EqualFold(root, "issues"):
		return xmlShapeBurp
	case strings.EqualFold(root, "owaspzapreport"):
		return xmlShapeZap
	default:
		return ""
	}
}

// xmlProbeRootName extracts the root element name from the peek buffer using
// a bounded xml.Decoder token scan over the peek only. It returns ok=false on
// malformed XML or when the root element starts beyond the buffered region
// (truncated peek), in which case no claim is made rather than a wrong one.
func xmlProbeRootName(peek []byte) (string, bool) {
	trim := bytesTrimSpace(peek)
	trim = bytes.TrimPrefix(trim, []byte{0xef, 0xbb, 0xbf})
	if len(trim) == 0 {
		return "", false
	}
	dec := xml.NewDecoder(bytes.NewReader(trim))
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t.Name.Local, true
		case xml.ProcInst, xml.Directive, xml.Comment, xml.CharData:
			// prolog, DOCTYPE, leading comments/whitespace: keep scanning
		default:
			return "", false
		}
	}
}

// xmlConfidence computes confidence for an XML importer based on probe shape,
// mirroring jsonConfidence: 0.85 base for correct shape, +0.05 extension
// tie-break (.xml), capped at 0.95. Renamed extensions still detect via
// content alone (base 0.85 ≥ threshold), matching the plain/json behavior.
func xmlConfidence(path string, peek []byte, want string) (float64, bool) {
	shape := xmlProbeShape(peek)
	if shape == "" || shape != want {
		return 0, false
	}
	conf := 0.85
	if ext(path) == "xml" {
		conf += 0.05
	}
	if conf > 0.95 {
		conf = 0.95
	}
	return conf, true
}

// xmlRecordTap retains a bounded, position-indexed window of the most recent
// source bytes so a record's verbatim text can be recovered for provenance.
//
// Why a ring window: xml.Decoder (and any bufio in front of it) reads ahead,
// so capturing bytes only "while inside a record" misses everything already
// buffered. Instead every byte flowing toward the decoder passes through
// Write exactly once and is indexed by its absolute stream offset — which is
// exactly the offset space xml.Decoder.InputOffset reports. A record is then
// extracted as window [markFrom, end) where end is the dec.InputOffset()
// captured after DecodeElement consumed the record — exactly the record's
// verbatim bytes, independent of read-ahead granularity.
//
// Memory: buf never exceeds win bytes (effectiveMaxLine + MaxOriginalRecordBytes).
type xmlRecordTap struct {
	win      int    // retained window size in bytes
	buf      []byte // most recent bytes written, len <= win
	abs      int64  // total bytes ever written through the tap
	markFrom int64  // absolute offset where the current record starts; <0 = unmarked
}

func newXMLRecordTap(win int) *xmlRecordTap {
	if win < 0 {
		win = 0
	}
	return &xmlRecordTap{win: win, markFrom: -1}
}

func (t *xmlRecordTap) Write(p []byte) (int, error) {
	t.abs += int64(len(p))
	if t.win <= 0 {
		return len(p), nil
	}
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.win; over > 0 {
		// Slide off the oldest bytes; memmove-safe overlapping copy,
		// amortized O(1) per byte, bounded retention.
		l := len(t.buf) - over
		copy(t.buf, t.buf[over:])
		t.buf = t.buf[:l]
	}
	return len(p), nil
}

// mark records the absolute offset at which the current record element
// starts (the decoder position before its StartElement token was produced).
func (t *xmlRecordTap) mark(from int64) {
	t.markFrom = from
}

// raw returns the verbatim source bytes of the marked record, trimmed of
// surrounding whitespace and capped at MaxOriginalRecordBytes (first 4 KiB)
// like every other importer. The window is exactly [markFrom, end): callers
// MUST pass end = dec.InputOffset() captured immediately after DecodeElement
// succeeded — that offset is the first byte past the record's closing tag,
// so neither the decoder's read-ahead beyond the record nor a pre-decode
// position inside it can leak into OriginalRecord. It returns "" when no
// record is marked, end precedes the mark, or the record's start was evicted
// from the window (records larger than the window get no OriginalRecord
// rather than a dishonest mid-record slice).
func (t *xmlRecordTap) raw(end int64) string {
	if t.markFrom < 0 {
		return ""
	}
	if end > t.abs {
		end = t.abs // defensive: never read past what flowed through the tap
	}
	if end <= t.markFrom {
		return ""
	}
	ringStart := t.abs - int64(len(t.buf))
	if t.markFrom < ringStart {
		return ""
	}
	s := string(t.buf[t.markFrom-ringStart : end-ringStart])
	s = strings.TrimSpace(s)
	if len(s) > MaxOriginalRecordBytes {
		s = s[:MaxOriginalRecordBytes]
	}
	return s
}

// eofTrackingReader records whether the underlying input stream reached EOF.
// A decode error while the input is exhausted means the FILE was truncated;
// a decode error with input remaining means the XML was malformed. The two
// get different honest outcomes (truncation vs structured failure).
type eofTrackingReader struct {
	rc     io.ReadCloser
	sawEOF bool
}

func (e *eofTrackingReader) Read(p []byte) (int, error) {
	n, err := e.rc.Read(p)
	if err == io.EOF {
		e.sawEOF = true
	}
	return n, err
}

// streamXMLElements streams path through an xml.Decoder token loop (NO DOM),
// invoking handle once per matching record element. It is the shared helper
// for both XML importers, mirroring readLines/streamJSON responsibilities:
//
//   - bounded memory: bufio.Reader 8 KiB; per-record provenance retention via
//     xmlRecordTap's ring window (≤ effectiveMaxLine + MaxOriginalRecordBytes);
//     OriginalRecord capped at MaxOriginalRecordBytes (4 KiB); DecodeElement
//     decodes into small structs
//   - gzip transparent via openStream; total decompressed bytes tallied
//     exactly via dec.InputOffset() deltas and capped at
//     effectiveMaxDecompressed(), aborting with truncation instead of OOM
//     (gzip-bomb guard, same discipline as arrayFramer's cumulative Consumed)
//   - an already-cancelled ctx fails fast before any IO; ctx checked per record
//   - a record whose XML decoding fails at the encoding/xml level (&bogus;
//     entities, invalid UTF-8, broken nesting) poisons the decoder: its err
//     is sticky, so the import counts that record failed ONCE and then aborts
//     with a structured decode error naming the reason — remaining records
//     are NOT silently skipped. Purely semantic record failures (missing
//     fields, bad URLs) leave the decoder usable; those resync at the next
//     element boundary (stuck-decoder guard prevents infinite loops);
//   - decode errors are classified by shape: EOF-shaped (io.EOF,
//     io.ErrUnexpectedEOF, xml "unexpected EOF") with input exhausted →
//     honest truncation, never silent completed; any other error → structured
//     failure, surfaced contextually (including when input is exhausted but
//     the error is not EOF-shaped, e.g. malformed bytes at end of file)
//
// It returns processed, failed, truncated counters and an error (open/read
// failure or ctx cancellation; record-level failures are folded into failed).
func streamXMLElements(ctx context.Context, env ImportEnv, path string, recordNames map[string]bool, handle func(dec *xml.Decoder, start xml.StartElement, recIndex int, tap *xmlRecordTap) error) (processed, failed, truncated int, err error) {
	if cerr := checkCtx(ctx); cerr != nil {
		return 0, 0, 0, cerr // fail fast on an already-cancelled ctx, before IO
	}
	maxDecomp := env.Bounds.effectiveMaxDecompressed()
	base := filepath.Base(path)
	rc, err := openStream(path)
	if err != nil {
		return 0, 0, 0, newImportError(base, path, "open", err)
	}
	defer rc.Close()
	src := &eofTrackingReader{rc: rc}

	br := bufio.NewReaderSize(src, 8192)
	progress := newProgressEmitter(env.Observer, env.now, "import")
	tap := newXMLRecordTap(env.Bounds.effectiveMaxLine() + MaxOriginalRecordBytes)
	dec := xml.NewDecoder(io.TeeReader(br, tap))

	var (
		bytesTallied int64 // decompressed bytes already applied toward maxDecomp
		recIndex     int
		lastOffset   int64 // decoder position after last completed record
		preTokenOff  int64 // decoder position before the current Token call
		lastRecErr   error // error object already folded into failed by handle
	)
	for {
		if cerr := checkCtx(ctx); cerr != nil {
			progress.flush()
			return processed, failed, truncated, cerr
		}
		preTokenOff = dec.InputOffset()
		tok, terr := dec.Token()
		// Exact cumulative decompressed tally: every byte the decoder pulled
		// through the TeeReader counts toward MaxDecompressedBytes — record
		// bodies AND inter-record framing — so padding between records cannot
		// evade the cap (arrayFramer Consumed parity).
		//
		// Known bound (accepted, documented): the cap is applied BETWEEN
		// tokens. One huge CharData token streams through the decoder's
		// internal buffer before it is ever tallied, so peak transient memory
		// for that single token is bounded only by decoder buffering plus this
		// tap window (≤ 8 KiB bufio + effectiveMaxLine + MaxOriginalRecordBytes),
		// not by maxDecomp. The cumulative tally itself stays exact; nothing
		// escapes the cap in aggregate.
		if delta := dec.InputOffset() - bytesTallied; delta > 0 {
			bytesTallied += delta
			progress.add(int(delta))
			if bytesTallied > int64(maxDecomp) {
				truncated++
				progress.flush()
				return processed, failed, truncated, nil
			}
		}
		switch {
		case terr == io.EOF:
			progress.flush()
			return processed, failed, truncated, nil
		case terr != nil:
			eofShaped := errors.Is(terr, io.EOF) || errors.Is(terr, io.ErrUnexpectedEOF) || isXMLUnexpectedEOFSyntaxErr(terr)
			if src.sawEOF && eofShaped {
				// Input exhausted mid-structure (cut in a prolog or between
				// elements): honest truncation, not a parse failure.
				truncated++
				progress.flush()
				return processed, failed, truncated, nil
			}
			if lastRecErr != nil && errors.Is(terr, lastRecErr) {
				// encoding/xml Decoder.err is sticky: this is the SAME
				// record-level decode failure already folded into failed
				// below — abort honestly with a structured error naming the
				// reason instead of double-counting and skipping every
				// remaining valid record.
				progress.flush()
				return processed, failed, truncated, newImportError(base, path, "decode",
					fmt.Errorf("record #%d is not XML-decodable and encoding/xml cannot resync (sticky decoder error): %w", recIndex, terr))
			}
			if src.sawEOF {
				// Input fully read but the error is not EOF-shaped: real
				// malformed bytes at the end of an otherwise complete file.
				// Structured failure surfaced with that context rather than
				// misreported as truncation.
				failed++
				progress.flush()
				return processed, failed, truncated, newImportError(base, path, "decode",
					fmt.Errorf("malformed XML after %d input bytes (input fully read): %w", bytesTallied, terr))
			}
			// Malformed XML framing with input remaining: honest structured
			// failure.
			failed++
			progress.flush()
			return processed, failed, truncated, newImportError(base, path, "decode", terr)
		}
		start, ok := tok.(xml.StartElement)
		if !ok || !recordNames[start.Name.Local] {
			continue // prolog, site/container wrappers, chardata, end elements
		}
		recIndex++
		tap.mark(preTokenOff)
		rerr := handle(dec, start, recIndex, tap)
		switch {
		case rerr == nil:
			processed++
			lastRecErr = nil
			lastOffset = dec.InputOffset()
		case isCtxErr(rerr, ctx):
			progress.flush()
			return processed, failed, truncated, ctx.Err()
		case errors.Is(rerr, errOutputTruncated):
			// MaxOutput cap reached: honest tail-drop with sticky flag.
			truncated++
			progress.flush()
			return processed, failed, truncated, nil
		case errors.Is(rerr, errDuplicate):
			// Duplicate: neither processed nor failed (readLines parity).
			lastRecErr = nil
			lastOffset = dec.InputOffset()
		default:
			lastRecErr = rerr
			if src.sawEOF && (errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) || isXMLUnexpectedEOFSyntaxErr(rerr)) {
				// The input ended while this record was still being read:
				// the file is truncated mid-record. Honest truncation (§0.6) —
				// the partial record is neither processed nor counted as a
				// parse failure, and the import stops at the real end of
				// input instead of pretending completion.
				truncated++
				progress.flush()
				return processed, failed, truncated, nil
			}
			failed++
			// Stuck-decoder guard: DecodeElement does not guarantee a usable
			// decoder after an unmarshal error. If the position did not
			// advance past the failed element, consume tokens until its
			// depth closes (bounded) so the loop cannot spin on it forever.
			if dec.InputOffset() <= lastOffset {
				skipXMLElement(dec)
			}
			lastOffset = dec.InputOffset()
		}
	}
}

// isXMLUnexpectedEOFSyntaxErr reports whether err is the encoding/xml syntax
// error raised when the document ends inside an unfinished token ("unexpected
// EOF"). encoding/xml wraps it as xml.SyntaxError without unwrapping io.EOF,
// so errors.Is cannot see it; match on the documented message instead,
// scoped tightly to keep false positives impossible for ordinary syntax bugs.
func isXMLUnexpectedEOFSyntaxErr(err error) bool {
	se, ok := err.(*xml.SyntaxError)
	return ok && se.Msg == "unexpected EOF"
}

// skipXMLElement consumes tokens until the currently-open element subtree
// closes, bounding work by token count so a pathological document cannot spin
// unbounded. Called only after a record-level failure left the decoder inside
// (or before) the broken element. A decoder error ends the skip; the main
// loop reports it on the next Token call.
func skipXMLElement(dec *xml.Decoder) {
	for depth, i := 1, 0; i < 100000 && depth > 0; i++ {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		}
	}
}

// sanitizeASCIILabel keeps only printable ASCII characters (the asset layer's
// finding-label contract), stops at max bytes, and trims the remainder.
// Non-printable and multibyte UTF-8 bytes are dropped rather than rejected so
// hostile or exotic tool output cannot fail the whole record.
func sanitizeASCIILabel(s string, max int) string {
	var b strings.Builder
	s = strings.TrimSpace(s)
	for i := 0; i < len(s) && b.Len() < max; i++ {
		if s[i] >= 0x20 && s[i] <= 0x7e {
			b.WriteByte(s[i])
		}
	}
	return strings.TrimSpace(b.String())
}

// finishXMLStats folds streamXMLElements results into ImportStats with the
// same honest-outcome rules as the JSON importers: cancellation and open/read
// errors surface their error with partial stats; any truncation sets
// Truncated plus the "import_truncated" sticky flag; normalizeSticky drops
// empty flag maps.
func finishXMLStats(processed, failed, truncated int, err error, out *Sink) (ImportStats, error) {
	stats := ImportStats{
		ItemsProcessed: processed,
		ItemsFailed:    failed,
		StickyFlags:    make(map[string]bool),
	}
	if truncated > 0 || out.truncated {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	stats.StickyFlags = normalizeSticky(stats.StickyFlags)
	return stats, err
}
