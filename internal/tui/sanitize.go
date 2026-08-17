package tui

import (
	"strings"
	"unicode/utf8"
)

// maxEscapeScan bounds how many bytes one ESC-prefixed sequence (CSI or
// OSC) may consume before the scan is cut. A hostile or corrupted stream
// can therefore never drive an unbounded scan; input beyond the cap is
// processed as ordinary text (the sequence is "truncated-stripped": the
// scanned prefix is removed, everything after it is re-processed normally).
// Event labels and messages are bounded to 512 bytes by the event model, so
// the cap only matters for callers that sanitize larger strings directly.
const maxEscapeScan = 4096

// Sanitize strips terminal-corruption and escape-sequence vectors from s so
// the rendered output can never move the cursor, change the terminal state,
// or smuggle control text into the frame. Every dynamic string that reaches
// a frame passes through Sanitize at ingestion (State.Apply), so the frame
// builder itself only ever sees clean text.
//
// What is stripped:
//
//   - ESC (U+001B) and its sequence: CSI ("ESC [ ..." up to the final byte
//     0x40–0x7E), OSC ("ESC ] ..." up to BEL 0x07 or ST "ESC \"), two-byte
//     escapes ("ESC X"), and a lone ESC. An unterminated sequence is
//     stripped through maxEscapeScan.
//   - C0 control bytes except TAB, LF, CR (0x00–0x08, 0x0B, 0x0C,
//     0x0E–0x1F) and DEL (0x7F).
//   - C1 controls (U+0080–U+009F, in their valid UTF-8 form), including the
//     C1 CSI/OSC codepoints (0x9B, 0x9D).
//   - Invalid UTF-8 bytes (including lone 0x80–0x9F bytes in
//     Latin-1-style input).
//
// What is preserved: TAB, LF, CR, printable ASCII, and all valid non-C1
// Unicode (é, €, ✓, CJK, ...) — sanitizing never corrupts legitimate
// non-ASCII text.
//
// Sanitize is deterministic and allocation-free on already-clean input
// (a byte scan decides; the common case is a single pass with no copy).
func Sanitize(s string) string {
	if !needsSanitizing(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Invalid byte: strip (covers lone C1-range bytes).
			i++
		case r == '\x1b':
			i += scanEscape(s[i:])
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteRune(r)
			i += size
		case r < 0x20 || r == 0x7f:
			// Other C0 controls and DEL.
			i += size
		case r >= 0x80 && r <= 0x9f:
			// C1 controls.
			i += size
		default:
			b.WriteRune(r)
			i += size
		}
	}
	return b.String()
}

// needsSanitizing reports whether s contains anything Sanitize would
// strip: ESC sequences, C0 controls (except TAB/LF/CR), DEL, C1 controls,
// or invalid UTF-8. It is the fast path: clean input (the overwhelmingly
// common case for well-behaved emitters — ASCII or valid non-C1 Unicode)
// is scanned in one allocation-free decode pass and returned untouched.
// The predicate mirrors the slow path exactly: anything it misses would
// pass through Sanitize unsanitized.
func needsSanitizing(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Invalid byte (overlong, surrogate, out-of-range, torn
			// sequence, or lone continuation).
			return true
		case r == '\x1b':
			return true
		case r == '\t' || r == '\n' || r == '\r':
			// Preserved by Sanitize.
		case r < 0x20 || r == 0x7f:
			// Other C0 controls and DEL.
			return true
		case r >= 0x80 && r <= 0x9f:
			// C1 controls (in their valid UTF-8 form).
			return true
		}
		i += size
	}
	return false
}

// scanEscape consumes one ESC-prefixed sequence starting at s[0] == ESC and
// returns the number of bytes it occupies (at least 1). The sequence is
// removed entirely; nothing inside it survives.
func scanEscape(s string) int {
	if len(s) == 1 {
		return 1 // lone ESC
	}
	switch s[1] {
	case '[':
		// CSI: ESC [ params (0x30–0x3F)* intermediates (0x20–0x2F)* final
		// (0x40–0x7E). The first final byte terminates the sequence.
		n := 2
		for n < len(s) && n < maxEscapeScan {
			if c := s[n]; c >= 0x40 && c <= 0x7e {
				return n + 1
			}
			n++
		}
		if n >= len(s) {
			return len(s) // unterminated: strip everything scanned
		}
		return maxEscapeScan // cut: strip the scanned prefix
	case ']':
		// OSC: ESC ] ... terminated by BEL or ST (ESC \).
		n := 2
		for n < len(s) && n < maxEscapeScan {
			switch c := s[n]; {
			case c == 0x07:
				return n + 1
			case c == 0x1b && n+1 < len(s) && s[n+1] == '\\':
				return n + 2
			}
			n++
		}
		if n >= len(s) {
			return len(s)
		}
		return maxEscapeScan
	default:
		// Two-byte escape ("ESC X") — consume both bytes. This covers the
		// legacy C1 7-bit forms (ESC D, ESC E, ESC H, ESC M, ESC N, ESC O,
		// ESC P, ESC V, ESC W, ESC X, ESC Z, ESC [ is handled above, ESC \,
		// ESC ], ESC ^, ESC _) and any other ESC-prefixed pair.
		return 2
	}
}
