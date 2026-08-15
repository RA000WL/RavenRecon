package techintel

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// containsFold reports whether s contains substr using the standard
// case-insensitive substring semantics of the analyzer (both sides are
// already lowercased by the caller; this wrapper exists so the matching
// primitives live in one place).
func containsFold(s, substr string) bool {
	return strings.Contains(s, substr)
}

// indexFold returns the byte index of substr in s, or -1 when absent. It is
// the index twin of containsFold (callers lowercase both sides).
func indexFold(s, substr string) int {
	return strings.Index(s, substr)
}

// foldByteLen returns how many bytes strings.ToLower emits for one decoded
// unit of the input: application of unicode.ToLower writes exactly
// RuneLen(ToLower(r)) bytes for every unit, including RuneError from an
// invalid byte (strings.ToLower replaces invalid input with U+FFFD, three
// bytes). Simple case folding can shrink a unit ("İ" 2 bytes folds to 1,
// "ẞ" 3 bytes folds to 2), which is precisely why folded byte offsets are
// not original byte offsets.
func foldByteLen(r rune) int {
	return utf8.RuneLen(unicode.ToLower(r))
}

// originalSpan maps a byte range of the FOLDED body (the bodyLower copy,
// exactly as strings.ToLower produced it) back to the byte span of the
// ORIGINAL body. Matching happens on the folded copy (case-insensitive),
// but evidence values must come from the ORIGINAL body: simple case
// folding changes byte lengths per rune, so a folded byte offset is not an
// original byte offset (indexing the original at the folded index tears
// multi-byte runes and corrupts evidence values).
//
// The walk is linear in the body length (one pass up to the end of the
// span, worst case the whole body) and allocation-free (runes are decoded
// in place; folded lengths are computed, never materialized). Per-rune
// folded lengths sum to exactly len(bodyLower) in the same iteration order
// (foldByteLen mirrors strings.ToLower byte-for-byte), so the fold cursor
// never drifts. A range boundary that falls inside a rune's folded
// expansion is clamped to the rune boundary: the whole original rune is
// the smallest honest unit the evidence value can carry.
func originalSpan(body string, foldedStart, foldedLen int) (int, int) {
	if foldedLen <= 0 {
		return foldedStart, foldedStart
	}
	endFold := foldedStart + foldedLen

	// Phase 1: consume runes until the fold cursor reaches foldedStart.
	// start is the original offset of the rune whose folded expansion
	// contains foldedStart (boundary-aligned when the cursor lands exactly
	// on a rune boundary); orig/fold are the offsets AFTER that rune.
	start := 0
	orig := 0
	fold := 0
	for orig < len(body) {
		r, sz := utf8.DecodeRuneInString(body[orig:])
		fl := foldByteLen(r)
		orig += sz
		fold += fl
		if fold >= foldedStart {
			if fold == foldedStart {
				start = orig
			} else {
				start = orig - sz
			}
			break
		}
	}

	// Phase 2: consume every further rune whose folded expansion intersects
	// the span. end starts after the rune consumed in phase 1 (its expansion
	// always intersects the span, so it is part of the evidence value) and
	// grows with each rune fully consumed; a span end inside a rune's
	// expansion clamps to the whole rune.
	end := orig
	for orig < len(body) && fold < endFold {
		r, sz := utf8.DecodeRuneInString(body[orig:])
		fl := foldByteLen(r)
		orig += sz
		fold += fl
		end = orig
	}
	if end > len(body) {
		end = len(body)
	}
	return start, end
}
