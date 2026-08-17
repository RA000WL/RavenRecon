package tui

import (
	"strings"
	"testing"
)

func TestSanitizePreservesCleanText(t *testing.T) {
	clean := "ravenrecon — example.com · é € ✓ 日本語 \t\n\r"
	if got := Sanitize(clean); got != clean {
		t.Fatalf("clean text must pass through untouched, got %q", got)
	}
}

func TestSanitizeStripsESCSequences(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"csi", "a\x1b[31mred", "ared"},
		{"csi with params and intermediates", "a\x1b[1;2;3;4;31mred", "ared"},
		{"osc bel", "a\x1b]0;title\x07b", "ab"},
		{"osc st", "a\x1b]0;title\x1b\\b", "ab"},
		{"two-byte", "a\x1bDb", "ab"},
		{"two-byte c1 form", "a\x1bMb", "ab"},
		{"two-byte consumes next byte", "a\x1bb", "a"},
		{"lone esc", "a\x1b", "a"},
		{"esc at start", "\x1b[1mlead", "lead"},
		{"esc at end", "tail\x1b[31m", "tail"},
		{"unterminated csi", "a\x1b[31", "a"},
		{"unterminated osc", "a\x1b]0;title", "a"},
		{"multiple", "a\x1b[31m\x1b]2;x\x07b", "ab"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sanitize(tc.in); got != tc.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeStripsC0ControlsAndDEL(t *testing.T) {
	for _, b := range []byte{0x00, 0x01, 0x02, 0x07, 0x08, 0x0b, 0x0c, 0x0e, 0x0f, 0x1f, 0x7f} {
		if got := Sanitize("a" + string(b) + "b"); got != "ab" {
			t.Fatalf("control byte 0x%02x must be stripped, got %q", b, got)
		}
	}
	// TAB, LF, CR are preserved.
	for _, b := range []byte{0x09, 0x0a, 0x0d} {
		in := "a" + string(b) + "b"
		if got := Sanitize(in); got != in {
			t.Fatalf("byte 0x%02x must be preserved, got %q", b, got)
		}
	}
}

func TestSanitizeStripsC1Controls(t *testing.T) {
	// C1 range in valid UTF-8 (U+0080..U+009F).
	for _, r := range []rune{0x80, 0x85, 0x90, 0x9b, 0x9d, 0x9f} {
		in := "a" + string(r) + "b"
		if got := Sanitize(in); got != "ab" {
			t.Fatalf("C1 control U+%04X must be stripped, got %q", r, got)
		}
	}
}

func TestSanitizeStripsInvalidUTF8(t *testing.T) {
	if got := Sanitize("a\xffb"); got != "ab" {
		t.Fatalf("invalid byte must be stripped, got %q", got)
	}
	if got := Sanitize("a\x80b"); got != "ab" {
		t.Fatalf("lone continuation byte must be stripped, got %q", got)
	}
	if got := Sanitize("a\xc3b"); got != "ab" {
		t.Fatalf("torn multibyte must be stripped, got %q", got)
	}
}

func TestSanitizeIsIdempotent(t *testing.T) {
	hostile := "a\x1b[31m\x00\xc2\x9db\xffc\x7fd"
	once := Sanitize(hostile)
	twice := Sanitize(once)
	if once != twice {
		t.Fatalf("Sanitize must be idempotent: %q vs %q", once, twice)
	}
}

func TestSanitizeEscapeScanCap(t *testing.T) {
	// A 5000-byte CSI parameter run cannot drive an unbounded scan: the
	// sequence is cut at maxEscapeScan and the tail is re-processed as
	// ordinary text. ESC '[' plus 5000 parameter bytes span 5002 bytes;
	// the scan consumes 4096 of them and the remaining 906 zeros plus the
	// tail pass through as ordinary text.
	in := "a\x1b[" + strings.Repeat("0", 5000) + "tail"
	got := Sanitize(in)
	want := "a" + strings.Repeat("0", 5002-maxEscapeScan) + "tail"
	if got != want {
		t.Fatalf("escape scan must be cut at %d, got len %d (want %d)", maxEscapeScan, len(got), len(want))
	}
}

func TestSanitizePreservesPrintableANSIWithinBounds(t *testing.T) {
	// Printable ASCII (including the CSI final-byte range) passes through.
	if got := Sanitize("abcXYZ@[\\]^_`{}~"); got != "abcXYZ@[\\]^_`{}~" {
		t.Fatalf("printable ASCII must pass through, got %q", got)
	}
}
