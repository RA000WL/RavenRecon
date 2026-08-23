package golden

import (
	"fmt"
	"strings"
)

// Diff returns a compact unified-style line diff (LCS-based, at most three
// context lines around every change, unchanged runs collapsed with a
// marker, output byte-capped). The golden documents are small; the cell cap
// bounds memory on pathological inputs.
func Diff(oldText, newText string) string {
	oldLines := splitLines(oldText)
	newLines := splitLines(newText)

	const maxCells = 4_000_000
	if len(oldLines)*len(newLines) > maxCells {
		return cappedFallback(oldText, newText)
	}

	lcs := make([][]int, len(oldLines)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(newLines)+1)
	}
	for i := len(oldLines) - 1; i >= 0; i-- {
		for j := len(newLines) - 1; j >= 0; j-- {
			switch {
			case oldLines[i] == newLines[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	type op struct {
		kind byte // '=', '-', '+'
		line string
	}
	var ops []op
	i, j := 0, 0
	for i < len(oldLines) && j < len(newLines) {
		if oldLines[i] == newLines[j] {
			ops = append(ops, op{'=', oldLines[i]})
			i++
			j++
			continue
		}
		if lcs[i+1][j] >= lcs[i][j+1] {
			ops = append(ops, op{'-', oldLines[i]})
			i++
		} else {
			ops = append(ops, op{'+', newLines[j]})
			j++
		}
	}
	for ; i < len(oldLines); i++ {
		ops = append(ops, op{'-', oldLines[i]})
	}
	for ; j < len(newLines); j++ {
		ops = append(ops, op{'+', newLines[j]})
	}

	// Collapse unchanged runs: keep at most 2*context+1 context lines around
	// the changes; longer runs become a marker with ctx lines either side.
	const ctx = 3
	var b strings.Builder
	var run []string
	flush := func() {
		if len(run) == 0 {
			return
		}
		if len(run) > 2*ctx+1 {
			for _, l := range run[:ctx] {
				b.WriteString("  " + l + "\n")
			}
			fmt.Fprintf(&b, "… (%d unchanged lines)\n", len(run)-2*ctx)
			for _, l := range run[len(run)-ctx:] {
				b.WriteString("  " + l + "\n")
			}
		} else {
			for _, l := range run {
				b.WriteString("  " + l + "\n")
			}
		}
		run = run[:0]
	}
	const maxOut = 8 << 10
	for _, o := range ops {
		if o.kind == '=' {
			run = append(run, o.line)
			continue
		}
		flush()
		if o.kind == '-' {
			b.WriteString("- " + o.line + "\n")
		} else {
			b.WriteString("+ " + o.line + "\n")
		}
		if b.Len() >= maxOut {
			b.WriteString("… (diff truncated)\n")
			return b.String()
		}
	}
	flush()
	return b.String()
}

// splitLines splits a document into lines, dropping the single trailing
// empty element a final newline produces.
func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// cappedFallback renders the oversized-input path: the LCS would exceed its
// cell cap, so Diff falls back to a labeled dump of both documents. The dump
// is byte-capped like every other Diff output path — each side gets half of
// the same 8 KiB budget the LCS renderer enforces, so the fallback can never
// be the one unbounded return.
func cappedFallback(oldText, newText string) string {
	const fallbackCap = 8 << 10
	var b strings.Builder
	b.WriteString("old:\n")
	writeCapped(&b, oldText, fallbackCap/2)
	b.WriteString("new:\n")
	writeCapped(&b, newText, fallbackCap/2)
	return b.String()
}

// writeCapped appends s to b, truncating at limit bytes with the same
// truncation marker the LCS path emits.
func writeCapped(b *strings.Builder, s string, limit int) {
	if len(s) <= limit {
		b.WriteString(s)
		return
	}
	b.WriteString(s[:limit])
	b.WriteString("\n… (diff truncated)\n")
}
