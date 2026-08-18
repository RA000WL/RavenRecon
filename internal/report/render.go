package report

import (
	"strconv"
	"strings"
	"time"
)

// Milliseconds is a duration that marshals to JSON as an integer
// millisecond count (the exports' human-scale time unit).
type Milliseconds int64

// MarshalJSON renders the count as a bare integer.
func (d Milliseconds) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(d), 10)), nil
}

// Ms converts a duration to milliseconds.
func Ms(d time.Duration) Milliseconds { return Milliseconds(d.Milliseconds()) }

// String renders the count with an "ms" suffix.
func (d Milliseconds) String() string { return strconv.FormatInt(int64(d), 10) + "ms" }

// formatDuration humanizes a millisecond count for the text reports
// (for example "1.24s", "2m30s", "1h5m").
func formatDuration(ms Milliseconds) string {
	switch v := int64(ms); {
	case v < 0:
		return "unknown"
	case v == 0:
		return "0ms"
	case v < 1000:
		return strconv.FormatInt(v, 10) + "ms"
	case v < 60_000:
		return strconv.FormatFloat(float64(v)/1000, 'f', 2, 64) + "s"
	case v < 3_600_000:
		m := v / 60_000
		s := (v % 60_000) / 1000
		return strconv.FormatInt(m, 10) + "m" + strconv.FormatInt(s, 10) + "s"
	default:
		h := v / 3_600_000
		m := (v % 3_600_000) / 60_000
		return strconv.FormatInt(h, 10) + "h" + strconv.FormatInt(m, 10) + "m"
	}
}

// formatTime renders a model timestamp for the text reports; the zero time
// renders as "-" (unknown).
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// formatScore renders a score in [0,1] with four decimals (the priority
// engine's rounding).
func formatScore(v float64) string {
	return strconv.FormatFloat(v, 'f', 4, 64)
}

// csvSafe neutralizes spreadsheet formula injection (OWASP CSV injection):
// a field whose first character is "=", "+", "-", "@", a tab, or a carriage
// return is prefixed with a single quote, so spreadsheet applications
// interpret it as text rather than a formula. The JSON export carries the
// exact bytes — this defense applies to the CSV presentation only.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// csvRow applies csvSafe to every field of a row.
func csvRow(row []string) []string {
	out := make([]string, len(row))
	for i, f := range row {
		out[i] = csvSafe(f)
	}
	return out
}

// mdEscape makes a cell safe for a Markdown table: backslashes are doubled
// FIRST, then pipes are escaped, and newlines collapse to spaces. The
// order is the standard one and it is load-bearing: escaping only the pipe
// would turn a literal backslash-pipe cell value ("f\|g") into "f\\|g",
// which GFM parses as an escaped backslash followed by a LIVE cell
// delimiter — a silent cell split. With backslashes doubled first, every
// emitted "\|" carries an odd backslash run (2N doubled content
// backslashes plus the escape's own), and GFM reads an odd run as "the
// last backslash escapes the pipe" — the cell boundary stays intact.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// conf renders a provenance confidence for text tables (blank when the
// observation carried none).
func conf(v float64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}
