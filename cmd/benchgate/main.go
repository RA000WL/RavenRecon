// Command benchgate compares a committed performance baseline against a
// fresh `go test -bench` run and fails when memory-allocation metrics
// regress. Stdlib-only by design (locked decision D4 on TODO.md NEW-56 —
// no benchstat dependency).
//
// # Baseline format and location convention
//
//   - Files live at testdata/bench/<pkg>.txt (e.g.,
//     testdata/bench/jsintel.txt): one file per baselined package,
//     committed to the repository.
//
//   - Each file is the verbatim stdout of ONE recording session:
//
//     go test -bench=. -benchmem -count=10 ./internal/<pkg> \
//     > testdata/bench/<pkg>.txt
//
//     recorded once and committed unmodified, so benchgate parses exactly
//     what go test printed (no post-processing step to drift).
//
//   - Regenerate a baseline only when hardware changes or a deliberate,
//     reviewed optimization lands; state the reason and date in the PR.
//
// # Comparison semantics
//
// For every benchmark name present in BOTH files, benchgate compares the
// MEDIAN of each metric across the recorded samples (-count=10 gives ten):
//
//   - B/op and allocs/op: hard gates. Exit 1 when the new median exceeds
//     the baseline median by more than the threshold (default 25%).
//   - ns/op: advisory-only. Printed for context, NEVER affects the exit
//     code (timing noise is environment-dependent; allocation counts are
//     far more stable).
//
// A benchmark missing from either side is reported as MISSING and never
// fails the gate: adding or removing benchmarks is development, not
// regression. A baseline median of 0 for a metric (metric absent from the
// baseline run) skips that metric's check. The mirror case — the baseline
// records a metric but every sample of the new run lacks it (a new run
// recorded without -benchmem) — is NOT skipped: the gate would otherwise
// pass vacuously with nothing verified, so benchgate fails with an
// explicit diagnostic naming the missing metric and its likely cause.
//
// # Usage
//
//	benchgate [-threshold 0.25] <baseline.txt> <new.txt>
//
// Exit codes: 0 = pass, 1 = allocation regression (or new-run
// allocation data missing where the baseline has it), 2 = usage or I/O
// error.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

// sample holds the parsed per-run metrics of one benchmark execution.
type sample struct {
	nsOp    float64
	bOp     float64
	allocs  float64
	hasBOp  bool
	hasAllo bool
}

// results maps a benchmark name (cpu suffix stripped) to its samples.
type results map[string][]sample

// parseBenchOutput parses `go test -bench` output. Lines whose first
// whitespace-delimited field does not start with "Benchmark" are ignored
// (go test intermixes package banners, ok lines, and progress output).
// The trailing -NN cpu suffix on benchmark names is stripped so baselines
// and new runs compare by bare name even across GOMAXPROCS differences.
func parseBenchOutput(r io.Reader) (results, error) {
	res := results{}
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "Benchmark") {
			continue
		}
		if _, err := strconv.Atoi(fields[1]); err != nil {
			return nil, fmt.Errorf("line %d: bad iteration count %q", lineNo, fields[1])
		}
		name := stripCPUSuffix(fields[0])
		var s sample
		for i := 2; i+1 < len(fields); i += 2 {
			v, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad metric value %q", lineNo, fields[i])
			}
			switch fields[i+1] {
			case "ns/op":
				s.nsOp = v
			case "B/op":
				s.bOp, s.hasBOp = v, true
			case "allocs/op":
				s.allocs, s.hasAllo = v, true
			}
		}
		// A trailing value with no unit (truncated/corrupted line) would
		// otherwise be silently dropped, zeroing a metric and letting a
		// corrupted new-side file pass the gate. Reject the whole file.
		if last := 2 + 2*((len(fields)-2)/2); last < len(fields) {
			return nil, fmt.Errorf("line %d: dangling metric value %q without unit", lineNo, fields[last])
		}
		res[name] = append(res[name], s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read bench output: %w", err)
	}
	return res, nil
}

// stripCPUSuffix removes a trailing "-NN" (GOMAXPROCS) suffix.
func stripCPUSuffix(name string) string {
	if i := strings.LastIndex(name, "-"); i > 0 {
		if _, err := strconv.Atoi(name[i+1:]); err == nil {
			return name[:i]
		}
	}
	return name
}

// median returns the median of vs (average of the two middle values for
// even lengths). Returns 0 for empty input; callers normally guarantee
// non-empty, but the guard keeps a missing-side bug from panicking.
func median(vs []float64) float64 {
	if len(vs) == 0 {
		return 0
	}
	s := append([]float64(nil), vs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func medians(rs []sample) (ns, bOp, allocs float64, hasB, hasA bool) {
	nsV := make([]float64, 0, len(rs))
	bV := make([]float64, 0, len(rs))
	aV := make([]float64, 0, len(rs))
	for _, s := range rs {
		nsV = append(nsV, s.nsOp)
		if s.hasBOp {
			bV = append(bV, s.bOp)
		}
		if s.hasAllo {
			aV = append(aV, s.allocs)
		}
	}
	return median(nsV), safeMedian(bV), safeMedian(aV), len(bV) > 0, len(aV) > 0
}

func safeMedian(vs []float64) float64 {
	if len(vs) == 0 {
		return 0
	}
	return median(vs)
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("benchgate", flag.ContinueOnError)
	threshold := fs.Float64("threshold", 0.25, "failure threshold as a fraction over baseline (0.25 = 25%)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: benchgate [-threshold 0.25] <baseline.txt> <new.txt>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return 2
	}
	// NaN or ±Inf silently disable every comparison (all of them come
	// back false), so a non-finite threshold must be rejected outright,
	// exactly like a negative one.
	if *threshold < 0 || math.IsNaN(*threshold) || math.IsInf(*threshold, 0) {
		fmt.Fprintf(stderr, "benchgate: invalid -threshold %v: must be finite and non-negative\n", *threshold)
		fs.Usage()
		return 2
	}
	base, err := parseFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "benchgate: %v\n", err)
		return 2
	}
	new, err := parseFile(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(stderr, "benchgate: %v\n", err)
		return 2
	}

	names := make([]string, 0, len(base))
	for n := range base {
		names = append(names, n)
	}
	sort.Strings(names)

	failed := false
	fmt.Fprintf(stdout, "%-45s %14s %14s %12s %12s %s\n", "BENCHMARK", "B/op old", "B/op new", "ALLOCS old", "ALLOCS new", "RESULT")
	for _, n := range names {
		bb, nb := base[n], new[n]
		if len(nb) == 0 {
			// Present in the baseline but not the new run: reported,
			// never fatal (removing a benchmark is development, not
			// regression).
			fmt.Fprintf(stdout, "%-45s %14s %14s %12s %12s MISSING (not in new run; never fails)\n", n, "-", "-", "-", "-")
			continue
		}
		bns, bbOp, bAl, bHasB, bHasA := medians(bb)
		nns, nbOp, nAl, nHasB, nHasA := medians(nb)
		// A metric present in the BASELINE but absent from every sample
		// of the new run (e.g. recorded without -benchmem) zeroes the
		// new median and would make both hard-gate comparisons
		// vacuously false — a silent pass with no verification at all.
		// That must fail loudly instead.
		var missing []string
		if bHasB && !nHasB {
			missing = append(missing, "B/op")
		}
		if bHasA && !nHasA {
			missing = append(missing, "allocs/op")
		}
		status := "ok"
		if len(missing) > 0 {
			status = fmt.Sprintf("FAIL (%s missing from new run; new run recorded without -benchmem?)", strings.Join(missing, " and "))
			failed = true
		}
		if bHasB && bbOp > 0 && nbOp > bbOp*(1+*threshold) {
			status = "FAIL (B/op)"
			failed = true
		}
		if bHasA && bAl > 0 && nAl > bAl*(1+*threshold) {
			status = "FAIL (allocs/op)"
			failed = true
		}
		fmt.Fprintf(stdout, "%-45s %14.0f %14.0f %12.0f %12.0f %s (ns/op %.0f -> %.0f, advisory)\n",
			n, bbOp, nbOp, bAl, nAl, status, bns, nns)
	}
	// Names only in the new run: additions are reported, never fatal.
	added := make([]string, 0)
	for n := range new {
		if _, ok := base[n]; !ok {
			added = append(added, n)
		}
	}
	sort.Strings(added)
	for _, n := range added {
		fmt.Fprintf(stdout, "%-45s %14s %14s %12s %12s NEW (no baseline; never fails)\n", n, "-", "-", "-", "-")
	}
	if failed {
		fmt.Fprintf(stdout, "FAIL: allocation regression above %.0f%% threshold\n", *threshold*100)
		return 1
	}
	fmt.Fprintf(stdout, "PASS: no allocation regression above %.0f%% threshold\n", *threshold*100)
	return 0
}

func parseFile(path string) (results, error) {
	f, err := os.Open(path) //nolint:gosec — path comes from the CLI argv by contract
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	res, err := parseBenchOutput(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("parse %s: no benchmark lines found", path)
	}
	return res, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
