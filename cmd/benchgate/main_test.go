package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Unit tests for the benchgate parser and comparator logic (NEW-56 D4).

func TestStripCPUSuffix(t *testing.T) {
	cases := map[string]string{
		"BenchmarkFoo-8":     "BenchmarkFoo",
		"BenchmarkFoo-128":   "BenchmarkFoo",
		"BenchmarkFoo":       "BenchmarkFoo",
		"BenchmarkFoo/sub-4": "BenchmarkFoo/sub", // sub-benchmarks keep their path
		"BenchmarkFoo-Bar":   "BenchmarkFoo-Bar", // non-numeric suffix is a name
	}
	for in, want := range cases {
		if got := stripCPUSuffix(in); got != want {
			t.Errorf("stripCPUSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseBenchOutput(t *testing.T) {
	in := strings.Join([]string{
		"goos: linux",
		"pkg: github.com/RA000WL/RavenRecon/internal/event",
		"BenchmarkValidate-8   \t1000000\t  1234.5 ns/op\t      56 B/op\t       2 allocs/op",
		"BenchmarkBusPublishFanout/sub-8\t  \t500\t  999 ns/op\t  10 B/op\t  1 allocs/op",
		"BenchmarkSetBytes-8\t100\t  200 ns/op\t  300 B/op\t  4 allocs/op\t 1234.5 MB/s",
		"BenchmarkNoMem-8\t100\t  200 ns/op",
		"ok  \tgithub.com/RA000WL/RavenRecon/internal/event\t1.234s",
		"", // blank noise
	}, "\n")
	res, err := parseBenchOutput(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseBenchOutput: %v", err)
	}
	if len(res) != 4 {
		t.Fatalf("parsed %d benchmarks, want 4", len(res))
	}
	v := res["BenchmarkValidate"]
	if len(v) != 1 || v[0].nsOp != 1234.5 || v[0].bOp != 56 || v[0].allocs != 2 {
		t.Fatalf("BenchmarkValidate = %+v", v)
	}
	sub := res["BenchmarkBusPublishFanout/sub"]
	if len(sub) != 1 || sub[0].allocs != 1 {
		t.Fatalf("sub-benchmark = %+v", sub)
	}
	sb := res["BenchmarkSetBytes"]
	if len(sb) != 1 || !sb[0].hasBOp || sb[0].bOp != 300 {
		t.Fatalf("SetBytes sample = %+v (extra MB/s metric must not break parsing)", sb)
	}
	nm := res["BenchmarkNoMem"]
	if len(nm) != 1 || nm[0].hasBOp || nm[0].hasAllo {
		t.Fatalf("NoMem sample = %+v (absent -benchmem metrics must parse)", nm)
	}
}

func TestParseBenchOutputBadCount(t *testing.T) {
	in := "BenchmarkFoo\tnotanumber\t100 ns/op\n"
	if _, err := parseBenchOutput(strings.NewReader(in)); err == nil {
		t.Fatal("want error for non-numeric iteration count")
	}
}

func TestMedian(t *testing.T) {
	if got := median([]float64{3, 1, 2}); got != 2 {
		t.Fatalf("median odd = %v, want 2", got)
	}
	if got := median([]float64{4, 1, 2, 3}); got != 2.5 {
		t.Fatalf("median even = %v, want 2.5", got)
	}
}

// runGate is a helper executing run() over two synthetic bench outputs.
func runGate(t *testing.T, base, new string) string {
	t.Helper()
	var out strings.Builder
	code := run([]string{"-threshold", "0.25", base, new}, &out, &strings.Builder{})
	return fmt.Sprintf("%d|%s", code, out.String())
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/b.txt"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

const benchLine = "BenchmarkFoo-8\t100\t%v ns/op\t%v B/op\t%v allocs/op\n"

func TestGatePassAndAdvisoryNsOnly(t *testing.T) {
	// ns/op doubles but B/op and allocs/op are flat: must PASS.
	base := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 10))
	new := writeTemp(t, fmt.Sprintf(benchLine, 200, 1050, 11))
	out := runGate(t, base, new)
	if !strings.HasPrefix(out, "0|") {
		t.Fatalf("ns/op regression alone must never fail; got %s", out)
	}
}

func TestGateFailOnBOp(t *testing.T) {
	base := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 10))
	new := writeTemp(t, fmt.Sprintf(benchLine, 100, 1300, 10)) // +30% B/op
	out := runGate(t, base, new)
	if !strings.HasPrefix(out, "1|") || !strings.Contains(out, "FAIL (B/op)") {
		t.Fatalf("+30%% B/op must fail with exit 1; got %s", out)
	}
}

func TestGateFailOnAllocs(t *testing.T) {
	base := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 10))
	new := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 14)) // +40% allocs
	out := runGate(t, base, new)
	if !strings.HasPrefix(out, "1|") || !strings.Contains(out, "FAIL (allocs/op)") {
		t.Fatalf("+40%% allocs/op must fail with exit 1; got %s", out)
	}
}

func TestGateWithinThresholdPasses(t *testing.T) {
	base := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 10))
	new := writeTemp(t, fmt.Sprintf(benchLine, 100, 1249, 12)) // just under +25%
	out := runGate(t, base, new)
	if !strings.HasPrefix(out, "0|") {
		t.Fatalf("within-threshold change must pass; got %s", out)
	}
}

func TestGateExactThresholdBoundary(t *testing.T) {
	base := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 10))
	// Exactly +25% (1000 -> 1250 B/op): the gate is STRICTLY greater
	// than the threshold, so this must PASS.
	exact := writeTemp(t, fmt.Sprintf(benchLine, 100, 1250, 10))
	if out := runGate(t, base, exact); !strings.HasPrefix(out, "0|") {
		t.Fatalf("exactly-at-threshold (+25%%) must pass (strict >); got %s", out)
	}
	// One unit over (+25.1%): must FAIL.
	over := writeTemp(t, fmt.Sprintf(benchLine, 100, 1251, 10))
	if out := runGate(t, base, over); !strings.HasPrefix(out, "1|") || !strings.Contains(out, "FAIL (B/op)") {
		t.Fatalf("1251 B/op vs 1000 baseline (>25%%) must fail; got %s", out)
	}
}

func TestParseBenchOutputDanglingValueRejected(t *testing.T) {
	// Truncated final pair: a value with no unit must be a hard parse
	// error, not a silently dropped metric (which could zero B/op and
	// let a corrupted file pass the gate).
	in := "BenchmarkFoo-8\t100\t100 ns/op\t1000\n"
	if _, err := parseBenchOutput(strings.NewReader(in)); err == nil {
		t.Fatal("dangling trailing value without unit must be rejected")
	} else if !strings.Contains(err.Error(), "dangling") {
		t.Fatalf("error should mention the dangling value; got %v", err)
	}
	// The well-formed form of the same line still parses cleanly.
	ok := "BenchmarkFoo-8\t100\t100 ns/op\t1000 B/op\n"
	if _, err := parseBenchOutput(strings.NewReader(ok)); err != nil {
		t.Fatalf("well-formed line rejected: %v", err)
	}
}

func TestGateMissingInEitherSideNeverFails(t *testing.T) {
	base := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 10)+"BenchmarkGone-8\t100\t50 ns/op\t50 B/op\t5 allocs/op\n")
	new := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 10)+"BenchmarkAdded-8\t100\t50 ns/op\t50 B/op\t5 allocs/op\n")
	out := runGate(t, base, new)
	if !strings.HasPrefix(out, "0|") {
		t.Fatalf("missing/added benchmarks must never fail; got %s", out)
	}
	if !strings.Contains(out, "MISSING") || !strings.Contains(out, "NEW") {
		t.Fatalf("missing/new benchmarks must be reported; got %s", out)
	}
}

func TestGateZeroBaselineSkipsMetric(t *testing.T) {
	// Baseline without -benchmem: no B/op data → metric check skipped.
	base := writeTemp(t, "BenchmarkFoo-8\t100\t100 ns/op\n")
	new := writeTemp(t, fmt.Sprintf(benchLine, 100, 100000, 999))
	out := runGate(t, base, new)
	if !strings.HasPrefix(out, "0|") {
		t.Fatalf("zero baseline for a metric must skip that check; got %s", out)
	}
}

func TestGateNewSideWithoutBenchmemFails(t *testing.T) {
	// Regression: baseline recorded WITH -benchmem vs a new run WITHOUT
	// it. The new medians come back 0 and both hard-gate comparisons
	// are vacuously false — the gate must FAIL loudly instead of
	// exiting 0 with nothing verified.
	base := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 10))
	new := writeTemp(t, "BenchmarkFoo-8\t100\t100 ns/op\n")
	out := runGate(t, base, new)
	if !strings.HasPrefix(out, "1|") {
		t.Fatalf("new run lacking B/op+allocs data must fail the gate, not pass vacuously; got %s", out)
	}
	if !strings.Contains(out, "B/op and allocs/op missing from new run") {
		t.Fatalf("diagnostic must name every missing metric; got %s", out)
	}
	if !strings.Contains(out, "-benchmem") {
		t.Fatalf("diagnostic must name the likely cause (-benchmem); got %s", out)
	}
}

func TestGateNewSidePartialAllocsMissingFails(t *testing.T) {
	// A single new-side sample omitting allocs/op (no b.ReportAllocs)
	// while the baseline carries it: exactly that metric's gate fails,
	// naming the missing metric only.
	base := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 10))
	new := writeTemp(t, "BenchmarkFoo-8\t100\t100 ns/op\t1000 B/op\n")
	out := runGate(t, base, new)
	if !strings.HasPrefix(out, "1|") || !strings.Contains(out, "FAIL (allocs/op missing") {
		t.Fatalf("new sample lacking allocs/op must fail naming the metric; got %s", out)
	}
	if strings.Contains(out, "B/op missing") {
		t.Fatalf("B/op present on both sides must not be flagged missing; got %s", out)
	}
}

func TestGateNonFiniteThresholdRejected(t *testing.T) {
	// Regression: NaN (and ±Inf) made every comparison false,
	// guaranteeing a pass. Non-finite thresholds must be rejected as
	// usage errors like negative ones.
	path := writeTemp(t, fmt.Sprintf(benchLine, 100, 1000, 10))
	for _, th := range []string{"NaN", "Inf", "+Inf", "-Inf"} {
		var out, errOut strings.Builder
		code := run([]string{"-threshold", th, path, path}, &out, &errOut)
		if code != 2 {
			t.Errorf("-threshold %s: code = %d, want 2 (non-finite threshold must be rejected)", th, code)
		}
		if !strings.Contains(errOut.String(), "must be finite and non-negative") {
			t.Errorf("-threshold %s: stderr should explain the rejection; got %q", th, errOut.String())
		}
	}
}

func TestGateUsageErrors(t *testing.T) {
	var out, errOut strings.Builder
	if code := run([]string{}, &out, &errOut); code != 2 {
		t.Fatalf("no args: code = %d, want 2", code)
	}
	if code := run([]string{"a.txt"}, &out, &errOut); code != 2 {
		t.Fatalf("one arg: code = %d, want 2", code)
	}
	if code := run([]string{"/nonexistent/x", "/nonexistent/y"}, &out, &errOut); code != 2 {
		t.Fatalf("missing files: code = %d, want 2", code)
	}
}
