package discovery

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestExtractVersion(t *testing.T) {
	cases := map[string]string{
		"Current Version: v2.6.3\n":   "v2.6.3",
		"subfinder v2.8.3\n":          "v2.8.3",
		"v3.23.0\n":                   "v3.23.0",
		"Version 1.2.3":               "1.2.3",
		"amass v3.22.1\nLicensing":    "v3.22.1",
		"garbage\nno versions here\n": "",
		"":                            "",
	}
	for in, want := range cases {
		if got := extractVersion([]byte(in)); got != want {
			t.Errorf("extractVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// detectEnv builds a toolEnv bound to the fakes. The scripted fakeLookup is
// adapted to the LookupFunc seam via its method value.
func detectEnv(t *testing.T, name string, runner Runner, lookup fakeLookup) toolEnv {
	t.Helper()
	return toolEnv{
		name:          name,
		runner:        runner,
		lookup:        lookup.LookPath,
		limits:        Limits{MaxOutput: 4096},
		detectTimeout: time.Second,
		now:           func() time.Time { return fixedTime },
	}
}

func TestDetectVersionedOK(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"subfinder -version": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("Current Version: v2.6.3\n")}, nil
		},
	})
	d := detectVersioned(context.Background(), detectEnv(t, "subfinder", r, newFakeLookup()), "-version")
	if d.Status != StatusOK {
		t.Fatalf("status = %s, want ok (reason: %s)", d.Status, d.Reason)
	}
	if !d.Exists || !d.Capable {
		t.Fatalf("expected Exists and Capable, got %+v", d)
	}
	if d.Version != "v2.6.3" {
		t.Fatalf("version = %q, want v2.6.3", d.Version)
	}
	if d.Reason == "" {
		t.Fatal("expected a reason")
	}
}

// TestDetectVersionedFailureIsWarnNotMissing is the key detection guarantee:
// a failing version command must never classify an installed tool as MISSING.
func TestDetectVersionedFailureIsWarnNotMissing(t *testing.T) {
	cases := map[string]func(Cmd) (RunResult, error){
		"version flag crashes": func(Cmd) (RunResult, error) {
			return RunResult{}, errors.New("permission denied")
		},
		"version flag times out": func(Cmd) (RunResult, error) {
			return RunResult{}, context.DeadlineExceeded
		},
		"version output garbled": func(Cmd) (RunResult, error) {
			return RunResult{Stdout: []byte("???"), ExitCode: 1}, nil
		},
		"version flag exits nonzero": func(Cmd) (RunResult, error) {
			return RunResult{Stderr: []byte("unrecognized flag"), ExitCode: 2}, nil
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
				"subfinder -version": fn,
			})
			d := detectVersioned(context.Background(), detectEnv(t, "subfinder", r, newFakeLookup()), "-version")
			if d.Status == StatusMissing {
				t.Fatalf("a failing version flag must not report MISSING; got %+v", d)
			}
			if d.Status != StatusWarn {
				t.Fatalf("status = %s, want warn", d.Status)
			}
			if !d.Exists {
				t.Fatal("Exists must stay true when the version flag fails")
			}
			if d.Reason == "" {
				t.Fatal("expected a reason")
			}
		})
	}
}

func TestDetectVersionedMissing(t *testing.T) {
	l := newFakeLookup()
	l.errs["subfinder"] = errors.New("not found in PATH")
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){})
	d := detectVersioned(context.Background(), detectEnv(t, "subfinder", r, l), "-version")
	if d.Status != StatusMissing {
		t.Fatalf("status = %s, want missing", d.Status)
	}
	if d.Exists {
		t.Fatal("Exists must be false for a missing tool")
	}
	if d.Reason == "" {
		t.Fatal("expected a reason")
	}
}

func TestDetectVersionedDisappearedBetweenLookupAndRun(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"subfinder -version": func(Cmd) (RunResult, error) {
			return RunResult{}, fmt.Errorf("%w: subfinder", ErrExecutableNotFound)
		},
	})
	d := detectVersioned(context.Background(), detectEnv(t, "subfinder", r, newFakeLookup()), "-version")
	if d.Status != StatusMissing {
		t.Fatalf("status = %s, want missing", d.Status)
	}
}

// TestDetectVersionedOnStderr verifies the version is recognized when a tool
// writes its version banner to stderr (subfinder does this); an installed
// tool with a working version flag must never be reported WARN merely
// because it picked the other stream.
func TestDetectVersionedOnStderr(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"subfinder -version": func(Cmd) (RunResult, error) {
			return RunResult{Stderr: []byte("[INF] Current Version: v2.15.0\n")}, nil
		},
	})
	d := detectVersioned(context.Background(), detectEnv(t, "subfinder", r, newFakeLookup()), "-version")
	if d.Status != StatusOK {
		t.Fatalf("status = %s, want ok (reason: %s)", d.Status, d.Reason)
	}
	if d.Version != "v2.15.0" {
		t.Fatalf("version = %q, want v2.15.0", d.Version)
	}
}

func TestDetectCapabilityOK(t *testing.T) {
	// assetfinder has no version flag; Go's flag package prints usage to
	// stderr and exits 2 for -h. That must be OK with no version — never a
	// MISSING and never a WARN about the version flag.
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"assetfinder -h": func(Cmd) (RunResult, error) {
			return RunResult{Stderr: []byte("Usage: assetfinder [domain]\n"), ExitCode: 2}, nil
		},
	})
	d := detectCapability(context.Background(), detectEnv(t, "assetfinder", r, newFakeLookup()), "-h")
	if d.Status != StatusOK {
		t.Fatalf("status = %s, want ok (reason: %s)", d.Status, d.Reason)
	}
	if !d.Capable {
		t.Fatal("expected Capable")
	}
	if d.Version != "" {
		t.Fatalf("version = %q, want empty (assetfinder has no version flag)", d.Version)
	}
}

func TestDetectCapabilityEmptyOutputIsWarn(t *testing.T) {
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){
		"assetfinder -h": func(Cmd) (RunResult, error) {
			return RunResult{}, nil
		},
	})
	d := detectCapability(context.Background(), detectEnv(t, "assetfinder", r, newFakeLookup()), "-h")
	if d.Status != StatusWarn {
		t.Fatalf("status = %s, want warn", d.Status)
	}
	if !d.Exists {
		t.Fatal("Exists must stay true")
	}
}

func TestDetectCapabilityMissing(t *testing.T) {
	l := newFakeLookup()
	l.errs["assetfinder"] = errors.New("not found in PATH")
	r := newFakeRunner(t, map[string]func(Cmd) (RunResult, error){})
	d := detectCapability(context.Background(), detectEnv(t, "assetfinder", r, l), "-h")
	if d.Status != StatusMissing {
		t.Fatalf("status = %s, want missing", d.Status)
	}
}

func TestDetectionLabel(t *testing.T) {
	cases := map[Status]string{
		StatusOK:      "[OK]",
		StatusWarn:    "[WARN]",
		StatusMissing: "[MISSING]",
	}
	for s, want := range cases {
		if got := s.Label(); got != want {
			t.Errorf("Label(%s) = %q, want %q", s, got, want)
		}
	}
}
