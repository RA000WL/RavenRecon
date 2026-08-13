package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The ExecRunner tests exercise the real exec.CommandContext path. They use
// the Go toolchain itself ("go version", "go <bad>") because the Go binary is
// guaranteed present wherever go test runs; they never require the discovery
// tools or the network, and they are portable (no shell, no Unix-isms).

func TestExecRunnerRunsCommand(t *testing.T) {
	res, err := (ExecRunner{}).Run(context.Background(), Cmd{Path: "go", Args: []string{"version"}}, Limits{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "go version") {
		t.Fatalf("stdout %q does not look like go version output", res.Stdout)
	}
}

func TestExecRunnerNonZeroExit(t *testing.T) {
	res, err := (ExecRunner{}).Run(context.Background(), Cmd{Path: "go", Args: []string{"ravenrecon-no-such-command-9f3"}}, Limits{})
	if err != nil {
		t.Fatalf("an executed-and-exited process must return nil error, got %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("expected a non-zero exit code for an unknown go command")
	}
	if len(res.Stderr) == 0 {
		t.Fatal("expected stderr output for an unknown go command")
	}
}

func TestExecRunnerExecutableNotFound(t *testing.T) {
	// A path containing a separator avoids PATH lookup entirely, so the
	// direct-exec not-exist path is exercised.
	for _, path := range []string{
		"/ravenrecon-no-such-binary-9f3",
		"ravenrecon-no-such-binary-in-path-9f3",
	} {
		_, err := (ExecRunner{}).Run(context.Background(), Cmd{Path: path, Args: nil}, Limits{})
		if !errors.Is(err, ErrExecutableNotFound) {
			t.Fatalf("path %q: want ErrExecutableNotFound, got %v", path, err)
		}
	}
}

func TestExecRunnerBoundedStdout(t *testing.T) {
	res, err := (ExecRunner{}).Run(context.Background(), Cmd{Path: "go", Args: []string{"version"}}, Limits{MaxOutput: 8})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}
	if !res.StdoutTruncated {
		t.Fatal("expected stdout truncation with an 8-byte cap")
	}
	if len(res.Stdout) > 8 {
		t.Fatalf("stdout is %d bytes, exceeding the 8-byte cap", len(res.Stdout))
	}
}

func TestExecRunnerBoundedStderr(t *testing.T) {
	res, err := (ExecRunner{}).Run(context.Background(), Cmd{Path: "go", Args: []string{"ravenrecon-no-such-command-9f3"}}, Limits{MaxOutput: 4})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.StderrTruncated {
		t.Fatal("expected stderr truncation with a 4-byte cap")
	}
	if len(res.Stderr) > 4 {
		t.Fatalf("stderr is %d bytes, exceeding the 4-byte cap", len(res.Stderr))
	}
}

func TestExecRunnerZeroCapUsesDefault(t *testing.T) {
	res, err := (ExecRunner{}).Run(context.Background(), Cmd{Path: "go", Args: []string{"version"}}, Limits{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StdoutTruncated {
		t.Fatal("small output must not be truncated under the default cap")
	}
	if len(res.Stdout) > int(DefaultMaxOutput) {
		t.Fatalf("stdout is %d bytes, exceeding DefaultMaxOutput", len(res.Stdout))
	}
}

func TestExecRunnerCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (ExecRunner{}).Run(ctx, Cmd{Path: "go", Args: []string{"version"}}, Limits{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestExecRunnerDeadlineContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure the deadline has elapsed
	_, err := (ExecRunner{}).Run(ctx, Cmd{Path: "go", Args: []string{"version"}}, Limits{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded, got %v", err)
	}
}

func TestExecRunnerEmptyPath(t *testing.T) {
	_, err := (ExecRunner{}).Run(context.Background(), Cmd{Path: "", Args: nil}, Limits{})
	if err == nil {
		t.Fatal("expected an error for an empty command path")
	}
}
