package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/config"
	"github.com/RA000WL/RavenRecon/internal/version"
)

const usage = `RavenRecon - intelligent reconnaissance framework

Usage:
  ravenrecon <command> [options]

Commands:
  version       Show version information
  doctor        Check the local RavenRecon environment

Options:
  -h, --help    Show this help message

Examples:
  ravenrecon version
  ravenrecon doctor

Reconnaissance commands will be introduced in later releases.

RavenRecon is intended for authorized security testing and
bug bounty programs where the target is explicitly in scope.
`

// Run executes the RavenRecon CLI.
func Run(ctx context.Context, args []string) error {
	if ctx == nil {
		return fmt.Errorf("context must not be nil")
	}

	if len(args) == 0 {
		return printUsage(os.Stdout)
	}

	switch args[0] {
	case "help", "-h", "--help":
		return printUsage(os.Stdout)

	case "version":
		return printVersion(os.Stdout)

	case "doctor":
		return runDoctor(os.Stdout)

	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}

func printUsage(w io.Writer) error {
	_, err := io.WriteString(w, usage)
	return err
}

func printVersion(w io.Writer) error {
	_, err := fmt.Fprintf(
		w,
		"RavenRecon %s\ncommit: %s\ndate: %s\n",
		version.Version,
		version.Commit,
		version.Date,
	)

	return err
}

func runDoctor(w io.Writer) error {
	cfg := config.Default()

	cacheDir := cfg.Cache.Dir
	if cacheDir == "" {
		if d, err := cache.DefaultDir(); err == nil {
			cacheDir = d
		} else {
			cacheDir = "(unavailable: " + err.Error() + ")"
		}
	}

	_, err := fmt.Fprintf(
		w,
		`RavenRecon doctor

Foundation: OK
Configuration:
  Concurrency: %d
  Timeout:     %s
  Rate:        %.2f req/s
  User-Agent:  %s
Cache:
  Enabled:     %t
  Directory:   %s
  TTL:         %s (0 = no expiration)
`,
		cfg.Concurrency,
		cfg.Timeout,
		cfg.Rate,
		cfg.UserAgent,
		cfg.Cache.Enabled,
		cacheDir,
		cfg.Cache.TTL,
	)

	return err
}
