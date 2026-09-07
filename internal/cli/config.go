package cli

import (
	"github.com/RA000WL/RavenRecon/internal/config"
)

// resolveBaseConfig builds the effective base configuration with the
// documented precedence: CLI flags > environment > file > defaults.
//
// The file step runs only when configPath is non-empty (a missing file is
// an error, never a silent default); the environment step always runs
// (invalid variables fail closed). Explicit CLI flags override the base
// later, at each use site through the per-flag *Set gates — so a flag the
// operator typed always wins over file and env.
func resolveBaseConfig(configPath string) (config.Config, error) {
	base := config.Default()
	if configPath != "" {
		f, err := config.LoadFile(configPath)
		if err != nil {
			return base, err
		}
		base = base.WithFile(f)
	}
	return base.WithEnv()
}
