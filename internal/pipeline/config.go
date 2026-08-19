// Package pipeline orchestrates the RavenRecon engines into one
// deterministic, cancellable end-to-end scan.
//
// T1 scope: this package is the pipeline skeleton. It defines the stage
// contract (Stage, StageInput, StageResult), the configuration surface
// (ScanConfig, StageConfig), the runner (Run) with fail-continue and
// cancellation semantics, the pipeline outcome fold, and the scope filter
// (InDomain, FilterHosts). No engine adapters ship yet: callers compose
// their stage implementations and pass them to Run explicitly. Corpus
// propagation (T2a) is real: stages return Additions, the runner merges
// them (first-seen dedup, deterministic order) into the corpus handed to
// later stages, bounded by the per-stage MaxCorpusSize caps (runner-side
// capping records the corpus_capped sticky flag). Additions carry the
// corpus kinds only (domains/hosts/URLs): results propagation
// (technology, evidence, findings, parameters) is a separate milestone.
// Eventing and report rendering are separate milestones.
package pipeline

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// StageName identifies one of the ten engine stages in the fixed pipeline
// order: discover → dns → httpprobe → urlintel → techintel → jsintel →
// secrentel → priority → detect → report.
type StageName string

const (
	StageDiscover    StageName = "discover"
	StageDNS         StageName = "dns"
	StageHTTPProbe   StageName = "httpprobe"
	StageURLIntel    StageName = "urlintel"
	StageTechIntel   StageName = "techintel"
	StageJSIntel     StageName = "jsintel"
	StageSecretIntel StageName = "secrentel"
	StagePriority    StageName = "priority"
	StageDetect      StageName = "detect"
	StageReport      StageName = "report"
)

// pipelineOrder is the fixed, deterministic pipeline order.
var pipelineOrder = []StageName{
	StageDiscover, StageDNS, StageHTTPProbe, StageURLIntel, StageTechIntel,
	StageJSIntel, StageSecretIntel, StagePriority, StageDetect, StageReport,
}

// AllStages returns the ten stage names in pipeline order as a fresh slice.
func AllStages() []StageName {
	out := make([]StageName, len(pipelineOrder))
	copy(out, pipelineOrder)
	return out
}

// ValidStage reports whether name is one of the ten engine stage names.
func ValidStage(name StageName) bool {
	for _, s := range pipelineOrder {
		if s == name {
			return true
		}
	}
	return false
}

func stageVocabulary() string {
	names := make([]string, len(pipelineOrder))
	for i, s := range pipelineOrder {
		names[i] = string(s)
	}
	return strings.Join(names, ", ")
}

// Default per-stage bound values. Zero fields of a StageConfig resolve to
// these through WithDefaults.
const (
	DefaultMaxConcurrency = 4      // workers per stage pool
	DefaultQueueSize      = 64     // bounded submission queue per stage
	DefaultBurst          = 1      // token-bucket capacity (meaningful when Rate > 0)
	DefaultMaxCorpusSize  = 100000 // max hosts+URLs corpus entries
	DefaultMaxOutput      = 100000 // max result entries a stage may retain
)

// DefaultStageConfig returns the default per-stage bounds. Timeout and
// Rate default to zero: no per-stage deadline and no rate limit
// (matching runtime.Pool, where 0 disables).
func DefaultStageConfig() StageConfig {
	return StageConfig{
		MaxConcurrency: DefaultMaxConcurrency,
		QueueSize:      DefaultQueueSize,
		Timeout:        0,
		Rate:           0,
		Burst:          DefaultBurst,
		MaxCorpusSize:  DefaultMaxCorpusSize,
		MaxOutput:      DefaultMaxOutput,
	}
}

// StageConfig is the per-stage bound set. Zero fields resolve to the
// defaults through WithDefaults; there is no way to express "explicitly
// zero" — 0 means "use the default", and the defaults for Timeout and
// Rate ARE zero (no deadline, no rate limit).
type StageConfig struct {
	// MaxConcurrency is the stage's pool concurrency (workers).
	MaxConcurrency int

	// QueueSize is the stage's bounded submission queue capacity.
	QueueSize int

	// Timeout is the per-stage run deadline; 0 means no deadline. A
	// stage whose deadline elapses is cancelled (its context is
	// cancelled); the run itself continues with the next stage.
	// Deadlines are real-time timers (context.WithTimeout): the injected
	// clock governs timestamps and rate limiting, never timer scheduling.
	Timeout time.Duration

	// Rate is the stage's job-start token refill rate in tokens per
	// second; 0 disables rate limiting (matching runtime.Pool).
	Rate float64

	// Burst is the token-bucket capacity; meaningful only when Rate > 0.
	// 0 resolves to the default (1) through WithDefaults — a positive
	// Rate with Burst 0 is valid and means "default burst capacity".
	Burst int

	// MaxCorpusSize bounds the shared corpus handed to the stage's
	// successors: hosts+URLs entries only (domains are scope, not corpus
	// entries, and are excluded from the count). Enforced at the merge
	// point after the stage runs (hosts kept first, URLs tail-dropped).
	// Entries cut by a cap remain first-seen and cannot re-enter the
	// corpus, even if a later stage's cap is larger; the cut records the
	// corpus_capped sticky flag (AGENTS §0.6 carve-out).
	MaxCorpusSize int

	// MaxOutput bounds the result entries a stage may retain; the stage
	// itself enforces the cap and reports Truncated honestly.
	MaxOutput int
}

// WithDefaults returns c with every zero field resolved to its default.
func (c StageConfig) WithDefaults() StageConfig {
	d := DefaultStageConfig()
	if c.MaxConcurrency == 0 {
		c.MaxConcurrency = d.MaxConcurrency
	}
	if c.QueueSize == 0 {
		c.QueueSize = d.QueueSize
	}
	if c.Timeout == 0 {
		c.Timeout = d.Timeout
	}
	if c.Rate == 0 {
		c.Rate = d.Rate
	}
	if c.Burst == 0 {
		c.Burst = d.Burst
	}
	if c.MaxCorpusSize == 0 {
		c.MaxCorpusSize = d.MaxCorpusSize
	}
	if c.MaxOutput == 0 {
		c.MaxOutput = d.MaxOutput
	}
	return c
}

// ScanConfig is the declarative description of one scan. The target is
// the canonical asset.Domain produced by asset.NewDomain — the single
// normalization point; the pipeline never normalizes a target itself.
//
// Cache and Clock appear here so the run description is complete and
// self-contained (a report stage records them). Run's explicit cache and
// clock parameters are the operative values and are never derived from
// these fields.
type ScanConfig struct {
	// Target is the canonical declared domain; must be built with
	// asset.NewDomain (validation rejects anything non-canonical).
	Target asset.Domain

	// Stages is the ordered stage selection. Entries must be one of the
	// ten StageName constants; order is exactly the run order; duplicates
	// are rejected.
	Stages []StageName

	// StageBounds optionally overrides per-stage bounds, keyed by stage
	// name. Zero fields resolve to defaults. The runner looks entries up
	// by name only — map iteration order can never affect a run.
	StageBounds map[StageName]StageConfig

	// StageParams optionally passes per-stage parameters (for example
	// tool selection) to the stages. Keys are stage names; values are
	// opaque string parameters. Validation checks the keys in sorted
	// order (unknown stage names are rejected); a nil inner map is
	// treated as empty. Empty by default. This is the seam T2 adapters
	// use for tool selection and similar per-stage choices.
	StageParams map[StageName]map[string]string

	// Cache is the caller-owned cache the run passes to its stages. The
	// pipeline never opens a cache. A nil Cache disables caching for the
	// run; stages must treat nil as caching-disabled.
	Cache cache.Cache

	// Clock is the injected clock required for determinism. Run's clock
	// parameter is the operative value.
	Clock runtime.Clock

	// OutputDir is where the report stage writes its output. The
	// pipeline never creates or opens it; the report stage validates it
	// (T6).
	OutputDir string
}

// ConfigError is one validation problem: a field path and the problem.
type ConfigError struct {
	Field   string
	Problem string
}

// Error implements error.
func (e ConfigError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Problem) }

// ValidationError aggregates every problem found by ScanConfig.Validate.
// Use errors.As to inspect the individual ConfigError problems.
type ValidationError struct {
	Problems []error
}

// Error implements error.
func (e *ValidationError) Error() string {
	var b strings.Builder
	b.WriteString("invalid scan config:")
	for i, p := range e.Problems {
		if i == 0 {
			b.WriteString(" ")
		} else {
			b.WriteString("; ")
		}
		b.WriteString(p.Error())
	}
	return b.String()
}

// Unwrap exposes the individual problems for errors.As/errors.Is.
func (e *ValidationError) Unwrap() []error { return e.Problems }

// Validate checks the config against the documented rules and returns a
// *ValidationError aggregating every problem found (nil when valid):
//
//   - missing or non-canonical Target (it must be the canonical form
//     asset.NewDomain produces);
//   - unknown, empty, or duplicate stage names in Stages;
//   - unknown stage names in StageBounds and StageParams;
//   - inverted or non-finite bounds (negatives; NaN/infinite Rate).
//     A positive Rate with Burst 0 is valid — Burst resolves to its
//     default; a negative Burst is rejected.
//
// Validation is deterministic: problems are reported in config order,
// with StageBounds keys inspected in sorted order.
func (cfg ScanConfig) Validate() error {
	var problems []error
	if cfg.Target.Name == "" {
		problems = append(problems, ConfigError{
			Field:   "target",
			Problem: "missing target domain; build the canonical asset with asset.NewDomain (the single normalization point)",
		})
	} else if canon, err := asset.NewDomain(cfg.Target.Name, asset.Provenance{}); err != nil || canon.Name != cfg.Target.Name {
		problems = append(problems, ConfigError{
			Field:   "target",
			Problem: fmt.Sprintf("target %q is not canonical; build it with asset.NewDomain (the single normalization point)", cfg.Target.Name),
		})
	}
	seen := make(map[StageName]bool, len(cfg.Stages))
	for i, name := range cfg.Stages {
		field := fmt.Sprintf("stages[%d]", i)
		if !ValidStage(name) {
			problems = append(problems, ConfigError{
				Field:   field,
				Problem: fmt.Sprintf("unknown stage %q (known stages: %s)", name, stageVocabulary()),
			})
			continue
		}
		if seen[name] {
			problems = append(problems, ConfigError{
				Field:   field,
				Problem: fmt.Sprintf("duplicate stage %q; each stage may appear at most once", name),
			})
		}
		seen[name] = true
	}
	if len(cfg.StageBounds) > 0 {
		keys := make([]StageName, 0, len(cfg.StageBounds))
		for name := range cfg.StageBounds {
			keys = append(keys, name)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, name := range keys {
			if !ValidStage(name) {
				problems = append(problems, ConfigError{
					Field:   fmt.Sprintf("bounds[%s]", name),
					Problem: fmt.Sprintf("unknown stage (known stages: %s)", stageVocabulary()),
				})
				continue
			}
			problems = append(problems, cfg.StageBounds[name].validate(fmt.Sprintf("bounds[%s]", name))...)
		}
	}
	if len(cfg.StageParams) > 0 {
		keys := make([]StageName, 0, len(cfg.StageParams))
		for name := range cfg.StageParams {
			keys = append(keys, name)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, name := range keys {
			if !ValidStage(name) {
				problems = append(problems, ConfigError{
					Field:   fmt.Sprintf("params[%s]", name),
					Problem: fmt.Sprintf("unknown stage (known stages: %s)", stageVocabulary()),
				})
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return &ValidationError{Problems: problems}
}

// validate checks one StageConfig for inverted or non-finite bounds.
func (c StageConfig) validate(field string) []error {
	var problems []error
	add := func(sub, problem string) {
		problems = append(problems, ConfigError{Field: field + "." + sub, Problem: problem})
	}
	if c.MaxConcurrency < 0 {
		add("MaxConcurrency", "inverted bound: must be >= 0 (0 resolves to the default)")
	}
	if c.QueueSize < 0 {
		add("QueueSize", "inverted bound: must be >= 0 (0 resolves to the default)")
	}
	if c.Timeout < 0 {
		add("Timeout", "inverted bound: must be >= 0 (0 means no deadline)")
	}
	if c.Rate < 0 {
		add("Rate", "inverted bound: must be >= 0 (0 disables rate limiting)")
	}
	if math.IsNaN(c.Rate) || math.IsInf(c.Rate, 0) {
		add("Rate", "must be finite")
	}
	if c.Burst < 0 {
		add("Burst", "inverted bound: must be >= 0 (0 resolves to the default)")
	}
	if c.Rate > 0 && c.Burst < 0 {
		add("Burst", "inverted bound: a positive Rate with a negative Burst is rejected; Burst 0 resolves to the default (1)")
	}
	if c.MaxCorpusSize < 0 {
		add("MaxCorpusSize", "inverted bound: must be >= 0 (0 resolves to the default)")
	}
	if c.MaxOutput < 0 {
		add("MaxOutput", "inverted bound: must be >= 0 (0 resolves to the default)")
	}
	return problems
}
