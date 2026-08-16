package secrentel

import (
	"context"
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// Config configures one Ingest run. All numeric fields are validated by
// Ingest; invalid values are rejected with an error rather than silently
// normalized (mirroring techintel and urlintel).
type Config struct {
	// Concurrency is the worker count. Must be > 0.
	Concurrency int
	// QueueSize is the bounded reader→worker queue. Must be > 0; the reader
	// blocks on a full queue (backpressure, never unbounded memory).
	QueueSize int
	// Timeout is the per-document processing deadline; 0 means no deadline.
	Timeout time.Duration
	// Rate is the optional per-job start rate limit (jobs/sec); 0 disables.
	Rate float64
	// Burst is the rate limiter burst size; values below 1 normalize to 1.
	Burst int
	// Clock is the injectable time seam; nil uses the wall clock.
	Clock runtime.Clock
	// Cache is the Phase 3 cache. When nil, cache-before-execute is disabled
	// and every document is scanned fresh (still merged and reported).
	Cache cache.Cache
	// DB is the compiled pattern database. When nil, Ingest loads it via
	// patterns.Load() (the compile-once contract: the engine NEVER compiles
	// regular expressions itself). Tests may inject a compiled DB.
	DB *patterns.DB
	// MaxCandidatesPerDocument bounds how many candidates one document may
	// report (overflow is counted, never silently dropped). Default 64.
	MaxCandidatesPerDocument int
	// MaxEvidencePerCandidate bounds each candidate's evidence records.
	// Default 8.
	MaxEvidencePerCandidate int
	// Emit, when non-nil, is called once per PROCESSED document (fresh or
	// cache-served) with the document reference and its merged entry.
	// Panics inside Emit are contained and reported as run diagnostics.
	Emit func(context.Context, DocumentRef, ReportEntry) error
	// Metrics, when non-nil, accumulates the run's work counters.
	Metrics *Metrics
}

// DefaultConfig returns the documented default Ingest configuration.
func DefaultConfig() Config {
	return Config{
		Concurrency:              8,
		QueueSize:                256,
		Timeout:                  30 * time.Second,
		Rate:                     0,
		Burst:                    1,
		MaxCandidatesPerDocument: 64,
		MaxEvidencePerCandidate:  8,
	}
}

// validateAndDefault validates a Config copy, fills defaults, and loads the
// pattern DB when none was injected.
func (c *Config) validateAndDefault() (*Config, error) {
	if c.Concurrency <= 0 {
		return nil, fmt.Errorf("config: Concurrency must be > 0")
	}
	if c.QueueSize <= 0 {
		return nil, fmt.Errorf("config: QueueSize must be > 0")
	}
	if c.Timeout < 0 {
		return nil, fmt.Errorf("config: Timeout must be >= 0")
	}
	if c.MaxCandidatesPerDocument < 0 {
		return nil, fmt.Errorf("config: MaxCandidatesPerDocument must be >= 0")
	}
	if c.MaxEvidencePerCandidate < 0 {
		return nil, fmt.Errorf("config: MaxEvidencePerCandidate must be >= 0")
	}

	d := *c
	if d.Clock == nil {
		d.Clock = wallClock{}
	}
	if d.DB == nil {
		db, err := patterns.Load()
		if err != nil {
			return nil, fmt.Errorf("load pattern database: %w", err)
		}
		d.DB = db
	}
	if d.MaxCandidatesPerDocument == 0 {
		d.MaxCandidatesPerDocument = 64
	}
	if d.MaxEvidencePerCandidate == 0 {
		d.MaxEvidencePerCandidate = 8
	}
	return &d, nil
}
