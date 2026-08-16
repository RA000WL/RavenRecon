package secrentel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// storeTimeout bounds a single cache write performed after the run context
// was already cancelled (persisting a completed record). Mirrors the Phase 4
// convention shared by techintel and urlintel.
const storeTimeout = 5 * time.Second

// shutdownGrace / shutdownForceBudget bound Shutdown's drain, mirroring the
// Phase 4 convention.
const (
	shutdownGrace       = 15 * time.Second
	shutdownForceBudget = 30 * time.Second
)

// maxRunDiagnostics bounds how many run-level error messages Ingest retains.
const maxRunDiagnostics = 32

// DocumentSource is the ingest seam: a stream of documents. Next returns
// io.EOF at end of stream and must honor ctx cancellation (the reader stops
// promptly when ctx is done).
type DocumentSource interface {
	Next(ctx context.Context) (Document, error)
}

// SliceDocumentSource wraps a fixed slice of documents for tests and static
// input.
type SliceDocumentSource []Document

// Next implements DocumentSource.
func (s *SliceDocumentSource) Next(ctx context.Context) (Document, error) {
	if len(*s) == 0 {
		return Document{}, io.EOF
	}
	d := (*s)[0]
	*s = (*s)[1:]
	return d, nil
}

// Metrics accumulates the run's work counters. It is safe for concurrent
// use; a nil *Metrics is a no-op.
type Metrics struct {
	mu          sync.Mutex
	documents   int
	scanned     int
	stored      int
	reads       int
	malformed   int
	suppressed  int
	dropNeg     int
	dropValid   int
	dropEntropy int
	dropLength  int
	dropDup     int
	overflow    int
}

// MetricsSnapshot is a consistent point-in-time copy of the counters.
type MetricsSnapshot struct {
	Documents        int
	Scanned          int
	Stored           int
	Reads            int
	Malformed        int
	SuppressedFP     int
	DroppedNegative  int
	DroppedValidator int
	DroppedEntropy   int
	DroppedLength    int
	DroppedDuplicate int
	OverflowDropped  int
}

func (m *Metrics) add(f func(*MetricsSnapshot)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.snapshotLocked()
	f(&s)
	m.load(s)
}

func (m *Metrics) snapshotLocked() MetricsSnapshot {
	return MetricsSnapshot{
		Documents: m.documents, Scanned: m.scanned, Stored: m.stored,
		Reads: m.reads, Malformed: m.malformed, SuppressedFP: m.suppressed,
		DroppedNegative: m.dropNeg, DroppedValidator: m.dropValid,
		DroppedEntropy: m.dropEntropy, DroppedLength: m.dropLength,
		DroppedDuplicate: m.dropDup, OverflowDropped: m.overflow,
	}
}

func (m *Metrics) load(s MetricsSnapshot) {
	m.documents, m.scanned, m.stored = s.Documents, s.Scanned, s.Stored
	m.reads, m.malformed, m.suppressed = s.Reads, s.Malformed, s.SuppressedFP
	m.dropNeg, m.dropValid, m.dropEntropy = s.DroppedNegative, s.DroppedValidator, s.DroppedEntropy
	m.dropLength, m.dropDup, m.overflow = s.DroppedLength, s.DroppedDuplicate, s.OverflowDropped
}

// addScanCounts folds one document's scan accounting into the metrics.
func (m *Metrics) addScanCounts(c scanCounts) {
	m.add(func(s *MetricsSnapshot) {
		s.SuppressedFP += c.SuppressedFP
		s.DroppedNegative += c.DroppedNegative
		s.DroppedValidator += c.DroppedValidator
		s.DroppedEntropy += c.DroppedEntropy
		s.DroppedLength += c.DroppedLength
		s.DroppedDuplicate += c.DroppedDuplicateValue
		s.OverflowDropped += c.OverflowDropped
	})
}

// Snapshot returns a consistent copy of the counters. A nil Metrics
// snapshots as all zeros.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotLocked()
}

// env is the immutable per-run environment shared by the reader and every
// worker.
type env struct {
	db      *patterns.DB
	cache   cache.Cache
	clock   runtime.Clock
	limits  scanLimits
	metrics *Metrics

	errMu  sync.Mutex
	diags  []error
	excess int
}

// recordErr appends one run diagnostic, bounded.
func (e *env) recordErr(err error) {
	if err == nil {
		return
	}
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if len(e.diags) < maxRunDiagnostics {
		e.diags = append(e.diags, err)
	} else {
		e.excess++
	}
}

// runError joins all recorded diagnostics into one error.
func (e *env) runError() error {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if len(e.diags) == 0 && e.excess == 0 {
		return nil
	}
	msgs := make([]string, 0, len(e.diags)+1)
	for _, d := range e.diags {
		msgs = append(msgs, d.Error())
	}
	if e.excess > 0 {
		msgs = append(msgs, fmt.Sprintf("... and %d more diagnostics suppressed", e.excess))
	}
	return errors.New("secrentel: " + joinStrings(msgs, "; "))
}

func joinStrings(msgs []string, sep string) string {
	out := ""
	for i, m := range msgs {
		if i > 0 {
			out += sep
		}
		out += m
	}
	return out
}

// recordCacheDiagnostic surfaces a cache problem as a run diagnostic; never
// fatal (mirroring techintel).
func (e *env) recordCacheDiagnostic(op string, err error) {
	if err == nil {
		return
	}
	e.recordErr(fmt.Errorf("secrentel: cache %s: %w", op, err))
}

// Ingest runs one secret-intelligence pass over the document source: for
// each document: validate and bound at ingest → cache-before-execute (a
// completed hit serves the stored scan with ZERO analysis) → scan →
// correlate → score → merge at emit → report. Truncated documents report
// their candidates but are stored incomplete and never served from cache.
// Cancellation performs a bounded drain with honest cancelled statuses and
// never leaks workers.
//
// The returned Report is deterministic. The returned error joins the bounded
// run diagnostics; cancellation is surfaced through entry statuses, never as
// an error.
func Ingest(ctx context.Context, cfg Config, src DocumentSource) (Report, error) {
	c, err := cfg.validateAndDefault()
	if err != nil {
		return Report{}, err
	}
	if src == nil {
		return Report{}, errors.New("secrentel: nil document source")
	}

	e := &env{
		db:    c.DB,
		cache: c.Cache,
		clock: c.Clock,
		limits: scanLimits{
			maxCandidates:        c.MaxCandidatesPerDocument,
			maxMatchesPerPattern: 64,
			maxEvidencePerCand:   c.MaxEvidencePerCandidate,
			maxPatternEvidence:   3,
		},
		metrics: c.Metrics,
	}

	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: c.Concurrency,
		QueueSize:   c.QueueSize,
		Timeout:     c.Timeout,
		Rate:        c.Rate,
		Burst:       c.Burst,
	})
	if err != nil {
		return Report{}, fmt.Errorf("secrentel: pool: %w", err)
	}

	acc := newAccumulator()

	// Reader: validate at ingest, pre-register cancelled placeholders,
	// submit one bounded job per document.
	readDone := make(chan struct{})
	var sourceErr error
	go func() {
		defer close(readDone)
		for {
			if ctx.Err() != nil {
				sourceErr = ctx.Err()
				return
			}
			d, err := src.Next(ctx)
			if err != nil {
				if err == io.EOF {
					return
				}
				if ctx.Err() != nil {
					sourceErr = ctx.Err()
					return
				}
				sourceErr = err
				return
			}

			now := e.clock.Now().UTC()
			sd, err := prepareDocument(d, now)
			if err != nil {
				acc.addMalformed()
				e.metrics.add(func(s *MetricsSnapshot) { s.Malformed++ })
				e.recordErr(fmt.Errorf("secrentel: malformed document: %w", err))
				continue
			}
			e.metrics.add(func(s *MetricsSnapshot) { s.Documents++ })
			acc.preRegister(sd)
			doc := sd
			if _, err := pool.Submit(ctx, runtime.Job{
				Func: func(ctx context.Context) (any, error) {
					entry := processDocument(ctx, doc, e)
					acc.merge(doc.identity.String(), &entry)
					if c.Emit != nil {
						if err := callEmit(ctx, c.Emit, doc.ref(), entry); err != nil {
							e.recordErr(fmt.Errorf("secrentel: emit: %w", err))
						}
					}
					return nil, nil
				},
			}); err != nil {
				if errors.Is(err, runtime.ErrPoolClosed) || ctx.Err() != nil {
					return // shutting down; the placeholder covers it
				}
				e.recordErr(fmt.Errorf("secrentel: submit: %w", err))
				return
			}
		}
	}()

	<-readDone

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout(c.Timeout))
	err = pool.Shutdown(shutdownCtx)
	cancel()
	if err != nil {
		e.recordErr(fmt.Errorf("secrentel: shutdown: %w", err))
	}
	if sourceErr != nil && ctx.Err() == nil {
		e.recordErr(fmt.Errorf("source: %w", sourceErr))
	}

	entries, malformed := acc.snapshot()
	rep := buildReport(entries, malformed, e.metrics.Snapshot(), e.clock)
	return rep, e.runError()
}

// shutdownTimeout derives the bounded drain budget (Phase 4 convention).
func shutdownTimeout(jobTimeout time.Duration) time.Duration {
	if jobTimeout <= 0 {
		return shutdownForceBudget
	}
	return jobTimeout + shutdownGrace
}

// callEmit runs the optional emit hook, containing panics.
func callEmit(ctx context.Context, fn func(context.Context, DocumentRef, ReportEntry) error, d DocumentRef, e ReportEntry) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("emit hook panicked: %v", r)
		}
	}()
	return fn(ctx, d, e)
}

// processDocument runs one document through cache-before-execute: a
// completed cache hit rebuilds and returns the stored scan (ZERO analysis);
// a miss scans, stores the completed record, and returns the fresh result.
// Truncated scans are stored incomplete (never served); failed and
// cancelled documents are never stored.
func processDocument(ctx context.Context, sd scannedDocument, e *env) ReportEntry {
	if e.cache != nil {
		key, err := secretKey(sd, e.db.Version())
		if err != nil {
			e.recordErr(fmt.Errorf("secrentel: cache key: %w", err))
			return failedEntry(sd, err)
		}
		if out := lookupScan(ctx, key, sd, e); out != nil {
			return *out
		}
	}

	if err := ctx.Err(); err != nil {
		return cancelledEntry(sd)
	}

	outcome := scanDocument(sd, e.db, e.limits)
	e.metrics.add(func(s *MetricsSnapshot) { s.Scanned++ })
	e.metrics.addScanCounts(outcome.counts)

	entry := ReportEntry{
		ID:            sd.identity,
		Status:        StatusCompleted,
		Doc:           sd.ref(),
		CandidateSrc:  sd.candidateSource(),
		EdgeSrc:       edgeSourceOf(&sd),
		Secrets:       outcome.candidates,
		Evidence:      outcome.evidence,
		Relationships: outcome.edges,
		Counts:        outcome.counts,
		Truncated:     sd.truncated,
		Overflow:      len(outcome.candidates) >= e.limits.maxCandidates,
		FirstSeen:     sd.observedAt,
		LastSeen:      sd.observedAt,
		Sources:       []string{sd.source},
	}
	if entry.Truncated {
		// An honest truncated prefix: candidates still report, but the scan
		// is incomplete by definition and never cached as completed.
		entry.Status = StatusIncomplete
	}

	if e.cache != nil {
		key, err := secretKey(sd, e.db.Version())
		if err != nil {
			return entry // scan succeeded; key failure only skips the store
		}
		storeScanDetached(ctx, key, sd, entry, e)
	}
	return entry
}

// edgeSourceOf snapshots the edge source (identity + kind + present) for
// report-time edge rebuilding from stored records.
func edgeSourceOf(sd *scannedDocument) edgeSourceSnapshot {
	from, kind, ok := sd.edgeSource()
	if !ok {
		return edgeSourceSnapshot{}
	}
	return edgeSourceSnapshot{From: from, Kind: kind, Present: true}
}

// cancelledEntry is the honest outcome for a document whose work never
// executed.
func cancelledEntry(sd scannedDocument) ReportEntry {
	return ReportEntry{
		ID:           sd.identity,
		Status:       StatusCancelled,
		Doc:          sd.ref(),
		CandidateSrc: sd.candidateSource(),
		EdgeSrc:      edgeSourceOf(&sd),
		FirstSeen:    sd.observedAt,
		Sources:      []string{sd.source},
	}
}

// failedEntry is the honest outcome for a document that could not be
// processed (cache-key failure).
func failedEntry(sd scannedDocument, err error) ReportEntry {
	e := cancelledEntry(sd)
	e.Status = StatusFailed
	e.Err = err
	return e
}

// lookupScan performs cache-before-execute. Any non-hit outcome falls
// through to a fresh scan; a completed hit is decoded with strict
// re-validation and a tampered record is deleted and recomputed.
func lookupScan(ctx context.Context, key cache.Key, sd scannedDocument, e *env) *ReportEntry {
	e.metrics.add(func(s *MetricsSnapshot) { s.Reads++ })
	out := e.cache.Get(ctx, key)
	switch out.State {
	case cache.StateHit:
		s, err := decodeStoredScan(*out.Record, sd, e.limits)
		if err != nil {
			e.recordCacheDiagnostic("hit rejected", err)
			e.recordCacheDiagnostic("delete", e.cache.Delete(ctx, key))
			return nil
		}
		entry := entryFromStored(sd, s)
		return &entry
	case cache.StateExpired:
		return nil
	case cache.StateCorrupt, cache.StateSchemaIncompatible, cache.StateIncomplete:
		if out.Err != nil {
			e.recordCacheDiagnostic("get", out.Err)
		}
		return nil
	case cache.StateError:
		if out.Err != nil && ctx.Err() == nil {
			e.recordCacheDiagnostic("get", out.Err)
		}
		return nil
	case cache.StateMiss:
		return nil
	}
	return nil
}

// storeScanDetached persists one scan's record. Completed, untruncated scans
// are stored completed; truncated scans are stored incomplete (their
// candidates remain attached for future inspection but are never served);
// failed and cancelled documents never reach this function.
func storeScanDetached(ctx context.Context, key cache.Key, sd scannedDocument, entry ReportEntry, e *env) {
	storeCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		storeCtx, cancel = context.WithTimeout(context.Background(), storeTimeout)
		defer cancel()
	}
	rec, err := encodeStoredScan(sd, entry, e.clock.Now())
	if err != nil {
		e.recordCacheDiagnostic("encode", err)
		return
	}
	if err := e.cache.Put(storeCtx, key, rec); err != nil {
		e.recordCacheDiagnostic("put", err)
		return
	}
	e.metrics.add(func(s *MetricsSnapshot) { s.Stored++ })
}

// wallClock is the production runtime.Clock (local twin, mirroring
// techintel).
type wallClock struct{}

func (wallClock) Now() time.Time                         { return time.Now() }
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
