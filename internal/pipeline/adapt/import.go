package adapt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/importer"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// This file implements the v1.8 T11 pipeline ingestion stage: the adapter
// that turns local import files (plain lists, httpx/dnsx/naabu/katana/nuclei
// JSON, Burp/ZAP XML, wayback CDX/WARC archives) into canonical Phase 2
// assets through the internal/importer engines, feeding the SAME pipeline
// stages — there is no parallel execution path (locked decision D6).
//
// Composition: NewIngestStage is the caller-side composition point the
// importer package's registration checklist documents — it registers ALL
// eighteen importers (16 specific + 2 generic fallbacks) and seals the
// registry before the stage is usable. Detect's generic-last fallback only
// behaves as tested with exactly this set.
//
// StageParams keys (all optional, unknown keys ignored):
//
//	paths                    newline- or comma-separated file and/or
//	                         directory paths. Directories are walked
//	                         recursively in deterministic (lexical) order;
//	                         every entry must exist and be a regular file or
//	                         a directory; path segments containing ".." are
//	                         rejected (no traversal escape); a missing entry
//	                         fails the stage with a structured error naming
//	                         it; an explicit directory expanding to zero
//	                         regular files (empty, or symlinks only — the
//	                         walk does not follow in-dir symlinks) fails the
//	                         stage with a structured error naming it; a file
//	                         reachable both explicitly and under a listed
//	                         directory is imported exactly once.
//	max_output               retained-set cap override (importer.Bounds.
//	                         MaxOutput); must parse as a positive int.
//	max_line_bytes           per-line buffer cap override (importer.Bounds.
//	                         MaxLineBytes); must parse as a positive int.
//	max_decompressed_bytes   gzip decompression cap override
//	                         (importer.Bounds.MaxDecompressedBytes); must
//	                         parse as a positive int.
//
// Detection and ambiguity: each file's first importer.PeekSize bytes are
// buffered once and handed to Registry.Detect(path, peek). The top match is
// the primary importer; ambiguous files (multiple non-generic matches) are
// resolved by Detect's own ordering (confidence desc, Name asc, generic
// fallbacks last) — primary wins, documented here and pinned by tests. No
// match at all → the file is counted failed (ItemsFailed), never silently
// skipped.
//
// Cache-before-execute: when StageInput.Cache is non-nil, each file job
// derives its content-hash key via importer.CacheKeyForFile (sha256 of the
// file bytes + schema + importer version + bounds config) and consults the
// cache first. A validated hit serves the stored record WITHOUT re-parsing.
// The stored payload embeds importer.ImportCacheData verbatim (the D4 slim
// shape: schema, importer, content-hash target, identities, stats) plus the
// full canonical assets and provenance records needed to serve byte-identical
// results from cache — the T13 attribution rides on the sidecar, so a warm
// run must not lose it (a slim-only record would make warm-run provenance
// differ from cold-run provenance). On decode the payload is revalidated
// through the Phase 2 builders (single normalization point); a
// semantically-wrong record is deleted and re-executed fresh in the same run
// (self-healing, mirroring discovery/cache.go decodeStored). Only clean
// engine invocations are stored: a truncated import stores
// cache.StatusIncomplete (never servable as a valid hit — a truncated
// retained set re-executes, AGENTS §0.6), a failed invocation stores nothing.
// A payload whose marshal exceeds cache.MaxRecordSize is skipped (best-effort
// caching; execution remains the source of truth).
//
// Outcome mapping (per-file → stage fold):
//
//	file imported clean            → completed
//	file truncated (engine sticky  → partial (+ Truncated=true + the
//	  flag "import_truncated")        engine's own flag, never swallowed)
//	file failed (no detect claim,  → failed (counted in ItemsFailed)
//	  structured error)
//	file cancelled                 → cancelled
//
//	stage fold: cancelled if any file was cancelled; else failed if every
//	file failed; else partial if any file failed or truncated (mirroring
//	run.go foldOutcome: a failed file among completed ones is partial);
//	else completed.
//
// Boundary filtering (adapt/doc.go contract): imported Domains, Hosts, and
// URLs additions are filtered against the declared target through
// pipeline.InDomain / pipeline.FilterHosts before propagation — out-of-scope
// entries an operator feeds in never enter the shared corpus. IPs,
// JavaScript, and Findings ride the results channels unfiltered (the same
// channels other adapters fill without domain filtering; findings reference
// subjects, not corpus members).
//
// CIDRs: the importer Sink collects CIDR strings, but the pipeline has no
// CIDR channel (Results mirrors report.Context 1:1 and neither has one).
// Their provenance records still reach the sidecar keyed "cidr:<prefix>";
// a dedicated channel is deferred (recorded in TODO.md NEW-59).
//
// Events: stage_started/stage_finished flow through the runner's standard
// Observer automatically once "ingest" is selected. Per-record progress
// events would require an Observer seam on StageInput, which does not exist
// yet (no adapter has one); ImportEnv.Observer therefore stays nil — the
// documented off switch — until that seam exists.

// ingestTruncatedFlag is the importer engine's own truncation marker
// (importer.ImportStats.StickyFlags["import_truncated"], locked decision D2).
// The adapter surfaces it VERBATIM — like discovery_truncated, it is the
// engine-level name, not an adapter invention — and never swallows it
// (AGENTS §0.6).
const ingestTruncatedFlag = "import_truncated"

// ingestStage adapts the Universal Asset Ingestion Framework
// (internal/importer) to the pipeline Stage contract.
type ingestStage struct {
	registry *importer.Registry
}

var _ pipeline.Stage = (*ingestStage)(nil)

// NewIngestStage constructs the ingest pipeline stage with the FULL registry
// composed and sealed (the caller-side composition point — see
// internal/importer/doc.go). Registering these fixed distinct names cannot
// fail; a future duplicate name is a programming error and panics loudly
// instead of being swallowed.
func NewIngestStage() pipeline.Stage {
	reg := importer.NewRegistry()
	for _, imp := range []importer.Importer{
		importer.NewPlainDomainsImporter(), importer.NewPlainSubdomainsImporter(),
		importer.NewPlainURLsImporter(), importer.NewPlainAliveImporter(),
		importer.NewPlainJSImporter(), importer.NewPlainIPsImporter(),
		importer.NewPlainCIDRsImporter(),
		importer.NewJSONHttpxImporter(), importer.NewJSONDnsxImporter(),
		importer.NewJSONNaabuImporter(), importer.NewJSONKatanaImporter(),
		importer.NewJSONNucleiImporter(),
		importer.NewXMLBurpImporter(), importer.NewXMLZapImporter(),
		importer.NewArchiveCDXImporter(), importer.NewArchiveWARCImporter(),
		importer.NewJSONGenericImporter(), importer.NewPlainGenericImporter(),
	} {
		if err := reg.Register(imp); err != nil {
			panic(fmt.Sprintf("adapt: compose ingest registry: %v", err))
		}
	}
	reg.Seal()
	return &ingestStage{registry: reg}
}

// Name implements pipeline.Stage.
func (s *ingestStage) Name() pipeline.StageName { return pipeline.StageIngest }

// ingestFileStatus is one file's coarse terminal status.
type ingestFileStatus int

const (
	ingestCompleted ingestFileStatus = iota
	ingestPartial
	ingestFailed
	ingestCancelled
)

// ingestCacheState records whether a file job was served from cache,
// executed after a miss, or ran with caching disabled/unavailable. Test
// observability only.
type ingestCacheState int

const (
	cacheStateNone ingestCacheState = iota
	cacheStateMiss
	cacheStateHit
)

// ingestFileOutcome is one file job's retained result.
type ingestFileOutcome struct {
	status     ingestFileStatus
	sink       *ingestSinkData
	stats      importer.ImportStats
	err        error
	cacheState ingestCacheState
}

// ingestSinkData is the retained output of one file's import: the canonical
// assets plus the provenance sidecar records (identity-keyed).
type ingestSinkData struct {
	Domains    []asset.Domain
	Hosts      []asset.Host
	URLs       []asset.URL
	IPs        []asset.IP
	CIDRs      []string
	JS         []asset.JavaScript
	Findings   []asset.Finding
	Provenance []importer.ProvenanceRecord
}

// empty reports whether the sink view holds nothing at all.
func (d *ingestSinkData) empty() bool {
	return d == nil || (len(d.Domains)+len(d.Hosts)+len(d.URLs)+len(d.IPs)+
		len(d.CIDRs)+len(d.JS)+len(d.Findings)+len(d.Provenance)) == 0
}

// Run implements pipeline.Stage.
func (s *ingestStage) Run(ctx context.Context, in pipeline.StageInput) (pipeline.StageResult, error) {
	if ctx == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: context must not be nil", s.Name())
	}
	if s.registry == nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: no registry composed", s.Name())
	}
	bounds, err := ingestBoundsParam(in.Config)
	if err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: %w", s.Name(), err)
	}
	paths, err := ingestPathsParam(in.Config)
	if err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: %w", s.Name(), err)
	}
	files, err := expandIngestPaths(paths)
	if err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: %w", s.Name(), err)
	}
	if len(files) == 0 {
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("stage %s: %w", s.Name(), err)
			return pipeline.StageResult{Outcome: pipeline.OutcomeCancelled, Err: wrapped}, wrapped
		}
		return pipeline.StageResult{Outcome: pipeline.OutcomeCompleted}, nil
	}

	// One bounded pool for the whole stage (AGENTS §10): explicit max
	// concurrency from the resolved bounds (defensively defaulted for
	// direct out-of-runner use), cancellation propagated, shutdown drained.
	concurrency := in.Bounds.MaxConcurrency
	if concurrency <= 0 {
		concurrency = pipeline.DefaultMaxConcurrency
	}
	queue := in.Bounds.QueueSize
	if queue <= 0 {
		queue = pipeline.DefaultQueueSize
	}
	pool, err := runtime.NewPool(ctx, runtime.Config{
		Concurrency: concurrency,
		QueueSize:   queue,
		Timeout:     in.Bounds.Timeout,
		Rate:        in.Bounds.Rate,
		Burst:       in.Bounds.Burst,
		Clock:       in.Clock,
	})
	if err != nil {
		return pipeline.StageResult{Outcome: pipeline.OutcomeFailed},
			fmt.Errorf("stage %s: create pool: %w", s.Name(), err)
	}

	env := importer.ImportEnv{
		Clock:  ingestEnvClock(in.Clock),
		Bounds: bounds,
	}

	outcomes := make([]ingestFileOutcome, len(files))
	// Every slot starts as cancelled: a job the pool never executed (its
	// context fired while the job sat queued — the forced-shutdown path
	// drops queued work without running Func) keeps this honest
	// placeholder instead of folding as the zero status (completed).
	for i := range outcomes {
		outcomes[i] = ingestFileOutcome{status: ingestCancelled}
	}
	for i, path := range files {
		idx := i
		if _, err := pool.Submit(ctx, runtime.Job{Func: func(jobCtx context.Context) (any, error) {
			outcomes[idx] = s.importOne(jobCtx, env, in.Cache, path, bounds)
			return nil, nil
		}}); err != nil {
			// Submission refused (context cancelled or pool closing): this
			// file and everything after it never ran — record them
			// cancelled honestly and stop submitting.
			cerr := ctx.Err()
			if cerr == nil {
				cerr = err
			}
			for j := i; j < len(files); j++ {
				outcomes[j] = ingestFileOutcome{status: ingestCancelled, err: cerr}
			}
			break
		}
	}
	// Join point (H-2 / NEW-61): the pool itself, never a caller-side
	// WaitGroup. A wg.Done inside the job closure deadlocks on
	// cancellation: the forced-shutdown path drops queued jobs WITHOUT
	// executing their Func, so their Done calls never fire and wg.Wait
	// blocks forever before the deferred pool.Shutdown runs. Shutdown
	// always waits for every worker to reach zero — draining cleanly when
	// the stage context is live, forcing queued and running jobs down and
	// STILL waiting to zero when it has already fired.
	_ = pool.Shutdown(ctx)

	res, execErr := foldIngestOutcomes(in, files, outcomes)
	if res.Outcome == pipeline.OutcomeCancelled && ctx.Err() != nil {
		// Attach the context error so the runner's cancellation
		// classification is unambiguous (isContextError traverses it).
		res.Err = ctx.Err()
	} else if res.Outcome == pipeline.OutcomeFailed && execErr != nil {
		res.Err = fmt.Errorf("stage %s: %w", s.Name(), execErr)
	}
	return res, nil
}

// ingestEnvClock bridges the pipeline clock onto ImportEnv's func() time.Time
// seam (same bridge the discovery adapter applies). A nil pipeline clock —
// direct out-of-runner use — leaves the env clock nil (env.now falls back to
// the wall clock, the documented default).
func ingestEnvClock(clock runtime.Clock) func() time.Time {
	if clock == nil {
		return nil
	}
	return func() time.Time { return clock.Now() }
}

// importOne runs one file through detect → cache-before-execute → Import.
func (s *ingestStage) importOne(ctx context.Context, env importer.ImportEnv, c cache.Cache, path string, bounds importer.Bounds) ingestFileOutcome {
	imp, derr := s.detect(path)
	if derr != nil {
		return ingestFileOutcome{status: ingestFailed, err: derr}
	}

	// Cache-before-execute around the engine call. Any key derivation
	// failure degrades to uncached execution — caching is best-effort,
	// never correctness-bearing.
	if c != nil {
		if parts, kerr := importer.CacheKeyForFile(path, imp, bounds); kerr == nil {
			if key, kerr := cache.NewKey(cache.KeyParts{
				Operation: parts.Operation,
				Target:    parts.Target,
				Config:    parts.Config,
				Tool:      cache.ToolInfo{Name: parts.ToolName, Version: parts.ToolVersion},
			}); kerr == nil {
				if out := c.Get(ctx, key); out.IsHit() {
					payload, serr := decodeIngestCache(out.Record.Data, parts, imp)
					if serr == nil {
						return ingestFileOutcome{
							status:     ingestStatusFromStats(payload.Stats),
							sink:       payload.toSinkData(),
							stats:      payload.Stats,
							cacheState: cacheStateHit,
						}
					}
					// Semantically wrong record: self-heal by deleting and
					// falling through to a fresh execution (mirrors the
					// discovery engine's decodeStored contract).
					_ = c.Delete(ctx, key)
				}
				sink, stats, execErr := s.execute(ctx, env, imp, path)
				if execErr == nil {
					storeIngestCache(ctx, c, key, parts, newIngestCachePayload(imp, parts.Target, sink, stats))
				}
				return ingestFileOutcome{
					status:     ingestStatusFromStatsWithErr(ctx, stats, execErr),
					sink:       sink,
					stats:      stats,
					err:        execErr,
					cacheState: cacheStateMiss,
				}
			}
		}
	}

	sink, stats, execErr := s.execute(ctx, env, imp, path)
	return ingestFileOutcome{
		status:     ingestStatusFromStatsWithErr(ctx, stats, execErr),
		sink:       sink,
		stats:      stats,
		err:        execErr,
		cacheState: cacheStateNone,
	}
}

// detect buffers the file's first PeekSize bytes once and asks the sealed
// registry for ordered matches; the top match wins (primary wins on
// ambiguity, per Detect's confidence desc / Name asc ordering with generic
// fallbacks last).
func (s *ingestStage) detect(path string) (importer.Importer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open for detection: %w", err)
	}
	peek := make([]byte, importer.PeekSize)
	n, rerr := io.ReadFull(f, peek)
	cerr := f.Close()
	if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
		return nil, fmt.Errorf("read detection peek: %w", rerr)
	}
	if cerr != nil {
		return nil, fmt.Errorf("close after detection peek: %w", cerr)
	}
	matches := s.registry.Detect(path, peek[:n])
	if len(matches) == 0 {
		return nil, fmt.Errorf("no importer claims %s", filepath.Base(path))
	}
	return matches[0].Importer, nil
}

// execute runs the importer engine into a fresh sink and snapshots the
// retained output.
func (s *ingestStage) execute(ctx context.Context, env importer.ImportEnv, imp importer.Importer, path string) (*ingestSinkData, importer.ImportStats, error) {
	sink := importer.NewSink()
	stats, err := imp.Import(ctx, env, path, sink)
	if sink == nil {
		return nil, stats, err
	}
	return sinkDataFrom(sink), stats, err
}

// ---- cache payload (D4 slim shape embedded + fidelity extension) ----

// ingestCachePayload is the structured Data stored under an ingest.import
// record by this adapter. The slim D4 shape (importer.ImportCacheData) is
// embedded verbatim; the fidelity extension carries the full canonical
// assets and provenance records so a validated cache hit serves
// byte-identical results (attribution included) instead of identity-only
// skeletons whose provenance would differ from a cold run. Bounded by the
// same effectiveMaxOutput cap that bounded the parse; never raw bytes.
type ingestCachePayload struct {
	importer.ImportCacheData

	Domains  []asset.Domain     `json:"domains,omitempty"`
	Hosts    []asset.Host       `json:"hosts,omitempty"`
	URLs     []asset.URL        `json:"urls,omitempty"`
	IPs      []asset.IP         `json:"ips,omitempty"`
	CIDRs    []string           `json:"cidrs,omitempty"`
	JS       []asset.JavaScript `json:"javascript,omitempty"`
	Findings []asset.Finding    `json:"findings,omitempty"`

	Provenance []importer.ProvenanceRecord `json:"provenance,omitempty"`
}

// newIngestCachePayload snapshots a finished import into the storable
// payload, deriving the slim shape's identity list from the retained assets.
func newIngestCachePayload(imp importer.Importer, target string, sink *ingestSinkData, stats importer.ImportStats) *ingestCachePayload {
	p := &ingestCachePayload{
		ImportCacheData: importer.ImportCacheData{
			SchemaVersion: importer.SchemaVersion,
			Importer:      imp.Name(),
			Target:        target,
			Stats:         stats,
		},
	}
	if sink == nil {
		return p
	}
	p.Domains = sink.Domains
	p.Hosts = sink.Hosts
	p.URLs = sink.URLs
	p.IPs = sink.IPs
	p.CIDRs = sink.CIDRs
	p.JS = sink.JS
	p.Findings = sink.Findings
	p.Provenance = sink.Provenance
	for _, d := range sink.Domains {
		p.Identities = append(p.Identities, d.Identity().String())
	}
	for _, h := range sink.Hosts {
		p.Identities = append(p.Identities, h.Identity().String())
	}
	for _, u := range sink.URLs {
		p.Identities = append(p.Identities, u.Identity().String())
	}
	for _, ip := range sink.IPs {
		p.Identities = append(p.Identities, ip.Identity().String())
	}
	for _, cidr := range sink.CIDRs {
		p.Identities = append(p.Identities, "cidr:"+cidr)
	}
	for _, j := range sink.JS {
		p.Identities = append(p.Identities, j.Identity().String())
	}
	for _, fnd := range sink.Findings {
		p.Identities = append(p.Identities, fnd.Identity().String())
	}
	return p
}

// toSinkData rebuilds the retained sink view from the payload.
func (p *ingestCachePayload) toSinkData() *ingestSinkData {
	return &ingestSinkData{
		Domains:    p.Domains,
		Hosts:      p.Hosts,
		URLs:       p.URLs,
		IPs:        p.IPs,
		CIDRs:      p.CIDRs,
		JS:         p.JS,
		Findings:   p.Findings,
		Provenance: p.Provenance,
	}
}

// validate re-checks a decoded payload against the queried key parts and
// importer and revalidates the assets through the Phase 2 builders (the
// single normalization point). A mismatch means the record is corrupt or
// tampered — the caller deletes it and re-executes fresh.
func (p *ingestCachePayload) validate(parts importer.CacheKeyParts, imp importer.Importer) error {
	if p.SchemaVersion != importer.SchemaVersion {
		return fmt.Errorf("stored ingest record schema %d does not match %d", p.SchemaVersion, importer.SchemaVersion)
	}
	if p.Importer != imp.Name() {
		return fmt.Errorf("stored ingest record importer %q does not match queried %q", p.Importer, imp.Name())
	}
	if p.Target != parts.Target {
		return fmt.Errorf("stored ingest record target %q does not match queried %q", p.Target, parts.Target)
	}
	for i, d := range p.Domains {
		canon, err := asset.NewDomain(d.Name, d.Prov)
		if err != nil || canon.Name != d.Name {
			return fmt.Errorf("stored domain %d (%q) invalid or non-canonical", i, d.Name)
		}
	}
	for i, h := range p.Hosts {
		canon, err := asset.NewHost(h.Name, h.Prov)
		if err != nil || canon.Name != h.Name {
			return fmt.Errorf("stored host %d (%q) invalid or non-canonical", i, h.Name)
		}
	}
	for i, u := range p.URLs {
		canon, err := asset.ParseURL(u.String(), u.Prov)
		if err != nil || canon.String() != u.String() {
			return fmt.Errorf("stored url %d (%q) invalid or non-canonical", i, u.String())
		}
	}
	known := make(map[string]struct{}, len(p.Identities))
	for _, id := range p.Identities {
		known[id] = struct{}{}
	}
	for i, rec := range p.Provenance {
		if rec.Identity == "" {
			continue
		}
		if _, ok := known[rec.Identity]; !ok {
			return fmt.Errorf("stored provenance record %d references unknown identity %q", i, rec.Identity)
		}
	}
	return nil
}

// storeIngestCache marshals and stores the payload best-effort: a marshal
// failure or an oversized (> cache.MaxRecordSize) payload skips caching —
// execution remains the source of truth, and the next run simply re-executes.
// Truncated imports store cache.StatusIncomplete (cache.Get refuses
// non-completed records, so a truncated retained set can never be served as
// a valid hit).
func storeIngestCache(ctx context.Context, c cache.Cache, key cache.Key, parts importer.CacheKeyParts, p *ingestCachePayload) {
	status := cache.StatusCompleted
	if p.Stats.Truncated {
		status = cache.StatusIncomplete
	}
	buf, err := json.Marshal(p)
	if err != nil || len(buf) > cache.MaxRecordSize {
		return
	}
	rec := cache.Record{
		Operation: parts.Operation,
		Target:    parts.Target,
		Tool:      cache.ToolInfo{Name: parts.ToolName, Version: parts.ToolVersion},
		Status:    status,
		Data:      buf,
	}
	_ = c.Put(ctx, key, rec)
}

// decodeIngestCache decodes and validates a stored payload.
func decodeIngestCache(raw json.RawMessage, parts importer.CacheKeyParts, imp importer.Importer) (*ingestCachePayload, error) {
	var p ingestCachePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse stored ingest record: %w", err)
	}
	if err := p.validate(parts, imp); err != nil {
		return nil, err
	}
	return &p, nil
}

// ---- outcome folding ----

// ingestStatusFromStats classifies a finished (nil-error) engine invocation:
// a truncated retained set is partial, everything else completed.
func ingestStatusFromStats(stats importer.ImportStats) ingestFileStatus {
	if stats.Truncated {
		return ingestPartial
	}
	return ingestCompleted
}

// ingestStatusFromStatsWithErr folds an execution error into the status: a
// context cancellation/deadline is cancelled (the honest vocabulary value),
// every other execution error is failed.
func ingestStatusFromStatsWithErr(ctx context.Context, stats importer.ImportStats, err error) ingestFileStatus {
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ingestCancelled
		}
		return ingestFailed
	}
	return ingestStatusFromStats(stats)
}

// foldIngestOutcomes reduces the per-file outcomes (in the deterministic
// sorted-file order) to one StageResult with the documented precedence —
// cancelled > all-failed > any-failed-or-truncated (partial) > completed —
// and merges every honest retained observation into
// Additions/Results/Provenance on EVERY path, including cancelled and failed
// files (LOW-2 convention: the runner merges a failed stage's additions).
// The second return is the deterministic join of the failed files' errors
// (nil unless at least one file failed).
func foldIngestOutcomes(in pipeline.StageInput, files []string, outcomes []ingestFileOutcome) (pipeline.StageResult, error) {
	anyCancelled, anyFailed, anyTruncated, anyCompleted := false, false, false, false
	itemsProcessed, itemsFailed := 0, 0
	flags := make(map[string]bool)
	var errs []error

	additions := pipeline.StageAdditions{}
	results := pipeline.Results{}
	var provenance []importer.ProvenanceRecord

	for i, oc := range outcomes {
		itemsProcessed += oc.stats.ItemsProcessed
		itemsFailed += oc.stats.ItemsFailed
		for k, v := range oc.stats.StickyFlags {
			if v {
				flags[k] = true
			}
		}
		switch oc.status {
		case ingestCompleted:
			anyCompleted = true
		case ingestPartial:
			anyTruncated = true
		case ingestFailed:
			anyFailed = true
			if oc.err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(files[i]), oc.err))
			}
		case ingestCancelled:
			anyCancelled = true
		}
		if oc.sink.empty() {
			continue
		}
		additions.Domains = append(additions.Domains, filterIngestDomains(in.Target, oc.sink.Domains)...)
		additions.Hosts = append(additions.Hosts, pipeline.FilterHosts(in.Target, oc.sink.Hosts)...)
		additions.URLs = append(additions.URLs, filterIngestURLs(in.Target, oc.sink.URLs)...)
		results.IPs = append(results.IPs, oc.sink.IPs...)
		results.JavaScript = append(results.JavaScript, oc.sink.JS...)
		results.Findings = append(results.Findings, oc.sink.Findings...)
		provenance = append(provenance, oc.sink.Provenance...)
	}

	truncated := flags[ingestTruncatedFlag]
	res := pipeline.StageResult{
		ItemsProcessed: itemsProcessed,
		ItemsFailed:    itemsFailed,
		Additions:      additions,
		Results:        results,
		Provenance:     provenance,
	}
	if len(flags) > 0 {
		// Every engine sticky flag survives the fold, not just the
		// truncation marker — a future non-truncation flag must never be
		// silently dropped here.
		res.StickyFlags = flags
	}
	if truncated {
		res.Truncated = true
	}

	switch {
	case anyCancelled:
		res.Outcome = pipeline.OutcomeCancelled
	case anyFailed && !anyCompleted:
		res.Outcome = pipeline.OutcomeFailed
	case anyFailed || anyTruncated:
		res.Outcome = pipeline.OutcomePartial
	default:
		res.Outcome = pipeline.OutcomeCompleted
	}

	var execErr error
	if len(errs) > 0 {
		execErr = errors.Join(errs...)
	}
	return res, execErr
}

// ---- params and path handling ----

// ingestPathsParam reads the "paths" StageParams key: entries separated by
// newlines (preferred — paths may contain commas) or commas when no newline
// is present. Whitespace around entries is trimmed; empty entries dropped.
// Absent or empty yields nil (the stage completes vacuously).
func ingestPathsParam(params map[string]string) ([]string, error) {
	v, ok := params["paths"]
	if !ok || strings.TrimSpace(v) == "" {
		return nil, nil
	}
	seps := "\n"
	if !strings.Contains(v, "\n") {
		seps = "\n,"
	}
	var out []string
	for _, part := range strings.Split(v, seps) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// ingestBoundsParam resolves the optional bound overrides. Invalid values
// are structured errors, never silently ignored (operator configuration must
// not misparse into a different cap).
func ingestBoundsParam(params map[string]string) (importer.Bounds, error) {
	var b importer.Bounds
	if v, ok := params["max_output"]; ok && strings.TrimSpace(v) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n <= 0 {
			return b, fmt.Errorf("invalid max_output %q: must be a positive integer", v)
		}
		b.MaxOutput = n
	}
	if v, ok := params["max_line_bytes"]; ok && strings.TrimSpace(v) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n <= 0 {
			return b, fmt.Errorf("invalid max_line_bytes %q: must be a positive integer", v)
		}
		b.MaxLineBytes = n
	}
	if v, ok := params["max_decompressed_bytes"]; ok && strings.TrimSpace(v) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n <= 0 {
			return b, fmt.Errorf("invalid max_decompressed_bytes %q: must be a positive integer", v)
		}
		b.MaxDecompressedBytes = n
	}
	return b, nil
}

// expandIngestPaths validates each entry (exists; regular file or dir; no
// ".." traversal segments after Clean) and expands directories via a lexical
// (deterministic) walk. The regular-file check follows symlinks at the
// top level (os.Stat), so an operator's symlinked entry works while
// FIFOs/devices are rejected; WalkDir deliberately does NOT follow symlinks
// inside directories (cycle safety), so a directory holding only symlinks
// expands to zero files — that case surfaces a structured error naming the
// directory instead of a silent vacuous success. The expanded list is sorted
// lexically and deduplicated: a file reachable twice (explicitly and under a
// listed directory) is imported exactly once.
func expandIngestPaths(paths []string) ([]string, error) {
	var files []string
	for _, raw := range paths {
		clean := filepath.Clean(raw)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("path %q escapes the working tree (.. segments rejected)", raw)
		}
		info, err := os.Stat(clean)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", clean, err)
		}
		switch {
		case info.Mode().IsRegular():
			files = append(files, clean)
		case info.IsDir():
			before := len(files)
			werr := filepath.WalkDir(clean, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.Type().IsRegular() {
					files = append(files, p)
				}
				return nil
			})
			if werr != nil {
				return nil, fmt.Errorf("walk %s: %w", clean, werr)
			}
			if len(files) == before {
				return nil, fmt.Errorf("directory %s contains no regular input files", clean)
			}
		default:
			return nil, fmt.Errorf("%s is neither a regular file nor a directory (mode %s)", clean, info.Mode())
		}
	}
	sort.Strings(files)
	deduped := make([]string, 0, len(files))
	for i, f := range files {
		if i == 0 || f != files[i-1] {
			deduped = append(deduped, f)
		}
	}
	return deduped, nil
}

// ---- boundary filtering (output side) ----

// filterIngestDomains keeps only domains equal to the declared target (an
// imported domain list may legitimately restate the target; anything else is
// out of scope).
func filterIngestDomains(declared asset.Domain, domains []asset.Domain) []asset.Domain {
	out := make([]asset.Domain, 0, len(domains))
	for _, d := range domains {
		if d.Name == declared.Name {
			out = append(out, d)
		}
	}
	return out
}

// filterIngestURLs drops every URL whose canonical host is not representable
// as an in-domain canonical asset.Host. The port-bearing HostPort is stripped
// through the package's ONE URL-host helper (urlHost, httpprobe.go — H-3 /
// NEW-63: feeding the raw HostPort to asset.NewHost rejected every explicit
// non-default port with a silent skip); IP-literal hosts are dropped — the
// same boundary every adapter applies through filterURLs.
func filterIngestURLs(declared asset.Domain, urls []asset.URL) []asset.URL {
	out := make([]asset.URL, 0, len(urls))
	for _, u := range urls {
		h, ok := urlHost(u)
		if !ok {
			continue
		}
		if pipeline.InDomain(declared, h) {
			out = append(out, u)
		}
	}
	return out
}

// sinkDataFrom snapshots the engine sink into the adapter's retained view.
func sinkDataFrom(s *importer.Sink) *ingestSinkData {
	if s == nil {
		return nil
	}
	return &ingestSinkData{
		Domains:    s.Domains,
		Hosts:      s.Hosts,
		URLs:       s.URLs,
		IPs:        s.IPs,
		CIDRs:      s.CIDRs,
		JS:         s.JS,
		Findings:   s.Findings,
		Provenance: s.ProvenanceRecords,
	}
}
