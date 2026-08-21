// The report accumulator: per-URL merge state, run metrics, and the
// materialized Report view. Mirrors urlintel/report.go in shape.
package jsintel

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// Status classifies one canonical candidate URL's outcome within a run.
//
// Completed entries carry the full observation. Incomplete entries were
// processed but only partially (a truncated fetch retains no content, a
// truncated parse retains a partial analysis — the JS asset, when present,
// is still recorded). Cancelled entries were consumed from the source but
// never processed (run teardown). Failed entries errored before a usable
// observation could be produced. Malformed raw lines are not entries at
// all: they are counted on the Report and never cached.
type Status string

const (
	// StatusCompleted: the URL was fully processed (freshly fetched or
	// served from a completed cache record), including completed negative
	// observations (conn_refused, tls) and completed positives with no JS
	// asset (non-JS content).
	StatusCompleted Status = "completed"
	// StatusIncomplete: the observation is partial — a fetch whose content
	// could not be fully retained (never served from cache), or a parse
	// that hit a parser cap. A JS asset, when recorded, is still honest.
	StatusIncomplete Status = "incomplete"
	// StatusFailed: processing could not produce a usable observation (a
	// failed fetch after retries, or a parse hard error). Never cached.
	StatusFailed Status = "failed"
	// StatusCancelled: the URL was consumed from the source but its work
	// never executed (run cancellation or forced shutdown). Never success.
	StatusCancelled Status = "cancelled"
)

// String returns the stable status label.
func (s Status) String() string { return string(s) }

// statusRank orders the merge priority: completed > incomplete > failed >
// cancelled. The highest-rank observation wins the entry's Status.
func statusRank(s Status) int {
	switch s {
	case StatusCompleted:
		return 4
	case StatusIncomplete:
		return 3
	case StatusFailed:
		return 2
	default:
		return 1
	}
}

// maxEntrySources bounds how many distinct observation sources one JSEntry
// retains. Every source is itself bounded to 128 bytes by Config
// validation (mirroring maxStoredSourceBytes), so the unioned list is
// bounded in both count and size. Beyond the cap, further sources are
// dropped silently.
const maxEntrySources = 32

// JSEntry is the merged emit record for one canonical candidate URL.
//
// It is the merge-at-emit unit: observations of the same candidate URL from
// any number of runs (or duplicate candidates within one run) merge into ONE
// entry. Sources are unioned in first-observation order, FirstSeen is the
// minimum and LastSeen the maximum observation time, and the payload lists
// are deduplicated and bounded by the per-entry caps.
type JSEntry struct {
	// URL is the canonical candidate URL (the entry's identity).
	URL asset.URL

	// Status classifies the outcome (see Status).
	Status Status

	// Cached reports that the observation was served from a completed
	// js.fetch cache record without any network request.
	Cached bool

	// Sources is the unioned, deduplicated list of sources (Config.Source
	// identities) that observed this URL, in first-observation order,
	// bounded to maxEntrySources entries.
	Sources []string

	// FirstSeen is the earliest observation time of this URL.
	FirstSeen time.Time

	// LastSeen is the latest observation time of this URL.
	LastSeen time.Time

	// JS is the observed JavaScript asset; nil when no JS asset was
	// observed (non-JS content, completed negatives, failed/cancelled, or
	// a truncated fetch).
	JS *asset.JavaScript

	// Content is the retained body bytes of the observation's fetch; nil
	// unless Config.RetainContent enabled retention AND the fetch's content
	// was fully retained (a truncated fetch never retains a partial
	// prefix). Bounded by MaxJSBytes per entry. Merged first-seen-wins:
	// the earliest observation's body is the retained one (mirrors the JS
	// asset's earliest-observation-wins rule).
	Content []byte

	// Imports are the javascript_to_javascript edges FROM this file to the
	// canonical URLs of its resolved imports, deduplicated by edge identity
	// and bounded per observation by MaxImportsPerFile. Edges are recorded
	// even when the imported URL was never fetched (depth/total caps).
	Imports []asset.Relationship

	// BareImports are the import specifiers with no relative meaning
	// (react, @scope/pkg, lodash/fp) — the roadmap's third-party library
	// identification — deduplicated, sorted, bounded by MaxImportsPerFile.
	BareImports []string

	// Exports are the module's exported names, deduplicated in
	// first-observation order.
	Exports []string

	// SourceMaps are the source map assets observed for this file
	// (sourceMappingURL comment and/or X-SourceMap header), deduplicated
	// by canonical URL and bounded by MaxSourceMapsPerFile. Detected only:
	// never fetched, never parsed.
	SourceMaps []asset.SourceMap

	// Endpoints are the classified endpoint candidates referenced in this
	// file's string literals, deduplicated by endpoint identity and
	// bounded by MaxEndpointsPerFile.
	Endpoints []asset.Endpoint

	// URLs are the URL assets observed in this file whose canonical
	// host:port differs from the file's own (CDN/external observations),
	// deduplicated by canonical URL and bounded by MaxEndpointsPerFile
	// (each such observation accompanies an endpoint). No edge kind links
	// them in this phase — the URL asset IS the observation.
	URLs []asset.URL

	// Secrets are the secret candidates detected in this file's string
	// literals, deduplicated by candidate identity and bounded by
	// MaxSecretsPerFile. Detection only: never verified.
	Secrets []asset.SecretCandidate

	// Technologies are the technologies detected in this file's content
	// markers, deduplicated by asset identity and bounded by
	// MaxTechPerFile. Prov.Confidence carries the detection score.
	Technologies []asset.Technology

	// Evidence are the per-marker MethodJS evidence records observed in
	// this file, deduplicated by evidence identity and bounded by
	// MaxEvidencePerFile.
	Evidence []asset.Evidence

	// Relationships are ALL typed edges from this entry (imports + source
	// map edges + endpoint/secret/technology/evidence edges),
	// deduplicated by edge identity.
	Relationships []asset.Relationship

	// Err carries the cause for cancelled and failed entries, plus the
	// body-read diagnostic of truncated fetches.
	Err error
}

// isPlaceholder reports whether e is a pre-registered cancelled entry that
// carries no observation (see RunInto's pre-registration). A placeholder is
// a cancelled entry with no timestamps and no cause; a REAL cancelled entry
// always carries its cancellation cause.
func isPlaceholder(e JSEntry) bool {
	return e.Status == StatusCancelled && e.FirstSeen.IsZero() && e.LastSeen.IsZero() && e.Err == nil
}

// mergeEntries merges src's observation of the same URL into dst. Rules:
//
//   - a placeholder dst is replaced wholesale by a real src;
//   - a placeholder src contributes only its sources (a candidate whose job
//     was dropped by shutdown still reports who discovered it) and its
//     cause (never set on a placeholder);
//   - the higher-status-rank observation wins (completed > incomplete >
//     failed > cancelled);
//   - sources are unioned in first-observation order, capped at
//     maxEntrySources;
//   - FirstSeen = min, LastSeen = max;
//   - JS assets merge via asset.MergeJavaScripts (earliest observation
//     wins conflicts);
//   - relationships are deduplicated by edge identity; source maps by
//     identity via asset.MergeSourceMaps; bare imports and exports are
//     unioned (bare imports re-sorted and re-capped at
//     cfg.MaxImportsPerFile);
//   - Cached is sticky (OR).
func mergeEntries(dst *JSEntry, src JSEntry, cfg Config) {
	if isPlaceholder(*dst) && !isPlaceholder(src) {
		*dst = src
		return
	}
	if isPlaceholder(src) {
		// The placeholder carries no observation; keep its discovery
		// sources so a dropped job still reports who found the URL.
		for _, s := range src.Sources {
			if !containsString(dst.Sources, s) {
				dst.Sources = append(dst.Sources, s)
			}
		}
		if dst.Err == nil && src.Err != nil {
			dst.Err = src.Err
		}
		return
	}
	if statusRank(src.Status) > statusRank(dst.Status) {
		dst.Status = src.Status
	}
	for _, s := range src.Sources {
		if len(dst.Sources) >= maxEntrySources {
			break
		}
		if !containsString(dst.Sources, s) {
			dst.Sources = append(dst.Sources, s)
		}
	}
	// A placeholder/cancelled dst carries zero timestamps; a real
	// observation must fill them in rather than compare against zero.
	if dst.FirstSeen.IsZero() || (!src.FirstSeen.IsZero() && src.FirstSeen.Before(dst.FirstSeen)) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
	switch {
	case dst.JS == nil:
		dst.JS = src.JS
	case src.JS != nil:
		if m, err := asset.MergeJavaScripts(*dst.JS, *src.JS); err == nil {
			dst.JS = &m
		}
	}
	dst.Imports = mergeRelationships(dst.Imports, src.Imports)
	dst.Relationships = mergeRelationships(dst.Relationships, src.Relationships)
	dst.BareImports = mergeStringsSorted(dst.BareImports, src.BareImports, cfg.MaxImportsPerFile)
	dst.Exports = mergeStrings(dst.Exports, src.Exports)
	dst.SourceMaps = mergeSourceMaps(dst.SourceMaps, src.SourceMaps, cfg.MaxSourceMapsPerFile)
	dst.Endpoints = mergeEndpoints(dst.Endpoints, src.Endpoints, cfg.MaxEndpointsPerFile)
	dst.URLs = mergeURLAssets(dst.URLs, src.URLs, cfg.MaxEndpointsPerFile)
	dst.Secrets = mergeSecrets(dst.Secrets, src.Secrets, cfg.MaxSecretsPerFile)
	dst.Technologies = mergeTechnologies(dst.Technologies, src.Technologies, cfg.MaxTechPerFile)
	dst.Evidence = mergeEvidence(dst.Evidence, src.Evidence, cfg.MaxEvidencePerFile)
	if dst.Content == nil && src.Content != nil {
		// First-seen wins: the earliest observation's retained body is the
		// entry's (mirrors the JS asset's earliest-observation-wins rule;
		// the placeholder-replacement path above already keeps the real
		// observation's content wholesale).
		dst.Content = src.Content
	}
	dst.Cached = dst.Cached || src.Cached
	dst.Err = joinEntryErrors(dst.Err, src.Err)
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func containsRelationship(rs []asset.Relationship, r asset.Relationship) bool {
	for _, x := range rs {
		if x.ID() == r.ID() {
			return true
		}
	}
	return false
}

// mergeRelationships unions two relationship lists by edge identity,
// preserving dst's order and then src's new edges in first-seen order.
func mergeRelationships(dst, src []asset.Relationship) []asset.Relationship {
	out := append([]asset.Relationship(nil), dst...)
	for _, r := range src {
		if !containsRelationship(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// mergeStrings unions two string lists preserving order and deduplicating.
func mergeStrings(dst, src []string) []string {
	out := append([]string(nil), dst...)
	for _, s := range src {
		if !containsString(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// mergeStringsSorted unions, caps at cap entries, and sorts: the merged
// bare-import list is deterministic regardless of observation order.
func mergeStringsSorted(dst, src []string, cap int) []string {
	out := mergeStrings(dst, src)
	if len(out) > cap {
		out = out[:cap]
	}
	sort.Strings(out)
	return out
}

// mergeSourceMaps unions two source map lists by asset identity, merging
// same-identity observations via asset.MergeSourceMaps and dropping new
// identities beyond the per-entry cap.
func mergeSourceMaps(dst, src []asset.SourceMap, cap int) []asset.SourceMap {
	out := append([]asset.SourceMap(nil), dst...)
	byID := make(map[asset.Identity]int, len(out)+len(src))
	for i, m := range out {
		byID[m.Identity()] = i
	}
	for _, m := range src {
		if idx, ok := byID[m.Identity()]; ok {
			if merged, err := asset.MergeSourceMaps(out[idx], m); err == nil {
				out[idx] = merged
			}
			continue
		}
		if len(out) >= cap {
			continue
		}
		byID[m.Identity()] = len(out)
		out = append(out, m)
	}
	return out
}

// mergeEndpoints unions two endpoint lists by asset identity, merging
// same-identity observations via asset.MergeEndpoints and dropping new
// identities beyond the per-entry cap.
func mergeEndpoints(dst, src []asset.Endpoint, cap int) []asset.Endpoint {
	out := append([]asset.Endpoint(nil), dst...)
	byID := make(map[asset.Identity]int, len(out)+len(src))
	for i, e := range out {
		byID[e.Identity()] = i
	}
	for _, e := range src {
		if idx, ok := byID[e.Identity()]; ok {
			if merged, err := asset.MergeEndpoints(out[idx], e); err == nil {
				out[idx] = merged
			}
			continue
		}
		if len(out) >= cap {
			continue
		}
		byID[e.Identity()] = len(out)
		out = append(out, e)
	}
	return out
}

// mergeURLAssets unions two URL observation lists by canonical identity,
// merging same-identity observations via asset.MergeURLs and dropping new
// identities beyond the per-entry cap.
func mergeURLAssets(dst, src []asset.URL, cap int) []asset.URL {
	out := append([]asset.URL(nil), dst...)
	byID := make(map[asset.Identity]int, len(out)+len(src))
	for i, u := range out {
		byID[u.Identity()] = i
	}
	for _, u := range src {
		if idx, ok := byID[u.Identity()]; ok {
			if merged, err := asset.MergeURLs(out[idx], u); err == nil {
				out[idx] = merged
			}
			continue
		}
		if len(out) >= cap {
			continue
		}
		byID[u.Identity()] = len(out)
		out = append(out, u)
	}
	return out
}

// mergeSecrets unions two secret candidate lists by asset identity, merging
// same-identity observations via asset.MergeSecretCandidates and dropping
// new identities beyond the per-entry cap.
func mergeSecrets(dst, src []asset.SecretCandidate, cap int) []asset.SecretCandidate {
	out := append([]asset.SecretCandidate(nil), dst...)
	byID := make(map[asset.Identity]int, len(out)+len(src))
	for i, s := range out {
		byID[s.Identity()] = i
	}
	for _, s := range src {
		if idx, ok := byID[s.Identity()]; ok {
			if merged, err := asset.MergeSecretCandidates(out[idx], s); err == nil {
				out[idx] = merged
			}
			continue
		}
		if len(out) >= cap {
			continue
		}
		byID[s.Identity()] = len(out)
		out = append(out, s)
	}
	return out
}

// mergeTechnologies unions two technology lists by asset identity, merging
// same-identity observations via asset.MergeTechnologies and dropping new
// identities beyond the per-entry cap.
func mergeTechnologies(dst, src []asset.Technology, cap int) []asset.Technology {
	out := append([]asset.Technology(nil), dst...)
	byID := make(map[asset.Identity]int, len(out)+len(src))
	for i, t := range out {
		byID[t.Identity()] = i
	}
	for _, t := range src {
		if idx, ok := byID[t.Identity()]; ok {
			if merged, err := asset.MergeTechnologies(out[idx], t); err == nil {
				out[idx] = merged
			}
			continue
		}
		if len(out) >= cap {
			continue
		}
		byID[t.Identity()] = len(out)
		out = append(out, t)
	}
	return out
}

// mergeEvidence unions two evidence lists by asset identity, merging
// same-identity observations via asset.MergeEvidence and dropping new
// identities beyond the per-entry cap.
func mergeEvidence(dst, src []asset.Evidence, cap int) []asset.Evidence {
	out := append([]asset.Evidence(nil), dst...)
	byID := make(map[asset.Identity]int, len(out)+len(src))
	for i, e := range out {
		byID[e.Identity()] = i
	}
	for _, e := range src {
		if idx, ok := byID[e.Identity()]; ok {
			if merged, err := asset.MergeEvidence(out[idx], e); err == nil {
				out[idx] = merged
			}
			continue
		}
		if len(out) >= cap {
			continue
		}
		byID[e.Identity()] = len(out)
		out = append(out, e)
	}
	return out
}

// joinEntryErrors folds src's error into dst's. The join is bounded: the
// first 8 individual errors are retained; every further error is only
// counted and reported by a single tail line, so a repeatedly failing
// observation can never grow the entry's Err string without bound.
func joinEntryErrors(dst, src error) error {
	if src == nil {
		return dst
	}
	if dst == nil {
		return src
	}
	const maxEntryErrors = 8
	var kept []error
	var excess int
	if b, ok := dst.(*boundedErrs); ok {
		kept = append([]error(nil), b.errs...)
		excess = b.excess
	} else {
		kept = []error{dst}
	}
	if len(kept) < maxEntryErrors {
		kept = append(kept, src)
	} else {
		excess++
	}
	return &boundedErrs{errs: kept, excess: excess}
}

// boundedErrs is the bounded per-entry error accumulator stored as a
// JSEntry.Err value; see joinEntryErrors.
type boundedErrs struct {
	errs   []error
	excess int
}

func (b *boundedErrs) Error() string {
	var sb strings.Builder
	for i, err := range b.errs {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(err.Error())
	}
	if b.excess > 0 {
		fmt.Fprintf(&sb, "\n... and %d more error(s)", b.excess)
	}
	return sb.String()
}

// Unwrap exposes the retained errors for errors.Is/errors.As traversal.
func (b *boundedErrs) Unwrap() []error { return b.errs }

// normalize sorts every entry's variable-length slices deterministically:
// imports and relationships by edge identity, bare imports and exports
// lexically, source maps by canonical URL, endpoints/secrets/technologies/
// evidence by asset identity, URL observations by canonical URL. Sources
// keep first-observation order (see JSEntry).
func (e *JSEntry) normalize() {
	sort.Slice(e.Imports, func(i, j int) bool { return e.Imports[i].ID() < e.Imports[j].ID() })
	sort.Slice(e.Relationships, func(i, j int) bool { return e.Relationships[i].ID() < e.Relationships[j].ID() })
	sort.Strings(e.BareImports)
	sort.Strings(e.Exports)
	sort.Slice(e.SourceMaps, func(i, j int) bool {
		return e.SourceMaps[i].URL.String() < e.SourceMaps[j].URL.String()
	})
	sort.Slice(e.Endpoints, func(i, j int) bool { return e.Endpoints[i].ID() < e.Endpoints[j].ID() })
	sort.Slice(e.URLs, func(i, j int) bool { return e.URLs[i].String() < e.URLs[j].String() })
	sort.Slice(e.Secrets, func(i, j int) bool { return e.Secrets[i].ID() < e.Secrets[j].ID() })
	sort.Slice(e.Technologies, func(i, j int) bool { return e.Technologies[i].ID() < e.Technologies[j].ID() })
	sort.Slice(e.Evidence, func(i, j int) bool { return e.Evidence[i].ID() < e.Evidence[j].ID() })
}

// Metrics collects run-level work counters. All methods are safe for
// concurrent use (the reader and pool workers increment them). A nil
// *Metrics is legal: every method no-ops.
type Metrics struct {
	mu          sync.Mutex
	lines       int
	candidates  int
	fetches     int
	reads       int
	stores      int
	parses      int
	malformed   int
	truncated   int
	skipped     int
	secretLines int
}

// Snapshot is a consistent point-in-time view of a Metrics.
type Snapshot struct {
	Lines       int // items of kind ItemLine consumed from the source
	Candidates  int // distinct candidate URLs claimed for processing
	Fetches     int // Fetch operations dispatched (cache misses)
	Reads       int // cache lookups performed
	Stores      int // cache records written (completed or incomplete)
	Parses      int // parser invocations
	Malformed   int // candidates rejected as malformed (lines, HTML refs, unsupported-scheme specifiers)
	Truncated   int // truncation events (oversized fetch, capped parse, oversized HTML body)
	Skipped     int // candidates dropped by a cap (MaxScripts, MaxImportDepth, MaxImportsPerFile, MaxSourceMapsPerFile, MaxHTMLScripts, MaxEndpointsPerFile, MaxSecretsPerFile, MaxTechPerFile, MaxEvidencePerFile)
	SecretLines int // lines in the secretfinder "name\t->\tvalue" form
}

// Snapshot returns a consistent point-in-time view of the counters.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{
		Lines:       m.lines,
		Candidates:  m.candidates,
		Fetches:     m.fetches,
		Reads:       m.reads,
		Stores:      m.stores,
		Parses:      m.parses,
		Malformed:   m.malformed,
		Truncated:   m.truncated,
		Skipped:     m.skipped,
		SecretLines: m.secretLines,
	}
}

func (m *Metrics) addLine() {
	if m != nil {
		m.mu.Lock()
		m.lines++
		m.mu.Unlock()
	}
}

func (m *Metrics) addCandidate() {
	if m != nil {
		m.mu.Lock()
		m.candidates++
		m.mu.Unlock()
	}
}

func (m *Metrics) addFetch() {
	if m != nil {
		m.mu.Lock()
		m.fetches++
		m.mu.Unlock()
	}
}

func (m *Metrics) addRead() {
	if m != nil {
		m.mu.Lock()
		m.reads++
		m.mu.Unlock()
	}
}

func (m *Metrics) addStore() {
	if m != nil {
		m.mu.Lock()
		m.stores++
		m.mu.Unlock()
	}
}

func (m *Metrics) addParse() {
	if m != nil {
		m.mu.Lock()
		m.parses++
		m.mu.Unlock()
	}
}

func (m *Metrics) addMalformed(n int) {
	if m != nil && n > 0 {
		m.mu.Lock()
		m.malformed += n
		m.mu.Unlock()
	}
}

func (m *Metrics) addTruncated() {
	if m != nil {
		m.mu.Lock()
		m.truncated++
		m.mu.Unlock()
	}
}

func (m *Metrics) addSkipped(n int) {
	if m != nil && n > 0 {
		m.mu.Lock()
		m.skipped += n
		m.mu.Unlock()
	}
}

func (m *Metrics) addSecretLine() {
	if m != nil {
		m.mu.Lock()
		m.secretLines++
		m.mu.Unlock()
	}
}

// Accumulator is the merge-at-emit state of one or more runs. It is keyed
// by canonical URL identity: observations of the same URL from any number
// of runs (or duplicate candidates within one run) merge into one entry.
//
// An Accumulator is safe for concurrent use: the reader pre-registers
// candidates and pool workers merge their observations into it under a
// mutex.
//
// Memory: the accumulator holds at most one entry per distinct candidate
// URL observed in the run(s); each entry's payload is bounded by the
// per-entry caps (maxEntrySources sources, MaxImportsPerFile bare imports,
// MaxSourceMapsPerFile source maps, MaxEndpointsPerFile endpoints and URL
// observations, MaxSecretsPerFile secrets, MaxTechPerFile technologies,
// MaxEvidencePerFile evidence, the parser's per-parse export cap, and the
// edge caps of extraction). With Config.RetainContent set, each entry
// additionally carries its fully-retained body bytes (JSEntry.Content),
// bounded by MaxJSBytes per entry — the opt-in retention surface
// (Report.RetainedContent). Run-wide, retained content is bounded twice:
// per entry by MaxJSBytes (2 MiB by default) AND in count by the run's
// script caps (MaxScripts, 500 by default — over-cap candidates are
// dropped, never retained), so the worst case is ~1 GiB held by reference
// per run (the merge copies the entry struct, never the body bytes). Off
// by default, so the default memory profile is unchanged: entries carry
// observations only. Consumers that must stream arbitrarily many distinct
// URLs without retention use the Config.Emit hook instead and never
// materialize a Report.
type Accumulator struct {
	mu            sync.Mutex
	cfg           Config
	byURL         map[asset.Identity]*JSEntry
	malformed     int
	healthAborted bool
}

// NewAccumulator returns an empty accumulator. cfg supplies the per-entry
// merge caps and, when non-nil, the run Metrics whose snapshot the Report
// carries; zero caps fall back to the documented defaults.
func NewAccumulator(cfg Config) *Accumulator {
	return &Accumulator{cfg: normalizeCaps(cfg), byURL: make(map[asset.Identity]*JSEntry)}
}

// adopt installs a validated run configuration: merges that happen during
// the run apply its per-entry caps. Called by RunInto after validation.
func (a *Accumulator) adopt(cfg Config) {
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
}

// SetHealthAborted records that the health gate aborted remaining fetches.
// It is set once, sticky, and preserved end-to-end (accumulator → Report).
func (a *Accumulator) setHealthAborted(v bool) {
	a.mu.Lock()
	a.healthAborted = v
	a.mu.Unlock()
}

// isHealthAborted reports whether the health gate triggered.
func (a *Accumulator) isHealthAborted() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.healthAborted
}

// merge folds one observation into the accumulator under the lock.
func (a *Accumulator) merge(src JSEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	dst := a.byURL[src.URL.Identity()]
	if dst == nil {
		c := src
		a.byURL[src.URL.Identity()] = &c
		return
	}
	mergeEntries(dst, src, a.cfg)
}

// remove deletes the entry for id, if present. Used by the health gate to
// abort queued jobs: their pre-registered cancelled placeholder is removed so
// the aborted URL never appears in the report (it is counted Skipped).
func (a *Accumulator) remove(id asset.Identity) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.byURL, id)
}

// addMalformed counts rejected raw lines or HTML references.
func (a *Accumulator) addMalformed(n int) {
	if n <= 0 {
		return
	}
	a.mu.Lock()
	a.malformed += n
	a.mu.Unlock()
}

// Malformed returns the number of rejected raw lines/HTML references so far.
func (a *Accumulator) Malformed() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.malformed
}

// finalizeCancelled stamps the cancellation cause onto every entry that was
// pre-registered but whose job never executed (a cancelled run drops
// not-yet-started jobs before their work can run). Real cancelled
// observations already carry their cause and are untouched; the stamp keeps
// the report honest: every pre-registered candidate of a cancelled run
// reports WHY it was never processed.
func (a *Accumulator) finalizeCancelled(cause error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.byURL {
		if isPlaceholder(*e) {
			e.Err = cause
		}
	}
}

// Report materializes the merged view: every entry normalized (sorted
// imports, relationships, bare imports, exports, source maps), entries
// sorted by canonical URL string, plus the malformed count and the run's
// metric snapshot. It is deterministic for a given set of observations
// regardless of processing order.
func (a *Accumulator) Report() Report {
	a.mu.Lock()
	defer a.mu.Unlock()
	entries := make([]JSEntry, 0, len(a.byURL))
	for _, e := range a.byURL {
		entries = append(entries, *e)
	}
	for i := range entries {
		entries[i].normalize()
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].URL.String() < entries[j].URL.String()
	})
	var snap Snapshot
	if a.cfg.Metrics != nil {
		snap = a.cfg.Metrics.Snapshot()
	}
	return Report{Entries: entries, Malformed: a.malformed, HealthAborted: a.healthAborted, metrics: snap}
}

// Report is the aggregated outcome of one or more runs: the merged,
// deterministically ordered emit entries plus run-level counters. It is a
// plain snapshot; the Accumulator owns the live merge state.
type Report struct {
	// Entries holds one entry per distinct candidate URL, sorted by
	// canonical URL string. Every slice inside an entry is sorted (sources
	// keep first-observation order).
	Entries []JSEntry

	// Malformed counts raw lines and HTML references rejected at the
	// ingest boundary. Malformed inputs are never cached and never appear
	// as entries.
	Malformed int

	// HealthAborted reports whether the health gate aborted remaining fetches:
	// the first 50 fetches had >90% failure, so the run stopped early,
	// emitted the jsintel_health_abort flag, and returned completed. The
	// flag is sticky (accumulator → Report) and is the engine's honest
	// early-stop signal.
	HealthAborted bool

	// metrics is the run's counter snapshot at materialization time.
	metrics Snapshot
}

// Metrics returns the run's counter snapshot. Named Metrics for symmetry
// with Config.Metrics; it returns the immutable Snapshot, never the live
// counter object.
func (r Report) Metrics() Snapshot { return r.metrics }

// RetainedContent is one fully-retained body: the canonical URL it was
// fetched from and the exact bytes, bounded by the run's MaxJSBytes.
// Content is never a truncated prefix — retention only ever carries
// complete bodies.
type RetainedContent struct {
	// URL is the canonical fetched URL.
	URL asset.URL

	// Content is the fully-retained body bytes (bounded by the run's
	// MaxJSBytes).
	Content []byte
}

// RetainedContent returns the run's retained bodies in canonical-URL
// order, deduplicated by URL identity (earliest wins), including only
// entries with non-nil Content — mirroring the report's other merged
// accessors (AllJavaScript, AllSourceMaps, AllRelationships), which
// deduplicate and sort internally rather than relying on the entries'
// invariants. Real reports hold one entry per canonical URL already, so
// the dedup is a no-op there and the order is the entries' canonical
// order; a hand-built report is normalized the same way. The list is
// empty unless Config.RetainContent enabled retention. Content is
// returned by reference — the entry (and the fetch result behind it) owns
// the bytes; consumers must not mutate it.
func (r Report) RetainedContent() []RetainedContent {
	seen := make(map[asset.Identity]struct{}, len(r.Entries))
	var out []RetainedContent
	for _, e := range r.Entries {
		if e.Content == nil {
			continue
		}
		if _, dup := seen[e.URL.Identity()]; dup {
			continue
		}
		seen[e.URL.Identity()] = struct{}{}
		out = append(out, RetainedContent{URL: e.URL, Content: e.Content})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL.String() < out[j].URL.String() })
	return out
}

// StatusCounts returns the number of entries per status. Every status key
// is always present, so consumers can rely on stable keys.
func (r Report) StatusCounts() map[Status]int {
	counts := map[Status]int{
		StatusCompleted:  0,
		StatusIncomplete: 0,
		StatusFailed:     0,
		StatusCancelled:  0,
	}
	for _, e := range r.Entries {
		counts[e.Status]++
	}
	return counts
}

// AllJavaScript merges every entry's JS asset across the report,
// deduplicated by asset identity via asset.MergeJavaScripts (earliest
// observation wins conflicts) and sorted by canonical URL.
func (r Report) AllJavaScript() []asset.JavaScript {
	var list []asset.JavaScript
	for _, e := range r.Entries {
		if e.JS != nil {
			list = append(list, *e.JS)
		}
	}
	return mergeJavaScripts(list)
}

// mergeJavaScripts deduplicates JS assets by identity via
// asset.MergeJavaScripts and sorts by canonical URL.
func mergeJavaScripts(list []asset.JavaScript) []asset.JavaScript {
	byID := make(map[asset.Identity]int)
	var out []asset.JavaScript
	for _, js := range list {
		if idx, ok := byID[js.Identity()]; ok {
			if m, err := asset.MergeJavaScripts(out[idx], js); err == nil {
				out[idx] = m
			}
			continue
		}
		byID[js.Identity()] = len(out)
		out = append(out, js)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL.String() < out[j].URL.String() })
	return out
}

// AllSourceMaps merges every entry's source maps across the report,
// deduplicated by asset identity via asset.MergeSourceMaps and sorted by
// canonical URL.
func (r Report) AllSourceMaps() []asset.SourceMap {
	var list []asset.SourceMap
	for _, e := range r.Entries {
		list = append(list, e.SourceMaps...)
	}
	byID := make(map[asset.Identity]int)
	var out []asset.SourceMap
	for _, m := range list {
		if idx, ok := byID[m.Identity()]; ok {
			if merged, err := asset.MergeSourceMaps(out[idx], m); err == nil {
				out[idx] = merged
			}
			continue
		}
		byID[m.Identity()] = len(out)
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL.String() < out[j].URL.String() })
	return out
}

// AllRelationships merges every entry's relationships across the report,
// deduplicated by edge identity (the same edge observed from two entries —
// e.g. a circular import — is one relationship) and sorted.
func (r Report) AllRelationships() []asset.Relationship {
	seen := make(map[string]struct{})
	var rels []asset.Relationship
	for _, e := range r.Entries {
		for _, rel := range e.Relationships {
			if _, ok := seen[rel.ID()]; ok {
				continue
			}
			seen[rel.ID()] = struct{}{}
			rels = append(rels, rel)
		}
	}
	sortRelationships(rels)
	return rels
}

// sortRelationships orders relationships deterministically by identity.
func sortRelationships(rs []asset.Relationship) []asset.Relationship {
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID() < rs[j].ID() })
	return rs
}
