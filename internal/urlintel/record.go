package urlintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Operation is the stable cache operation name for the URL intelligence
// pipeline. It is part of the Phase 3 cache key payload; changing it
// invalidates every previously stored URL record by construction.
const Operation = "url.ingest"

// maxObservedValues mirrors asset.maxParameterValues (unexported): the
// per-parameter observed-value cap, re-checked at decode time so a tampered
// record can never smuggle more values than the model permits.
const maxObservedValues = 1024

// maxSourceBytes mirrors asset.maxParameterSourceBytes (unexported): the
// per-source name bound, re-checked at decode time so a tampered record can
// never smuggle an oversized source name into the report.
const maxSourceBytes = 128

// urlKey derives the Phase 3 cache key for one (canonical URL, adapter)
// observation.
//
// The key contains every input that materially changes the result: the
// operation ("url.ingest"), the canonical Phase 2 URL identity (raw input
// never reaches a key), the adapter identity (the same URL observed by
// different sources is a different observation — this is the user's
// per-adapter key spec), and the result-relevant ParseParameters flag
// (parameter extraction changes the stored payload). Nothing else:
// timings, timeouts, concurrency, and rate limits never enter a key, and
// the fixed caps (maxRawURLLen, maxParametersPerURL) are constants, so a
// completed entry written under the current caps stays valid under any
// future caps that only retain more.
func urlKey(u asset.URL, adapter string, parseParams bool) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    u.Identity().String(),
		Config: map[string]string{
			"adapter":          adapter,
			"parse_parameters": strconv.FormatBool(parseParams),
		},
	})
}

// storedURL is the structured Data payload of one (canonical URL, adapter)
// cache record. It is never terminal output: the URL, endpoint, and
// parameters are stored as the typed Phase 2 assets (with provenance)
// exactly as they will be served back. The stored URL is ALWAYS in canonical
// form — ingest redacts userinfo at the construction point (see parseRawURL
// in engine.go), so URL.Original equals URL.String() and no credential-bearing
// raw line can reach the record. A record that nonetheless carries userinfo
// in a stored Original (tampering, or a record written by a pre-redaction
// build) is refused at decode time and self-healed, never served as a hit
// (see decodeStoredURL). Relationships and the host asset are
// NOT stored: they are rebuilt deterministically at emit time by graphOf
// from the URL, host, endpoints, and parameters, so a cached observation
// reproduces the exact same graph as a fresh extraction.
type storedURL struct {
	// Target is the canonical URL identity the record belongs to, e.g.
	// "url:http://example.com/p?a=1".
	Target string `json:"target"`
	// URL is the canonical URL asset, always stored in canonical form:
	// Original equals String() (userinfo is redacted at ingest — see
	// parseRawURL), so the record never carries credentials. Decode
	// refuses a stored URL whose non-empty Original differs from String()
	// — userinfo included, parseable or not (tampering or a pre-redaction
	// record) — instead of serving it.
	URL asset.URL `json:"url"`
	// Adapter is the adapter identity the observation came from.
	Adapter string `json:"adapter"`
	// Endpoints are the classified endpoints (GET on the URL). At most one
	// today: GET is the only 6B-observable method (see doc.go).
	Endpoints []asset.Endpoint `json:"endpoints,omitempty"`
	// Parameters are the extracted query parameters, in first-observation
	// order (merged by identity when the same URL was observed repeatedly).
	Parameters []asset.Parameter `json:"parameters,omitempty"`
	// Sources are the observation sources (the adapter name).
	Sources []string `json:"sources,omitempty"`
	// FirstSeen is the earliest and LastSeen the latest observation time.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Overflow reports that parameters were dropped past maxParametersPerURL.
	// Such records are still stored completed — the flag is the honest
	// marker of the incomplete parameter set.
	Overflow bool `json:"overflow,omitempty"`
}

// decodeStoredURL validates and decodes a stored per-URL payload before it
// may be served as a hit. It re-validates the URL through the Phase 2 asset
// model (canonical form required, identity contained in the key's target),
// refuses payloads whose identity fields contradict the queried URL or the
// adapter, re-validates every endpoint (GET on the same URL, canonical) and
// every parameter (query location only, bounds re-checked through
// asset.NewParameter / asset.WithValue so a tampered record can never
// smuggle oversized or control-character names/values), refuses stored URLs
// whose Original is non-empty and not in canonical form — including any
// Original carrying credentials in its userinfo, parseable or not (the
// record's own URL and every endpoint URL: userinfo is preserved in
// Original by the asset model by design, and every legitimate path stores
// the canonical form, so a non-canonical Original can only be tampering or
// a pre-redaction record) — and refuses contradictory time windows
// (LastSeen before FirstSeen) — so a corrupt, tampered, or legacy completed
// record can never produce bogus assets. On any error the caller deletes
// the record and falls through to a fresh extraction (self-healing), never
// serving it as a hit.
func decodeStoredURL(raw json.RawMessage, u asset.URL, adapter string) (storedURL, error) {
	var s storedURL
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("parse stored result: %w", err)
	}
	if s.Target != u.Identity().String() {
		return s, fmt.Errorf("stored result target %q does not match %q", s.Target, u.Identity().String())
	}
	if s.Adapter != adapter {
		return s, fmt.Errorf("stored result adapter %q does not match %q", s.Adapter, adapter)
	}
	// The URL must re-parse canonically and must be the queried URL: a
	// record found under this key whose URL differs could only be tampered
	// with or mis-stored.
	got, err := asset.ParseURL(s.URL.String(), s.URL.Prov)
	if err != nil {
		return s, fmt.Errorf("stored url %q does not parse: %w", s.URL.String(), err)
	}
	if got.String() != s.URL.String() {
		return s, fmt.Errorf("stored url %q is not in canonical form (normalized %q)", s.URL.String(), got.String())
	}
	if got.Identity() != u.Identity() {
		return s, fmt.Errorf("stored url identity %q does not match %q", got.Identity().String(), u.Identity().String())
	}
	// Credential defense at decode time: asset.URL.Original preserves
	// userinfo by design, and a stored record whose Original is non-empty
	// and differs from the canonical String() — a credential-bearing
	// form, for example, or one written by a pre-redaction build of this
	// pipeline — must never be served as a hit: it is refused, deleted,
	// and recomputed by the self-healing path. Fresh records never trip
	// this: ingest redacts userinfo at the construction point
	// (parseRawURL), so Original always equals the canonical String().
	if storedURLCarriesCredentials(s.URL) {
		return s, fmt.Errorf("stored url carries credentials in its original form")
	}
	if len(s.Endpoints) > 1 {
		return s, fmt.Errorf("stored result retains %d endpoints (cap 1)", len(s.Endpoints))
	}
	for _, ep := range s.Endpoints {
		if ep.Method != "GET" {
			return s, fmt.Errorf("stored endpoint method %q is not GET", ep.Method)
		}
		if ep.URL.Identity() != u.Identity() {
			return s, fmt.Errorf("stored endpoint url %q does not match %q", ep.URL.String(), u.Identity().String())
		}
		nep, err := asset.NewEndpoint("GET", ep.URL.String(), ep.Prov)
		if err != nil {
			return s, fmt.Errorf("stored endpoint does not validate: %w", err)
		}
		if nep.Identity() != ep.Identity() {
			return s, fmt.Errorf("stored endpoint is not in canonical form")
		}
		// Same credential defense as the record URL: an endpoint whose
		// Original is non-empty and differs from the canonical form can
		// only be tampering or a pre-redaction record, and must never be
		// served into a report.
		if storedURLCarriesCredentials(ep.URL) {
			return s, fmt.Errorf("stored endpoint url carries credentials in its original form")
		}
	}
	if len(s.Parameters) > maxParametersPerURL {
		return s, fmt.Errorf("stored result retains %d parameters (cap %d)", len(s.Parameters), maxParametersPerURL)
	}
	for _, p := range s.Parameters {
		if p.Location != "query" {
			return s, fmt.Errorf("stored parameter location %q is not query", p.Location)
		}
		if len(p.ObservedValues) == 0 {
			return s, fmt.Errorf("stored parameter %q has no observed values", truncateName(p.Name))
		}
		if len(p.ObservedValues) > maxObservedValues {
			return s, fmt.Errorf("stored parameter %q retains %d values (cap %d)", truncateName(p.Name), len(p.ObservedValues), maxObservedValues)
		}
		// Bounds re-validation through the Phase 2 model: the parameter must
		// be reproducible as a fresh asset. All observed values are checked,
		// not just the first, so a tampered record cannot smuggle an
		// oversized value.
		base, err := asset.NewParameter(p.Name, "query", p.ObservedValues[0], adapter, p.FirstSeen, p.Prov)
		if err != nil {
			return s, fmt.Errorf("stored parameter %q invalid: %w", truncateName(p.Name), err)
		}
		for _, v := range p.ObservedValues[1:] {
			if _, err := asset.WithValue(base, v, adapter, p.LastSeen); err != nil {
				return s, fmt.Errorf("stored parameter %q value invalid: %w", truncateName(p.Name), err)
			}
		}
		if base.Identity() != p.Identity() {
			return s, fmt.Errorf("stored parameter identity %q does not match its name", p.Identity().String())
		}
	}
	if len(s.Sources) == 0 {
		return s, fmt.Errorf("stored result has no sources")
	}
	for _, src := range s.Sources {
		if src == "" {
			return s, fmt.Errorf("stored result has an empty source")
		}
		if len(src) > maxSourceBytes {
			return s, fmt.Errorf("stored result has a source longer than %d bytes", maxSourceBytes)
		}
	}
	if s.FirstSeen.IsZero() || s.LastSeen.IsZero() {
		return s, fmt.Errorf("stored result timestamps are incomplete")
	}
	if s.LastSeen.Before(s.FirstSeen) {
		return s, fmt.Errorf("stored result last_seen %v is before first_seen %v", s.LastSeen, s.FirstSeen)
	}
	return s, nil
}

// storedURLCarriesCredentials reports whether a stored URL asset's Original
// field must be refused at decode time. Every legitimate construction path
// stores the canonical form: ingest redacts userinfo and rebuilds any
// non-canonical Original through the canonical string (parseRawURL in
// engine.go), endpoints are built from the canonical string (extractURL),
// and no merge path introduces a non-canonical Original (asset.MergeURLs
// keeps the first observation's, which is canonical). A stored Original
// that differs from the canonical String() — including one carrying
// userinfo, whether it parses or not (e.g. a control byte in the path, or
// an out-of-range port) — can only belong to a tampered record or one
// written by a pre-redaction build of this pipeline. Fresh records never
// trip this, but such an Original must never be served into a report, so
// decode refuses it (mirrors httpprobe's decode-time refusal).
func storedURLCarriesCredentials(u asset.URL) bool {
	if u.Original == "" {
		return false
	}
	// Any stored Original differing from the canonical form is refused: no
	// legitimate path stores non-canonical Originals (parseRawURL rebuilds
	// them at ingest), and a userinfo-bearing Original that does not even
	// parse (e.g. a control byte in the path) must not slip through a
	// parse-based check into the report.
	if u.Original != u.String() {
		return true
	}
	if orig, oerr := url.Parse(u.Original); oerr == nil && orig.User != nil {
		return true
	}
	return false
}

// truncateName bounds a possibly hostile stored parameter name echoed into
// an error message.
func truncateName(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

// entryToStored renders a completed entry as the structured payload of its
// (URL, adapter) cache record.
func entryToStored(entry URLEntry, adapter string) storedURL {
	return storedURL{
		Target:     entry.URL.Identity().String(),
		URL:        entry.URL,
		Adapter:    adapter,
		Endpoints:  entry.Endpoints,
		Parameters: entry.Parameters,
		Sources:    entry.Sources,
		FirstSeen:  entry.FirstSeen,
		LastSeen:   entry.LastSeen,
		Overflow:   entry.Overflow,
	}
}

// storedToEntry rebuilds the emit entry for a validated stored observation:
// Status completed, Cached true, and the host asset and graph edges rebuilt
// deterministically (they are not stored; see storedURL).
func storedToEntry(s storedURL, u asset.URL) URLEntry {
	prov := asset.Provenance{Source: s.Adapter, DiscoveredAt: s.FirstSeen}
	host := hostOrZero(u, prov)
	return URLEntry{
		URL:           u,
		Host:          host,
		Status:        StatusCompleted,
		Cached:        true,
		Sources:       s.Sources,
		FirstSeen:     s.FirstSeen,
		LastSeen:      s.LastSeen,
		Endpoints:     s.Endpoints,
		Parameters:    s.Parameters,
		Overflow:      s.Overflow,
		Relationships: graphOf(u, host, s.Endpoints, s.Parameters),
	}
}

// lookupURL is the cache-before-execute read side for one (URL, adapter)
// observation. It returns the entry either served from a completed,
// validated, unexpired record (Status completed, Cached true), or with an
// empty Status to fall through to execution (miss, expired, incomplete, or
// discarded unusable records), or already classified failed when the key
// cannot be built.
func lookupURL(ctx context.Context, u asset.URL, e *env) URLEntry {
	key, err := urlKey(u, e.adapter, e.parseParams)
	if err != nil {
		return URLEntry{
			URL:    u,
			Status: StatusFailed,
			Err:    fmt.Errorf("urlintel: %s: build cache key: %w", u.String(), err),
		}
	}
	out := e.cache.Get(ctx, key)
	e.metricsRead()
	if !out.IsHit() {
		// Miss / expired / incomplete / corrupt / schema-incompatible are
		// all "execute" outcomes; only a Get that carries a diagnosis
		// (StateError — the state payloads carry no Err) is surfaced, as a
		// warning, never as a failure: the run falls through to a fresh
		// extraction.
		e.recordCacheDiagnostic(u, "cache get", out.Err)
		return URLEntry{URL: u}
	}

	// Only a completed, unexpired record for the exact key is a hit (the
	// cache enforces that). The record's own identity fields must also
	// match the observation — a record found under this key with different
	// operation or target fields could only be tampered with — and the
	// payload is cross-checked by decodeStoredURL. A record failing either
	// check is deleted and recomputed in this same run (self-healing), so
	// it is never served as a hit and never wedges the observation into
	// repeated failures.
	if out.Record.Operation != Operation || out.Record.Target != u.Identity().String() {
		if delerr := e.cache.Delete(ctx, key); delerr != nil {
			e.recordCacheDiagnostic(u, "delete mismatched cached record", delerr)
		}
		e.recordErr(fmt.Errorf("urlintel: %s: discarded cached record with mismatched identity %q/%q",
			u.String(), out.Record.Operation, out.Record.Target))
		return URLEntry{URL: u}
	}
	st, derr := decodeStoredURL(out.Record.Data, u, e.adapter)
	if derr != nil {
		if delerr := e.cache.Delete(ctx, key); delerr != nil {
			e.recordCacheDiagnostic(u, "delete unusable cached record", delerr)
		}
		e.recordErr(fmt.Errorf("urlintel: %s: discarded unusable cached result: %w", u.String(), derr))
		return URLEntry{URL: u}
	}
	return storedToEntry(st, u)
}

// recordCacheDiagnostic records a cache-operation diagnostic unless the
// cache error wraps a context cancellation or deadline error: cancellation
// is surfaced through entry statuses only (see doc.go, "Cancellation"),
// never as a spurious run diagnostic. All other cache failures remain
// non-fatal warnings.
func (e *env) recordCacheDiagnostic(u asset.URL, what string, err error) {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	e.recordErr(fmt.Errorf("urlintel: %s: %s: %w", u.String(), what, err))
}

// storeURL is the cache write side: it persists the observation as a
// completed Phase 3 record (with Overflow flagged when parameters were
// dropped). Failed and cancelled observations are NEVER stored — a second
// run must re-work them (there is no sub-work to resume, so no partial
// record is written). A cancelled run still persists its terminal completed
// records using a detached, bounded context so the write cannot wedge
// shutdown (Phase 4 convention).
func storeURL(ctx context.Context, u asset.URL, entry URLEntry, e *env) URLEntry {
	if entry.Status != StatusCompleted {
		// Failed / cancelled observations are never cached: a later run
		// must re-work them, and no partial state exists to resume.
		return entry
	}
	key, err := urlKey(u, e.adapter, e.parseParams)
	if err != nil {
		entry.Err = errors.Join(entry.Err, fmt.Errorf("urlintel: %s: build cache key: %w", u.String(), err))
		return entry
	}
	st := entryToStored(entry, e.adapter)
	data, err := json.Marshal(st)
	if err != nil {
		entry.Err = errors.Join(entry.Err, fmt.Errorf("urlintel: %s: encode result: %w", u.String(), err))
		return entry
	}
	rec := cache.Record{
		Operation: Operation,
		Target:    u.Identity().String(),
		Status:    cache.StatusCompleted,
		Meta:      map[string]string{"adapter": e.adapter},
		Data:      data,
	}
	storeCtx := ctx
	if ctx.Err() != nil {
		var scancel context.CancelFunc
		storeCtx, scancel = context.WithTimeout(context.Background(), storeTimeout)
		defer scancel()
	}
	if perr := e.cache.Put(storeCtx, key, rec); perr != nil {
		entry.Err = errors.Join(entry.Err, fmt.Errorf("urlintel: %s: cache put: %w", u.String(), perr))
	} else {
		e.metricsStored()
	}
	return entry
}
