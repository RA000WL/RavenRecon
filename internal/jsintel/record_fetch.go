// The js.fetch cache operation: key derivation, the stored record shape,
// decode re-validation, and the cache-before-execute lookup/store sides.
package jsintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Stored-record defense bounds, re-checked at decode time so a tampered or
// corrupt record can never smuggle values past the model. maxStoredContent
// equals the fetch layer's maxMaxJSBytes: a record written under the current
// caps can never exceed it, and a tampered record that does is discarded.
// The record envelope itself is additionally bounded by cache.MaxRecordSize
// (16 MiB).
const (
	maxStoredContent     = 8 << 20 // 8 MiB
	maxStoredSourceBytes = 128
)

// fetchKey derives the Phase 3 cache key for one (canonical URL) fetch
// observation.
//
// The key contains every input that materially changes the result: the
// operation ("js.fetch") and the canonical Phase 2 URL identity. Nothing
// else: the request shape is fixed (GET, canonical URL, fixed user agent,
// no cookies), so there is no result-relevant configuration today, and
// timings, retries, caps, and concurrency NEVER enter a key. In particular
// MaxJSBytes is deliberately absent: cap changes never invalidate entries —
// a completed record stays a complete record under any cap (a lowered cap
// simply means the re-fetch path truncates again), and truncated records are
// never served as hits anyway.
func fetchKey(u asset.URL) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: FetchOperation,
		Target:    u.Identity().String(),
	})
}

// storedFetch is the structured Data payload of one js.fetch cache record.
// It mirrors FetchResult exactly (minus the transient Err) plus the
// observation provenance: Sources, FirstSeen, LastSeen. The content fields
// (Size, Hash, Content) are kept mutually consistent at store time — the
// hash is recomputed from the retained bytes, never trusted from the result
// — and re-validated at decode time.
type storedFetch struct {
	// Target is the canonical URL identity the record belongs to, e.g.
	// "url:http://example.com/app.js".
	Target string `json:"target"`
	// URL is the requested canonical URL asset.
	URL asset.URL `json:"url"`
	// FinalURL is the final URL after redirects; absent when the fetch
	// never dispatched (only reachable through tampering — completed
	// fetches always carry it).
	FinalURL asset.URL `json:"final_url,omitempty"`
	// StatusCode is the final response status; 0 for negative observations.
	StatusCode int `json:"status_code"`
	// ContentType is the captured Content-Type (printable ASCII, ≤ 128).
	ContentType string `json:"content_type,omitempty"`
	// ETag is the captured ETag (≤ 256 bytes).
	ETag string `json:"etag,omitempty"`
	// LastModified is the parsed Last-Modified time; zero when absent.
	LastModified time.Time `json:"last_modified,omitempty"`
	// XSourceMap is the captured X-SourceMap header (≤ 4096 bytes).
	XSourceMap string `json:"x_source_map,omitempty"`
	// ContentLength is the server-declared Content-Length (-1 unknown).
	ContentLength int64 `json:"content_length,omitempty"`
	// Size is the retained content size; 0 when nothing was retained.
	Size int64 `json:"size"`
	// Hash is the lowercase hex SHA-256 of Content; empty when Size is 0.
	Hash string `json:"hash,omitempty"`
	// Content is the retained body (base64 in JSON), ≤ maxStoredContent.
	Content []byte `json:"content,omitempty"`
	// Truncated marks a fetch whose content was not fully retained. Such
	// records are stored under StatusIncomplete (never served as a hit);
	// a completed record never carries Truncated.
	Truncated bool `json:"truncated,omitempty"`
	// Redirects is the number of redirect hops followed (0..MaxRedirects).
	Redirects int `json:"redirects,omitempty"`
	// Reason is the completed-negative cause: "conn_refused" or "tls".
	// Completed positive observations leave it empty.
	Reason string `json:"reason,omitempty"`
	// Sources are the observation sources, non-empty and each ≤ 128 bytes.
	Sources []string `json:"sources,omitempty"`
	// FirstSeen is the earliest and LastSeen the latest observation time.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// decodeStoredFetch validates and decodes a stored js.fetch payload before
// it may be served as a hit. It refuses payloads whose identity fields
// contradict the queried URL, whose content fields are mutually inconsistent
// (truncated-with-content, size/hash mismatches, completed-negatives with
// content), whose hash does not verify against the retained content, whose
// header captures are oversized or non-printable, whose reason is unknown,
// whose sources are missing or oversized, or whose timestamps are inverted —
// so a corrupt, tampered, or legacy completed record can never produce bogus
// observations. On any error the caller deletes the record and falls through
// to a fresh fetch (self-healing), never serving it as a hit.
func decodeStoredFetch(raw json.RawMessage, u asset.URL) (storedFetch, error) {
	var s storedFetch
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("jsintel: parse stored fetch: %w", err)
	}
	if s.Target != u.Identity().String() {
		return s, fmt.Errorf("jsintel: stored fetch target %q does not match %q", truncateStored(s.Target), u.Identity().String())
	}
	// The URL must re-parse canonically and must be the queried URL: a
	// record found under this key whose URL differs could only be tampered
	// with or mis-stored.
	got, err := asset.ParseURL(s.URL.String(), s.URL.Prov)
	if err != nil {
		return s, fmt.Errorf("jsintel: stored fetch url %q does not parse: %w", truncateStored(s.URL.String()), err)
	}
	if got.String() != s.URL.String() {
		return s, fmt.Errorf("jsintel: stored fetch url %q is not in canonical form (normalized %q)", truncateStored(s.URL.String()), got.String())
	}
	if got.Identity() != u.Identity() {
		return s, fmt.Errorf("jsintel: stored fetch url identity %q does not match %q", got.Identity().String(), u.Identity().String())
	}
	// The final URL, when set, must re-parse canonically (it legitimately
	// differs from the queried URL: a redirect target).
	if s.FinalURL != (asset.URL{}) {
		fu, err := asset.ParseURL(s.FinalURL.String(), s.FinalURL.Prov)
		if err != nil {
			return s, fmt.Errorf("jsintel: stored final url %q does not parse: %w", truncateStored(s.FinalURL.String()), err)
		}
		if fu.String() != s.FinalURL.String() {
			return s, fmt.Errorf("jsintel: stored final url %q is not in canonical form (normalized %q)", truncateStored(s.FinalURL.String()), fu.String())
		}
	}
	if s.StatusCode < 0 || s.StatusCode > 599 || (s.StatusCode > 0 && s.StatusCode < 100) {
		return s, fmt.Errorf("jsintel: stored fetch status code %d out of range", s.StatusCode)
	}
	if len(s.ContentType) > maxContentTypeBytes || !printableASCII(s.ContentType) {
		return s, fmt.Errorf("jsintel: stored content type is not printable ASCII within %d bytes", maxContentTypeBytes)
	}
	if len(s.ETag) > maxETagBytes || !printableASCII(s.ETag) {
		return s, fmt.Errorf("jsintel: stored etag is not printable ASCII within %d bytes", maxETagBytes)
	}
	if len(s.XSourceMap) > maxSourceMapBytes || !printableASCII(s.XSourceMap) {
		return s, fmt.Errorf("jsintel: stored x-source-map is not printable ASCII within %d bytes", maxSourceMapBytes)
	}
	if !s.LastModified.IsZero() && s.LastModified.Year() > 9999 {
		return s, fmt.Errorf("jsintel: stored last_modified year %d is out of range", s.LastModified.Year())
	}
	if s.ContentLength < -1 {
		return s, fmt.Errorf("jsintel: stored content_length %d is out of range", s.ContentLength)
	}
	// Content invariants: a truncated record retains nothing; a completed
	// record's size, hash, and content must agree exactly (the hash is
	// verified against the retained bytes, so a tampered content cannot be
	// served under a stale hash).
	if s.Truncated {
		if len(s.Content) != 0 || s.Size != 0 {
			return s, fmt.Errorf("jsintel: truncated stored fetch retains content")
		}
		if s.Hash != "" {
			return s, fmt.Errorf("jsintel: truncated stored fetch retains a hash")
		}
	} else {
		if int64(len(s.Content)) != s.Size {
			return s, fmt.Errorf("jsintel: stored fetch size %d does not match content length %d", s.Size, len(s.Content))
		}
		if len(s.Content) > maxStoredContent {
			return s, fmt.Errorf("jsintel: stored fetch retains %d bytes (cap %d)", len(s.Content), maxStoredContent)
		}
		if s.Size > 0 {
			if len(s.Hash) != 64 || !lowerHex(s.Hash) {
				return s, fmt.Errorf("jsintel: stored fetch hash %q is not 64 lowercase hex digits", truncateStored(s.Hash))
			}
			sum := sha256.Sum256(s.Content)
			if s.Hash != hex.EncodeToString(sum[:]) {
				return s, fmt.Errorf("jsintel: stored fetch hash does not verify against the retained content")
			}
		} else if s.Hash != "" {
			return s, fmt.Errorf("jsintel: stored fetch carries a hash without content")
		}
	}
	// Completed-negative records (conn_refused / tls) carry no response
	// observation; any other reason is unknown.
	switch s.Reason {
	case "", "conn_refused", "tls":
	default:
		return s, fmt.Errorf("jsintel: stored fetch reason %q is unknown", truncateStored(s.Reason))
	}
	if s.Reason != "" {
		if len(s.Content) != 0 || s.Size != 0 || s.StatusCode != 0 || s.Hash != "" {
			return s, fmt.Errorf("jsintel: completed-negative stored fetch carries a response observation")
		}
	}
	if len(s.Sources) == 0 {
		return s, fmt.Errorf("jsintel: stored fetch has no sources")
	}
	for _, src := range s.Sources {
		if src == "" {
			return s, fmt.Errorf("jsintel: stored fetch has an empty source")
		}
		if len(src) > maxStoredSourceBytes {
			return s, fmt.Errorf("jsintel: stored fetch has a source longer than %d bytes", maxStoredSourceBytes)
		}
	}
	if s.FirstSeen.IsZero() || s.LastSeen.IsZero() {
		return s, fmt.Errorf("jsintel: stored fetch timestamps are incomplete")
	}
	if s.LastSeen.Before(s.FirstSeen) {
		return s, fmt.Errorf("jsintel: stored fetch last_seen %v is before first_seen %v", s.LastSeen, s.FirstSeen)
	}
	if s.Redirects < 0 || s.Redirects > MaxRedirects {
		return s, fmt.Errorf("jsintel: stored fetch redirects %d out of range", s.Redirects)
	}
	return s, nil
}

// printableASCII reports whether s contains only printable ASCII bytes.
// The empty string is printable (vacuous truth): absent optional fields are
// valid.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// lowerHex reports whether s consists solely of lowercase hex digits.
func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// truncateStored bounds a possibly hostile stored value echoed into an error
// message.
func truncateStored(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

// fetchLookup is the outcome of one cache lookup: a validated hit with its
// provenance window, or a fall-through to execution (miss, expired,
// incomplete, or a discarded unusable record). Err is a diagnostic (key
// build failure, discarded record, cache error) — never fatal; the caller
// falls through to a fresh fetch and reports the diagnostic.
type fetchLookup struct {
	// Result is the reconstructed observation on a hit (Status
	// FetchCompleted, content byte-identical to the stored record). Zero
	// otherwise.
	Result FetchResult
	// FirstSeen and LastSeen are the record's observation window on a hit.
	FirstSeen time.Time
	LastSeen  time.Time
	// Hit reports a usable completed record was served.
	Hit bool
	// Err carries the diagnostic of a lookup that could not serve a hit
	// for a non-miss reason (key build failure, cache error, discarded
	// mismatched or unusable record). Nil on a hit and on a clean miss.
	Err error
}

// lookupFetch is the cache-before-execute read side for one fetch
// observation. It returns a usable hit (completed, validated, unexpired
// record for the exact key — zero network requests), or a fall-through to
// execution with an optional diagnostic. The engine performs the lookup
// BEFORE any limiter token wait, so a cache hit performs zero token waits
// and zero network requests.
//
// A hit serves the stored record regardless of the current MaxJSBytes: cap
// changes never invalidate entries, and a completed record stays a complete
// record (see fetchKey). Records failing the identity or decode validation
// are deleted and recomputed in this same run (self-healing), so they are
// never served as hits and never wedge the observation into repeated
// failures. cfg, clock, and source are accepted for the engine's calling
// convention and future use; the lookup itself does not consult them — its
// inputs are the URL, the cache, and the context only.
func lookupFetch(ctx context.Context, u asset.URL, cfg FetchConfig, c cache.Cache, clock runtime.Clock, source string) fetchLookup {
	key, err := fetchKey(u)
	if err != nil {
		return fetchLookup{Err: fmt.Errorf("jsintel: %s: build cache key: %w", u.String(), err)}
	}
	out := c.Get(ctx, key)
	if !out.IsHit() {
		// Miss, expired, incomplete, corrupt, and schema-incompatible are
		// all "execute" outcomes (the cache self-heals corrupt and
		// schema-incompatible entries itself). Only a filesystem-level
		// failure carries a diagnosis; it is surfaced as a warning, never
		// as a failure — the run falls through to a fresh fetch. Cache
		// failures that wrap context cancellation are suppressed: they are
		// not diagnostics, the caller's context is simply done.
		if out.State == cache.StateError && out.Err != nil &&
			!errors.Is(out.Err, context.Canceled) && !errors.Is(out.Err, context.DeadlineExceeded) {
			return fetchLookup{Err: fmt.Errorf("jsintel: %s: cache get: %w", u.String(), out.Err)}
		}
		return fetchLookup{}
	}

	// Only a completed, unexpired record for the exact key is a hit (the
	// cache enforces that). The record's own identity fields must also
	// match the observation — a record found under this key with different
	// operation or target fields could only be tampered with — and the
	// payload is cross-checked by decodeStoredFetch.
	if out.Record.Operation != FetchOperation || out.Record.Target != u.Identity().String() {
		if delerr := c.Delete(ctx, key); delerr != nil {
			return fetchLookup{Err: fmt.Errorf("jsintel: %s: delete mismatched cached record: %w", u.String(), delerr)}
		}
		return fetchLookup{Err: fmt.Errorf("jsintel: %s: discarded cached record with mismatched identity %q/%q",
			u.String(), out.Record.Operation, out.Record.Target)}
	}
	st, derr := decodeStoredFetch(out.Record.Data, u)
	if derr != nil {
		if delerr := c.Delete(ctx, key); delerr != nil {
			return fetchLookup{Err: fmt.Errorf("jsintel: %s: delete unusable cached record: %w", u.String(), delerr)}
		}
		return fetchLookup{Err: fmt.Errorf("jsintel: %s: discarded unusable cached fetch: %w", u.String(), derr)}
	}

	res := FetchResult{
		URL:           u,
		FinalURL:      st.FinalURL,
		StatusCode:    st.StatusCode,
		ContentType:   st.ContentType,
		ETag:          st.ETag,
		LastModified:  st.LastModified,
		XSourceMap:    st.XSourceMap,
		ContentLength: st.ContentLength,
		Size:          st.Size,
		Hash:          st.Hash,
		Content:       st.Content,
		Truncated:     st.Truncated,
		Redirects:     st.Redirects,
		Status:        FetchCompleted,
	}
	switch st.Reason {
	case "conn_refused":
		res.Reason = ReasonConnRefused
	case "tls":
		res.Reason = ReasonTLS
	}
	return fetchLookup{Result: res, FirstSeen: st.FirstSeen, LastSeen: st.LastSeen, Hit: true}
}

// storeFetch is the cache write side for one fetch observation. Completed
// observations — including the completed negatives conn_refused and tls —
// with fully retained content are persisted as completed records. Truncated
// observations are persisted as INCOMPLETE records (never served as a hit; a
// later run re-fetches). Failed and cancelled observations are NEVER stored:
// a second run must re-work them.
//
// The content fields are derived from the retained bytes, never trusted from
// the result: the hash is recomputed and Size is len(Content), so a record
// this layer writes always satisfies the decode invariants. Zero provenance
// timestamps default to the clock; a cancelled run still persists its
// terminal records using a detached, bounded context so the write cannot
// wedge shutdown (Phase 4 convention). Put failures are returned as
// diagnostics, never fatal. cfg is accepted for the engine's calling
// convention and future use; storage derives everything from the result.
func storeFetch(ctx context.Context, cfg FetchConfig, c cache.Cache, clock runtime.Clock, res FetchResult, sources []string, firstSeen, lastSeen time.Time) error {
	if res.Status != FetchCompleted && res.Status != FetchTruncated {
		// Failed / cancelled observations are never cached: a later run
		// must re-work them, and no partial state exists to resume.
		return nil
	}
	if clock == nil {
		clock = wallClock{}
	}
	if firstSeen.IsZero() {
		firstSeen = clock.Now().UTC()
	}
	if lastSeen.IsZero() {
		lastSeen = firstSeen
	}
	if lastSeen.Before(firstSeen) {
		lastSeen = firstSeen
	}
	// A record this layer writes must never be rejected by its own decode:
	// sources must be present and bounded.
	if len(sources) == 0 {
		return fmt.Errorf("jsintel: store fetch %s: no sources", res.URL.String())
	}
	for _, src := range sources {
		if src == "" {
			return fmt.Errorf("jsintel: store fetch %s: empty source", res.URL.String())
		}
		if len(src) > maxStoredSourceBytes {
			return fmt.Errorf("jsintel: store fetch %s: source longer than %d bytes", res.URL.String(), maxStoredSourceBytes)
		}
	}

	st := storedFetch{
		Target:        res.URL.Identity().String(),
		URL:           res.URL,
		FinalURL:      res.FinalURL,
		StatusCode:    res.StatusCode,
		ContentType:   res.ContentType,
		ETag:          res.ETag,
		LastModified:  res.LastModified,
		XSourceMap:    res.XSourceMap,
		ContentLength: res.ContentLength,
		Truncated:     res.Truncated,
		Redirects:     res.Redirects,
		Sources:       sources,
		FirstSeen:     firstSeen,
		LastSeen:      lastSeen,
	}
	if !res.Truncated && len(res.Content) > 0 {
		st.Content = res.Content
		st.Size = int64(len(res.Content))
		sum := sha256.Sum256(res.Content)
		st.Hash = hex.EncodeToString(sum[:])
	}
	if res.Status == FetchCompleted && res.Reason != ReasonNone {
		st.Reason = string(res.Reason)
	}

	key, err := fetchKey(res.URL)
	if err != nil {
		return fmt.Errorf("jsintel: store fetch %s: build cache key: %w", res.URL.String(), err)
	}
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("jsintel: store fetch %s: encode result: %w", res.URL.String(), err)
	}
	status := cache.StatusCompleted
	if res.Status == FetchTruncated {
		status = cache.StatusIncomplete
	}
	rec := cache.Record{
		Operation: FetchOperation,
		Target:    res.URL.Identity().String(),
		Status:    status,
		Meta:      map[string]string{"source": sources[0]},
		Data:      data,
	}
	storeCtx := ctx
	if ctx.Err() != nil {
		var scancel context.CancelFunc
		storeCtx, scancel = context.WithTimeout(context.Background(), storeTimeout)
		defer scancel()
	}
	if perr := c.Put(storeCtx, key, rec); perr != nil {
		return fmt.Errorf("jsintel: store fetch %s: cache put: %w", res.URL.String(), perr)
	}
	return nil
}
