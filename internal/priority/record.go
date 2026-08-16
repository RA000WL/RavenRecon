package priority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Operation is the stable cache operation name for priority scores.
const Operation = "priority.score"

// scoreTolerance is the float slack allowed when re-deriving a stored
// score/interestingness/confidence at decode: engine-produced values are
// exactly round4(compose(...)) plus the JSON round trip, so the tolerance
// only absorbs float noise — anything beyond it is a tampered record.
const scoreTolerance = 1e-9

// signalFingerprint is the canonical form of every signal field that
// materially changes the score. Field order is fixed by the struct (the
// JSON encoding is canonical by construction), and list fields keep their
// given order: reordering a list can reorder emitted factor evidence, so
// two orderings are different results and must not share a key.
//
// Deliberately excluded: FirstSeen and ScoredAt. They are echoed result
// metadata, not score inputs — including them would bust the cache on
// every distinct timestamp while producing bit-identical scores.
type signalFingerprint struct {
	Identity       string         `json:"identity"`
	Kind           string         `json:"kind"`
	Path           string         `json:"path,omitempty"`
	Hostname       string         `json:"hostname,omitempty"`
	EndpointMethod string         `json:"endpoint_method,omitempty"`
	ParameterNames []string       `json:"parameter_names,omitempty"`
	JSBundleBytes  int64          `json:"js_bundle_bytes,omitempty"`
	Technologies   []TechSignal   `json:"technologies,omitempty"`
	Secrets        []SecretSignal `json:"secrets,omitempty"`
	Port           int            `json:"port,omitempty"`
	Service        string         `json:"service,omitempty"`
	Headers        []string       `json:"headers,omitempty"`
	Observations   int            `json:"observations,omitempty"`
}

// fingerprintSignal digests the score-material fields of one signal.
func fingerprintSignal(sig Signal) (string, error) {
	fp := signalFingerprint{
		Identity:       sig.Identity.String(),
		Kind:           string(sig.Kind),
		Path:           sig.Path,
		Hostname:       sig.Hostname,
		EndpointMethod: sig.EndpointMethod,
		ParameterNames: sig.ParameterNames,
		JSBundleBytes:  sig.JSBundleBytes,
		Technologies:   sig.Technologies,
		Secrets:        sig.Secrets,
		Port:           sig.Port,
		Service:        sig.Service,
		Headers:        sig.Headers,
		Observations:   sig.Observations,
	}
	buf, err := json.Marshal(fp)
	if err != nil {
		return "", fmt.Errorf("priority: fingerprint signal: %w", err)
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

// priorityKey builds the cache key for one signal's score. The key covers
// every input that materially changes the stored result:
//
//   - the operation constant "priority.score" (the KeyParts operation);
//   - the cache schema version (inside every cache key by construction);
//   - the priority SchemaVersion and the combined catalog digest — ANY
//     edit to either production catalog (weight, term, regex, threshold,
//     kind, reason, recommendation) changes the digest and invalidates
//     every cached score by construction;
//   - the full normalized asset fingerprint (see signalFingerprint);
//   - the target: the canonical Phase 2 identity string.
//
// Timings, concurrency, rate limits, and the timestamps never enter the
// key.
func priorityKey(sig Signal, digest string) (cache.Key, error) {
	fp, err := fingerprintSignal(sig)
	if err != nil {
		return "", err
	}
	return cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    sig.Identity.String(),
		Config: map[string]string{
			"schema":   strconv.Itoa(SchemaVersion),
			"catalogs": digest,
			"asset":    fp,
		},
	})
}

// storedSurface is the structured payload of one completed score record.
type storedSurface struct {
	Version int          `json:"version"`
	Surface SurfaceAsset `json:"surface"`
}

// encodeStoredSurface serializes one scored surface into a cache record.
// The envelope's CreatedAt is stamped from the STORE time (the run clock),
// never the observation time: TTL is measured from CreatedAt (the Phase 3
// convention). Only completed scores reach this function.
func encodeStoredSurface(s SurfaceAsset, now time.Time) (cache.Record, error) {
	data, err := json.Marshal(storedSurface{Version: SchemaVersion, Surface: s})
	if err != nil {
		return cache.Record{}, fmt.Errorf("priority: encode stored surface: %w", err)
	}
	return cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Operation:     Operation,
		Target:        s.Identity.String(),
		Status:        cache.StatusCompleted,
		CreatedAt:     now.UTC(),
		Data:          data,
	}, nil
}

// decodeStoredSurface strictly re-validates a completed cache record
// before it is served: EVERY violated invariant rejects the record (the
// caller treats it as a miss and evicts it; it is never served, never
// silently re-clamped). Validation covers:
//
//   - the envelope: completed status, this operation, this target, the
//     cache schema version (checked by the cache itself), and the payload
//     version (the priority SchemaVersion — a record from a different
//     engine version is foreign by construction);
//   - the identity: non-zero, equal to the scored signal's identity, kind
//     mirror consistent, and canonically parseable for its kind (URL,
//     endpoint, host, domain, IP, JavaScript, and source-map values
//     re-round-trip through the Phase 2 builders; other kinds must carry
//     a non-empty value);
//   - the level: a known level, and exactly the level the stored score
//     and indicator-category count re-gate to (a level the factors could
//     never produce is tampering or a bug);
//   - every factor passes Factor.validate — including the NaN weight
//     guard — within the maxFactors bound, with indicator factors
//     carrying a bounded recommendation and confidence factors none;
//   - the numbers: score, interestingness, and confidence finite in
//     [0,1] and equal to compose(factors) re-run on the stored factor
//     list through the same pure functions (a factor list that
//     contradicts its own score is tampering or a bug).
func decodeStoredSurface(rec cache.Record, sig Signal) (*SurfaceAsset, error) {
	if rec.Status != cache.StatusCompleted {
		return nil, fmt.Errorf("record status %q is not completed", rec.Status)
	}
	if rec.Operation != Operation {
		return nil, fmt.Errorf("record operation %q != %q", rec.Operation, Operation)
	}
	if rec.Target != sig.Identity.String() {
		return nil, fmt.Errorf("record target does not match the signal identity")
	}
	if len(rec.Data) == 0 {
		return nil, fmt.Errorf("record payload is empty")
	}
	var st storedSurface
	if err := json.Unmarshal(rec.Data, &st); err != nil {
		return nil, fmt.Errorf("decode record payload: %w", err)
	}
	if st.Version != SchemaVersion {
		return nil, fmt.Errorf("record analysis version %d != %d", st.Version, SchemaVersion)
	}

	s := st.Surface
	if err := validateSurfaceInvariants(s, sig); err != nil {
		return nil, err
	}
	return &s, nil
}

// validateSurfaceInvariants checks the decoded surface against the
// engine's own output contract (and against the signal it claims to
// score). It is also the encode-side gate: only surfaces that pass it are
// stored, keeping the cache coherent with the decode checks.
func validateSurfaceInvariants(s SurfaceAsset, sig Signal) error {
	if s.Identity.IsZero() {
		return fmt.Errorf("identity must not be zero")
	}
	if s.Identity != sig.Identity {
		return fmt.Errorf("record identity does not match the signal identity")
	}
	if s.Kind != sig.Kind || s.Kind != s.Identity.Kind {
		return fmt.Errorf("kind mirror is inconsistent")
	}
	if err := validateCanonicalIdentity(s.Identity); err != nil {
		return fmt.Errorf("identity is not canonical: %w", err)
	}
	if _, err := ParsePriorityLevel(s.Level.String()); err != nil {
		return fmt.Errorf("unknown level %q", s.Level)
	}
	for _, v := range []struct {
		what  string
		value float64
	}{
		{"score", s.Score},
		{"interestingness", s.Interestingness},
		{"confidence", s.Confidence},
	} {
		if math.IsNaN(v.value) || v.value < 0 || v.value > 1 {
			return fmt.Errorf("%s %v is NaN or out of [0,1]", v.what, v.value)
		}
	}
	if len(s.Factors) > maxFactors {
		return fmt.Errorf("%d factors over bound %d", len(s.Factors), maxFactors)
	}
	indicatorCategories := 0
	seenGroups := map[string]bool{}
	for i, f := range s.Factors {
		if err := f.validate(); err != nil {
			return fmt.Errorf("factor %d: %w", i, err)
		}
		key := groupKey(f)
		if !seenGroups[key] {
			seenGroups[key] = true
			if key != "confidence" {
				indicatorCategories++
			}
		}
		if strings.HasPrefix(f.Name, "confidence") {
			if f.Recommendation != "" {
				return fmt.Errorf("confidence factor %q carries a recommendation", f.Name)
			}
			continue
		}
		// Recommendation refs resolve: every indicator factor must carry
		// the recommendation its winning catalog entry rendered at score
		// time (the compile-time template bound guarantees the length).
		if f.Recommendation == "" {
			return fmt.Errorf("indicator factor %q carries no recommendation", f.Name)
		}
	}

	score, interestingness, confidence, categories := compose(s.Factors)
	if math.Abs(s.Score-score) > scoreTolerance {
		return fmt.Errorf("score %.4f does not match the recomposed score %.4f from its factors", s.Score, score)
	}
	if math.Abs(s.Interestingness-interestingness) > scoreTolerance {
		return fmt.Errorf("interestingness %.4f does not match the recomposed %.4f", s.Interestingness, interestingness)
	}
	if math.Abs(s.Confidence-confidence) > scoreTolerance {
		return fmt.Errorf("confidence %.4f does not match the recomposed %.4f", s.Confidence, confidence)
	}
	if lv := levelFor(score, categories); s.Level != lv {
		return fmt.Errorf("level %s does not match the re-gated level %s for score %.4f with %d indicator categories",
			s.Level, lv, score, categories)
	}
	if categories != indicatorCategories {
		return fmt.Errorf("recomposed category count %d disagrees with the factor list %d", categories, indicatorCategories)
	}
	return nil
}

// validateCanonicalIdentity checks that an identity value re-parses
// through the Phase 2 builder of its kind and round-trips to the same
// identity. Only canonical identities are cached (the encode-side gate);
// a stored record carrying anything else is foreign or tampered.
func validateCanonicalIdentity(id asset.Identity) error {
	prov := asset.Provenance{}
	same := func(got asset.Identity) error {
		if got != id {
			return fmt.Errorf("value %q round-trips to %q", id.Value, got.String())
		}
		return nil
	}
	switch id.Kind {
	case asset.KindURL:
		u, err := asset.ParseURL(id.Value, prov)
		if err != nil {
			return fmt.Errorf("url %q does not parse: %w", id.Value, err)
		}
		return same(u.Identity())
	case asset.KindEndpoint:
		method, raw, ok := strings.Cut(id.Value, " ")
		if !ok {
			return fmt.Errorf("endpoint value %q lacks a method", id.Value)
		}
		e, err := asset.NewEndpoint(method, raw, prov)
		if err != nil {
			return fmt.Errorf("endpoint %q does not parse: %w", id.Value, err)
		}
		return same(e.Identity())
	case asset.KindHost:
		h, err := asset.NewHost(id.Value, prov)
		if err != nil {
			return fmt.Errorf("host %q does not parse: %w", id.Value, err)
		}
		return same(h.Identity())
	case asset.KindDomain:
		d, err := asset.NewDomain(id.Value, prov)
		if err != nil {
			return fmt.Errorf("domain %q does not parse: %w", id.Value, err)
		}
		return same(d.Identity())
	case asset.KindIP:
		ip, err := asset.NewIP(id.Value, prov)
		if err != nil {
			return fmt.Errorf("ip %q does not parse: %w", id.Value, err)
		}
		return same(ip.Identity())
	case asset.KindJavaScript:
		j, err := asset.NewJavaScript(id.Value, prov)
		if err != nil {
			return fmt.Errorf("javascript %q does not parse: %w", id.Value, err)
		}
		return same(j.Identity())
	case asset.KindSourceMap:
		m, err := asset.NewSourceMap(id.Value, prov)
		if err != nil {
			return fmt.Errorf("source map %q does not parse: %w", id.Value, err)
		}
		return same(m.Identity())
	}
	// Remaining kinds (port, service, parameter, technology,
	// secret_candidate, evidence, tls_certificate) embed their own
	// structure in the identity value; the decode seam requires a
	// non-empty value and relies on the kind namespacing.
	if id.Value == "" {
		return fmt.Errorf("identity value is empty")
	}
	return nil
}
