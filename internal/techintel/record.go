package techintel

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// Operation is the stable cache operation name for technology detection.
const Operation = "tech.detect"

// techKey builds the cache key for one observation's detection run. The key
// covers the observation identity; the fingerprint database schema version
// (bumping fingerprints.SchemaVersion invalidates every cached detection by
// construction); the fingerprint database CONTENT digest
// (fingerprints.DB.Digest — ANY data-only edit to the fingerprint tables,
// with no schema bump, changes the digest and invalidates every cached
// detection, so stale detections can never be replayed after a table
// edit); and the sources bitmask (sorted letters: b body, c cookies, d DNS,
// e endpoint, h headers, t TLS). Timings, concurrency, the status code, and
// the fixed analysis caps never enter keys.
func techKey(o Observation, schema int, dbDigest string) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    o.identity().String(),
		Config: map[string]string{
			"schema":    fmt.Sprintf("%d", schema),
			"db_digest": dbDigest,
			"sources":   sourcesMask(o),
		},
	})
}

// storedTech is the structured payload of one completed detection record.
// Technology scores are carried in Prov.Confidence so a cache hit rebuilds
// results with ZERO analysis; levels are stored explicitly because the
// scorer's caps (spoofable-only, lone-weak) are contract, not derivable
// from the score alone. VersionOrdinals persist the DB order of each
// technology's version-bearing indicator (see TechnologyResult), so a
// cache-served contributor takes part in the deterministic merge tie-break
// exactly like a fresh one. The entry's StatusCode is stored too: on a
// cache hit the entry's status code comes from THIS record — it is never
// re-derived from the observation and never enters the cache key.
type storedTech struct {
	Sources         string              `json:"sources"`
	StatusCode      int                 `json:"status_code,omitempty"`
	Technologies    []asset.Technology  `json:"technologies"`
	Levels          []string            `json:"levels"`
	VersionOrdinals []int               `json:"version_ordinals,omitempty"`
	Evidence        []asset.Evidence    `json:"evidence,omitempty"`
	TechEvidence    map[string][]string `json:"tech_evidence,omitempty"`
	Conflicts       int                 `json:"conflicts,omitempty"`
	Truncated       bool                `json:"truncated,omitempty"`
	Overflow        Overflow            `json:"overflow,omitempty"`
	FirstSeen       time.Time           `json:"first_seen"`
	LastSeen        time.Time           `json:"last_seen"`
}

// encodeStoredTech serializes one completed observation's entry into a
// cache record. Failed and cancelled observations never reach this
// function.
//
// The envelope's CreatedAt is stamped from the STORE time (the run clock),
// never from the caller-composed ObservedAt: TTL is measured from
// CreatedAt, so an observation with a stale ObservedAt would otherwise be
// instantly expired and one with a future ObservedAt immortal. The
// observation's own times stay in the payload (FirstSeen/LastSeen) and in
// the asset Provenance timestamps.
func encodeStoredTech(o Observation, entry ReportEntry, mask string, now time.Time) (cache.Record, error) {
	techs := make([]asset.Technology, 0, len(entry.Technologies))
	levels := make([]string, 0, len(entry.Technologies))
	ordinals := make([]int, 0, len(entry.Technologies))
	for _, tr := range entry.Technologies {
		t := tr.Technology
		t.Prov.Confidence = tr.Score
		techs = append(techs, t)
		levels = append(levels, tr.Level.String())
		ordinals = append(ordinals, tr.versionOrdinal)
	}
	st := storedTech{
		Sources:         mask,
		StatusCode:      entry.StatusCode,
		Technologies:    techs,
		Levels:          levels,
		VersionOrdinals: ordinals,
		Evidence:        entry.Evidence,
		TechEvidence:    entry.techEvidence,
		Conflicts:       entry.Conflicts,
		Truncated:       entry.Truncated,
		Overflow:        entry.Overflow,
		FirstSeen:       entry.FirstSeen,
		LastSeen:        entry.LastSeen,
	}
	data, err := json.Marshal(st)
	if err != nil {
		return cache.Record{}, fmt.Errorf("encode stored tech: %w", err)
	}
	return cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Operation:     Operation,
		Target:        o.identity().String(),
		Status:        cache.StatusCompleted,
		CreatedAt:     now.UTC(),
		Data:          data,
	}, nil
}

// decodeStoredTech strictly re-validates a completed cache record before it
// is served. Every violated invariant rejects the record (never served);
// the caller deletes it and recomputes. Validation covers: envelope fields
// (status, schema, operation, target identity containment), JSON payload,
// sources-mask equality, timestamp ordering, parallel-array lengths
// (levels, version ordinals), canonical technology and evidence
// identities, scores in [0,1], levels never stronger than the score allows,
// evidence methods possible for the mask (a body-less record can never
// carry HTML-derived evidence — the truncated-as-completed tamper class),
// tech->evidence links only to retained identities, and counts within the
// current run's caps.
func decodeStoredTech(rec cache.Record, o Observation, wantMask string, capTech, capInd int) (*storedTech, error) {
	if rec.Status != cache.StatusCompleted {
		return nil, fmt.Errorf("record status %q is not completed", rec.Status)
	}
	if rec.SchemaVersion != cache.SchemaVersion {
		return nil, fmt.Errorf("record schema version %d != %d", rec.SchemaVersion, cache.SchemaVersion)
	}
	if rec.Operation != Operation {
		return nil, fmt.Errorf("record operation %q != %q", rec.Operation, Operation)
	}
	if len(rec.Data) == 0 {
		return nil, fmt.Errorf("record payload is empty")
	}
	if rec.Target != o.identity().String() {
		return nil, fmt.Errorf("record target %q != observation identity %q", rec.Target, o.identity().String())
	}

	var s storedTech
	if err := json.Unmarshal(rec.Data, &s); err != nil {
		return nil, fmt.Errorf("decode record payload: %w", err)
	}
	if s.Sources != wantMask {
		return nil, fmt.Errorf("record sources %q != %q", s.Sources, wantMask)
	}
	if len(s.Technologies) != len(s.Levels) {
		return nil, fmt.Errorf("record has %d technologies but %d levels", len(s.Technologies), len(s.Levels))
	}
	if len(s.VersionOrdinals) != len(s.Technologies) {
		return nil, fmt.Errorf("record has %d technologies but %d version ordinals", len(s.Technologies), len(s.VersionOrdinals))
	}
	if len(s.Technologies) > capTech {
		return nil, fmt.Errorf("record has %d technologies over run cap %d", len(s.Technologies), capTech)
	}
	if len(s.Evidence) > capInd {
		return nil, fmt.Errorf("record has %d evidence over run cap %d", len(s.Evidence), capInd)
	}
	if s.FirstSeen.IsZero() || s.LastSeen.IsZero() || s.LastSeen.Before(s.FirstSeen) {
		return nil, fmt.Errorf("record timestamps %v..%v are not ordered", s.FirstSeen, s.LastSeen)
	}

	for i, t := range s.Technologies {
		score := t.Prov.Confidence
		if err := validateStoredScore(t.Name, score); err != nil {
			return nil, err
		}
		// Canonical identity: the stored technology must round-trip through
		// the asset constructor unchanged.
		canon, err := asset.NewTechnology(t.Name, t.Category, t.Prov)
		if err != nil {
			return nil, fmt.Errorf("technology %q is not canonical: %w", t.Name, err)
		}
		if canon.Name != t.Name || canon.Category != t.Category {
			return nil, fmt.Errorf("technology %q diverges from canonical form", t.Name)
		}
		lv, err := ParseConfidenceLevel(s.Levels[i])
		if err != nil {
			return nil, fmt.Errorf("technology %q level: %w", t.Name, err)
		}
		if lv.stronger(levelForScore(score)) {
			return nil, fmt.Errorf("technology %q level %s stronger than score %.3f allows", t.Name, lv, score)
		}
	}

	evIDs := make(map[string]bool, len(s.Evidence))
	for _, ev := range s.Evidence {
		if !methodPossible(s.Sources, ev.Method) {
			return nil, fmt.Errorf("evidence method %q impossible for sources %q", ev.Method, s.Sources)
		}
		rebuilt, err := asset.NewEvidence(ev.Method, ev.Indicator, ev.Value, ev.Source, ev.Prov)
		if err != nil {
			return nil, fmt.Errorf("evidence is not canonical: %w", err)
		}
		if rebuilt.ID() != ev.ID() {
			return nil, fmt.Errorf("evidence identity diverges from canonical form")
		}
		evIDs[ev.ID()] = true
	}
	for techID, ids := range s.TechEvidence {
		for _, id := range ids {
			if !evIDs[id] {
				return nil, fmt.Errorf("technology %q links missing evidence %q", techID, id)
			}
		}
	}
	return &s, nil
}

// validateStoredScore enforces the stored-score contract on one decoded
// technology. NaN is rejected explicitly (defense in depth): encoding/json
// can neither marshal nor unmarshal a NaN float, so a payload stored on
// disk can never carry one — this guard covers a tampered in-memory record
// or a future non-JSON storage format. A NaN score must never pass the
// [0,1] bounds (both comparisons are false for NaN) and reach
// levelForScore, where it would silently fall through every threshold to
// LevelUnknown.
func validateStoredScore(name string, score float64) error {
	if math.IsNaN(score) || score < 0 || score > 1 {
		return fmt.Errorf("technology %q score %v is NaN or out of [0,1]", name, score)
	}
	return nil
}

// methodPossible reports whether a detection method can ever fire under a
// sources mask. It is the tamper guard that makes a body-less record unable
// to carry HTML-derived (or generator/meta/script/css/attribute/sourcemap)
// evidence.
func methodPossible(mask string, m asset.DetectionMethod) bool {
	switch m {
	case asset.MethodHeader:
		return maskHas(mask, 'h')
	case asset.MethodCookie:
		// Cookie evidence fires from caller-provided Cookies ('c') AND from
		// Cookie/Set-Cookie headers ('h'), which the cookie analyzer parses
		// into cookie observations: either family alone can produce it.
		return maskHas(mask, 'c') || maskHas(mask, 'h')
	case asset.MethodHTML, asset.MethodGenerator, asset.MethodMeta,
		asset.MethodScript, asset.MethodCSS, asset.MethodAttribute,
		asset.MethodSourceMap:
		return maskHas(mask, 'b')
	case asset.MethodEndpoint:
		// endpoint_path indicators match the observation URL's path, which
		// every observation carries: endpoint-derived evidence is possible
		// under ANY mask, so the guard cannot reject it.
		return true
	case asset.MethodTLS:
		return maskHas(mask, 't')
	case asset.MethodDNS:
		return maskHas(mask, 'd')
	}
	return false
}
