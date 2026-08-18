package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
)

// SchemaVersion versions the detection framework's record layout and key
// semantics. Bump it when the stored payload structure or the key inputs
// change: a bump invalidates every previously cached rule result by
// construction — the version enters every rule key ("schema" part below)
// and every stored payload (storedFindings.Version, re-validated on
// decode), so old records are both unreachable and rejected.
//
// Version 2: the snapshot fingerprint now covers every observable
// asset.JavaScript field (legacy hash, canonical host name, content type,
// ETag, last-modified, discovery source, status code, final URL) and the
// provenance source of evidence/endpoints and reference of secrets.
const SchemaVersion = 2

// Operation is the stable cache operation name for rule results.
const Operation = "detect.rule"

// maxCachedFindingsPerRule bounds the findings stored in one rule record
// (equal to the engine's per-rule output bound).
const maxCachedFindingsPerRule = 256

// fingerprintTech / fingerprintEvidence / fingerprintSecret /
// fingerprintScript / fingerprintEndp are the canonical per-element forms
// the run fingerprint digests. They cover every observable field a rule can
// read through the Context that materially changes what it can observe:
// technology version, source, reference, and confidence; evidence and
// endpoint source, reference, and confidence (the evidence identity already
// embeds the source asset, which is separate from the provenance source);
// JavaScript — every observation field (legacy hash, canonical host name,
// content hash, size, content type, ETag, last-modified, discovery source,
// status code, final URL) plus provenance source, reference, and confidence;
// secret source, reference, and confidence. Nested assets (the JavaScript
// URL, final URL, and host) enter by their canonical form only — the raw
// Originals and nested provenance are echo metadata, exactly like the core
// asset list's identity-only entries. Relationships carry no provenance in
// the asset model, so their edge ID is the complete observable. Provenance
// timestamps (DiscoveredAt) are deliberately excluded from every form —
// they are echoed metadata that changes every run while producing identical
// findings; including them would bust the cache on every run for zero
// difference.
type fingerprintTech struct {
	Identity   string  `json:"id"`
	Version    string  `json:"version,omitempty"`
	Source     string  `json:"source,omitempty"`
	Reference  string  `json:"reference,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

type fingerprintEvidence struct {
	Identity   string  `json:"id"`
	Source     string  `json:"source,omitempty"`
	Reference  string  `json:"reference,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

type fingerprintSecret struct {
	Identity   string  `json:"id"`
	Source     string  `json:"source,omitempty"`
	Reference  string  `json:"reference,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

type fingerprintScript struct {
	Identity        string  `json:"id"`
	Hash            string  `json:"hash,omitempty"`
	Host            string  `json:"host,omitempty"`
	ContentHash     string  `json:"content_hash,omitempty"`
	Size            int64   `json:"size,omitempty"`
	ContentType     string  `json:"content_type,omitempty"`
	ETag            string  `json:"etag,omitempty"`
	LastModified    string  `json:"last_modified,omitempty"`
	DiscoverySource string  `json:"discovery_source,omitempty"`
	StatusCode      int     `json:"status_code,omitempty"`
	FinalURL        string  `json:"final_url,omitempty"`
	Source          string  `json:"source,omitempty"`
	Reference       string  `json:"reference,omitempty"`
	Confidence      float64 `json:"confidence,omitempty"`
}

type fingerprintEndp struct {
	Identity   string  `json:"id"`
	Source     string  `json:"source,omitempty"`
	Reference  string  `json:"reference,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// snapshotFingerprint is the canonical form of every snapshot domain the
// fingerprint digests. All lists are sorted by identity (normalizeSnapshot
// guarantees it), so the fingerprint is a deterministic function of the
// input corpus.
type snapshotFingerprint struct {
	Assets        []string              `json:"assets,omitempty"`
	Relationships []string              `json:"relationships,omitempty"`
	Evidence      []fingerprintEvidence `json:"evidence,omitempty"`
	Technologies  []fingerprintTech     `json:"technologies,omitempty"`
	Secrets       []fingerprintSecret   `json:"secrets,omitempty"`
	JavaScript    []fingerprintScript   `json:"javascript,omitempty"`
	Endpoints     []fingerprintEndp     `json:"endpoints,omitempty"`
}

// fingerprintSnapshot digests the normalized corpus: every result-relevant
// input a rule can observe. Two corpora whose fingerprints differ can never
// share a cached rule result; two whose fingerprints match produce
// (provably, per the key contract) identical findings.
func fingerprintSnapshot(c *corpus) (string, error) {
	fp := snapshotFingerprint{
		Assets: make([]string, 0, len(c.context.Assets)),
	}
	for _, id := range c.context.Assets {
		fp.Assets = append(fp.Assets, id.String())
	}
	for _, rel := range c.context.Relationships {
		fp.Relationships = append(fp.Relationships, rel.ID())
	}
	for _, ev := range c.context.Evidence {
		fp.Evidence = append(fp.Evidence, fingerprintEvidence{
			Identity:   ev.Identity().Value,
			Source:     ev.Prov.Source,
			Reference:  ev.Prov.Reference,
			Confidence: ev.Prov.Confidence,
		})
	}
	for _, t := range c.context.Technologies {
		fp.Technologies = append(fp.Technologies, fingerprintTech{
			Identity:   t.Identity().Value,
			Version:    t.Version,
			Source:     t.Prov.Source,
			Reference:  t.Prov.Reference,
			Confidence: t.Prov.Confidence,
		})
	}
	for _, s := range c.context.Secrets {
		fp.Secrets = append(fp.Secrets, fingerprintSecret{
			Identity:   s.Identity().Value,
			Source:     s.Prov.Source,
			Reference:  s.Prov.Reference,
			Confidence: s.Prov.Confidence,
		})
	}
	for _, j := range c.context.JavaScript {
		// Nested assets enter by their canonical form only: the host by its
		// canonical name, the final URL by its canonical identity string.
		// Zero values mean "not observed" and are omitted.
		host := ""
		if !j.Host.Identity().IsZero() {
			host = j.Host.Name
		}
		finalURL := ""
		if !j.FinalURL.IsZero() {
			finalURL = j.FinalURL.String()
		}
		// The observed Last-Modified header time is an observation, not a
		// provenance timestamp: it enters the fingerprint in canonical UTC
		// form, so equal instants in different zones cannot diverge.
		lastModified := ""
		if !j.LastModified.IsZero() {
			lastModified = j.LastModified.UTC().Format(time.RFC3339Nano)
		}
		fp.JavaScript = append(fp.JavaScript, fingerprintScript{
			Identity:        j.Identity().Value,
			Hash:            j.Hash,
			Host:            host,
			ContentHash:     j.ContentHash,
			Size:            j.Size,
			ContentType:     j.ContentType,
			ETag:            j.ETag,
			LastModified:    lastModified,
			DiscoverySource: j.DiscoverySource,
			StatusCode:      j.StatusCode,
			FinalURL:        finalURL,
			Source:          j.Prov.Source,
			Reference:       j.Prov.Reference,
			Confidence:      j.Prov.Confidence,
		})
	}
	for _, e := range c.context.Endpoints {
		fp.Endpoints = append(fp.Endpoints, fingerprintEndp{
			Identity:   e.Identity().Value,
			Source:     e.Prov.Source,
			Reference:  e.Prov.Reference,
			Confidence: e.Prov.Confidence,
		})
	}
	buf, err := json.Marshal(fp)
	if err != nil {
		return "", fmt.Errorf("detect: fingerprint snapshot: %w", err)
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

// ruleFingerprint is the canonical form of a rule's declared metadata. The
// detector closure itself is not fingerprintable: the documented contract is
// that a rule's Version is bumped whenever its logic changes, and the
// version enters both the fingerprint and the key.
type ruleFingerprint struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Version     string   `json:"version"`
	Inputs      []string `json:"inputs"`
	Outputs     []string `json:"outputs"`
	Deps        []string `json:"deps,omitempty"`
	Kinds       []string `json:"kinds,omitempty"`
	Cost        string   `json:"cost"`
	Timeout     string   `json:"timeout"`
	Author      string   `json:"author"`
}

// fingerprintRule digests the rule's declared metadata.
func fingerprintRule(r Rule) string {
	fp := ruleFingerprint{
		ID: r.ID, Name: r.Name, Description: r.Description,
		Category: r.Category.String(), Version: r.Version,
		Inputs: make([]string, 0, len(r.Inputs)), Outputs: make([]string, 0, len(r.Outputs)),
		Deps: r.Dependencies, Cost: r.EstimatedCost.String(),
		Timeout: r.Timeout.String(), Author: r.Author,
	}
	for _, in := range r.Inputs {
		fp.Inputs = append(fp.Inputs, string(in))
	}
	for _, out := range r.Outputs {
		fp.Outputs = append(fp.Outputs, string(out))
	}
	for _, k := range r.RequiredAssetTypes {
		fp.Kinds = append(fp.Kinds, string(k))
	}
	buf, err := json.Marshal(fp)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// ruleKey builds the cache key for one rule's findings. The key covers
// every input that materially changes the stored result:
//
//   - the operation constant "detect.rule" and the cache schema version
//     (inside every cache key by construction);
//   - the detect SchemaVersion;
//   - the rule identity: the rule ID (the target) plus the fingerprint of
//     the rule's full declared metadata, including its version — any edit
//     that bumps the version invalidates the rule's cached results;
//   - the fingerprint of the normalized snapshot (the rule's inputs);
//   - every run configuration entry (prefixed "cfg:") delivered to rules.
//
// Timings, concurrency, rate limits, and the pool's knobs never enter the
// key.
func ruleKey(r Rule, snapshotFP string, cfg map[string]string) (cache.Key, error) {
	parts := map[string]string{
		"schema":  strconv.Itoa(SchemaVersion),
		"rule":    fingerprintRule(r),
		"inputs":  snapshotFP,
		"version": r.Version,
	}
	for k, v := range cfg {
		parts["cfg:"+k] = v
	}
	return cache.NewKey(cache.KeyParts{
		Operation: Operation,
		Target:    "rule:" + r.ID,
		Config:    parts,
	})
}

// storedFindings is the structured payload of one completed rule record.
type storedFindings struct {
	Version  int             `json:"version"`
	Findings []asset.Finding `json:"findings"`
}

// encodeStoredFindings serializes one rule's validated findings into a
// completed cache record. Only completed executions reach this function —
// partial executions are never cached.
func encodeStoredFindings(ruleID string, findings []asset.Finding, now time.Time) (cache.Record, error) {
	data, err := json.Marshal(storedFindings{Version: SchemaVersion, Findings: findings})
	if err != nil {
		return cache.Record{}, fmt.Errorf("detect: encode stored findings: %w", err)
	}
	return cache.Record{
		SchemaVersion: cache.SchemaVersion,
		Operation:     Operation,
		Target:        "rule:" + ruleID,
		Status:        cache.StatusCompleted,
		CreatedAt:     now.UTC(),
		Data:          data,
	}, nil
}

// decodeStoredFindings strictly re-validates a completed cache record before
// it is served: the envelope (completed status, this operation, this rule's
// target, a non-empty payload, the payload version) and EVERY finding
// through the same validateFinding the fresh path applies — canonical
// round-trip, executing-rule metadata match (a stored finding that claims a
// different rule is tampering or corruption), vocabulary checks, and
// observed-corpus membership. A rejected record is never served.
func decodeStoredFindings(rec cache.Record, r Rule, observed map[asset.Identity]struct{}) ([]asset.Finding, error) {
	if rec.Status != cache.StatusCompleted {
		return nil, fmt.Errorf("record status %q is not completed", rec.Status)
	}
	if rec.Operation != Operation {
		return nil, fmt.Errorf("record operation %q != %q", rec.Operation, Operation)
	}
	if rec.Target != "rule:"+r.ID {
		return nil, fmt.Errorf("record target %q does not match rule %q", rec.Target, r.ID)
	}
	if len(rec.Data) == 0 {
		return nil, fmt.Errorf("record payload is empty")
	}
	var st storedFindings
	if err := json.Unmarshal(rec.Data, &st); err != nil {
		return nil, fmt.Errorf("decode record payload: %w", err)
	}
	if st.Version != SchemaVersion {
		return nil, fmt.Errorf("record payload version %d != %d", st.Version, SchemaVersion)
	}
	if len(st.Findings) > maxCachedFindingsPerRule {
		return nil, fmt.Errorf("record carries %d findings over bound %d", len(st.Findings), maxCachedFindingsPerRule)
	}
	for i, f := range st.Findings {
		if err := validateFinding(f, r, observed); err != nil {
			return nil, fmt.Errorf("stored finding %d: %w", i, err)
		}
	}
	return st.Findings, nil
}
