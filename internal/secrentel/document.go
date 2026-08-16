package secrentel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// DocumentKind identifies the source family a scanned document came from.
// String values are canonical lowercase forms; unknown values are rejected at
// ingest.
type DocumentKind string

// The 11 supported document kinds (Phase 8's source-support list).
const (
	KindJS        DocumentKind = "js"
	KindSourceMap DocumentKind = "sourcemap"
	KindHTML      DocumentKind = "html"
	KindJSON      DocumentKind = "json"
	KindEnv       DocumentKind = "env"
	KindConfig    DocumentKind = "config"
	KindYAML      DocumentKind = "yaml"
	KindXML       DocumentKind = "xml"
	KindGraphQL   DocumentKind = "graphql"
	KindOpenAPI   DocumentKind = "openapi"
	KindHTTP      DocumentKind = "http"
)

// Valid reports whether k is one of the 11 known kinds.
func (k DocumentKind) Valid() bool {
	switch k {
	case KindJS, KindSourceMap, KindHTML, KindJSON, KindEnv, KindConfig,
		KindYAML, KindXML, KindGraphQL, KindOpenAPI, KindHTTP:
		return true
	}
	return false
}

// KnownDocumentKinds returns every kind in canonical sorted order.
func KnownDocumentKinds() []DocumentKind {
	return []DocumentKind{
		KindConfig, KindEnv, KindGraphQL, KindHTML, KindHTTP, KindJS,
		KindJSON, KindOpenAPI, KindSourceMap, KindXML, KindYAML,
	}
}

// Fixed bounds applied to every document at the ingest boundary. They are
// deliberately not configuration (mirroring the other phases' fixed caps):
// they bound hostile input, never change results for in-bounds documents,
// and never enter cache keys (the scanned-prefix identity does).
const (
	// MaxDocumentBytes bounds how much of one document is scanned. Larger
	// documents are scanned as an honest truncated prefix: candidates are
	// still reported for the run, but the entry is marked Truncated, stored
	// incomplete, and never served from cache.
	MaxDocumentBytes = 2 << 20 // 2 MiB
	// maxFilenameBytes bounds the document filename hint.
	maxFilenameBytes = 512
	// maxRepoBytes bounds the repository path.
	maxRepoBytes = 512
	// maxTechPerDocument bounds the caller-provided technology hints.
	maxTechPerDocument = 32
	// maxTechNameBytes bounds each technology name.
	maxTechNameBytes = 64
	// maxSourceNameBytes bounds the provenance source name.
	maxSourceNameBytes = 128
	// maxHostnameBytes bounds the hostname hint.
	maxHostnameBytes = 253
)

// Document is the ingest seam: one bounded piece of content to scan, with
// the metadata the confidence model consumes. Documents are caller-composed
// (the engine never fetches), mirroring techintel observations.
type Document struct {
	// Kind is the source family (required).
	Kind DocumentKind

	// Content is the raw content to scan. Documents over MaxDocumentBytes
	// are truncated at ingest to an honest scanned prefix (Truncated flag).
	Content []byte

	// URL is the optional canonical URL the content came from (built
	// through asset.ParseURL; never a raw string).
	URL *asset.URL

	// SourceAsset is the optional identity of the asset the document came
	// from — for example a JavaScript asset identity from jsintel. When
	// present it becomes the candidates' Source identity (so identical
	// values found by jsintel and secrentel deduplicate to ONE Phase 2
	// candidate) and drives the source→candidate edge kind.
	SourceAsset *asset.Identity

	// Filename is an optional filename or path hint (repo-style input). It
	// feeds the context and false-positive engines.
	Filename string

	// Repo is an optional repository path recorded on results. It does not
	// affect scanning or confidence and never enters a cache key.
	Repo string

	// Hostname optionally names the host the document was observed on; it is
	// derived from URL when absent. It feeds correlation.
	Hostname string

	// Technology carries optional technology names observed on the target
	// (from techintel detections) used as correlation signals.
	Technology []string

	// Source is the provenance source name; defaulted to "secrentel".
	Source string

	// ObservedAt is the observation time; defaulted to the run clock at
	// ingest.
	ObservedAt time.Time
}

// scannedDocument is the normalized, bounded, immutable form the engine
// scans. Built only by prepareDocument — the single normalization point.
type scannedDocument struct {
	kind        DocumentKind
	content     []byte // the scanned prefix (≤ MaxDocumentBytes)
	truncated   bool   // content exceeded the cap and was cut
	url         *asset.URL
	sourceAsset *asset.Identity
	filename    string
	repo        string
	hostname    string
	technology  []string
	source      string
	observedAt  time.Time
	identity    asset.Identity // scan identity: covers every result-relevant input
}

// DocumentRef is the report-level reference to the document a secret was found in.
type DocumentRef struct {
	Kind          DocumentKind `json:"kind"`
	URL           string       `json:"url,omitempty"`
	Hostname      string       `json:"hostname,omitempty"`
	Filename      string       `json:"filename,omitempty"`
	Repo          string       `json:"repo,omitempty"`
	SourceAssetID string       `json:"source_asset,omitempty"`
}

// refOf builds the bounded document reference for reports.
func (d *scannedDocument) ref() DocumentRef {
	r := DocumentRef{Kind: d.kind, Filename: d.filename, Repo: d.repo, Hostname: d.hostname}
	if d.url != nil {
		r.URL = d.url.Original
	}
	if d.sourceAsset != nil {
		r.SourceAssetID = d.sourceAsset.String()
	}
	return r
}

// prepareDocument validates and normalizes one raw Document. It is the ONLY
// construction path of scannedDocument: every bound is enforced here, and
// malformed input is rejected with an error (the reader counts it and moves
// on). The scan identity covers every input that materially changes the
// scan's result: kind, content (scanned prefix), filename, URL identity,
// source asset, hostname, the technology hints, and the provenance source —
// so two documents whose scans differ can never collide on one accumulator
// entry or one cache key. ObservedAt is deliberately excluded: it is
// observation time, not a result-relevant input, so two observations of the
// same document at different times share one identity (timestamps are
// widened on merge, never keyed).
func prepareDocument(d Document, now time.Time) (scannedDocument, error) {
	if !d.Kind.Valid() {
		return scannedDocument{}, fmt.Errorf("unknown document kind %q", d.Kind)
	}
	if len(d.Filename) > maxFilenameBytes {
		return scannedDocument{}, fmt.Errorf("filename is %d bytes, over bound %d", len(d.Filename), maxFilenameBytes)
	}
	if len(d.Repo) > maxRepoBytes {
		return scannedDocument{}, fmt.Errorf("repo path is %d bytes, over bound %d", len(d.Repo), maxRepoBytes)
	}
	if len(d.Technology) > maxTechPerDocument {
		return scannedDocument{}, fmt.Errorf("%d technology hints over bound %d", len(d.Technology), maxTechPerDocument)
	}
	tech := make([]string, 0, len(d.Technology))
	for _, t := range d.Technology {
		if t == "" || len(t) > maxTechNameBytes {
			return scannedDocument{}, fmt.Errorf("technology hint %q is empty or over %d bytes", t, maxTechNameBytes)
		}
		tech = append(tech, strings.ToLower(t))
	}
	sort.Strings(tech)
	if len(d.Source) > maxSourceNameBytes {
		return scannedDocument{}, fmt.Errorf("source name is %d bytes, over bound %d", len(d.Source), maxSourceNameBytes)
	}
	hostname := strings.ToLower(strings.TrimSpace(d.Hostname))
	if hostname == "" && d.URL != nil {
		hostname = d.URL.HostPort
		if i := strings.LastIndexByte(hostname, ':'); i >= 0 && !strings.Contains(hostname[i:], "]") {
			hostname = hostname[:i]
		}
		hostname = strings.Trim(hostname, "[]")
	}
	if hostname != "" {
		if len(hostname) > maxHostnameBytes {
			return scannedDocument{}, fmt.Errorf("hostname is %d bytes, over bound %d", len(hostname), maxHostnameBytes)
		}
		if _, err := asset.NewHost(hostname, asset.Provenance{}); err != nil {
			return scannedDocument{}, fmt.Errorf("hostname %q: %w", hostname, err)
		}
	}

	src := d.Source
	if src == "" {
		src = "secrentel"
	}
	observed := d.ObservedAt
	if observed.IsZero() {
		observed = now
	}

	content := d.Content
	truncated := false
	if len(content) > MaxDocumentBytes {
		content = content[:MaxDocumentBytes]
		truncated = true
	}

	sd := scannedDocument{
		kind:        d.Kind,
		content:     content,
		truncated:   truncated,
		url:         d.URL,
		sourceAsset: d.SourceAsset,
		filename:    d.Filename,
		repo:        d.Repo,
		hostname:    hostname,
		technology:  tech,
		source:      src,
		observedAt:  observed.UTC(),
	}
	sd.identity = sd.deriveIdentity()
	return sd, nil
}

// deriveIdentity computes the scan identity: kind "document", value a
// lowercase hex SHA-256 over every result-relevant input (including the
// provenance source: scans of the same content under different sources must
// never share one identity, an accumulator entry, or a cache key). Raw
// content bytes never appear in the identity (only their digest), so the
// identity is safe for cache keys and path-free. Deterministic: equal
// inputs always produce equal identities; any result-relevant difference
// produces a different one.
func (d scannedDocument) deriveIdentity() asset.Identity {
	h := sha256.New()
	writeField := func(tag byte, s string) {
		h.Write([]byte{tag, byte(len(s) >> 8), byte(len(s))}) // length-prefixed, unambiguous
		h.Write([]byte(s))
	}
	writeField('k', string(d.kind))
	writeField('c', digestHex(d.content))
	writeField('f', d.filename)
	if d.url != nil {
		writeField('u', d.url.Identity().Value)
	}
	if d.sourceAsset != nil {
		writeField('a', d.sourceAsset.String())
	}
	writeField('p', d.source)
	writeField('h', d.hostname)
	writeField('t', strings.Join(d.technology, "\x00"))
	return asset.Identity{Kind: "document", Value: hex.EncodeToString(h.Sum(nil))}
}

// candidateSource returns the identity used as scanned candidates' Source:
// the source asset when provided (jsintel dedup contract), otherwise the
// scan identity itself.
func (d scannedDocument) candidateSource() asset.Identity {
	if d.sourceAsset != nil && !d.sourceAsset.IsZero() {
		return *d.sourceAsset
	}
	return d.identity
}

// edgeSource returns the identity and relationship kind for the
// source→candidate edges: an explicit source asset when provided (a
// JavaScript source uses the Phase 7 kind — jsintel dedup), otherwise a
// canonical URL (the Phase 8 kind); source-less documents emit no edge.
func (d scannedDocument) edgeSource() (asset.Identity, asset.RelationshipKind, bool) {
	if d.sourceAsset != nil && !d.sourceAsset.IsZero() {
		switch d.sourceAsset.Kind {
		case asset.KindJavaScript:
			return *d.sourceAsset, asset.RelationshipJavaScriptToSecretCandidate, true
		case asset.KindURL:
			return *d.sourceAsset, asset.RelationshipURLToSecretCandidate, true
		}
		return asset.Identity{}, "", false
	}
	if d.url != nil {
		return d.url.Identity(), asset.RelationshipURLToSecretCandidate, true
	}
	return asset.Identity{}, "", false
}

// digestHex returns the lowercase hex SHA-256 of b.
func digestHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// techDigest is the stable serialization of technology hints for the cache
// key configuration.
func (d scannedDocument) techDigest() string {
	if len(d.technology) == 0 {
		return ""
	}
	return digestHex([]byte(strings.Join(d.technology, "\x00")))
}

// cacheConfig returns the result-relevant configuration of this document's
// scan for the cache key: the pattern DB schema, the engine analysis
// version, and the metadata the key must cover beyond the target identity
// (the scan identity itself covers content, filename, URL, source asset,
// hostname, technology hints, and the provenance source).
func (d scannedDocument) cacheConfig(schema int) map[string]string {
	cfg := map[string]string{
		"schema": fmt.Sprintf("%d", schema),
		"engine": fmt.Sprintf("%d", analysisVersion),
		"kind":   string(d.kind),
		"source": d.source,
		"tech":   d.techDigest(),
	}
	if d.filename != "" {
		cfg["filename"] = d.filename
	}
	if d.url != nil {
		cfg["url"] = d.url.Identity().Value
	}
	if d.hostname != "" {
		cfg["hostname"] = d.hostname
	}
	return cfg
}

// analysisVersion versions the engine's analysis semantics (factor weights,
// caps, context and correlation rules, and the provenance source in the scan
// identity). Bumping it invalidates every cached scan by construction (it
// enters every cache key) without touching the pattern database's own
// schema.
const analysisVersion = 2
