package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/priority"
)

// Model list bounds (fixed constants). They sit far above the documented
// performance targets (100 .. 100,000 assets) and protect normalization
// memory from runaway caller input. An over-bound list is rejected outright
// — never silently truncated: truncating input would silently change every
// export.
const (
	maxModelHosts         = 200_000
	maxModelURLs          = 200_000
	maxModelEndpoints     = 200_000
	maxModelRelationships = 200_000
	// maxModelPerKind bounds every remaining per-kind list (domains, IPs,
	// ports, services, JavaScript, parameters, technologies, secrets,
	// evidence, findings, TLS certificates, source maps, surfaces).
	maxModelPerKind = 100_000
	maxModelGroups  = 50_000
	maxModelPaths   = 10_000
	maxModelErrors  = 10_000
	// maxModelRecommendations bounds the projected recommendation list.
	maxModelRecommendations = 10_000
)

// maxTargetBytes bounds the declared target string (the DNS name bound).
const maxTargetBytes = 253

// Model is the canonical report model: the deterministic, normalized form
// of one report Context. NewModel validates every entry through the Phase 2
// builders, deduplicates and merges by identity, sorts every list by its
// canonical identity, and computes the statistics, run summary, error
// summary, and digest exactly once. Every renderer — JSON, CSV, Markdown,
// HTML, or any future format — renders from the same Model, so no format
// re-validates, re-sorts, or re-traverses the corpus.
//
// A Model is immutable by contract: renderers must not mutate it, and the
// engine shares one Model across every concurrent render job.
type Model struct {
	// SchemaVersion is the report schema version (always SchemaVersion).
	SchemaVersion int `json:"schema_version"`

	// Target is the run's declared target (display metadata).
	Target string `json:"target"`

	// StartedAt and EndedAt bracket the described run (caller-declared
	// inputs; zero means "unknown").
	StartedAt time.Time `json:"started_at,omitempty"`
	EndedAt   time.Time `json:"ended_at,omitempty"`

	// The normalized corpus: every list sorted by canonical identity,
	// deduplicated, and merged through the Phase 2 merge primitives.
	Domains         []asset.Domain          `json:"domains,omitempty"`
	Hosts           []asset.Host            `json:"hosts,omitempty"`
	IPs             []asset.IP              `json:"ips,omitempty"`
	Ports           []asset.Port            `json:"ports,omitempty"`
	Services        []asset.Service         `json:"services,omitempty"`
	URLs            []asset.URL             `json:"urls,omitempty"`
	Endpoints       []asset.Endpoint        `json:"endpoints,omitempty"`
	JavaScript      []asset.JavaScript      `json:"javascript,omitempty"`
	Parameters      []asset.Parameter       `json:"parameters,omitempty"`
	Technologies    []asset.Technology      `json:"technologies,omitempty"`
	Secrets         []asset.SecretCandidate `json:"secrets,omitempty"`
	Evidence        []asset.Evidence        `json:"evidence,omitempty"`
	Findings        []asset.Finding         `json:"findings,omitempty"`
	TLSCertificates []asset.TLSCertificate  `json:"tls_certificates,omitempty"`
	SourceMaps      []asset.SourceMap       `json:"source_maps,omitempty"`
	Relationships   []asset.Relationship    `json:"relationships,omitempty"`

	// The normalized priority outputs, each deduplicated by identity and
	// sorted by (score desc, identity asc) — the deterministic
	// attention order every renderer presents.
	Surfaces    []priority.SurfaceAsset `json:"surfaces,omitempty"`
	Groups      []priority.Group        `json:"groups,omitempty"`
	AttackPaths []priority.AttackPath   `json:"attack_paths,omitempty"`

	// Recommendations is the deterministic projection of the surfaces'
	// factor lists through priority.Recommend (surface order, factor
	// order), capped at maxModelRecommendations.
	Recommendations []SurfaceRecommendation `json:"recommendations,omitempty"`

	// The run's own statistics (presented verbatim; see Statistics).
	Runtime   RuntimeStats `json:"runtime"`
	Cache     CacheStats   `json:"cache"`
	Execution ExecStats    `json:"execution"`

	// Errors groups the run's error records by category.
	Errors ErrorSummary `json:"errors"`

	// errorRecords is the full merged, sorted error record list behind
	// Errors (bounded at maxModelErrors); only the digest reads it.
	errorRecords []ErrorRecord

	// Stats is the dataset census, computed once.
	Stats Statistics `json:"statistics"`

	// Summary is the fixed-vocabulary run summary, computed once.
	Summary RunSummary `json:"summary"`

	// Digest is the lowercase hex SHA-256 of the canonical digest payload
	// (see computeDigest): a deterministic fingerprint of every byte the
	// exports render — the corpus (identities AND observations), the
	// priority outputs and their factors, the recommendations, statistics,
	// summaries, error records, and run metadata. Any export-visible
	// change changes the digest; identical content produces an identical
	// digest.
	Digest string `json:"digest"`
}

// SurfaceRecommendation is one evidence-tied reconnaissance recommendation
// projected from one scored surface (see priority.Recommend; the text is
// preserved verbatim — the framework never rephrases guidance).
type SurfaceRecommendation struct {
	// Surface is the canonical identity of the recommended surface.
	Surface asset.Identity `json:"surface"`

	// Factor is the factor the guidance resolves from.
	Factor string `json:"factor"`

	// Text is the rendered guidance (verbatim from the priority engine).
	Text string `json:"text"`

	// Evidence cites the factor's evidence references.
	Evidence []string `json:"evidence,omitempty"`

	// Weight is the cited factor's weight.
	Weight float64 `json:"weight"`
}

// NewModel validates, normalizes, and canonicalizes a report Context into
// the deterministic Model. A non-canonical entry is rejected with a
// structured error naming it (the caller-composed snapshot contract shared
// with the detection framework); garbage in a Context is a caller bug, not
// a noisy observation. The returned Model is safe for concurrent reads.
func NewModel(input Context) (*Model, error) {
	m := &Model{SchemaVersion: SchemaVersion, Target: input.Target}

	if len(input.Target) > maxTargetBytes {
		return nil, fmt.Errorf("report: target %q is over %d bytes", input.Target, maxTargetBytes)
	}
	for i := 0; i < len(input.Target); i++ {
		if input.Target[i] < 0x20 || input.Target[i] == 0x7f {
			return nil, fmt.Errorf("report: target %q contains a control character", input.Target)
		}
	}
	if !input.StartedAt.IsZero() && !input.EndedAt.IsZero() && input.EndedAt.Before(input.StartedAt) {
		return nil, fmt.Errorf("report: ended-at %s precedes started-at %s", input.EndedAt, input.StartedAt)
	}
	m.StartedAt, m.EndedAt = input.StartedAt, input.EndedAt

	var err error
	if m.Domains, err = normalizeDomains(input.Domains); err != nil {
		return nil, err
	}
	if m.Hosts, err = normalizeHosts(input.Hosts); err != nil {
		return nil, err
	}
	if m.IPs, err = normalizeIPs(input.IPs); err != nil {
		return nil, err
	}
	if m.Ports, err = normalizePorts(input.Ports); err != nil {
		return nil, err
	}
	if m.Services, err = normalizeServices(input.Services); err != nil {
		return nil, err
	}
	if m.URLs, err = normalizeURLs(input.URLs); err != nil {
		return nil, err
	}
	if m.Endpoints, err = normalizeEndpoints(input.Endpoints); err != nil {
		return nil, err
	}
	if m.JavaScript, err = normalizeJavaScript(input.JavaScript); err != nil {
		return nil, err
	}
	if m.Parameters, err = normalizeParameters(input.Parameters); err != nil {
		return nil, err
	}
	if m.Technologies, err = normalizeTechnologies(input.Technologies); err != nil {
		return nil, err
	}
	if m.Secrets, err = normalizeSecrets(input.Secrets); err != nil {
		return nil, err
	}
	if m.Evidence, err = normalizeEvidence(input.Evidence); err != nil {
		return nil, err
	}
	if m.Findings, err = normalizeFindings(input.Findings); err != nil {
		return nil, err
	}
	if m.TLSCertificates, err = normalizeTLSCertificates(input.TLSCertificates); err != nil {
		return nil, err
	}
	if m.SourceMaps, err = normalizeSourceMaps(input.SourceMaps); err != nil {
		return nil, err
	}
	if m.Relationships, err = normalizeRelationships(input.Relationships); err != nil {
		return nil, err
	}
	if m.Surfaces, err = normalizeSurfaces(input.Surfaces); err != nil {
		return nil, err
	}
	if m.Groups, err = normalizeGroups(input.Groups); err != nil {
		return nil, err
	}
	if m.AttackPaths, err = normalizeAttackPaths(input.AttackPaths); err != nil {
		return nil, err
	}
	if m.Errors, err = normalizeErrors(input.Errors, &m.errorRecords); err != nil {
		return nil, err
	}
	m.Runtime, m.Cache, m.Execution = input.Runtime, input.Cache, input.Execution
	if err := validateRuntimeStats(m.Runtime); err != nil {
		return nil, err
	}
	if err := validateCacheStats(m.Cache); err != nil {
		return nil, err
	}
	if err := validateExecStats(m.Execution); err != nil {
		return nil, err
	}

	m.Recommendations = projectRecommendations(m.Surfaces)
	m.Stats = buildStatistics(m)
	m.Summary = buildRunSummary(m)
	digest, err := computeDigest(m)
	if err != nil {
		return nil, err
	}
	m.Digest = digest
	return m, nil
}

// ---- per-kind validation + normalization ----

func normalizeDomains(list []asset.Domain) ([]asset.Domain, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("domains", len(list), maxModelPerKind)
	}
	for i, d := range list {
		canonical, err := asset.NewDomain(d.Name, d.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: domain %d (%q): %w", i, d.Name, err)
		}
		if canonical.Name != d.Name {
			return nil, fmt.Errorf("report: domain %d (%q) is not canonical", i, d.Name)
		}
	}
	return mergeByIdentity(list, "domain", func(d asset.Domain) asset.Identity { return d.Identity() },
		asset.MergeDomains)
}

func normalizeHosts(list []asset.Host) ([]asset.Host, error) {
	if len(list) > maxModelHosts {
		return nil, overBound("hosts", len(list), maxModelHosts)
	}
	for i, h := range list {
		canonical, err := asset.NewHost(h.Name, h.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: host %d (%q): %w", i, h.Name, err)
		}
		if canonical.Name != h.Name {
			return nil, fmt.Errorf("report: host %d (%q) is not canonical", i, h.Name)
		}
	}
	return mergeByIdentity(list, "host", func(h asset.Host) asset.Identity { return h.Identity() },
		asset.MergeHosts)
}

func normalizeIPs(list []asset.IP) ([]asset.IP, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("ips", len(list), maxModelPerKind)
	}
	for i, ip := range list {
		if !ip.Addr.IsValid() {
			return nil, fmt.Errorf("report: ip %d is zero", i)
		}
		canonical, err := asset.NewIP(ip.String(), ip.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: ip %d (%q): %w", i, ip.String(), err)
		}
		if canonical.Identity() != ip.Identity() {
			return nil, fmt.Errorf("report: ip %d (%q) is not canonical", i, ip.String())
		}
	}
	return mergeByIdentity(list, "ip", func(ip asset.IP) asset.Identity { return ip.Identity() },
		asset.MergeIPs)
}

func normalizePorts(list []asset.Port) ([]asset.Port, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("ports", len(list), maxModelPerKind)
	}
	for i, p := range list {
		canonical, err := asset.NewPort(int(p.Number), p.Protocol, p.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: port %d: %w", i, err)
		}
		if canonical != p {
			return nil, fmt.Errorf("report: port %d (%s) is not canonical", i, p.String())
		}
	}
	return mergeByIdentity(list, "port", func(p asset.Port) asset.Identity { return p.Identity() },
		asset.MergePorts)
}

func normalizeServices(list []asset.Service) ([]asset.Service, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("services", len(list), maxModelPerKind)
	}
	for i, s := range list {
		canonical, err := asset.NewService(s.Name, s.Port, s.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: service %d (%q): %w", i, s.Name, err)
		}
		if canonical.Identity() != s.Identity() {
			return nil, fmt.Errorf("report: service %d (%q) is not canonical", i, s.Name)
		}
	}
	return mergeByIdentity(list, "service", func(s asset.Service) asset.Identity { return s.Identity() },
		asset.MergeServices)
}

func normalizeURLs(list []asset.URL) ([]asset.URL, error) {
	if len(list) > maxModelURLs {
		return nil, overBound("urls", len(list), maxModelURLs)
	}
	for i, u := range list {
		if u.Identity().IsZero() {
			return nil, fmt.Errorf("report: url %d is zero", i)
		}
		reparsed, err := asset.ParseURL(u.String(), u.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: url %d (%q): %w", i, u.String(), err)
		}
		if reparsed.Identity() != u.Identity() {
			return nil, fmt.Errorf("report: url %d (%q) is not canonical", i, u.String())
		}
	}
	return mergeByIdentity(list, "url", func(u asset.URL) asset.Identity { return u.Identity() },
		asset.MergeURLs)
}

func normalizeEndpoints(list []asset.Endpoint) ([]asset.Endpoint, error) {
	if len(list) > maxModelEndpoints {
		return nil, overBound("endpoints", len(list), maxModelEndpoints)
	}
	for i, ep := range list {
		if ep.URL.Identity().IsZero() {
			return nil, fmt.Errorf("report: endpoint %d has a zero URL", i)
		}
		canonical, err := asset.NewEndpoint(ep.Method, ep.URL.String(), ep.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: endpoint %d: %w", i, err)
		}
		if canonical.Identity() != ep.Identity() {
			return nil, fmt.Errorf("report: endpoint %d (%s %s) is not canonical", i, ep.Method, ep.URL.String())
		}
	}
	return mergeByIdentity(list, "endpoint", func(ep asset.Endpoint) asset.Identity { return ep.Identity() },
		asset.MergeEndpoints)
}

func normalizeJavaScript(list []asset.JavaScript) ([]asset.JavaScript, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("javascript", len(list), maxModelPerKind)
	}
	for i, js := range list {
		if js.URL.Identity().IsZero() {
			return nil, fmt.Errorf("report: javascript %d has a zero URL", i)
		}
		canonical, err := asset.NewJavaScript(js.URL.String(), js.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: javascript %d (%q): %w", i, js.URL.String(), err)
		}
		if canonical.Identity() != js.Identity() {
			return nil, fmt.Errorf("report: javascript %d (%q) is not canonical", i, js.URL.String())
		}
		if js.Size < 0 {
			return nil, fmt.Errorf("report: javascript %d carries a negative size", i)
		}
		if js.StatusCode != 0 && (js.StatusCode < 100 || js.StatusCode > 599) {
			return nil, fmt.Errorf("report: javascript %d carries status code %d outside 100..599", i, js.StatusCode)
		}
		if err := validateHex64(js.ContentHash, "content hash"); err != nil {
			return nil, fmt.Errorf("report: javascript %d: %w", i, err)
		}
	}
	return mergeByIdentity(list, "javascript", func(js asset.JavaScript) asset.Identity { return js.Identity() },
		asset.MergeJavaScripts)
}

func normalizeParameters(list []asset.Parameter) ([]asset.Parameter, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("parameters", len(list), maxModelPerKind)
	}
	for i, p := range list {
		if p.Identity().IsZero() {
			return nil, fmt.Errorf("report: parameter %d is zero", i)
		}
		if p.Name == "" || p.Location == "" {
			return nil, fmt.Errorf("report: parameter %d has an empty name or location", i)
		}
		if !p.FirstSeen.IsZero() && !p.LastSeen.IsZero() && p.LastSeen.Before(p.FirstSeen) {
			return nil, fmt.Errorf("report: parameter %d (%q) last-seen precedes first-seen", i, p.Name)
		}
	}
	return mergeByIdentity(list, "parameter", func(p asset.Parameter) asset.Identity { return p.Identity() },
		asset.MergeParameters)
}

func normalizeTechnologies(list []asset.Technology) ([]asset.Technology, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("technologies", len(list), maxModelPerKind)
	}
	for i, t := range list {
		canonical, err := asset.NewTechnology(t.Name, t.Category, t.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: technology %d (%q): %w", i, t.Name, err)
		}
		if canonical.Identity() != t.Identity() {
			return nil, fmt.Errorf("report: technology %d (%q) is not canonical", i, t.Name)
		}
		if len(t.Version) > 128 {
			return nil, fmt.Errorf("report: technology %d (%q) version is over 128 bytes", i, t.Name)
		}
	}
	return mergeByIdentity(list, "technology", func(t asset.Technology) asset.Identity { return t.Identity() },
		asset.MergeTechnologies)
}

func normalizeSecrets(list []asset.SecretCandidate) ([]asset.SecretCandidate, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("secrets", len(list), maxModelPerKind)
	}
	for i, sec := range list {
		canonical, err := asset.NewSecretCandidate(sec.Type, sec.Value, sec.Source, sec.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: secret candidate %d: %w", i, err)
		}
		if canonical != sec {
			return nil, fmt.Errorf("report: secret candidate %d is not canonical", i)
		}
	}
	return mergeByIdentity(list, "secret", func(sec asset.SecretCandidate) asset.Identity { return sec.Identity() },
		asset.MergeSecretCandidates)
}

func normalizeEvidence(list []asset.Evidence) ([]asset.Evidence, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("evidence", len(list), maxModelPerKind)
	}
	for i, ev := range list {
		canonical, err := asset.NewEvidence(ev.Method, ev.Indicator, ev.Value, ev.Source, ev.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: evidence %d: %w", i, err)
		}
		if canonical != ev {
			return nil, fmt.Errorf("report: evidence %d is not canonical", i)
		}
	}
	return mergeByIdentity(list, "evidence", func(ev asset.Evidence) asset.Identity { return ev.Identity() },
		asset.MergeEvidence)
}

func normalizeFindings(list []asset.Finding) ([]asset.Finding, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("findings", len(list), maxModelPerKind)
	}
	canonical := make([]asset.Finding, 0, len(list))
	for i, f := range list {
		normed, err := asset.NewFinding(f)
		if err != nil {
			return nil, fmt.Errorf("report: finding %d: %w", i, err)
		}
		canonical = append(canonical, normed)
	}
	return mergeByIdentity(canonical, "finding", func(f asset.Finding) asset.Identity { return f.Identity() },
		asset.MergeFindings)
}

func normalizeTLSCertificates(list []asset.TLSCertificate) ([]asset.TLSCertificate, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("tls certificates", len(list), maxModelPerKind)
	}
	for i, cert := range list {
		canonical, err := asset.NewTLSCertificate(cert.Fingerprint, cert.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: tls certificate %d: %w", i, err)
		}
		if canonical.Identity() != cert.Identity() {
			return nil, fmt.Errorf("report: tls certificate %d is not canonical", i)
		}
	}
	return mergeByIdentity(list, "tls_certificate", func(c asset.TLSCertificate) asset.Identity { return c.Identity() },
		asset.MergeTLSCertificates)
}

func normalizeSourceMaps(list []asset.SourceMap) ([]asset.SourceMap, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("source maps", len(list), maxModelPerKind)
	}
	for i, sm := range list {
		if sm.URL.Identity().IsZero() {
			return nil, fmt.Errorf("report: source map %d has a zero URL", i)
		}
		canonical, err := asset.NewSourceMap(sm.URL.String(), sm.Prov)
		if err != nil {
			return nil, fmt.Errorf("report: source map %d: %w", i, err)
		}
		if canonical.Identity() != sm.Identity() {
			return nil, fmt.Errorf("report: source map %d is not canonical", i)
		}
		if err := validateHex64(sm.Hash, "hash"); err != nil {
			return nil, fmt.Errorf("report: source map %d: %w", i, err)
		}
		if sm.Size < 0 {
			return nil, fmt.Errorf("report: source map %d carries a negative size", i)
		}
	}
	return mergeByIdentity(list, "source_map", func(sm asset.SourceMap) asset.Identity { return sm.Identity() },
		asset.MergeSourceMaps)
}

func normalizeRelationships(list []asset.Relationship) ([]asset.Relationship, error) {
	if len(list) > maxModelRelationships {
		return nil, overBound("relationships", len(list), maxModelRelationships)
	}
	for i, rel := range list {
		canonical, err := asset.NewRelationship(rel.From, rel.Kind, rel.To)
		if err != nil {
			return nil, fmt.Errorf("report: relationship %d: %w", i, err)
		}
		if canonical != rel {
			return nil, fmt.Errorf("report: relationship %d is not canonical", i)
		}
	}
	sorted := make([]asset.Relationship, len(list))
	copy(sorted, list)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID() < sorted[j].ID() })
	out := make([]asset.Relationship, 0, len(sorted))
	for _, rel := range sorted {
		if n := len(out); n > 0 && out[n-1].ID() == rel.ID() {
			continue
		}
		out = append(out, rel)
	}
	return out, nil
}

// normalizeSurfaces validates the observable surface contract, deduplicates
// by identity (keeping the highest score on an identity tie), and sorts by
// (score desc, identity asc).
func normalizeSurfaces(list []priority.SurfaceAsset) ([]priority.SurfaceAsset, error) {
	if len(list) > maxModelPerKind {
		return nil, overBound("surfaces", len(list), maxModelPerKind)
	}
	for i, s := range list {
		if err := validateSurface(s); err != nil {
			return nil, fmt.Errorf("report: surface %d: %w", i, err)
		}
	}
	sorted := make([]priority.SurfaceAsset, len(list))
	copy(sorted, list)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Identity.String() != sorted[j].Identity.String() {
			return sorted[i].Identity.String() < sorted[j].Identity.String()
		}
		return sorted[i].Score > sorted[j].Score
	})
	deduped := make([]priority.SurfaceAsset, 0, len(sorted))
	for _, s := range sorted {
		if n := len(deduped); n > 0 && deduped[n-1].Identity == s.Identity {
			continue
		}
		deduped = append(deduped, s)
	}
	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].Score != deduped[j].Score {
			return deduped[i].Score > deduped[j].Score
		}
		return deduped[i].Identity.String() < deduped[j].Identity.String()
	})
	return deduped, nil
}

func normalizeGroups(list []priority.Group) ([]priority.Group, error) {
	if len(list) > maxModelGroups {
		return nil, overBound("groups", len(list), maxModelGroups)
	}
	for i, g := range list {
		if g.Anchor.IsZero() {
			return nil, fmt.Errorf("report: group %d has a zero anchor", i)
		}
		if len(g.Members) == 0 {
			return nil, fmt.Errorf("report: group %d (%s) has no members", i, g.Anchor)
		}
		if err := validateScore(g.Score, "score"); err != nil {
			return nil, fmt.Errorf("report: group %d (%s): %w", i, g.Anchor, err)
		}
		if err := validateScore(g.Confidence, "confidence"); err != nil {
			return nil, fmt.Errorf("report: group %d (%s): %w", i, g.Anchor, err)
		}
		if !g.Level.Valid() {
			return nil, fmt.Errorf("report: group %d (%s) has invalid level %q", i, g.Anchor, string(g.Level))
		}
		if len(g.Members) > maxGroupMembers {
			return nil, fmt.Errorf("report: group %d (%s) carries %d members over bound %d",
				i, g.Anchor, len(g.Members), maxGroupMembers)
		}
		for j, member := range g.Members {
			if err := validateSurface(member); err != nil {
				return nil, fmt.Errorf("report: group %d (%s) member %d: %w", i, g.Anchor, j, err)
			}
		}
	}
	sorted := make([]priority.Group, len(list))
	copy(sorted, list)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Anchor.String() != sorted[j].Anchor.String() {
			return sorted[i].Anchor.String() < sorted[j].Anchor.String()
		}
		return sorted[i].Score > sorted[j].Score
	})
	deduped := make([]priority.Group, 0, len(sorted))
	for _, g := range sorted {
		if n := len(deduped); n > 0 && deduped[n-1].Anchor == g.Anchor {
			continue
		}
		deduped = append(deduped, g)
	}
	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].Score != deduped[j].Score {
			return deduped[i].Score > deduped[j].Score
		}
		return deduped[i].Anchor.String() < deduped[j].Anchor.String()
	})
	return deduped, nil
}

func normalizeAttackPaths(list []priority.AttackPath) ([]priority.AttackPath, error) {
	if len(list) > maxModelPaths {
		return nil, overBound("attack paths", len(list), maxModelPaths)
	}
	for i, p := range list {
		if p.Root.IsZero() {
			return nil, fmt.Errorf("report: attack path %d has a zero root", i)
		}
		if len(p.Steps) == 0 {
			return nil, fmt.Errorf("report: attack path %d (%s) has no steps", i, p.Root)
		}
		if len(p.Steps) > maxStepsPerPath {
			return nil, fmt.Errorf("report: attack path %d (%s) carries %d steps over bound %d",
				i, p.Root, len(p.Steps), maxStepsPerPath)
		}
		if err := validateScore(p.Score, "score"); err != nil {
			return nil, fmt.Errorf("report: attack path %d (%s): %w", i, p.Root, err)
		}
		if !p.Level.Valid() {
			return nil, fmt.Errorf("report: attack path %d (%s) has invalid level %q", i, p.Root, string(p.Level))
		}
	}
	sorted := make([]priority.AttackPath, len(list))
	copy(sorted, list)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Root.String() != sorted[j].Root.String() {
			return sorted[i].Root.String() < sorted[j].Root.String()
		}
		return sorted[i].Score > sorted[j].Score
	})
	deduped := make([]priority.AttackPath, 0, len(sorted))
	for _, p := range sorted {
		if n := len(deduped); n > 0 && deduped[n-1].Root == p.Root {
			continue
		}
		deduped = append(deduped, p)
	}
	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].Score != deduped[j].Score {
			return deduped[i].Score > deduped[j].Score
		}
		return deduped[i].Root.String() < deduped[j].Root.String()
	})
	return deduped, nil
}

// normalizeErrors canonicalizes every record, then sorts by (category,
// stage, message) and merges identical adjacent records by summing counts.
// The full merged record list is stored on the model (unexported — the
// digest covers it completely); the exported Errors field is the grouped
// summary.
func normalizeErrors(list []ErrorRecord, recordsOut *[]ErrorRecord) (ErrorSummary, error) {
	if len(list) > maxModelErrors {
		return ErrorSummary{}, overBound("errors", len(list), maxModelErrors)
	}
	records := make([]ErrorRecord, 0, len(list))
	for i, r := range list {
		normed, err := normalizeErrorRecord(r)
		if err != nil {
			return ErrorSummary{}, fmt.Errorf("report: error record %d: %w", i, err)
		}
		records = append(records, normed)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Category != records[j].Category {
			return records[i].Category < records[j].Category
		}
		if records[i].Stage != records[j].Stage {
			return records[i].Stage < records[j].Stage
		}
		return records[i].Message < records[j].Message
	})
	merged := make([]ErrorRecord, 0, len(records))
	for _, r := range records {
		if n := len(merged); n > 0 && merged[n-1].Category == r.Category &&
			merged[n-1].Stage == r.Stage && merged[n-1].Message == r.Message {
			merged[n-1].Count += r.Count
			continue
		}
		merged = append(merged, r)
	}
	*recordsOut = merged
	return buildErrorSummary(merged), nil
}

// projectRecommendations flattens the surfaces' recommendations in surface
// order (score desc, identity asc — the model order), capped at
// maxModelRecommendations.
func projectRecommendations(surfaces []priority.SurfaceAsset) []SurfaceRecommendation {
	var out []SurfaceRecommendation
	for _, s := range surfaces {
		for _, rec := range priority.Recommend(s) {
			out = append(out, SurfaceRecommendation{
				Surface:  s.Identity,
				Factor:   rec.Factor,
				Text:     rec.Text,
				Evidence: rec.Evidence,
				Weight:   rec.Weight,
			})
			if len(out) >= maxModelRecommendations {
				return out
			}
		}
	}
	return out
}

// ---- validation helpers ----

func overBound(what string, got, max int) error {
	return fmt.Errorf("report: %s list carries %d entries over bound %d", what, got, max)
}

func validateScore(v float64, what string) error {
	if math.IsNaN(v) || v < 0 || v > 1 {
		return fmt.Errorf("%s %v is NaN or out of [0,1]", what, v)
	}
	return nil
}

func validateHex64(s, what string) error {
	if s == "" {
		return nil
	}
	if len(s) != 64 {
		return fmt.Errorf("%s %q is not 64 characters", what, s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%s %q is not lowercase hex", what, s)
		}
	}
	return nil
}

// Surface validation bounds (light, observable invariants; the priority
// engine validated the full contract at score time).
const (
	maxFactorNameBytes    = 128
	maxFactorReasonBytes  = 1024
	maxFactorEvidenceRefs = 32
	maxFactorsPerSurface  = 64
	maxGroupMembers       = 1024
	maxStepsPerPath       = 64
)

func validateSurface(s priority.SurfaceAsset) error {
	if s.Identity.IsZero() || !s.Identity.Kind.Valid() {
		return fmt.Errorf("surface identity %v is zero or has an unknown kind", s.Identity)
	}
	if err := validateScore(s.Score, "score"); err != nil {
		return err
	}
	if err := validateScore(s.Interestingness, "interestingness"); err != nil {
		return err
	}
	if err := validateScore(s.Confidence, "confidence"); err != nil {
		return err
	}
	if !s.Level.Valid() {
		return fmt.Errorf("level %q is invalid", string(s.Level))
	}
	if len(s.Factors) > maxFactorsPerSurface {
		return fmt.Errorf("carries %d factors over bound %d", len(s.Factors), maxFactorsPerSurface)
	}
	for _, f := range s.Factors {
		if f.Name == "" || len(f.Name) > maxFactorNameBytes {
			return fmt.Errorf("factor name %q is empty or over %d bytes", f.Name, maxFactorNameBytes)
		}
		if err := validateScore(f.Weight, "factor weight"); err != nil {
			return fmt.Errorf("factor %q: %w", f.Name, err)
		}
		if f.Reason == "" || len(f.Reason) > maxFactorReasonBytes {
			return fmt.Errorf("factor %q reason is empty or over %d bytes", f.Name, maxFactorReasonBytes)
		}
		if len(f.Evidence) > maxFactorEvidenceRefs {
			return fmt.Errorf("factor %q carries %d evidence refs over bound %d", f.Name, len(f.Evidence), maxFactorEvidenceRefs)
		}
	}
	if len(s.Factors) > 0 && s.ScoredAt.IsZero() {
		return fmt.Errorf("scored surface carries no scored-at time")
	}
	return nil
}

func validateRuntimeStats(s RuntimeStats) error {
	if s.Workers < 0 || s.Jobs < 0 || s.JobsCompleted < 0 || s.JobsFailed < 0 ||
		s.JobsCancelled < 0 || s.JobsTimedOut < 0 || s.WorkerTime < 0 {
		return fmt.Errorf("report: runtime statistics carry a negative value")
	}
	return nil
}

func validateCacheStats(s CacheStats) error {
	if s.Hits < 0 || s.Misses < 0 || s.Reads < 0 || s.Stores < 0 || s.Evictions < 0 {
		return fmt.Errorf("report: cache statistics carry a negative value")
	}
	return nil
}

func validateExecStats(s ExecStats) error {
	if s.Rules < 0 || s.Executions < 0 || s.Errors < 0 || s.Timeouts < 0 ||
		s.Panics < 0 || s.CacheHits < 0 || s.CacheMisses < 0 {
		return fmt.Errorf("report: execution statistics carry a negative value")
	}
	return nil
}

// truncateRunes bounds s to at most max bytes, trimming an incomplete
// trailing UTF-8 sequence and appending the "…" marker when truncation
// happened. Values within the bound are returned unchanged.
func truncateRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	prefix := s[:max-len(errorTruncationMarker)]
	for len(prefix) > 0 {
		r, size := utf8.DecodeLastRuneInString(prefix)
		if r != utf8.RuneError || size > 1 {
			break
		}
		prefix = prefix[:len(prefix)-1]
	}
	return prefix + errorTruncationMarker
}

// mergeByIdentity sorts by identity, deduplicates, and merges same-identity
// neighbors through the Phase 2 merge primitive. The result is the
// deterministic per-kind model list.
func mergeByIdentity[T any](list []T, what string, id func(T) asset.Identity, merge func(a, b T) (T, error)) ([]T, error) {
	sorted := make([]T, len(list))
	copy(sorted, list)
	sort.Slice(sorted, func(i, j int) bool { return id(sorted[i]).String() < id(sorted[j]).String() })
	out := make([]T, 0, len(sorted))
	for _, item := range sorted {
		if n := len(out); n > 0 {
			if merged, err := merge(out[n-1], item); err == nil {
				out[n-1] = merged
				continue
			}
		}
		out = append(out, item)
	}
	return out, nil
}

// digestPayload is the canonical input to the model digest: the complete
// export-equivalent content of the normalized model — every corpus list
// with its full stored fields (identities and observations), the priority
// outputs (score, level, sub-scores, factors) and the projected
// recommendations, the statistics, run summary, the FULL merged error
// records, and the run metadata. Every field is marshaled exactly as the
// JSON export renders it, so the digest is one-directional: digest equal ⟹
// byte-identical exports (the digest is a superset of every export's
// content); digest different says nothing — the JSON export only
// summarizes the error records (category totals plus up to 8 samples per
// category), so identical exports can still differ in digest when error
// records beyond the sample cut differ. Determinism holds by construction:
// struct fields marshal in fixed declaration order and the encoder sorts
// map keys, so Finding.Metadata — a map — hashes deterministically, and
// equal models hash equal.
type digestPayload struct {
	Schema    int       `json:"schema"`
	Target    string    `json:"target"`
	StartedAt time.Time `json:"started_at,omitempty"`
	EndedAt   time.Time `json:"ended_at,omitempty"`

	Domains         []asset.Domain          `json:"domains,omitempty"`
	Hosts           []asset.Host            `json:"hosts,omitempty"`
	IPs             []asset.IP              `json:"ips,omitempty"`
	Ports           []asset.Port            `json:"ports,omitempty"`
	Services        []asset.Service         `json:"services,omitempty"`
	URLs            []asset.URL             `json:"urls,omitempty"`
	Endpoints       []asset.Endpoint        `json:"endpoints,omitempty"`
	JavaScript      []asset.JavaScript      `json:"javascript,omitempty"`
	Parameters      []asset.Parameter       `json:"parameters,omitempty"`
	Technologies    []asset.Technology      `json:"technologies,omitempty"`
	Secrets         []asset.SecretCandidate `json:"secrets,omitempty"`
	Evidence        []asset.Evidence        `json:"evidence,omitempty"`
	Findings        []asset.Finding         `json:"findings,omitempty"`
	TLSCertificates []asset.TLSCertificate  `json:"tls_certificates,omitempty"`
	SourceMaps      []asset.SourceMap       `json:"source_maps,omitempty"`
	Relationships   []asset.Relationship    `json:"relationships,omitempty"`

	Surfaces    []priority.SurfaceAsset `json:"surfaces,omitempty"`
	Groups      []priority.Group        `json:"groups,omitempty"`
	AttackPaths []priority.AttackPath   `json:"attack_paths,omitempty"`

	// Recommendations is the projected recommendation list (derived from
	// the surfaces, digested explicitly — it is exported content).
	Recommendations []SurfaceRecommendation `json:"recommendations,omitempty"`

	// Statistics and Summary are the derived census and run-summary blocks
	// the exports present (digested explicitly for the same reason).
	Statistics Statistics `json:"statistics"`
	Summary    RunSummary `json:"summary"`

	// ErrorRecords is the full merged error record list; Errors (the
	// exported summary) is its deterministic projection.
	ErrorRecords []ErrorRecord `json:"error_records,omitempty"`

	Runtime   RuntimeStats `json:"runtime"`
	Cache     CacheStats   `json:"cache"`
	Execution ExecStats    `json:"execution"`
}

// computeDigest derives the model's integrity fingerprint. Times marshal
// exactly as the JSON export renders them (RFC3339Nano with the value's
// own offset), so the digest tracks the exports: identical digest ⟹
// identical exported content (the digest is a superset of every export).
// The converse does not hold — the digest covers the full merged error
// records while the exports only summarize them — so identical exports
// can still differ in digest.
//
// Wall-clock timing (StartedAt, EndedAt, Duration, WorkerTime) is
// deliberately excluded from the digest input: the digest is the
// render-cache key (report:digest) and must remain stable when an
// honest run duration is carried into the Model's RunSummary. Two
// reports with identical content but different wall-clock brackets
// therefore share the same digest and the same cache entry; the JSON
// export still carries the honest wall-clock times.
func computeDigest(m *Model) (string, error) {
	// Timing is wall-clock metadata, not content: exclude it from the
	// digest so the same logical report remains cache-hit stable across
	// different run brackets (OPT-P0-5). Every other field is digested
	// exactly as the JSON export renders it.
	statsForDigest := m.Stats
	statsForDigest.Duration = 0
	// Runtime.WorkerTime is also wall-clock derived (pool event
	// timestamps) — exclude it as well so worker-time jitter does not
	// perturb the cache key; the JSON still reports it honestly.
	statsForDigest.Runtime.WorkerTime = 0
	summaryForDigest := m.Summary
	summaryForDigest.StartedAt = time.Time{}
	summaryForDigest.EndedAt = time.Time{}
	summaryForDigest.Duration = 0
	summaryForDigest.WorkerTime = 0
	runtimeForDigest := m.Runtime
	runtimeForDigest.WorkerTime = 0
	p := digestPayload{
		Schema: m.SchemaVersion,
		Target: m.Target,
		// StartedAt and EndedAt are wall-clock brackets — excluded
		// from the digest for the same stability reason (see above).
		Domains:         m.Domains,
		Hosts:           m.Hosts,
		IPs:             m.IPs,
		Ports:           m.Ports,
		Services:        m.Services,
		URLs:            m.URLs,
		Endpoints:       m.Endpoints,
		JavaScript:      m.JavaScript,
		Parameters:      m.Parameters,
		Technologies:    m.Technologies,
		Secrets:         m.Secrets,
		Evidence:        m.Evidence,
		Findings:        m.Findings,
		TLSCertificates: m.TLSCertificates,
		SourceMaps:      m.SourceMaps,
		Relationships:   m.Relationships,
		Surfaces:        m.Surfaces,
		Groups:          m.Groups,
		AttackPaths:     m.AttackPaths,
		Recommendations: m.Recommendations,
		Statistics:      statsForDigest,
		Summary:         summaryForDigest,
		ErrorRecords:    m.errorRecords,
		Runtime:         runtimeForDigest,
		Cache:           m.Cache,
		Execution:       m.Execution,
	}

	buf, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("report: marshal digest payload: %w", err)
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}
