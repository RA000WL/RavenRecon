// Package diff answers a hunter's highest-value question — "what changed?"
// — by comparing two report JSON exports (see internal/report) and
// reporting presence deltas per dataset plus priority-level movements.
//
// A Delta is purely observational: identities present in one report and
// absent in the other, and surfaces present in both whose level or score
// moved. It never claims exploitability, never rescans, and never mutates
// either input. Baselines are explicit files (the caller manages
// retention); comparing runs of different targets is rejected, because a
// cross-target delta is meaningless.
package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/RA000WL/RavenRecon/internal/priority"
	"github.com/RA000WL/RavenRecon/internal/report"
)

// maxReportBytes bounds one report JSON export read by LoadReport (256
// MiB, far above any legitimate export: every per-kind list is itself
// bounded by the report model, so a larger file is corrupt or hostile).
// Over-bound input is rejected before decoding — never read unbounded
// into memory (fail-closed).
const maxReportBytes = 256 << 20

// datasetKinds are the model datasets diffed as presence sets, in stable
// render order. Runtime/cache/execution statistics, errors, evidence,
// relationships, live records, and attribution are run metadata or
// derivable detail — not attack surface — and stay out of the delta.
// (Domains, IPs, and TLS certificates ARE attack surface and are
// covered; everything else excluded is enumerated here so the coverage
// boundary is explicit, not accidental.)
var datasetKinds = []string{
	"domains", "hosts", "ips", "urls", "endpoints", "parameters", "technologies",
	"secrets", "findings", "javascript", "source_maps", "ports", "services",
	"tls_certificates",
}

// Snapshot is one report's diffable surface: per-dataset sorted identity
// strings plus the scored-surface map. Snapshots build from a decoded
// report Model (SnapshotOf) or directly in tests.
type Snapshot struct {
	Target   string
	Digest   string
	Sets     map[string][]string
	Surfaces map[string]SurfaceState
	// Takeover is the (rule, provider) histogram of the snapshot's
	// takeover findings (see takeover.go buildTakeoverCounts): nil when
	// the snapshot tracks no takeover findings. Hand-rolled test
	// snapshots leave it nil (bloom absent); SnapshotOf always
	// populates it (nil-or-valued, never a partial histogram).
	Takeover map[string]int
}

// SurfaceState is one scored surface's attention position.
type SurfaceState struct {
	Level priority.PriorityLevel
	Score float64
}

// SurfaceChange is a surface present in both snapshots whose attention
// position moved.
type SurfaceChange struct {
	Identity string  `json:"identity"`
	OldLevel string  `json:"old_level"`
	NewLevel string  `json:"new_level"`
	OldScore float64 `json:"old_score"`
	NewScore float64 `json:"new_score"`
}

// Delta is the computed difference of two snapshots: per-dataset sorted
// added/removed identity strings, plus surface movements. Empty lists
// mean no change on that axis — never nil-vs-empty ambiguity (every list
// is non-nil after Diff).
type Delta struct {
	Target         string              `json:"target"`
	BaselineDigest string              `json:"baseline_digest"`
	CurrentDigest  string              `json:"current_digest"`
	Added          map[string][]string `json:"added"`
	Removed        map[string][]string `json:"removed"`
	Changed        []SurfaceChange     `json:"changed_surfaces"`
	// Takeover is the derived takeover bloom (see takeover.go): nil iff
	// neither snapshot tracks takeover findings. A non-nil bloom with
	// empty cells means takeover is tracked with no count change. The
	// bloom never affects Empty, AddedCount, or RemovedCount — it
	// projects the findings axis, it is not a new axis.
	Takeover *TakeoverBloom `json:"takeover,omitempty"`
}

// LoadReport reads and decodes one report JSON export. Files over
// maxReportBytes are rejected before decoding (fail-closed); the schema
// version must match the linked report package: a stale or foreign file
// is rejected before any comparison, never coerced.
func LoadReport(path string) (*report.Model, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("diff: read %s: %w", path, err)
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > maxReportBytes {
		return nil, fmt.Errorf("diff: %s is %d bytes, over the %d-byte bound (refusing to decode)", path, st.Size(), maxReportBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("diff: read %s: %w", path, err)
	}
	if len(raw) > maxReportBytes {
		return nil, fmt.Errorf("diff: %s is over the %d-byte bound (refusing to decode)", path, maxReportBytes)
	}
	var m report.Model
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("diff: parse %s: %w", path, err)
	}
	if m.SchemaVersion != report.SchemaVersion {
		return nil, fmt.Errorf("diff: %s schema version %d, want %d (regenerate the report)", path, m.SchemaVersion, report.SchemaVersion)
	}
	return &m, nil
}

// SnapshotOf extracts the diffable surface of a decoded report. The
// decoded model round-trips through report.NewModel — the single
// normalization point — so every entry re-validates through the Phase 2
// builders: a malformed stored value fails here with a structured error
// naming the offender (never a silent drift of the delta), over-bound
// per-kind lists are rejected, duplicates merge by identity, and zero
// identities are refused. Only the fields the delta reads are passed
// (corpora, relationships, surfaces, liveness, run statistics — the
// grouped error summary is not replayed: the Model keeps no raw error
// records and the delta never reads errors); derived projections the
// delta never reads (groups, attack paths, attribution, recommendations)
// are left out so corruption confined to them cannot block a surface
// comparison.
//
// The snapshot digest is the decoded export's recorded digest, carried
// verbatim — diff never recomputes it, so digest equality means "the
// runs recorded identical digests", not an independent verification.
func SnapshotOf(m *report.Model) (Snapshot, error) {
	if m == nil {
		return Snapshot{}, fmt.Errorf("diff: snapshot of nil report model")
	}
	nm, err := report.NewModel(report.Context{
		Target: m.Target, StartedAt: m.StartedAt, EndedAt: m.EndedAt,
		Domains: m.Domains, Hosts: m.Hosts, IPs: m.IPs,
		Ports: m.Ports, Services: m.Services, URLs: m.URLs,
		Endpoints: m.Endpoints, JavaScript: m.JavaScript,
		Parameters: m.Parameters, Technologies: m.Technologies,
		Secrets: m.Secrets, Evidence: m.Evidence, Findings: m.Findings,
		TLSCertificates: m.TLSCertificates, SourceMaps: m.SourceMaps,
		Relationships: m.Relationships, Surfaces: m.Surfaces,
		LiveRecords: m.LiveRecords,
		Runtime:     m.Runtime, Cache: m.Cache, Execution: m.Execution,
	})
	if err != nil {
		return Snapshot{}, fmt.Errorf("diff: snapshot %q: %w", m.Target, err)
	}
	s := Snapshot{Target: nm.Target, Digest: m.Digest, Sets: make(map[string][]string, len(datasetKinds)), Surfaces: map[string]SurfaceState{}}
	collect := func(kind string, ids []string) {
		sorted := append([]string(nil), ids...)
		sort.Strings(sorted)
		s.Sets[kind] = sorted
	}
	var domains []string
	for _, d := range nm.Domains {
		domains = append(domains, d.Identity().String())
	}
	collect("domains", domains)
	var hosts []string
	for _, h := range nm.Hosts {
		hosts = append(hosts, h.Identity().String())
	}
	collect("hosts", hosts)
	var ips []string
	for _, ip := range nm.IPs {
		ips = append(ips, ip.Identity().String())
	}
	collect("ips", ips)
	var urls []string
	for _, u := range nm.URLs {
		urls = append(urls, u.Identity().String())
	}
	collect("urls", urls)
	var endpoints []string
	for _, e := range nm.Endpoints {
		endpoints = append(endpoints, e.Identity().String())
	}
	collect("endpoints", endpoints)
	var params []string
	for _, p := range nm.Parameters {
		params = append(params, p.Identity().String())
	}
	collect("parameters", params)
	var techs []string
	for _, t := range nm.Technologies {
		techs = append(techs, t.Identity().String())
	}
	collect("technologies", techs)
	var secrets []string
	for _, sec := range nm.Secrets {
		secrets = append(secrets, sec.Identity().String())
	}
	collect("secrets", secrets)
	var findings []string
	for _, f := range nm.Findings {
		findings = append(findings, f.Identity().String())
	}
	collect("findings", findings)
	var js []string
	for _, j := range nm.JavaScript {
		js = append(js, j.Identity().String())
	}
	collect("javascript", js)
	var maps []string
	for _, sm := range nm.SourceMaps {
		maps = append(maps, sm.Identity().String())
	}
	collect("source_maps", maps)
	var ports []string
	for _, p := range nm.Ports {
		ports = append(ports, p.Identity().String())
	}
	collect("ports", ports)
	var services []string
	for _, sv := range nm.Services {
		services = append(services, sv.Identity().String())
	}
	collect("services", services)
	var certs []string
	for _, c := range nm.TLSCertificates {
		certs = append(certs, c.Identity().String())
	}
	collect("tls_certificates", certs)
	for _, sf := range nm.Surfaces {
		s.Surfaces[sf.Identity.String()] = SurfaceState{Level: sf.Level, Score: sf.Score}
	}
	s.Takeover = buildTakeoverCounts(nm.Findings)
	return s, nil
}

// Diff computes the delta from baseline to current. Different targets are
// rejected; identical recorded digests yield a valid empty delta (nothing
// changed as recorded — the digest is carried from the inputs, never
// recomputed, so this is a recorded-equality shortcut, not a verification).
func Diff(baseline, current Snapshot) (*Delta, error) {
	if baseline.Target != current.Target {
		return nil, fmt.Errorf("diff: target mismatch (%q vs %q): deltas across targets are meaningless", baseline.Target, current.Target)
	}
	d := &Delta{
		Target:         current.Target,
		BaselineDigest: baseline.Digest,
		CurrentDigest:  current.Digest,
		Added:          make(map[string][]string, len(datasetKinds)),
		Removed:        make(map[string][]string, len(datasetKinds)),
		Changed:        []SurfaceChange{},
	}
	for _, kind := range datasetKinds {
		added, removed := stringSetDiff(baseline.Sets[kind], current.Sets[kind])
		d.Added[kind] = added
		d.Removed[kind] = removed
	}
	for id, cur := range current.Surfaces {
		old, ok := baseline.Surfaces[id]
		if !ok {
			continue // brand-new surfaces surface via their datasets, not here
		}
		if old.Level != cur.Level || old.Score != cur.Score {
			d.Changed = append(d.Changed, SurfaceChange{
				Identity: id,
				OldLevel: string(old.Level), NewLevel: string(cur.Level),
				OldScore: old.Score, NewScore: cur.Score,
			})
		}
	}
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].Identity < d.Changed[j].Identity })
	d.Takeover = diffTakeover(baseline.Takeover, current.Takeover)
	return d, nil
}

// Empty reports whether the delta carries no change on any axis.
func (d *Delta) Empty() bool {
	for _, kind := range datasetKinds {
		if len(d.Added[kind]) > 0 || len(d.Removed[kind]) > 0 {
			return false
		}
	}
	return len(d.Changed) == 0
}

// AddedCount and RemovedCount total presence changes across datasets.
func (d *Delta) AddedCount() int {
	n := 0
	for _, kind := range datasetKinds {
		n += len(d.Added[kind])
	}
	return n
}

// RemovedCount totals removals across datasets.
func (d *Delta) RemovedCount() int {
	n := 0
	for _, kind := range datasetKinds {
		n += len(d.Removed[kind])
	}
	return n
}

// stringSetDiff returns sorted (added, removed) between two identity
// lists. Both outputs are non-nil, sorted, and deduplicated — duplicate
// inputs (which snapshots never produce after NewModel dedup, but callers
// may hand-roll) stay duplicates in neither output.
func stringSetDiff(baseline, current []string) (added, removed []string) {
	added = []string{}
	removed = []string{}
	inCurrent := make(map[string]struct{}, len(current))
	for _, id := range current {
		inCurrent[id] = struct{}{}
	}
	inBaseline := make(map[string]struct{}, len(baseline))
	for _, id := range baseline {
		inBaseline[id] = struct{}{}
	}
	seenRemoved := make(map[string]struct{}, len(baseline))
	for _, id := range baseline {
		if _, ok := inCurrent[id]; !ok {
			if _, dup := seenRemoved[id]; !dup {
				seenRemoved[id] = struct{}{}
				removed = append(removed, id)
			}
		}
	}
	seenAdded := make(map[string]struct{}, len(current))
	for _, id := range current {
		if _, ok := inBaseline[id]; !ok {
			if _, dup := seenAdded[id]; !dup {
				seenAdded[id] = struct{}{}
				added = append(added, id)
			}
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
