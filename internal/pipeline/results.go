package pipeline

import (
	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
	"github.com/RA000WL/RavenRecon/internal/priority"
)

// Results is the pipeline's typed results channel: the Phase-2 values
// stages produce beyond the corpus itself (technologies, evidence,
// findings, parameters, secrets, endpoints, JavaScript assets, scoring
// output...). Every channel mirrors one report.Context data channel 1:1
// (internal/report/context.go) — the report stage consumes the full
// Context from this struct (T3d).
//
// Producers: the secrentel T3c adapter was the first Results producer;
// the T3d adapters wired the remaining stage families (the producers are
// documented per field below). A stage that has nothing to add leaves its
// fields nil or empty — that is legal and means "nothing added".
//
// The channel is assembled by the runner: every stage receives the
// merged state of the EARLIER stages via StageInput.Results (read-only),
// contributes its own additions via StageResult.Results, and the runner
// merges them (first-seen dedup, deterministic order, per-channel
// MaxOutput caps at each merge) into RunReport.Results.
type Results struct {
	// IPs are the canonical resolved addresses (asset.IP). Producer: the
	// dns and httpprobe stage families (wired in T3d — the engines'
	// AllIPs accessors, copied, never rebuilt).
	IPs []asset.IP

	// Ports are the canonical listening ports (asset.Port). Producer: the
	// httpprobe stage family (wired in T3d).
	Ports []asset.Port

	// Services are the canonical services identified on ports
	// (asset.Service). Producer: the httpprobe stage family (wired in
	// T3d).
	Services []asset.Service

	// Endpoints are the canonical endpoint candidates (asset.Endpoint).
	// Producer: the httpprobe, urlintel, and jsintel stage families
	// (wired in T3d).
	Endpoints []asset.Endpoint

	// JavaScript are the canonical script assets (asset.JavaScript).
	// Producer: the jsintel stage family (wired in T3d).
	JavaScript []asset.JavaScript

	// Parameters are the canonical observed parameters
	// (asset.Parameter). Producer: the urlintel and jsintel stage
	// families (wired in T3d).
	Parameters []asset.Parameter

	// Technologies are the canonical detected technologies
	// (asset.Technology). Producer: the techintel and jsintel stage
	// families (wired in T3d).
	Technologies []asset.Technology

	// Secrets are the canonical secret candidates
	// (asset.SecretCandidate). Producer: the secrentel stage family (its
	// T3c adapter is wired) and the jsintel stage family (wired in T3d).
	// The secrentel adapter consumes the pipeline-internal document channel
	// as its document source, never this channel's JavaScript field.
	Secrets []asset.SecretCandidate

	// Evidence are the canonical evidence observations
	// (asset.Evidence). Producer: the techintel and jsintel stage
	// families (wired in T3d) and the secrentel T3c adapter (wired — the
	// engine's evidence passes through the adapter, never rebuilt).
	Evidence []asset.Evidence

	// Findings are the detection findings (asset.Finding). Producer: the
	// detect stage family (wired in T3d — the engine report's findings,
	// copied, never rebuilt).
	Findings []asset.Finding

	// TLSCertificates are the canonical TLS leaf certificates
	// (asset.TLSCertificate, keyed by fingerprint). Producer: the
	// httpprobe stage family (wired in T3d).
	TLSCertificates []asset.TLSCertificate

	// SourceMaps are the canonical source-map assets (asset.SourceMap).
	// Producer: the jsintel stage family (wired in T3d).
	SourceMaps []asset.SourceMap

	// Relationships are the typed, directed asset-graph edges
	// (asset.Relationship). Producer: the httpprobe, urlintel, techintel,
	// and jsintel stage families (wired in T3d) and the secrentel T3c
	// adapter (wired — the engine's relationships pass through the
	// adapter, never rebuilt).
	Relationships []asset.Relationship

	// Surfaces are the scored surfaces of the priority engine
	// (priority.SurfaceAsset). Producer: the priority stage family (wired
	// in T3d — one surface per completed asset result, copied).
	Surfaces []priority.SurfaceAsset

	// Groups are the correlated surface groups of the priority engine
	// (priority.Group). Producer: the priority stage family (wired in
	// T3d). Dedup: first-seen group per anchor wins — the merge keys on
	// Group.Anchor (see mergeResults), so when two stages contribute
	// groups anchored at the same identity, the first stage's group
	// survives and the later group's members are dropped wholesale. That
	// is the documented first-seen dedup semantics (identical to the
	// corpus merge), NOT a truncation: it never sets a flag. Group-level
	// member truncation (Group.Truncated) rides on the group values only;
	// the run-level correlation cut maps to the priority_groups_truncated
	// sticky flag on the producing stage.
	Groups []priority.Group

	// AttackPaths are the attack-path hypotheses of the priority engine
	// (priority.AttackPath). Producer: the priority stage family (wired
	// in T3d). Dedup: first-seen path per root wins — the merge keys on
	// AttackPath.Root (see mergeResults), with the same non-truncation
	// semantics documented on Groups.
	AttackPaths []priority.AttackPath

	// LiveRecords are the URL liveness observations (httpprobe.LiveRecord).
	// Producer: the urllive stage family (OPT-P0-3). Each record is keyed by
	// the canonical URL identity (asset.URL.Identity().String()), so the same
	// URL observed by multiple sources deduplicates to the first-seen
	// observation. The channel is bounded by MaxOutput and participates in
	// the <channel>_truncated sticky-flag vocabulary as "live_records".
	LiveRecords []httpprobe.LiveRecord
}

// mergeResults appends one stage's result additions to the run's
// accumulated Results channel, dropping entries whose canonical identity
// already appeared (first-seen wins, stable order — identical to the
// corpus merge), then enforces the per-channel cap: after the merge every
// channel holds at most cap entries, first-seen order kept, tail dropped.
// Cut entries remain first-seen — the run-wide seen map is never pruned —
// so they cannot re-enter the channel, even through a later stage with a
// larger cap (identical to the corpus cap's permanence).
//
// Dedup keys are the canonical identity strings:
//
//   - asset types (asset.IP through asset.SourceMap): the "kind:value"
//     form of their Identity() method — asset.Identity.String(), exactly
//     how the corpus merge derives its keys;
//   - asset.Relationship: its ID() string (the asset type has no
//     Identity() method; ID() is its documented canonical identity — the
//     same directed edge added twice deduplicates, the reverse or
//     differently-kind edge stays distinct);
//   - priority.SurfaceAsset / Group / AttackPath: their Identity field /
//     Anchor / Root — the canonical asset.Identity values — stringified
//     the same "kind:value" way.
//
// Dedup is PER CHANNEL: the seen map is shared across all channels, so
// every key is namespaced by its channel name. Without the namespace, the
// same canonical identity legitimately carried by two channels (a Group
// anchored at the same host identity as an AttackPath's Root, or a
// SurfaceAsset whose Identity kind matches an asset channel, e.g. an
// ip:-keyed surface next to the IPs channel) would collide and drop the
// later channel's first-seen entry.
//
// It returns the names of the channels the cap cut, in fixed channel
// order, from the documented vocabulary: ips, ports, services, endpoints,
// javascript, parameters, technologies, secrets, evidence, findings,
// tls_certificates, source_maps, relationships, surfaces, groups,
// attack_paths, live_records. The runner records the "<name>_truncated" sticky flag and
// report.Truncated for each returned name (AGENTS §0.6 carve-out,
// mirroring corpus_capped).
//
// The merge runs regardless of the stage's outcome — a failed stage's
// retained results are still merged (mirroring the corpus Additions
// semantics; the merge consumes the stage's raw StageResult, exactly like
// the corpus merge). The returned slices never alias add; when a
// channel's additions are empty the destination slice is returned
// without copying (the cap may still re-slice it).
func mergeResults(dst *Results, add Results, seen map[string]struct{}, cap int) []string {
	var capped []string
	note := func(cut bool, name string) {
		if cut {
			capped = append(capped, name)
		}
	}
	var cut bool
	dst.IPs, cut = mergeChannel(dst.IPs, add.IPs, seen, "ips", cap, func(a asset.IP) string { return a.Identity().String() })
	note(cut, "ips")
	dst.Ports, cut = mergeChannel(dst.Ports, add.Ports, seen, "ports", cap, func(a asset.Port) string { return a.Identity().String() })
	note(cut, "ports")
	dst.Services, cut = mergeChannel(dst.Services, add.Services, seen, "services", cap, func(a asset.Service) string { return a.Identity().String() })
	note(cut, "services")
	dst.Endpoints, cut = mergeChannel(dst.Endpoints, add.Endpoints, seen, "endpoints", cap, func(a asset.Endpoint) string { return a.Identity().String() })
	note(cut, "endpoints")
	dst.JavaScript, cut = mergeChannel(dst.JavaScript, add.JavaScript, seen, "javascript", cap, func(a asset.JavaScript) string { return a.Identity().String() })
	note(cut, "javascript")
	dst.Parameters, cut = mergeChannel(dst.Parameters, add.Parameters, seen, "parameters", cap, func(a asset.Parameter) string { return a.Identity().String() })
	note(cut, "parameters")
	dst.Technologies, cut = mergeChannel(dst.Technologies, add.Technologies, seen, "technologies", cap, func(a asset.Technology) string { return a.Identity().String() })
	note(cut, "technologies")
	dst.Secrets, cut = mergeChannel(dst.Secrets, add.Secrets, seen, "secrets", cap, func(a asset.SecretCandidate) string { return a.Identity().String() })
	note(cut, "secrets")
	dst.Evidence, cut = mergeChannel(dst.Evidence, add.Evidence, seen, "evidence", cap, func(a asset.Evidence) string { return a.Identity().String() })
	note(cut, "evidence")
	dst.Findings, cut = mergeChannel(dst.Findings, add.Findings, seen, "findings", cap, func(a asset.Finding) string { return a.Identity().String() })
	note(cut, "findings")
	dst.TLSCertificates, cut = mergeChannel(dst.TLSCertificates, add.TLSCertificates, seen, "tls_certificates", cap, func(a asset.TLSCertificate) string { return a.Identity().String() })
	note(cut, "tls_certificates")
	dst.SourceMaps, cut = mergeChannel(dst.SourceMaps, add.SourceMaps, seen, "source_maps", cap, func(a asset.SourceMap) string { return a.Identity().String() })
	note(cut, "source_maps")
	dst.Relationships, cut = mergeChannel(dst.Relationships, add.Relationships, seen, "relationships", cap, func(r asset.Relationship) string { return r.ID() })
	note(cut, "relationships")
	dst.Surfaces, cut = mergeChannel(dst.Surfaces, add.Surfaces, seen, "surfaces", cap, func(s priority.SurfaceAsset) string { return s.Identity.String() })
	note(cut, "surfaces")
	dst.Groups, cut = mergeChannel(dst.Groups, add.Groups, seen, "groups", cap, func(g priority.Group) string { return g.Anchor.String() })
	note(cut, "groups")
	dst.AttackPaths, cut = mergeChannel(dst.AttackPaths, add.AttackPaths, seen, "attack_paths", cap, func(p priority.AttackPath) string { return p.Root.String() })
	note(cut, "attack_paths")
	dst.LiveRecords, cut = mergeChannel(dst.LiveRecords, add.LiveRecords, seen, "live_records", cap, func(r httpprobe.LiveRecord) string { return r.URL.Identity().String() })
	note(cut, "live_records")
	return capped
}

// mergeChannel merges one results channel: it appends add to cur, dropping
// entries whose canonical identity key already appeared (first-seen wins,
// stable order), then enforces the cap with a deterministic tail drop (a
// negative cap retains nothing). It reports whether the cap cut anything.
// Keys are namespaced by the channel's name (ns) so identical canonical
// identities carried by different channels never collide in the shared
// seen map — dedup is per channel. The returned slice is fresh whenever
// add is non-empty and never aliases add or cur; when add is empty, cur is
// returned unchanged (the runner owns cur and no stage ever aliases it).
func mergeChannel[T any](cur []T, add []T, seen map[string]struct{}, ns string, cap int, key func(T) string) ([]T, bool) {
	if len(add) > 0 {
		out := make([]T, 0, len(cur)+len(add))
		out = append(out, cur...)
		for _, a := range add {
			k := ns + "\x00" + key(a)
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, a)
		}
		cur = out
	}
	keep := cap
	if keep < 0 {
		keep = 0
	}
	if len(cur) > keep {
		cur = cur[:keep]
		return cur, true
	}
	return cur, false
}
