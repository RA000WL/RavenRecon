package adapt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/discovery"
)

// Optional port discovery (naabu) — an opt-in enhancement to the httpprobe
// stage. When StageParams["port_discovery"] enables it, the stage runs naabu
// over the addresses the dns stage resolved (StageInput.Results.IPs — i.e.
// AFTER dns resolution) BEFORE HTTP probing begins, and emits every open
// ip:port pair as results-channel additions: asset.Port assets (tcp) plus
// asset.RelationshipIPToPort edges from each resolved address to the port
// found on it.
//
// Execution follows the shared external-tool discipline (AGENTS §8, the
// internal/discovery runner contract, mirrored by internal/crawl/katana.go):
// exec.CommandContext semantics through discovery.ExecRunner, arguments as
// separate argv values (never shell-interpolated — the target-derived IP
// list travels in a temp FILE named by a single argv value), bounded output
// capture (discovery.DefaultMaxOutput per stream), context cancellation
// honored, and structured errors returned.
//
// Honesty markers (sticky flags on the producing stage; the stage outcome
// itself stays whatever probing earned — completed + flag is the §0.6
// carve-out for "the operator asked, here is exactly why nothing appeared"):
//
//   - ports_naabu_missing  — port discovery was requested but the naabu
//     binary does not exist (exec.LookPath failed). Existence and capability
//     are separate concerns (§9): absence is decided ONLY by LookPath,
//     never by a failed version probe.
//   - ports_naabu_failed   — naabu ran but failed (runner error, non-zero
//     exit without usable output). Pairs parsed before a failure are still
//     retained and merged (honest partial retained set).
//   - ports_output_truncated — naabu's stdout exceeded the capture cap; the
//     retained pair set is incomplete. Sets Truncated + the flag (§0.6:
//     truncation is never swallowed), stored in the cache record and
//     replayed with it.
//
// Caching (op "ports.discover", §11): the key covers the schema version,
// operation, target domain identity, a SHA-256 scope hash of the sorted
// input IPs, the result-affecting naabu flags (-top-ports/-rate/-c, mirroring
// crawlCacheKey's inclusion of the pacing flags), and the tool version. A
// version that cannot be probed disables caching entirely (never guessed);
// only StatusCompleted records are ever served, revalidated against the
// current scope hash and the asset model before replay, corrupt records are
// self-healed by deletion.
//
// Scope note (documented deferral, mirrors adapt/doc.go v1.3): the pipeline
// corpus carries no IP assets, so the host→ip leg of the graph remains
// deferred; this adapter emits the ip→port leg over the addresses the dns
// stage already reported. Discovered ports propagate through the results
// channel; since NEW-121 they ALSO become probe targets when the operator
// opts into probing them (StageParams "probe_ports" alongside
// "port_discovery" — a separate knob, because inventory traffic and
// probing traffic are different budgets): the httpprobe stage resolves
// each in-scope host's ports through the host→IP edges the dns stage
// publishes (plus one CNAME hop) and probes scheme://host:port/ pairs
// through the standard engine path. Consumers treat flagged entries as an
// incomplete retained set.

// Port-target synthesis bounds (NEW-121).
const (
	// maxProbePortsPerHost caps synthesized probe ports per host: worst
	// case twice that many probes per host job, inside pool/queue
	// budgets, with the per-job deadline bounding slow ones honestly. Cut
	// hosts set httpprobePortTargetsTruncatedFlag — never silent.
	//
	// Timeout guidance (review wave 2026-09-03): the engine's per-job
	// deadline (30 s default) covers a host's whole target list, so a
	// port-dense host with several slow handshakes exhausts it and
	// records the tail cancelled (honest partial, retried next run
	// since failures never cache). Port-dense scopes should raise the
	// stage deadline (--timeout well above 30 s); refused ports fail in
	// milliseconds and never approach the budget.
	maxProbePortsPerHost = 16
	// httpprobePortTargetsTruncatedFlag marks a run whose per-host port
	// set exceeded maxProbePortsPerHost: only the sorted head was
	// probed.
	httpprobePortTargetsTruncatedFlag = "httpprobe_port_targets_truncated"
)

const (
	// portsOperation is the cache operation name for naabu port discovery.
	portsOperation = "ports.discover"

	// naabuBinary is the external tool this adapter executes.
	naabuBinary = "naabu"

	// naabuTopPorts is the -top-ports value (the 100 most common ports).
	naabuTopPorts = 100
	// naabuRate is the -rate packets-per-second cap.
	naabuRate = 300
	// naabuConcurrency is the -c worker count.
	naabuConcurrency = 25
	// naabuDefaultTimeout bounds one execution when the caller sets none.
	naabuDefaultTimeout = 2 * time.Minute
)

// Sticky-flag vocabulary (see the package-level honesty notes above). The
// names follow the <engine>_<what> convention (adapt/doc.go): "ports" is
// this feature's token inside the httpprobe stage's flag namespace.
const (
	// portsNaabuMissingFlag marks a requested run skipped because the naabu
	// binary does not exist.
	portsNaabuMissingFlag = "ports_naabu_missing"
	// portsNaabuFailedFlag marks a requested run whose naabu execution
	// failed (runner error or unusable non-zero exit); pairs parsed before
	// the failure still merge.
	portsNaabuFailedFlag = "ports_naabu_failed"
	// portsOutputTruncatedFlag marks a run whose stdout hit the capture cap;
	// the retained pair set is incomplete.
	portsOutputTruncatedFlag = "ports_output_truncated"
)

// portDiscoveryConfig carries the per-run inputs the discoverer needs beyond
// the target and address list. Cache nil disables caching; Timeout <= 0
// resolves to naabuDefaultTimeout.
type portDiscoveryConfig struct {
	// Cache is the caller-owned cache (nil = caching disabled).
	Cache cache.Cache
	// Timeout bounds one naabu execution; 0 means naabuDefaultTimeout.
	Timeout time.Duration
}

// portDiscoveryOutput is what one port-discovery attempt produced. Ports and
// Relationships are deduplicated and deterministically sorted; the boolean
// markers map onto the sticky flags above by the producing stage.
type portDiscoveryOutput struct {
	// Ports are the discovered listening ports (tcp), validated through
	// asset.NewPort, deduplicated by identity, sorted ascending.
	Ports []asset.Port
	// Relationships link each input address identity to a port observed on
	// it (asset.RelationshipIPToPort), deduplicated by edge identity,
	// sorted deterministically.
	Relationships []asset.Relationship
	// Truncated reports that naabu's captured output was cut at the stream
	// cap: the retained pair set is incomplete.
	Truncated bool
	// MissingTool reports that naabu does not exist (LookPath failed): the
	// requested discovery never executed.
	MissingTool bool
	// Failed reports that naabu executed but failed (runner error or
	// non-zero exit without usable output). Set by the CALLER from the
	// error return — cancellation is excluded there (the outcome carries
	// it, never a diagnostic flag).
	Failed bool
}

// flags renders the output's sticky-flag set (nil when empty). Truncation
// also drives StageResult.Truncated at the merge site.
func (o *portDiscoveryOutput) flags() map[string]bool {
	if o == nil {
		return nil
	}
	var m map[string]bool
	add := func(name string) {
		if m == nil {
			m = make(map[string]bool, 3)
		}
		m[name] = true
	}
	if o.MissingTool {
		add(portsNaabuMissingFlag)
	}
	if o.Failed {
		add(portsNaabuFailedFlag)
	}
	if o.Truncated {
		add(portsOutputTruncatedFlag)
	}
	return m
}

// portDiscoverer is the seam between the httpprobe stage and a port-discovery
// backend. The production implementation is naabuPortSource; tests inject a
// fake through the HTTPProbeStage field, never through StageParams (params
// are operator configuration, not test plumbing — adapt/doc.go).
type portDiscoverer interface {
	DiscoverPorts(ctx context.Context, target asset.Domain, ips []asset.IP, cfg portDiscoveryConfig) (portDiscoveryOutput, error)
}

// naabuPortSource is the production portDiscoverer: it runs the naabu binary
// when present. runner nil means discovery.ExecRunner; lookPath nil means
// exec.LookPath (both resolved lazily so tests can inject either seam).
type naabuPortSource struct {
	runner   discovery.Runner
	lookPath discovery.LookupFunc
}

// newNaabuPortSource constructs the source. Nil seams select the production
// implementations.
func newNaabuPortSource(runner discovery.Runner, lookPath discovery.LookupFunc) *naabuPortSource {
	return &naabuPortSource{runner: runner, lookPath: lookPath}
}

var _ portDiscoverer = (*naabuPortSource)(nil)

// storedPorts is the cache payload for one ports.discover record. The scope
// hash binds the record to the exact input address list (§11: every
// result-affecting input participates in the key AND is re-verified at
// replay); Truncated rides the record end-to-end so a warm run re-derives
// the §0.6 marker from replayed data. Relationships carry the per-IP
// attribution (which address each port was observed on): without them a
// warm replay could only rebuild a cross-product join, misattributing
// every port to every address.
type storedPorts struct {
	Scope         string               `json:"scope"`
	Ports         []asset.Port         `json:"ports"`
	Relationships []asset.Relationship `json:"relationships,omitempty"`
	Truncated     bool                 `json:"truncated,omitempty"`
}

// DiscoverPorts implements portDiscoverer.
//
// Flow: LookPath("naabu") → missing ⇒ ({MissingTool}, nil); version probe →
// cache lookup (completed hits only, scope-revalidated) → write the input
// addresses to a temp file → execute naabu → parse ip:port pairs → cache
// store on success. Every path returns promptly on ctx cancellation with a
// context-wrapped error.
func (s *naabuPortSource) DiscoverPorts(ctx context.Context, target asset.Domain, ips []asset.IP, cfg portDiscoveryConfig) (portDiscoveryOutput, error) {
	if ctx == nil {
		return portDiscoveryOutput{}, fmt.Errorf("ports.discover: context must not be nil")
	}
	if len(ips) == 0 {
		// Nothing resolved to scan: an honest zero-cost no-op (the caller
		// gates on this too; defensive for direct callers).
		return portDiscoveryOutput{}, nil
	}
	ips = normalizeIPs(ips)

	lookPath := s.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	path, err := lookPath(naabuBinary)
	if err != nil {
		// Missing binary: an honest skip marker, never an error (mirrors
		// katana's StatusMissing class). Existence is decided ONLY here.
		return portDiscoveryOutput{MissingTool: true}, nil
	}
	runner := s.runner
	if runner == nil {
		runner = discovery.ExecRunner{}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = naabuDefaultTimeout
	}

	scope := portsScopeHash(ips)
	version := detectNaabuVersion(ctx, runner, path)

	// Cache-before-execute (consumer-side composition; internal/runtime
	// never imports internal/cache — AGENTS §0.4). Unknown version ⇒ no
	// caching at all (never guess a version into a key).
	if cfg.Cache != nil && version != "" {
		if key, kerr := portsCacheKey(target, scope, version); kerr == nil {
			out := cfg.Cache.Get(ctx, key)
			if out.IsHit() && out.Record != nil && out.Record.Status == cache.StatusCompleted {
				// Envelope check (mirrors httpprobe lookupProbe): a record
				// found under this key with different operation or target
				// fields could only be tampered with — delete and re-execute.
				if out.Record.Operation != portsOperation || out.Record.Target != target.Identity().String() {
					_ = cfg.Cache.Delete(ctx, key)
				} else {
					var sp storedPorts
					if jerr := json.Unmarshal(out.Record.Data, &sp); jerr == nil && sp.Scope == scope {
						if ports, valid := validStoredPorts(sp.Ports); valid {
							if rels, rok := validStoredPortRelationships(sp.Relationships, ips, ports); rok {
								return portDiscoveryOutput{
									Ports:         ports,
									Relationships: rels,
									Truncated:     sp.Truncated,
								}, nil
							}
						}
					}
					// Corrupt or scope-mismatched record: self-heal by deletion
					// and fall through to execution (best-effort delete).
					_ = cfg.Cache.Delete(ctx, key)
				}
			}
		}
	}

	// Target-derived data travels in a temp file named by ONE argv value —
	// never composed into shell syntax (§8).
	f, err := os.CreateTemp("", "ravenrecon-naabu-*.txt")
	if err != nil {
		return portDiscoveryOutput{}, fmt.Errorf("ports.discover: create input file: %w", err)
	}
	tmpName := f.Name()
	defer os.Remove(tmpName)
	var b strings.Builder
	for _, ip := range ips {
		b.WriteString(ip.String())
		b.WriteByte('\n')
	}
	if _, werr := f.WriteString(b.String()); werr != nil {
		f.Close()
		return portDiscoveryOutput{}, fmt.Errorf("ports.discover: write input file: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		return portDiscoveryOutput{}, fmt.Errorf("ports.discover: write input file: %w", cerr)
	}

	// Separate argv values; ctx bounds the child (plus the explicit per-tool
	// deadline below); bounded per-stream capture via Limits.
	args := []string{
		"-l", tmpName,
		"-top-ports", strconv.Itoa(naabuTopPorts),
		"-silent",
		"-rate", strconv.Itoa(naabuRate),
		"-c", strconv.Itoa(naabuConcurrency),
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	res, rerr := runner.Run(runCtx, discovery.Cmd{Path: path, Args: args}, discovery.Limits{MaxOutput: discovery.DefaultMaxOutput})
	cancel()

	out := portDiscoveryOutput{}
	if res.StdoutTruncated || res.StderrTruncated {
		out.Truncated = true
	}
	if rerr != nil {
		if ctx.Err() != nil || isContextError(rerr) {
			// Cancellation dominates: the stage outcome will carry it; the
			// partial capture is discarded (nothing honest was retained —
			// the process was killed mid-write).
			return portDiscoveryOutput{}, fmt.Errorf("ports.discover: %w", rerr)
		}
		return out, fmt.Errorf("ports.discover: run %s: %w", naabuBinary, rerr)
	}

	pairs, rels, malformed := parseNaabuOutput(res.Stdout, ips)
	out.Ports = pairs
	out.Relationships = rels
	if res.ExitCode != 0 && len(pairs) == 0 {
		// Non-zero exit with NOTHING usable: a genuine failure (the
		// malformed counter, when present, explains why parsing yielded
		// nothing). Retained-set-empty + failure flag beats silence.
		return out, fmt.Errorf("ports.discover: %s exited %d without usable output (%d unparseable line(s))",
			naabuBinary, res.ExitCode, malformed)
	}
	// Non-zero exit WITH usable output keeps the pairs (honest partial
	// retained set) and surfaces the failure through the error so the
	// caller raises ports_naabu_failed instead of a bare completed.
	if res.ExitCode != 0 {
		return out, fmt.Errorf("ports.discover: %s exited %d (%d pair(s) retained)", naabuBinary, res.ExitCode, len(pairs))
	}

	// Store only clean runs: failures re-execute next run (the cache serves
	// completed records only, and a failed discovery must not masquerade as
	// a servable hit). A truncated-output run stores completed WITH the
	// marker — the documented §0.6 carve-out.
	if cfg.Cache != nil && version != "" {
		if key, kerr := portsCacheKey(target, scope, version); kerr == nil {
			sp := storedPorts{Scope: scope, Ports: out.Ports, Relationships: out.Relationships, Truncated: out.Truncated}
			if data, merr := json.Marshal(sp); merr == nil {
				rec := cache.Record{
					Operation: portsOperation,
					Target:    target.Identity().String(),
					Tool:      cache.ToolInfo{Name: naabuBinary, Version: version},
					Status:    cache.StatusCompleted,
					Data:      data,
				}
				_ = cfg.Cache.Put(ctx, key, rec)
			}
		}
	}
	return out, nil
}

// detectNaabuVersion probes the tool version for the cache key. Failure of
// ANY kind yields "" (= caching disabled) — it never claims the binary is
// absent (existence was already decided by LookPath; §9 separates the two).
func detectNaabuVersion(ctx context.Context, runner discovery.Runner, path string) string {
	lookCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := runner.Run(lookCtx, discovery.Cmd{Path: path, Args: []string{"-version"}}, discovery.Limits{MaxOutput: 4 << 10})
	if err != nil {
		return ""
	}
	out := string(res.Stdout)
	if strings.TrimSpace(out) == "" {
		out = string(res.Stderr)
	}
	for _, field := range strings.Fields(out) {
		f := strings.Trim(field, ",;()[]\"'v")
		if strings.Contains(f, ".") && f != "" {
			return f
		}
	}
	return ""
}

// portsScopeHash derives the deterministic scope binding: hex SHA-256 of the
// canonical input address strings joined by "," (sorted, deduplicated).
func portsScopeHash(ips []asset.IP) string {
	names := make([]string, 0, len(ips))
	for _, ip := range ips {
		names = append(names, ip.String())
	}
	sort.Strings(names)
	h := sha256.Sum256([]byte(strings.Join(names, ",")))
	return hex.EncodeToString(h[:])
}

// portsCacheKey builds the ports.discover key: schema version (applied by
// NewKey), operation, target identity, scope hash, result-affecting config,
// tool version (§11 — mirroring crawlCacheKey's inclusion of the pacing
// flags on the safe side of staleness).
func portsCacheKey(target asset.Domain, scope, version string) (cache.Key, error) {
	return cache.NewKey(cache.KeyParts{
		Operation: portsOperation,
		Target:    target.Identity().String(),
		Config: map[string]string{
			"scope":       scope,
			"top_ports":   strconv.Itoa(naabuTopPorts),
			"rate":        strconv.Itoa(naabuRate),
			"concurrency": strconv.Itoa(naabuConcurrency),
		},
		Tool: cache.ToolInfo{Name: naabuBinary, Version: version},
	})
}

// parseNaabuOutput parses naabu's silent stdout ("ip:port" lines) into
// validated tcp Port assets plus per-IP ip→port relationships. Each line's
// address attributes exactly one edge: 1.1.1.1:80 and 2.2.2.2:443 yield
// 1.1.1.1→80 and 2.2.2.2→443 — never the cross-product (every address to
// every port). Lines are bounded by the runner's capture cap;
// unparseable lines are counted as malformed (diagnostic material, never a
// panic or a silent drop of the whole capture). Bracketed IPv6 literals
// ("[2001:db8::1]:443") resolve through net.SplitHostPort; bare IPv6 without
// a bracket cannot be disambiguated from ip:port and counts as malformed.
// Lines for addresses outside the scanned set keep their port (union
// inventory) but yield no edge: an unattributed port is never joined to a
// host it was not observed on.
func parseNaabuOutput(stdout []byte, known []asset.IP) ([]asset.Port, []asset.Relationship, int) {
	byAddr := make(map[string]asset.IP, len(known))
	for _, ip := range known {
		byAddr[ip.String()] = ip
	}
	var ports []asset.Port
	seenPort := make(map[asset.Identity]bool)
	var rels []asset.Relationship
	seenRel := make(map[string]bool)
	malformed := 0
	for _, raw := range bytes.Split(stdout, []byte{'\n'}) {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		host, portStr, err := net.SplitHostPort(line)
		if err != nil {
			malformed++
			continue
		}
		host = strings.TrimPrefix(host, "[")
		host = strings.TrimSuffix(host, "]")
		addr, err := netip.ParseAddr(host)
		if err != nil {
			malformed++
			continue
		}
		canonical := addr.Unmap().String()
		n, err := strconv.Atoi(portStr)
		if err != nil || n < 1 || n > 65535 {
			malformed++
			continue
		}
		prov := asset.Provenance{Source: "naabu"}
		var srcIP asset.IP
		srcOK := false
		if ip, ok := byAddr[canonical]; ok {
			prov = asset.Provenance{Source: "naabu", DiscoveredAt: ip.Prov.DiscoveredAt}
			srcIP, srcOK = ip, true
		}
		p, err := asset.NewPort(n, "tcp", prov)
		if err != nil {
			malformed++
			continue
		}
		if !seenPort[p.Identity()] {
			seenPort[p.Identity()] = true
			ports = append(ports, p)
		}
		if !srcOK {
			continue
		}
		r, err := asset.NewRelationship(srcIP.Identity(), asset.RelationshipIPToPort, p.Identity())
		if err != nil {
			continue // both endpoints are validated assets; defensive
		}
		if id := r.ID(); !seenRel[id] {
			seenRel[id] = true
			rels = append(rels, r)
		}
	}
	sortPorts(ports)
	sort.SliceStable(rels, func(i, j int) bool { return rels[i].ID() < rels[j].ID() })
	return ports, rels, malformed
}

// validStoredPorts revalidates every decoded port through the asset model
// before a cached record may be served (self-healing boundary, mirroring
// katana's replay validation). Any invalid entry refuses the WHOLE record.
func validStoredPorts(in []asset.Port) ([]asset.Port, bool) {
	out := make([]asset.Port, 0, len(in))
	for _, p := range in {
		v, err := asset.NewPort(int(p.Number), p.Protocol, p.Prov)
		if err != nil {
			return nil, false
		}
		out = append(out, v)
	}
	sortPorts(out)
	return out, true
}

// validStoredPortRelationships revalidates stored ip→port edges before a
// cached record may be served: every edge must be an IPToPort relationship
// whose endpoints re-parse through the asset model and whose source is one
// of the current input addresses and whose target is one of the validated
// ports. Any invalid edge refuses the WHOLE record (self-heal by
// re-execution). Old records without relationships (pre-per-IP shape) are
// refused as well — they can only rebuild a cross-product join.
func validStoredPortRelationships(in []asset.Relationship, ips []asset.IP, ports []asset.Port) ([]asset.Relationship, bool) {
	if len(ports) > 0 && len(in) == 0 {
		return nil, false
	}
	byIP := make(map[string]bool, len(ips))
	for _, ip := range ips {
		byIP[ip.Identity().String()] = true
	}
	byPort := make(map[string]bool, len(ports))
	for _, p := range ports {
		byPort[p.Identity().String()] = true
	}
	out := make([]asset.Relationship, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, r := range in {
		if r.Kind != asset.RelationshipIPToPort {
			return nil, false
		}
		v, err := asset.NewRelationship(r.From, r.Kind, r.To)
		if err != nil {
			return nil, false
		}
		if !byIP[v.From.String()] || !byPort[v.To.String()] {
			return nil, false
		}
		if id := v.ID(); !seen[id] {
			seen[id] = true
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out, true
}

// normalizeIPs returns the input addresses canonically (unmapped v4-in-v6,
// deduplicated by identity, sorted) — matching how the dns stage reports
// them, so identity comparisons and the scope hash are stable even when a
// direct caller passes raw addresses.
func normalizeIPs(ips []asset.IP) []asset.IP {
	seen := make(map[string]bool, len(ips))
	out := make([]asset.IP, 0, len(ips))
	for _, ip := range ips {
		canonical := ip
		canonical.Addr = canonical.Addr.Unmap()
		key := canonical.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, canonical)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// sortPorts orders ports by number then protocol (deterministic).
func sortPorts(ports []asset.Port) {
	sort.SliceStable(ports, func(i, j int) bool {
		if ports[i].Number != ports[j].Number {
			return ports[i].Number < ports[j].Number
		}
		return ports[i].Protocol < ports[j].Protocol
	})
}

// portProbeEnabled reports whether discovered ports are additionally
// probed as scheme://host:port/ targets (NEW-121), via
// StageParams["probe_ports"]. OFF by default; truthy values follow the
// port_discovery spelling convention ("true"/"1"/"yes"/"on",
// case-insensitive). It is a SEPARATE knob from port_discovery on
// purpose — knob philosophy (review wave 2026-09-03): cheap,
// usually-zero-traffic enrichment defaults ON (urllive reflection,
// takeover confirmation), while traffic-multiplying features default
// OFF (naabu discovery, port probing). Operators opt into budgets,
// never out of surprises.
func portProbeEnabled(params map[string]string) bool {
	if params == nil {
		return false
	}
	v, ok := params["probe_ports"]
	if !ok {
		return false
	}
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// synthesizePortTargets resolves each in-scope host's probe ports
// (NEW-121): the union of ports open on the host's own addresses plus
// the addresses reachable through one CNAME hop (a vhost behind a CNAME
// is served from that infrastructure under the host's name), joined from
// the dns stage's host→IP/host→CNAME edges through naabu's ip→port
// edges. The join is per-IP, never the cross-product: only ports with an
// ip→port edge on the host's own (or CNAME-hop) addresses are attributed.
// Only TCP ports validated port assets carry are honored (naabu
// emits TCP exclusively; anything else is skipped, never probed).
// Output is one ascending-sorted list per host name; hosts without ports
// are absent. Beyond maxProbePortsPerHost the sorted head is kept and
// the second return reports the cut (never silent).
func synthesizePortTargets(hosts []asset.Host, rels []asset.Relationship, pd *portDiscoveryOutput) (map[string][]int, bool) {
	if pd == nil || len(pd.Ports) == 0 {
		return nil, false
	}
	portByID := make(map[string]int, len(pd.Ports))
	for _, p := range pd.Ports {
		if p.Protocol != "tcp" {
			continue
		}
		portByID[p.Identity().String()] = int(p.Number)
	}
	// Address ownership: direct host->IP edges, plus one CNAME hop
	// (host->CNAME-target, then the target's own host->IP edges).
	direct := make(map[string][]string)
	cnames := make(map[string][]string)
	for _, r := range rels {
		switch r.Kind {
		case asset.RelationshipHostToIP:
			h := r.From.String()
			direct[h] = append(direct[h], r.To.String())
		case asset.RelationshipHostToCNAME:
			h := r.From.String()
			cnames[h] = append(cnames[h], r.To.String())
		}
	}
	ipPorts := make(map[string][]int)
	for _, r := range pd.Relationships {
		if r.Kind != asset.RelationshipIPToPort {
			continue
		}
		n, ok := portByID[r.To.String()]
		if !ok {
			continue
		}
		ip := r.From.String()
		ipPorts[ip] = append(ipPorts[ip], n)
	}
	var out map[string][]int
	truncated := false
	for _, h := range hosts {
		key := h.Identity().String()
		seen := make(map[int]bool)
		var ports []int
		addrs := append(append([]string(nil), direct[key]...), transitiveAddrs(cnames, direct, key)...)
		for _, ip := range addrs {
			for _, n := range ipPorts[ip] {
				if !seen[n] {
					seen[n] = true
					ports = append(ports, n)
				}
			}
		}
		if len(ports) == 0 {
			continue
		}
		sort.Ints(ports)
		if len(ports) > maxProbePortsPerHost {
			ports = ports[:maxProbePortsPerHost]
			truncated = true
		}
		if out == nil {
			out = make(map[string][]int)
		}
		out[h.Name] = ports
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, truncated
}

// transitiveAddrs returns the addresses owned through one CNAME hop:
// every address owned by the host's CNAME targets.
func transitiveAddrs(cnames map[string][]string, direct map[string][]string, host string) []string {
	var out []string
	for _, target := range cnames[host] {
		out = append(out, direct[target]...)
	}
	return out
}
