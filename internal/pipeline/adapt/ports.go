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
// channel rather than mutating the engine's probe-target list (probe targets
// are hostname-built URL forms); consumers treat flagged entries as an
// incomplete retained set.

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
// the §0.6 marker from replayed data.
type storedPorts struct {
	Scope     string       `json:"scope"`
	Ports     []asset.Port `json:"ports"`
	Truncated bool         `json:"truncated,omitempty"`
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
				var sp storedPorts
				if jerr := json.Unmarshal(out.Record.Data, &sp); jerr == nil && sp.Scope == scope {
					if ports, valid := validStoredPorts(sp.Ports); valid {
						return portDiscoveryOutput{
							Ports:         ports,
							Relationships: ipPortRelationships(ips, ports),
							Truncated:     sp.Truncated,
						}, nil
					}
				}
				// Corrupt or scope-mismatched record: self-heal by deletion
				// and fall through to execution (best-effort delete).
				_ = cfg.Cache.Delete(ctx, key)
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

	pairs, malformed := parseNaabuOutput(res.Stdout, ips)
	out.Ports = pairs
	out.Relationships = ipPortRelationships(ips, pairs)
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
			sp := storedPorts{Scope: scope, Ports: out.Ports, Truncated: out.Truncated}
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
// validated tcp Port assets. Lines are bounded by the runner's capture cap;
// unparseable lines are counted as malformed (diagnostic material, never a
// panic or a silent drop of the whole capture). Bracketed IPv6 literals
// ("[2001:db8::1]:443") resolve through net.SplitHostPort; bare IPv6 without
// a bracket cannot be disambiguated from ip:port and counts as malformed.
func parseNaabuOutput(stdout []byte, known []asset.IP) ([]asset.Port, int) {
	byAddr := make(map[string]asset.IP, len(known))
	for _, ip := range known {
		byAddr[ip.String()] = ip
	}
	var ports []asset.Port
	seen := make(map[asset.Identity]bool)
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
		if ip, ok := byAddr[canonical]; ok {
			prov = asset.Provenance{Source: "naabu", DiscoveredAt: ip.Prov.DiscoveredAt}
		}
		p, err := asset.NewPort(n, "tcp", prov)
		if err != nil {
			malformed++
			continue
		}
		if seen[p.Identity()] {
			continue
		}
		seen[p.Identity()] = true
		ports = append(ports, p)
	}
	sortPorts(ports)
	return ports, malformed
}

// ipPortRelationships links every input address identity to every discovered
// port (asset.RelationshipIPToPort), deduplicated by edge identity and
// sorted deterministically. Edges are built from the DNS-stage address
// assets themselves so identities match the rest of the graph.
func ipPortRelationships(ips []asset.IP, ports []asset.Port) []asset.Relationship {
	if len(ips) == 0 || len(ports) == 0 {
		return nil
	}
	var rels []asset.Relationship
	seen := make(map[string]bool)
	for _, ip := range ips {
		for _, p := range ports {
			r, err := asset.NewRelationship(ip.Identity(), asset.RelationshipIPToPort, p.Identity())
			if err != nil {
				continue // both endpoints are validated assets; defensive
			}
			id := r.ID()
			if seen[id] {
				continue
			}
			seen[id] = true
			rels = append(rels, r)
		}
	}
	sort.SliceStable(rels, func(i, j int) bool { return rels[i].ID() < rels[j].ID() })
	return rels
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
