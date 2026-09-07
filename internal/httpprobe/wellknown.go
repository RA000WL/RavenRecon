package httpprobe

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Well-known mistake paths: developer-mistake and operations surfaces worth
// fetching on every live host (robots/sitemaps, version control, env files,
// actuator/health/metrics/debug endpoints, API docs, GraphQL playgrounds,
// backup/database dumps, package manifests, legacy debug handlers). Curated
// lists live with the caller (the pipeline adapter ships the default set);
// the engine only bounds, validates, and probes them.
//
// Probing rules (see probeHost): paths run only when a ROOT target completed
// with an HTTP response — a refused/TLS-failed/DNS-dead host proves no HTTP
// server, so paths would only bill budget and log noise. The scheme follows
// the responding root (https preferred); redirects still cross schemes
// through the standard in-scope follow path. Port-target responses do not
// enable paths (v1 scope: roots gate, paths ride the canonical deployment).
const (
	// maxWellKnownPaths bounds one run's per-host path list. The pipeline
	// adapter's curated set sits well below it; direct callers exceeding it
	// are rejected (caller bug, mirroring the HostPorts boundary).
	maxWellKnownPaths = 64
	// maxWellKnownPathBytes bounds one path entry.
	maxWellKnownPathBytes = 256
)

// normalizeWellKnownPaths validates the configured path list at the
// boundary, before any pool or limiter exists: every entry must be a bare
// absolute path (leading "/", no scheme or host), within the byte bound,
// with at most maxWellKnownPaths entries — or the whole call is rejected
// (caller bug, mirroring normalizeHostPorts). A bare "/" entry is elided
// (it duplicates the root target; planned once, never probed twice).
// Output is deduplicated and sorted, so identical configurations probe
// identical surfaces in identical order.
func normalizeWellKnownPaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	if len(paths) > maxWellKnownPaths {
		return nil, fmt.Errorf("httpprobe: %d well-known paths over bound %d", len(paths), maxWellKnownPaths)
	}
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || p == "/" {
			continue // blank, or the root itself (planned once)
		}
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("httpprobe: well-known path %q must be absolute (leading /)", p)
		}
		if strings.Contains(p, "://") {
			return nil, fmt.Errorf("httpprobe: well-known path %q must not carry a scheme or host", p)
		}
		if len(p) > maxWellKnownPathBytes {
			return nil, fmt.Errorf("httpprobe: well-known path %q over bound %d bytes", p, maxWellKnownPathBytes)
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// respondingScheme reports which root scheme proved an HTTP server: "https"
// when the https root completed with an HTTP response, else "http" when the
// http root did, else "" (no server proven — paths stay unprobed). Roots are
// matched by canonical identity so port-target responses never gate paths.
func respondingScheme(probes []ProbeResult, httpRootID, httpsRootID string) string {
	responded := func(id string) bool {
		for _, pr := range probes {
			if pr.URL.Identity().String() == id && pr.StatusCode != 0 {
				return true
			}
		}
		return false
	}
	if responded(httpsRootID) {
		return "https"
	}
	if responded(httpRootID) {
		return "http"
	}
	return ""
}

// wellKnownSpecs builds one host's path probe targets on scheme: canonical
// Phase 2 URLs skipped when their identity duplicates an already-planned
// target (a path of "/" can never arrive — normalized away — but defense in
// depth costs nothing). Targets are emitted in the normalized (sorted)
// path order.
func wellKnownSpecs(host asset.Host, scheme string, paths []string, clock runtime.Clock, seen map[string]bool) ([]probeTargetSpec, error) {
	var specs []probeTargetSpec
	for _, p := range paths {
		u, err := asset.ParseURL(scheme+"://"+host.Name+p, asset.Provenance{
			Source:       "http-probe",
			DiscoveredAt: clock.Now().UTC(),
		})
		if err != nil {
			return nil, err
		}
		if seen[u.Identity().String()] {
			continue
		}
		seen[u.Identity().String()] = true
		specs = append(specs, probeTargetSpec{url: u, scheme: scheme})
	}
	return specs, nil
}
