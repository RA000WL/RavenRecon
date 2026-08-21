package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// chaos is the chaos-client adapter (ProjectDiscovery).
//
// Invocation (passive only):
//
//	chaos -d <domain> -silent -json
//
// -d selects the target; -silent suppresses banners; -json emits one JSON
// object per line {"domain":"..."} (fallback to plain text first-token if a
// line is not JSON). No active options are ever passed. Version detection
// uses -version. Chaos requires PDCP_API_KEY (free tier 10k req/m) — without
// it the dataset cannot be queried; Detect surfaces a missing key as
// StatusMissing so doctor and pre-run detection make the configuration gap
// explicit (the binary may exist but is unusable without the key).
type chaos struct{ env toolEnv }

// Name implements Source.
func (c chaos) Name() string { return "chaos" }

// Detect implements Source.
func (c chaos) Detect(ctx context.Context) Detection {
	e := c.env.sanitized()
	d := Detection{Source: e.name}
	ctx, cancel := context.WithTimeout(ctx, e.detectTimeout)
	defer cancel()
	path, err := e.lookup(e.binOrName())
	if err != nil {
		d.Status = StatusMissing
		d.Reason = fmt.Sprintf("executable %q not found", e.binOrName())
		return d
	}
	d.Exists = true
	// Chaos requires PDCP_API_KEY: without it the tool cannot query the Chaos
	// dataset. Report this as missing (not warn) so the doctor output reads
	// "chaos: missing (PDCP_API_KEY not set)" and the operator knows the tool
	// is not usable in this environment. The key is free tier 10k req/m.
	if v := strings.TrimSpace(os.Getenv("PDCP_API_KEY")); v == "" {
		d.Status = StatusMissing
		d.Reason = fmt.Sprintf("executable %s exists but PDCP_API_KEY not set (chaos requires PDCP_API_KEY; free tier 10k req/m)", path)
		return d
	}
	res, err := e.runner.Run(ctx, Cmd{Path: path, Args: []string{"-version"}}, Limits{MaxOutput: 4 << 10})
	if err != nil {
		if errors.Is(err, ErrExecutableNotFound) {
			d.Status = StatusMissing
			d.Reason = fmt.Sprintf("executable %q not found", e.binOrName())
			return d
		}
		d.Status = StatusWarn
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			d.Reason = fmt.Sprintf("executable %s exists but the check was cancelled: %v", path, err)
		} else {
			d.Reason = fmt.Sprintf("executable %s exists but could not be executed: %v", path, err)
		}
		return d
	}
	v := extractVersion(res.Stdout)
	if v == "" {
		v = extractVersion(res.Stderr)
	}
	if v != "" {
		d.Status = StatusOK
		d.Version = v
		d.Capable = true
		d.Reason = fmt.Sprintf("executable %s; version %s", path, v)
		return d
	}
	d.Status = StatusWarn
	d.Reason = fmt.Sprintf("executable %s exists; %s produced no recognizable version", path, strings.Join([]string{"-version"}, " "))
	return d
}

// Discover implements Source.
func (c chaos) Discover(ctx context.Context, target asset.Domain) (DiscoverResult, error) {
	e := c.env.sanitized()
	path, err := e.lookup(e.binOrName())
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("%s: %w (%s)", c.Name(), ErrExecutableNotFound, e.binOrName())
	}
	res, err := e.runner.Run(ctx, Cmd{Path: path, Args: []string{"-d", target.Name, "-silent", "-json"}}, e.limits)
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("%s: %w", c.Name(), err)
	}
	hosts, malformed := parseChaosLines(res.Stdout, e.provenance())
	dres := DiscoverResult{Hosts: hosts, Malformed: malformed, Truncated: res.StdoutTruncated}
	if res.ExitCode != 0 {
		return dres, fmt.Errorf("%s: exited with code %d", c.Name(), res.ExitCode)
	}
	return dres, nil
}

// parseChaosLines converts chaos stdout — untrusted input — into normalized
// Phase 2 hosts. Each non-blank line is expected to be JSON
// {"domain":"..."}; a plain text line is accepted via fallback first-token
// parsing (mirroring parseHostLines) so variations in output are not fatal.
// Every candidate is normalized only through asset.NewHost; lines that do not
// normalize are counted and skipped. Duplicates are removed by identity and the
// result is sorted by canonical name.
func parseChaosLines(stdout []byte, prov asset.Provenance) ([]asset.Host, int) {
	var hosts []asset.Host
	seen := make(map[asset.Identity]struct{})
	malformed := 0
	for _, raw := range splitLines(stdout) {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		domain := ""
		// Try JSON: expected {"domain":"..."}; tolerate extra fields.
		if strings.HasPrefix(line, "{") {
			var rec struct {
				Domain string `json:"domain"`
			}
			if err := json.Unmarshal([]byte(line), &rec); err == nil {
				domain = strings.TrimSpace(rec.Domain)
			}
			if domain == "" {
				// JSON did not contain a usable domain — fall back to first-token
				// parsing so a plain host per line is still accepted; if the
				// first token is not a valid host it will be counted malformed.
				fields := strings.Fields(line)
				if len(fields) > 0 {
					domain = fields[0]
				}
			}
		} else {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			domain = fields[0]
		}
		if domain == "" {
			malformed++
			continue
		}
		h, err := asset.NewHost(domain, prov)
		if err != nil {
			malformed++
			continue
		}
		if _, dup := seen[h.Identity()]; dup {
			continue
		}
		seen[h.Identity()] = struct{}{}
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	return hosts, malformed
}
