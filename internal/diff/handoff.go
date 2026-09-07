package diff

import (
	"encoding/json"
	"fmt"
	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/report"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Handoff is the feeder export for external scanners: observed root
// targets, per-host technology attribution, and a per-finding severity
// map. RavenRecon finds what to look at; nuclei/httpx/katana look
// closer. The export is deterministic (sorted) and observational: it
// restates the report and never re-verifies reachability — a target
// listed here was recorded as a root URL when the report was written,
// not proven live now (stale feed, stale targets).
type Handoff struct {
	Target   string              `json:"target"`
	Digest   string              `json:"digest"`
	Targets  []string            `json:"targets"`
	Tech     map[string][]string `json:"tech_by_host"`
	Severity map[string]string   `json:"severity_by_finding"`
}

// priorityToSeverity maps the recon attention level (info/low/medium/
// high/critical) onto scanner severity vocabulary. It is an ORDERING hint
// for template filtering (run critical templates against high surfaces
// first), never a vulnerability claim: no finding here was verified.
func priorityToSeverity(level string) string {
	switch level {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

// HandoffOf builds the feeder export from a decoded report. Targets are
// the model's observed root URLs (path "/" with no query — a bare
// "?query" on "/" is a parameterized observation, not the root —
// deduplicated and sorted); they restate what the report recorded, with
// no freshness claim. Technology attribution follows host_to_technology
// edges ONLY: url_to_technology and endpoint_to_technology edges are out
// of scope by design (the export attributes per host, never per URL or
// endpoint — a scanner picks templates per host). Severities map each
// finding's attention priority through priorityToSeverity (unknown labels
// coerce to "info": an ordering hint, never a vulnerability claim).
// Every list is sorted; maps are non-nil.
func HandoffOf(m *report.Model) *Handoff {
	h := &Handoff{
		Target:   m.Target,
		Digest:   m.Digest,
		Targets:  []string{},
		Tech:     map[string][]string{},
		Severity: map[string]string{},
	}
	seen := map[string]struct{}{}
	for _, u := range m.URLs {
		if u.Path != "/" || u.Query != "" {
			continue
		}
		s := u.String()
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		h.Targets = append(h.Targets, s)
	}
	sort.Strings(h.Targets)
	techNames := map[string]string{}
	for _, t := range m.Technologies {
		techNames[t.Identity().String()] = t.Name
	}
	byHost := map[string]map[string]struct{}{}
	for _, r := range m.Relationships {
		if r.Kind != asset.RelationshipHostToTechnology {
			continue
		}
		name, ok := techNames[r.To.String()]
		if !ok {
			continue
		}
		host := r.From.String()
		if byHost[host] == nil {
			byHost[host] = map[string]struct{}{}
		}
		byHost[host][name] = struct{}{}
	}
	for host, set := range byHost {
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		h.Tech[host] = names
	}
	for _, f := range m.Findings {
		h.Severity[f.Identity().String()] = priorityToSeverity(f.Priority)
	}
	return h
}

// WriteHandoff writes targets.txt (one observed root target per line,
// sorted) and handoff.json (full export) into dir, creating dir
// (including nested parents) as needed. Empty target lists still write
// both files (an empty handoff is a finding: nothing observed to feed) —
// never an error, never silence.
func WriteHandoff(dir string, h *Handoff) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("diff: create output directory %s: %w", dir, err)
	}
	var b strings.Builder
	for _, t := range h.Targets {
		b.WriteString(t)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "targets.txt"), []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("diff: write targets.txt: %w", err)
	}
	raw, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return fmt.Errorf("diff: marshal handoff: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(dir, "handoff.json"), raw, 0o644); err != nil {
		return fmt.Errorf("diff: write handoff.json: %w", err)
	}
	return nil
}
