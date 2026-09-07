package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxRenderIdentities bounds one rendered identity list in the human
// outputs (markdown Summary-adjacent sections, surface movements): a
// rescoped run can diff tens of thousands of identities, and the human
// doc must not grow unbounded with the delta. Cut lists print an
// explicit "+N more" marker naming delta.json as the complete record —
// truncation here is marked, never silent. delta.json itself is always
// complete (bounded end-to-end by the LoadReport input cap instead).
const maxRenderIdentities = 1000

// renderIdentityList writes up to maxRenderIdentities items as "- `id`"
// lines, then an explicit overflow marker when the list was cut.
func renderIdentityList(b *strings.Builder, ids []string) {
	n := len(ids)
	if n > maxRenderIdentities {
		n = maxRenderIdentities
	}
	for _, id := range ids[:n] {
		fmt.Fprintf(b, "- `%s`\n", id)
	}
	if len(ids) > maxRenderIdentities {
		fmt.Fprintf(b, "- … +%d more (complete list in delta.json)\n", len(ids)-maxRenderIdentities)
	}
}

// counts (only nonzero axes), surface movements, and the two digests. An
// empty delta says so in one line — silence is never the signal.
func (d *Delta) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "diff %s: +%d/-%d identities", d.Target, d.AddedCount(), d.RemovedCount())
	if len(d.Changed) > 0 {
		fmt.Fprintf(&b, ", %d surface movements", len(d.Changed))
	}
	b.WriteByte('\n')
	if d.Empty() {
		b.WriteString("no changes between the runs\n")
		return b.String()
	}
	for _, kind := range datasetKinds {
		a, r := len(d.Added[kind]), len(d.Removed[kind])
		if a == 0 && r == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s: +%d/-%d\n", kind, a, r)
	}
	for _, c := range d.Changed {
		fmt.Fprintf(&b, "surface %s: %s (%.4f) -> %s (%.4f)\n",
			c.Identity, c.OldLevel, c.OldScore, c.NewLevel, c.NewScore)
	}
	return b.String()
}

// WriteJSON writes the full machine-readable delta (complete: every
// identity on every axis — bounded end-to-end by the LoadReport input
// cap, never cut here). Key order is Go's deterministic marshal order
// (map keys sort alphabetically, NOT in datasetKinds order — the map
// projection below carries exactly the datasetKinds membership; the
// orderedDelta name refers to that fixed membership, not to key order).
// The parent directory is created as needed so --output may name a
// nested path that does not exist yet.
func WriteJSON(path string, d *Delta) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("diff: create output directory %s: %w", dir, err)
		}
	}
	raw, err := json.MarshalIndent(orderedDelta(d), "", "  ")
	if err != nil {
		return fmt.Errorf("diff: marshal delta: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("diff: write %s: %w", path, err)
	}
	return nil
}

// orderedDelta projects a Delta into a fixed-membership map: exactly the
// datasetKinds keys (identities already sorted, surfaces by identity).
// Marshal order is alphabetical by key (Go map semantics) — consumers
// must not read datasetKinds order out of the JSON.
func orderedDelta(d *Delta) map[string]any {
	added := make(map[string][]string, len(datasetKinds))
	removed := make(map[string][]string, len(datasetKinds))
	for _, kind := range datasetKinds {
		added[kind] = d.Added[kind]
		removed[kind] = d.Removed[kind]
	}
	return map[string]any{
		"target":           d.Target,
		"baseline_digest":  d.BaselineDigest,
		"current_digest":   d.CurrentDigest,
		"added":            added,
		"removed":          removed,
		"changed_surfaces": d.Changed,
	}
}

// WriteMarkdown writes the human triage doc: counts, then the added
// identities per dataset (new attack surface first — what the hunter
// reads), then removals, then surface movements, then digests. Human
// lists are bounded at maxRenderIdentities per list with an explicit
// "+N more" marker (delta.json is the complete record); counts and the
// summary stay exact regardless. The parent directory is created as
// needed so --output may name a nested path that does not exist yet.
func WriteMarkdown(path string, d *Delta) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("diff: create output directory %s: %w", dir, err)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Recon diff: %s\n\n", d.Target)
	fmt.Fprintf(&b, "Baseline `%s` → current `%s`\n\n", shortDigest(d.BaselineDigest), shortDigest(d.CurrentDigest))
	if d.Empty() {
		b.WriteString("No changes between the runs.\n")
	} else {
		b.WriteString("## New attack surface\n\n")
		anyAdded := false
		for _, kind := range datasetKinds {
			if len(d.Added[kind]) == 0 {
				continue
			}
			anyAdded = true
			fmt.Fprintf(&b, "### %s (+%d)\n\n", kind, len(d.Added[kind]))
			renderIdentityList(&b, d.Added[kind])
			b.WriteByte('\n')
		}
		if !anyAdded {
			b.WriteString("No new identities.\n\n")
		}
		b.WriteString("## Removed\n\n")
		anyRemoved := false
		for _, kind := range datasetKinds {
			if len(d.Removed[kind]) == 0 {
				continue
			}
			anyRemoved = true
			fmt.Fprintf(&b, "### %s (-%d)\n\n", kind, len(d.Removed[kind]))
			renderIdentityList(&b, d.Removed[kind])
			b.WriteByte('\n')
		}
		if !anyRemoved {
			b.WriteString("Nothing removed.\n\n")
		}
		if len(d.Changed) > 0 {
			b.WriteString("## Surface movements\n\n")
			n := len(d.Changed)
			if n > maxRenderIdentities {
				n = maxRenderIdentities
			}
			for _, c := range d.Changed[:n] {
				fmt.Fprintf(&b, "- `%s`: %s (%.4f) → %s (%.4f)\n",
					c.Identity, c.OldLevel, c.OldScore, c.NewLevel, c.NewScore)
			}
			if len(d.Changed) > maxRenderIdentities {
				fmt.Fprintf(&b, "- … +%d more (complete list in delta.json)\n", len(d.Changed)-maxRenderIdentities)
			}
			b.WriteByte('\n')
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("diff: write %s: %w", path, err)
	}
	return nil
}

// shortDigest renders the first 12 hex characters (or the whole string
// when shorter — synthetic test digests stay readable).
func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	if d == "" {
		return "(no digest)"
	}
	return d
}
