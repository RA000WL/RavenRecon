package discovery

import (
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// parseHostLines converts tool stdout — untrusted input — into normalized
// Phase 2 hosts.
//
// Each non-blank line contributes its first whitespace-delimited token, which
// handles tools (amass) that print annotations such as
// "name (FQDN) --> 1.2.3.4" after the name. Every token is normalized through
// the Phase 2 asset model (asset.NewHost); there is no second normalization
// implementation, so uppercase, surrounding whitespace, and trailing dots all
// collapse to the same identity. Lines whose first token is not a valid host
// are counted and skipped, never emitted. Duplicates are removed by Phase 2
// identity. The result is sorted by canonical name for deterministic output.
func parseHostLines(stdout []byte, prov asset.Provenance) ([]asset.Host, int) {
	var hosts []asset.Host
	seen := make(map[asset.Identity]struct{})
	malformed := 0
	for _, line := range splitLines(stdout) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue // blank or whitespace-only line
		}
		h, err := asset.NewHost(fields[0], prov)
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

// splitLines splits b on '\n', dropping empty segments so a trailing newline
// does not produce a phantom line. A lone '\r' (CRLF output) is removed
// downstream by strings.Fields, so tool output from any platform parses
// identically.
func splitLines(b []byte) []string {
	var lines []string
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			if i > start {
				lines = append(lines, string(b[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, string(b[start:]))
	}
	return lines
}
