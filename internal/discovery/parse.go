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
// "name (FQDN) --> 1.2.3.4" after the name. Tokens without a dot are
// rejected as malformed before normalization: tool log/progress lines leak
// bare words (amass emitted a lone "no", NEW-130) and a bare word is never
// a valid enumerated subdomain — the asset model accepts single-label
// names by design, so the discovery layer must refuse them or junk hosts
// bill downstream DNS budget. Every token is normalized through
// asset.NewHost — the single normalization point — unparseable tokens are
// counted and skipped, duplicates are dropped by identity, and output is
// sorted by name. The dot rule scopes to subdomain enumeration only.
func parseHostLines(stdout []byte, prov asset.Provenance) ([]asset.Host, int) {
	var hosts []asset.Host
	seen := make(map[asset.Identity]struct{})
	malformed := 0
	for _, line := range splitLines(stdout) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue // blank or whitespace-only line
		}
		if !strings.Contains(fields[0], ".") {
			malformed++ // bare word: tool chatter, never a subdomain (NEW-130)
			continue
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
