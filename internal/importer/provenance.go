package importer

import (
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// ProvenanceSourceForImporter maps importer name to original-tool label.
// It is deterministic and stable for provenance sidecars.
func ProvenanceSourceForImporter(importerName string) string {
	switch importerName {
	case "plain-domains":
		return "plain-domains"
	case "plain-subdomains":
		return "plain-subdomains"
	case "plain-hosts":
		return "plain-hosts"
	case "plain-urls":
		return "plain-urls"
	case "plain-alive":
		return "plain-alive"
	case "plain-js":
		return "plain-js"
	case "plain-ips":
		return "plain-ips"
	case "plain-cidrs":
		return "plain-cidrs"
	case "json-httpx":
		return "httpx"
	case "json-dnsx":
		return "dnsx"
	case "json-naabu":
		return "naabu"
	case "json-katana":
		return "katana"
	case "json-nuclei":
		return "nuclei"
	case "json-generic":
		return "json-generic"
	default:
		return importerName
	}
}

// truncateOriginalRecord bounds the original record to MaxOriginalRecordBytes
// (first 4 KiB) with no marker — the stored value is the raw prefix.
func truncateOriginalRecord(s string) string {
	if len(s) <= MaxOriginalRecordBytes {
		return s
	}
	return s[:MaxOriginalRecordBytes]
}

// buildProvenance returns the asset Provenance for one record and the
// sidecar ProvenanceRecord. It layers importer, tool, filename, time, and
// original record over env.ProvenanceBase without mutating asset Identity.
func buildProvenance(env ImportEnv, importerName, filename, originalRecord string, at time.Time) (asset.Provenance, ProvenanceRecord) {
	base := env.ProvenanceBase
	prov := asset.Provenance{
		Source:       ProvenanceSourceForImporter(importerName),
		DiscoveredAt: at,
		Reference:    filename,
		Confidence:   base.Confidence,
	}
	if prov.Confidence == 0 {
		prov.Confidence = 1.0
	}
	rec := ProvenanceRecord{
		Importer:       importerName,
		OriginalTool:   ProvenanceSourceForImporter(importerName),
		Filename:       filename,
		ImportTime:     at,
		OriginalRecord: truncateOriginalRecord(originalRecord),
		Confidence:     prov.Confidence,
		Metadata:       nil,
	}
	return prov, rec
}
