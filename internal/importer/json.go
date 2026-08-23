package importer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// JSON importers for v1.8 T6: httpx, dnsx, naabu, katana, nuclei + generic NDJSON fallback.
// Each streams via json.Decoder on bufio.Reader 8 KiB, UseNumber(), handles NDJSON and JSON array,
// ignores unknown fields, uses only asset builders, preserves provenance, dedups via Sink.

// JSONHttpxImporter consumes httpx JSON output (NDJSON or array).
type JSONHttpxImporter struct{ importerBase }

func NewJSONHttpxImporter() *JSONHttpxImporter {
	return &JSONHttpxImporter{importerBase{name: "json-httpx", version: "1.0.0", tool: "httpx"}}
}

func (j *JSONHttpxImporter) CanImport(path string, peek []byte) (float64, bool) {
	return jsonConfidence(path, peek, "httpx")
}

func (j *JSONHttpxImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	maxOut := env.Bounds.effectiveMaxOutput()
	filename := filepath.Base(path)
	now := env.now()
	stats := ImportStats{StickyFlags: make(map[string]bool)}
	processed, failed, truncatedSig, err := streamJSON(ctx, env, path, func(raw json.RawMessage, rawStr string, lineNum int) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		var rec httpxRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		uStr := strings.TrimSpace(rec.URL)
		if uStr == "" {
			uStr = strings.TrimSpace(rec.Input)
		}
		if uStr == "" {
			return fmt.Errorf("httpx record missing url")
		}
		prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
		prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
		srec.OriginalRecord = truncateOriginalRecord(rawStr)
		// Normalize via asset builder only
		u, err := asset.ParseURL(uStr, prov)
		if err != nil {
			return err
		}
		key := u.Identity().String()
		if _, dup := out.seen[key]; dup {
			return errDuplicate
		}
		if totalAssets(out) >= maxOut {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
			out.truncated = true
			return errOutputTruncated
		}
		out.seen[key] = struct{}{}
		out.URLs = append(out.URLs, u)
		srec.Identity = key
		out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
		return nil
	})
	if err != nil {
		stats.ItemsProcessed = processed
		stats.ItemsFailed = failed
		if truncatedSig {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
		}
		if ctx.Err() != nil {
			stats.StickyFlags = normalizeSticky(stats.StickyFlags)
			return stats, ctx.Err()
		}
		return stats, err
	}
	stats.ItemsProcessed = processed
	stats.ItemsFailed = failed
	if truncatedSig {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	if out.truncated {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	stats.StickyFlags = normalizeSticky(stats.StickyFlags)
	return stats, nil
}

type httpxRecord struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Tech       []string `json:"tech"`
	WebServer  string   `json:"webserver"`
}

// JSONDnsxImporter consumes dnsx JSON.
type JSONDnsxImporter struct{ importerBase }

func NewJSONDnsxImporter() *JSONDnsxImporter {
	return &JSONDnsxImporter{importerBase{name: "json-dnsx", version: "1.0.0", tool: "dnsx"}}
}

func (j *JSONDnsxImporter) CanImport(path string, peek []byte) (float64, bool) {
	return jsonConfidence(path, peek, "dnsx")
}

func (j *JSONDnsxImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	maxOut := env.Bounds.effectiveMaxOutput()
	filename := filepath.Base(path)
	now := env.now()
	stats := ImportStats{StickyFlags: make(map[string]bool)}
	processed, failed, truncatedSig, err := streamJSON(ctx, env, path, func(raw json.RawMessage, rawStr string, lineNum int) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		var rec dnsxRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		hostStr := strings.TrimSpace(rec.Host)
		if hostStr == "" {
			return fmt.Errorf("dnsx missing host")
		}
		// Normalize host via asset builder
		prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
		prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
		srec.OriginalRecord = truncateOriginalRecord(rawStr)
		h, err := asset.NewHost(hostStr, prov)
		if err != nil {
			return err
		}
		key := h.Identity().String()
		isDupHost := false
		if _, dup := out.seen[key]; dup {
			isDupHost = true
		} else {
			if totalAssets(out) >= maxOut {
				stats.Truncated = true
				stats.StickyFlags["import_truncated"] = true
				out.truncated = true
				return errOutputTruncated
			}
			out.seen[key] = struct{}{}
			out.Hosts = append(out.Hosts, h)
			srec2 := srec
			srec2.Identity = key
			out.ProvenanceRecords = append(out.ProvenanceRecords, srec2)
		}
		// Also ingest A/AAAA IPs; track whether anything was actually
		// appended so duplicate-host accounting stays honest.
		addedIP := false
		for _, ipStr := range rec.A {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr == "" {
				continue
			}
			provIP, recIP := buildProvenance(env, j.Name(), filename, rawStr, now)
			provIP.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
			recIP.OriginalRecord = truncateOriginalRecord(rawStr)
			ip, err := asset.NewIP(ipStr, provIP)
			if err != nil {
				continue
			}
			ik := ip.Identity().String()
			if _, dup := out.seen[ik]; dup {
				continue
			}
			if totalAssets(out) >= maxOut {
				stats.Truncated = true
				stats.StickyFlags["import_truncated"] = true
				out.truncated = true
				return errOutputTruncated
			}
			out.seen[ik] = struct{}{}
			out.IPs = append(out.IPs, ip)
			recIP.Identity = ik
			out.ProvenanceRecords = append(out.ProvenanceRecords, recIP)
			addedIP = true
		}
		for _, ipStr := range rec.AAAA {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr == "" {
				continue
			}
			provIP, recIP := buildProvenance(env, j.Name(), filename, rawStr, now)
			provIP.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
			recIP.OriginalRecord = truncateOriginalRecord(rawStr)
			ip, err := asset.NewIP(ipStr, provIP)
			if err != nil {
				continue
			}
			ik := ip.Identity().String()
			if _, dup := out.seen[ik]; dup {
				continue
			}
			if totalAssets(out) >= maxOut {
				stats.Truncated = true
				stats.StickyFlags["import_truncated"] = true
				out.truncated = true
				return errOutputTruncated
			}
			out.seen[ik] = struct{}{}
			out.IPs = append(out.IPs, ip)
			recIP.Identity = ik
			out.ProvenanceRecords = append(out.ProvenanceRecords, recIP)
			addedIP = true
		}
		if isDupHost {
			// Duplicate host: count the record as processed only if this
			// call actually appended at least one new IP asset; otherwise
			// nothing was stored and it is honestly a duplicate.
			if !addedIP {
				return errDuplicate
			}
			return nil
		}
		return nil
	})
	if err != nil {
		stats.ItemsProcessed = processed
		stats.ItemsFailed = failed
		if truncatedSig {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
		}
		if ctx.Err() != nil {
			stats.StickyFlags = normalizeSticky(stats.StickyFlags)
			return stats, ctx.Err()
		}
		return stats, err
	}
	stats.ItemsProcessed = processed
	stats.ItemsFailed = failed
	if truncatedSig {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	if out.truncated {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	stats.StickyFlags = normalizeSticky(stats.StickyFlags)
	return stats, nil
}

type dnsxRecord struct {
	Host   string   `json:"host"`
	A      []string `json:"a"`
	AAAA   []string `json:"aaaa"`
	CNAME  string   `json:"cname"`
	Answer []string `json:"answer"`
}

// JSONNaabuImporter consumes naabu JSON.
type JSONNaabuImporter struct{ importerBase }

func NewJSONNaabuImporter() *JSONNaabuImporter {
	return &JSONNaabuImporter{importerBase{name: "json-naabu", version: "1.0.0", tool: "naabu"}}
}

func (j *JSONNaabuImporter) CanImport(path string, peek []byte) (float64, bool) {
	return jsonConfidence(path, peek, "naabu")
}

func (j *JSONNaabuImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	maxOut := env.Bounds.effectiveMaxOutput()
	filename := filepath.Base(path)
	now := env.now()
	stats := ImportStats{StickyFlags: make(map[string]bool)}
	processed, failed, truncatedSig, err := streamJSON(ctx, env, path, func(raw json.RawMessage, rawStr string, lineNum int) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		var rec naabuRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		hostStr := strings.TrimSpace(rec.Host)
		ipStr := strings.TrimSpace(rec.IP)
		if hostStr == "" && ipStr == "" {
			return fmt.Errorf("naabu missing host/ip")
		}
		added := false
		if hostStr != "" {
			prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
			prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
			srec.OriginalRecord = truncateOriginalRecord(rawStr)
			h, err := asset.NewHost(hostStr, prov)
			if err == nil {
				key := h.Identity().String()
				if _, dup := out.seen[key]; !dup {
					if totalAssets(out) >= maxOut {
						stats.Truncated = true
						stats.StickyFlags["import_truncated"] = true
						out.truncated = true
						return errOutputTruncated
					}
					out.seen[key] = struct{}{}
					out.Hosts = append(out.Hosts, h)
					srec.Identity = key
					out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
					added = true
				}
			}
		}
		if ipStr != "" {
			prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
			prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
			srec.OriginalRecord = truncateOriginalRecord(rawStr)
			ip, err := asset.NewIP(ipStr, prov)
			if err == nil {
				key := ip.Identity().String()
				if _, dup := out.seen[key]; !dup {
					if totalAssets(out) >= maxOut {
						stats.Truncated = true
						stats.StickyFlags["import_truncated"] = true
						out.truncated = true
						return errOutputTruncated
					}
					out.seen[key] = struct{}{}
					out.IPs = append(out.IPs, ip)
					srec.Identity = key
					out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
					added = true
				}
			}
		}
		if !added {
			// Both were duplicates
			return errDuplicate
		}
		return nil
	})
	if err != nil {
		stats.ItemsProcessed = processed
		stats.ItemsFailed = failed
		if truncatedSig {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
		}
		if ctx.Err() != nil {
			stats.StickyFlags = normalizeSticky(stats.StickyFlags)
			return stats, ctx.Err()
		}
		return stats, err
	}
	stats.ItemsProcessed = processed
	stats.ItemsFailed = failed
	if truncatedSig {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	if out.truncated {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	stats.StickyFlags = normalizeSticky(stats.StickyFlags)
	return stats, nil
}

type naabuRecord struct {
	Host string      `json:"host"`
	IP   string      `json:"ip"`
	Port json.Number `json:"port"`
}

// JSONKatanaImporter consumes katana JSON.
type JSONKatanaImporter struct{ importerBase }

func NewJSONKatanaImporter() *JSONKatanaImporter {
	return &JSONKatanaImporter{importerBase{name: "json-katana", version: "1.0.1", tool: "katana"}}
}

func (j *JSONKatanaImporter) CanImport(path string, peek []byte) (float64, bool) {
	return jsonConfidence(path, peek, "katana")
}

func (j *JSONKatanaImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	maxOut := env.Bounds.effectiveMaxOutput()
	filename := filepath.Base(path)
	now := env.now()
	stats := ImportStats{StickyFlags: make(map[string]bool)}
	processed, failed, truncatedSig, err := streamJSON(ctx, env, path, func(raw json.RawMessage, rawStr string, lineNum int) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		var rec katanaRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		uStr := strings.TrimSpace(rec.URL)
		if uStr == "" && rec.Request != nil {
			// Modern katana -jsonl nests the crawled endpoint under
			// "request"."endpoint"; the "response" sibling is deliberately
			// not bound, keeping per-record decode memory bounded.
			uStr = strings.TrimSpace(rec.Request.Endpoint)
		}
		if uStr == "" {
			return fmt.Errorf("katana missing url")
		}
		prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
		prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
		srec.OriginalRecord = truncateOriginalRecord(rawStr)
		u, err := asset.ParseURL(uStr, prov)
		if err != nil {
			return err
		}
		key := u.Identity().String()
		if _, dup := out.seen[key]; dup {
			return errDuplicate
		}
		if totalAssets(out) >= maxOut {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
			out.truncated = true
			return errOutputTruncated
		}
		out.seen[key] = struct{}{}
		out.URLs = append(out.URLs, u)
		srec.Identity = key
		out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
		return nil
	})
	if err != nil {
		stats.ItemsProcessed = processed
		stats.ItemsFailed = failed
		if truncatedSig {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
		}
		if ctx.Err() != nil {
			stats.StickyFlags = normalizeSticky(stats.StickyFlags)
			return stats, ctx.Err()
		}
		return stats, err
	}
	stats.ItemsProcessed = processed
	stats.ItemsFailed = failed
	if truncatedSig {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	if out.truncated {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	stats.StickyFlags = normalizeSticky(stats.StickyFlags)
	return stats, nil
}

type katanaRecord struct {
	URL     string         `json:"url"`
	Method  string         `json:"method"`
	Request *katanaRequest `json:"request"`
}

// katanaRequest mirrors the nested request object of modern katana -jsonl
// output. Only Endpoint is consumed; unknown fields (and the whole
// "response" object) are skipped by the struct decoder without retention.
type katanaRequest struct {
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
}

// JSONNucleiImporter consumes nuclei JSON and creates Findings.
type JSONNucleiImporter struct{ importerBase }

func NewJSONNucleiImporter() *JSONNucleiImporter {
	return &JSONNucleiImporter{importerBase{name: "json-nuclei", version: "1.0.0", tool: "nuclei"}}
}

func (j *JSONNucleiImporter) CanImport(path string, peek []byte) (float64, bool) {
	return jsonConfidence(path, peek, "nuclei")
}

func (j *JSONNucleiImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	maxOut := env.Bounds.effectiveMaxOutput()
	filename := filepath.Base(path)
	now := env.now()
	stats := ImportStats{StickyFlags: make(map[string]bool)}
	processed, failed, truncatedSig, err := streamJSON(ctx, env, path, func(raw json.RawMessage, rawStr string, lineNum int) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		var rec nucleiRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		// Normalize template-id with aliases
		tid := strings.TrimSpace(rec.TemplateID)
		if tid == "" {
			tid = strings.TrimSpace(rec.TemplateID2)
		}
		if tid == "" {
			tid = strings.TrimSpace(rec.TemplateID3)
		}
		if tid == "" {
			// Try generic map fallback
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw, &m); err == nil {
				for _, k := range []string{"template-id", "templateID", "template_id", "templateId"} {
					if v, ok := m[k]; ok {
						var s string
						if err := json.Unmarshal(v, &s); err == nil {
							tid = strings.TrimSpace(s)
							if tid != "" {
								break
							}
						}
					}
				}
			}
		}
		if tid == "" {
			return fmt.Errorf("nuclei missing template-id")
		}
		hostStr := strings.TrimSpace(rec.Host)
		matchedAt := strings.TrimSpace(rec.MatchedAt)
		if matchedAt == "" {
			matchedAt = strings.TrimSpace(rec.MatchedAt2)
		}
		subjectStr := matchedAt
		if subjectStr == "" {
			subjectStr = hostStr
		}
		if subjectStr == "" {
			return fmt.Errorf("nuclei missing host/matched-at")
		}
		prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
		prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
		srec.OriginalRecord = truncateOriginalRecord(rawStr)

		// Subject identity: try URL first, then Host
		var subject asset.Identity
		if u, err := asset.ParseURL(subjectStr, prov); err == nil {
			subject = u.Identity()
			// Also optionally add URL to sink? But nuclei finding subject is enough; we don't need to duplicate URL asset here.
			// To preserve deduplication and asset graph, we could also ensure URL is in sink if not already? Not required for T6.
		} else if h, err := asset.NewHost(subjectStr, prov); err == nil {
			subject = h.Identity()
		} else if ip, err := asset.NewIP(subjectStr, prov); err == nil {
			subject = ip.Identity()
		} else {
			return fmt.Errorf("nuclei subject not a valid URL/host/ip: %q", subjectStr)
		}

		// Evidence: one per finding
		indicator := tid
		if len(indicator) > 128 {
			indicator = indicator[:128]
		}
		val := matchedAt
		if val == "" {
			val = hostStr
		}
		if val == "" {
			val = tid
		}
		ev, err := asset.NewEvidence(asset.MethodDetection, indicator, val, subject, prov)
		if err != nil {
			return err
		}
		// Finding fields with bounds
		ruleName := strings.TrimSpace(rec.Info.Name)
		if ruleName == "" {
			ruleName = tid
		}
		if len(ruleName) > 256 {
			ruleName = ruleName[:256]
		}
		category := "nuclei"
		if rec.Info.Tags != nil && len(rec.Info.Tags) > 0 {
			// Use first tag as category if printable and within bound
			cand := strings.TrimSpace(rec.Info.Tags[0])
			if cand != "" && len(cand) <= 64 {
				// ensure printable
				ok := true
				for i := 0; i < len(cand); i++ {
					if cand[i] < 0x20 || cand[i] > 0x7e {
						ok = false
						break
					}
				}
				if ok {
					category = cand
				}
			}
		}
		severity := strings.ToLower(strings.TrimSpace(rec.Severity))
		if severity == "" {
			severity = strings.ToLower(strings.TrimSpace(rec.Info.Severity))
		}
		priority := nucleiSeverityToPriority(severity)
		// Status vocabulary: use "open"
		status := "open"
		metadata := make(map[string]string)
		if severity != "" {
			metadata["severity"] = severity
		}
		if tid != "" {
			metadata["template-id"] = tid
		}
		if matchedAt != "" {
			metadata["matched-at"] = matchedAt
		}
		if hostStr != "" {
			metadata["host"] = hostStr
		}
		// Ensure metadata values within 256
		for k, v := range metadata {
			if len(v) > 256 {
				metadata[k] = v[:256]
			}
		}
		finding := asset.Finding{
			RuleID:     tid,
			RuleName:   ruleName,
			Category:   category,
			Subject:    subject,
			Confidence: 1.0,
			Evidence:   []asset.Evidence{ev},
			Priority:   priority,
			Status:     status,
			Created:    now,
			Updated:    now,
			Metadata:   metadata,
		}
		nf, err := asset.NewFinding(finding)
		if err != nil {
			return err
		}
		key := nf.Identity().String()
		if _, dup := out.seen[key]; dup {
			return errDuplicate
		}
		if totalAssets(out) >= maxOut {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
			out.truncated = true
			return errOutputTruncated
		}
		out.seen[key] = struct{}{}
		out.Findings = append(out.Findings, nf)
		srec.Identity = key
		out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
		return nil
	})
	if err != nil {
		stats.ItemsProcessed = processed
		stats.ItemsFailed = failed
		if truncatedSig {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
		}
		if ctx.Err() != nil {
			stats.StickyFlags = normalizeSticky(stats.StickyFlags)
			return stats, ctx.Err()
		}
		return stats, err
	}
	stats.ItemsProcessed = processed
	stats.ItemsFailed = failed
	if truncatedSig {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	if out.truncated {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	stats.StickyFlags = normalizeSticky(stats.StickyFlags)
	return stats, nil
}

func nucleiSeverityToPriority(s string) string {
	switch s {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		if s == "" {
			return "unknown"
		}
		// ensure printable and within 32
		if len(s) > 32 {
			s = s[:32]
		}
		for i := 0; i < len(s); i++ {
			if s[i] < 0x20 || s[i] > 0x7e {
				return "unknown"
			}
		}
		return s
	}
}

type nucleiRecord struct {
	TemplateID  string     `json:"template-id"`
	TemplateID2 string     `json:"templateID"`
	TemplateID3 string     `json:"template_id"`
	Host        string     `json:"host"`
	MatchedAt   string     `json:"matched-at"`
	MatchedAt2  string     `json:"matched_at"`
	Severity    string     `json:"severity"`
	Info        nucleiInfo `json:"info"`
}

type nucleiInfo struct {
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags"`
}

// JSONGenericImporter is the fallback for any JSON that is not claimed by specific importers.
type JSONGenericImporter struct{ importerBase }

func NewJSONGenericImporter() *JSONGenericImporter {
	return &JSONGenericImporter{importerBase{name: "json-generic", version: "1.0.0", tool: "json-generic"}}
}

func (j *JSONGenericImporter) CanImport(path string, peek []byte) (float64, bool) {
	if !isJSONLike(peek) {
		return 0, false
	}
	// Generic claims any JSON with low confidence; specifics outrank it
	return 0.4, true
}

func (j *JSONGenericImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	maxOut := env.Bounds.effectiveMaxOutput()
	filename := filepath.Base(path)
	now := env.now()
	stats := ImportStats{StickyFlags: make(map[string]bool)}
	processed, failed, truncatedSig, err := streamJSON(ctx, env, path, func(raw json.RawMessage, rawStr string, lineNum int) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		// Try to decode as map to extract generic fields
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			// If raw is not object but string? Try string
			var s string
			if err2 := json.Unmarshal(raw, &s); err2 == nil {
				// Treat string as URL/host attempt
				s = strings.TrimSpace(s)
				if s != "" {
					if u, err := asset.ParseURL(s, asset.Provenance{Source: ProvenanceSourceForImporter(j.Name()), DiscoveredAt: now, Reference: fmt.Sprintf("%s:%d", filename, lineNum)}); err == nil {
						prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
						prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
						srec.OriginalRecord = truncateOriginalRecord(rawStr)
						key := u.Identity().String()
						if _, dup := out.seen[key]; dup {
							return errDuplicate
						}
						if totalAssets(out) >= maxOut {
							stats.Truncated = true
							stats.StickyFlags["import_truncated"] = true
							out.truncated = true
							return errOutputTruncated
						}
						_ = prov
						out.seen[key] = struct{}{}
						out.URLs = append(out.URLs, u)
						srec.Identity = key
						out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
						return nil
					}
				}
			}
			return err
		}
		// Extract possible fields generically
		// Priority: url > host > ip > hostname
		if v, ok := m["url"]; ok {
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				s = strings.TrimSpace(s)
				if s != "" {
					prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
					prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
					srec.OriginalRecord = truncateOriginalRecord(rawStr)
					if u, err := asset.ParseURL(s, prov); err == nil {
						key := u.Identity().String()
						if _, dup := out.seen[key]; dup {
							return errDuplicate
						}
						if totalAssets(out) >= maxOut {
							stats.Truncated = true
							stats.StickyFlags["import_truncated"] = true
							out.truncated = true
							return errOutputTruncated
						}
						out.seen[key] = struct{}{}
						out.URLs = append(out.URLs, u)
						srec.Identity = key
						out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
						return nil
					}
				}
			}
		}
		if v, ok := m["host"]; ok {
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				s = strings.TrimSpace(s)
				if s != "" {
					// host may be URL? Try URL first
					if strings.Contains(s, "://") {
						prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
						prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
						srec.OriginalRecord = truncateOriginalRecord(rawStr)
						if u, err := asset.ParseURL(s, prov); err == nil {
							key := u.Identity().String()
							if _, dup := out.seen[key]; dup {
								return errDuplicate
							}
							if totalAssets(out) >= maxOut {
								stats.Truncated = true
								stats.StickyFlags["import_truncated"] = true
								out.truncated = true
								return errOutputTruncated
							}
							out.seen[key] = struct{}{}
							out.URLs = append(out.URLs, u)
							srec.Identity = key
							out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
							return nil
						}
					}
					prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
					prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
					srec.OriginalRecord = truncateOriginalRecord(rawStr)
					if h, err := asset.NewHost(s, prov); err == nil {
						key := h.Identity().String()
						if _, dup := out.seen[key]; dup {
							return errDuplicate
						}
						if totalAssets(out) >= maxOut {
							stats.Truncated = true
							stats.StickyFlags["import_truncated"] = true
							out.truncated = true
							return errOutputTruncated
						}
						out.seen[key] = struct{}{}
						out.Hosts = append(out.Hosts, h)
						srec.Identity = key
						out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
						return nil
					}
				}
			}
		}
		if v, ok := m["ip"]; ok {
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				s = strings.TrimSpace(s)
				if s != "" {
					prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
					prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
					srec.OriginalRecord = truncateOriginalRecord(rawStr)
					if ip, err := asset.NewIP(s, prov); err == nil {
						key := ip.Identity().String()
						if _, dup := out.seen[key]; dup {
							return errDuplicate
						}
						if totalAssets(out) >= maxOut {
							stats.Truncated = true
							stats.StickyFlags["import_truncated"] = true
							out.truncated = true
							return errOutputTruncated
						}
						out.seen[key] = struct{}{}
						out.IPs = append(out.IPs, ip)
						srec.Identity = key
						out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
						return nil
					}
				}
			}
		}
		// Try input field as URL
		if v, ok := m["input"]; ok {
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				s = strings.TrimSpace(s)
				if s != "" {
					prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
					prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
					srec.OriginalRecord = truncateOriginalRecord(rawStr)
					if u, err := asset.ParseURL(s, prov); err == nil {
						key := u.Identity().String()
						if _, dup := out.seen[key]; dup {
							return errDuplicate
						}
						if totalAssets(out) >= maxOut {
							stats.Truncated = true
							stats.StickyFlags["import_truncated"] = true
							out.truncated = true
							return errOutputTruncated
						}
						out.seen[key] = struct{}{}
						out.URLs = append(out.URLs, u)
						srec.Identity = key
						out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
						return nil
					}
				}
			}
		}
		// If still not matched, try any string value that looks like URL/host/ip
		for _, v := range m {
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				continue
			}
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if strings.Contains(s, "://") {
				prov, srec := buildProvenance(env, j.Name(), filename, rawStr, now)
				prov.Reference = fmt.Sprintf("%s:%d", filename, lineNum)
				srec.OriginalRecord = truncateOriginalRecord(rawStr)
				if u, err := asset.ParseURL(s, prov); err == nil {
					key := u.Identity().String()
					if _, dup := out.seen[key]; dup {
						continue
					}
					if totalAssets(out) >= maxOut {
						stats.Truncated = true
						stats.StickyFlags["import_truncated"] = true
						out.truncated = true
						return errOutputTruncated
					}
					out.seen[key] = struct{}{}
					out.URLs = append(out.URLs, u)
					srec.Identity = key
					out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
					return nil
				}
			}
		}
		return fmt.Errorf("generic: no url/host/ip field")
	})
	if err != nil {
		stats.ItemsProcessed = processed
		stats.ItemsFailed = failed
		if truncatedSig {
			stats.Truncated = true
			stats.StickyFlags["import_truncated"] = true
		}
		if ctx.Err() != nil {
			stats.StickyFlags = normalizeSticky(stats.StickyFlags)
			return stats, ctx.Err()
		}
		return stats, err
	}
	stats.ItemsProcessed = processed
	stats.ItemsFailed = failed
	if truncatedSig {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	if out.truncated {
		stats.Truncated = true
		stats.StickyFlags["import_truncated"] = true
	}
	stats.StickyFlags = normalizeSticky(stats.StickyFlags)
	return stats, nil
}

// streamJSON is the shared streaming helper for JSON importers.
// It handles both NDJSON (one JSON per line/object) and JSON array ([ {...}, ... ]).
// Bounded memory: bufio.Reader 8 KiB, decoder ~4 KiB, no whole-file load.
// Progress via env.Observer every 64 KiB / 10k, ctx per record, truncation via MaxOutput handled by caller via errOutputTruncated.
// It returns processed, failed, truncatedSig and error (ctx cancellation or read error).
func streamJSON(ctx context.Context, env ImportEnv, path string, handle func(raw json.RawMessage, rawStr string, lineNum int) error) (int, int, bool, error) {
	maxDecomp := env.Bounds.effectiveMaxDecompressed()
	base := filepath.Base(path)
	rc, err := openStream(path)
	if err != nil {
		return 0, 0, false, newImportError(base, path, "open", err)
	}
	defer rc.Close()

	br := bufio.NewReaderSize(rc, 8192)

	progress := newProgressEmitter(env.Observer, env.now, "import")
	processed := 0
	failed := 0
	truncated := false
	var bytesRead int
	var counted int // framer.consumed bytes already applied to bytesRead
	lineNum := 0

	// Peek first non-space byte to decide array vs NDJSON without consuming decoder state.
	// We need to handle gzip: openStream already decompresses, so br is decompressed.
	// Use a small peek to find first non-space/BOM char.
	peekProbe := func() (byte, bool) {
		// Peek up to 8 KiB
		b, err := br.Peek(8192)
		if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
			return 0, false
		}
		// Strip BOM and whitespace
		i := 0
		if len(b) >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
			i = 3
		}
		for i < len(b) && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
			i++
		}
		if i >= len(b) {
			return 0, false
		}
		return b[i], true
	}

	firstByte, hasFirst := peekProbe()
	isArray := hasFirst && firstByte == '['

	if isArray {
		// Array mode: frame elements with the bounded byte-wise framer.
		// dec (json.Decoder over br) is no longer used for the array body:
		// framing directly on br keeps per-element allocation ≤ cap bytes,
		// so a single huge element cannot spike the heap before the
		// decompressed tally (the MEDIUM finding).
		framer := newArrayFramer(br, env.Bounds.effectiveMaxLine())
		isArray = false
		if opened, err := framer.open(); err != nil {
			progress.flush()
			return processed, failed, truncated, newImportError(base, path, "read", err)
		} else if opened {
			isArray = true
			for {
				raw, ok, ferr := framer.next(ctx)
				// Cumulative decompressed tally: the framer counts every
				// byte it consumes — element bodies PLUS the separators,
				// whitespace, and framing brackets BETWEEN elements — so
				// MaxDecompressedBytes cannot be evaded by padding outside
				// elements (previously 8 MiB of commas vs a 64 KiB cap
				// escaped the tally entirely, Truncated=false). Only the
				// not-yet-counted delta is applied per iteration; retained
				// element bytes are part of that delta and are not added
				// again below.
				if delta := framer.consumed - counted; delta > 0 {
					counted = framer.consumed
					bytesRead += delta
					progress.add(delta)
					// Decompressed-byte cap (gzip-bomb guard), parity with
					// readLines: exceeding it aborts truncated before the
					// element is handled.
					if bytesRead > maxDecomp {
						truncated = true
						progress.flush()
						return processed, failed, truncated, nil
					}
				}
				switch {
				case ferr == nil && !ok:
					// Clean end of array (']' consumed or EOF before content).
					progress.flush()
					return processed, failed, truncated, nil
				case errors.Is(ferr, io.ErrUnexpectedEOF):
					// File ends mid-element: honest truncation.
					failed++
					truncated = true
					progress.flush()
					return processed, failed, truncated, nil
				case ferr == errArrayElementTooLarge:
					// Oversized element: drain semantics aligned with
					// readLines — failed+truncated, handle never called,
					// framing already resumed past the element. Its bytes
					// were tallied above toward the decompressed cap.
					failed++
					truncated = true
					continue
				case isCtxErr(ferr, ctx):
					progress.flush()
					return processed, failed, truncated, ctx.Err()
				case ferr != nil:
					progress.flush()
					return processed, failed, truncated, newImportError(base, path, "read", ferr)
				}
				lineNum++
				rawStr := string(raw)
				n := len(rawStr)
				if strings.TrimSpace(rawStr) == "" {
					continue
				}
				// Strict per-record cap (parity with readLines' trimmed-length
				// recheck; framer cap == effectiveMaxLine so this rarely fires).
				if n > env.Bounds.effectiveMaxLine() || n > MaxLineBytes {
					failed++
					truncated = true
					continue
				}
				err := handle(raw, rawStr, lineNum)
				if err != nil {
					if isCtxErr(err, ctx) {
						progress.flush()
						return processed, failed, truncated, ctx.Err()
					}
					if err == errDuplicate || err == errOutputTruncated {
						if err == errOutputTruncated {
							truncated = true
						}
					} else {
						failed++
					}
				} else {
					processed++
				}
			}
		}
	}
	if !isArray {
		// NDJSON / single object mode: use bounded line reader (reuses readLines logic for correct per-line isolation)
		// We delegate to readLines which handles gzip, progress, decompressed cap, oversized, and per-record ctx.
		lineNumLocal := 0
		// We need to track processed/failed/truncated via readLines return and handle's error mapping
		// readLines already tracks bytesRead and progress via its own progress emitter, but we need to integrate handle that expects RawMessage
		// Use readLines directly
		pProcessed, pFailed, pTruncated, pErr := readLines(ctx, env, path, func(line, raw string) error {
			if err := checkCtx(ctx); err != nil {
				return err
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				return nil // should not happen as readLines skips empty, but just in case
			}
			// line is trimmed JSON string; raw is original with newline
			var rawMsg json.RawMessage = json.RawMessage(trimmed)
			// Validate JSON (also handles empty lines)
			if !json.Valid([]byte(trimmed)) {
				return fmt.Errorf("invalid json")
			}
			lineNumLocal++
			// rawStr for provenance should be trimmed line (without newline) but we preserve original raw for 4KiB
			rawStr := trimmed
			err := handle(rawMsg, rawStr, lineNumLocal)
			if err != nil {
				if err == errDuplicate || err == errOutputTruncated {
					return err
				}
				// For validation errors, return err to be counted as failed
				return err
			}
			return nil
		})
		// readLines returns processed as count of successful handle returns (nil)
		// failed already includes both oversized and handle errors (excluding duplicate/truncated)
		// Merge with outer counters (which are currently 0 for NDJSON path)
		processed += pProcessed
		failed += pFailed
		if pTruncated {
			truncated = true
		}
		if pErr != nil {
			if pErr == context.Canceled || pErr == context.DeadlineExceeded {
				return processed, failed, truncated, pErr
			}
			// readLines only returns err on open/read or ctx; otherwise nil
			return processed, failed, truncated, pErr
		}
		return processed, failed, truncated, nil
	}
	progress.flush()
	return processed, failed, truncated, nil
}

// errArrayElementTooLarge signals that an array element exceeded the
// per-record bound. Internal to streamJSON's array framer; never escapes the
// package.
var errArrayElementTooLarge = errors.New("array element exceeds per-record bound")

// arrayFramer extracts raw JSON array elements one at a time from br using a
// bounded byte-wise state machine. It is the array-mode analogue of
// readLines' per-line isolation: no element ever allocates more than cap
// bytes. Once an element exceeds cap, remaining bytes are discarded until the
// element's closing bracket is consumed, after which framing resumes
// normally — mirroring readLines' bounded oversized drain.
//
// Strings are tracked with escape awareness so brackets/commas inside string
// values cannot desynchronize framing; nesting depth tracks objects/arrays so
// element-boundary commas at depth 0 are detected correctly.
//
// Consumed is cumulative across open()+next() calls and counts EVERY byte
// read from br — elements, separators, whitespace, framing brackets — so the
// caller can apply MaxDecompressedBytes exactly (bytes between elements never
// become part of a retained element, yet still consume decompressed input).
type arrayFramer struct {
	br        *bufio.Reader
	cap       int
	buf       []byte // element bytes, capped at cap
	consumed  int    // cumulative bytes consumed from br (elements + separators + framing)
	oversized bool
	done      bool // top-level closing ']' consumed or EOF reached
}

func newArrayFramer(br *bufio.Reader, capBytes int) *arrayFramer {
	return &arrayFramer{br: br, cap: capBytes}
}

// open consumes leading whitespace and the opening '['. It reports whether an
// array was actually entered; false means the value is not an array (caller
// falls back to NDJSON handling, which reopens the file independently) or the
// stream ended before any value.
func (f *arrayFramer) open() (bool, error) {
	for {
		b, err := f.br.ReadByte()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		f.consumed++
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case 0xef, 0xbb, 0xbf:
			// UTF-8 BOM bytes: skip (peekProbe tolerates them too).
			continue
		case '[':
			return true, nil
		default:
			return false, nil
		}
	}
}

func (f *arrayFramer) appendByte(b byte) {
	if len(f.buf) < f.cap {
		f.buf = append(f.buf, b)
	} else {
		f.oversized = true
	}
}

// next returns the next array element verbatim. ok=false means clean end of
// array. A too-large element yields ok=false with errArrayElementTooLarge;
// its bytes are included in Consumed and framing has already resumed
// past the element. Other errors are read errors or ctx cancellation.
// Cumulative consumed bytes for this call equal Consumed minus the value
// before the call.
func (f *arrayFramer) next(ctx context.Context) (raw json.RawMessage, ok bool, err error) {
	if f.done {
		return nil, false, nil
	}
	f.buf = f.buf[:0]
	f.oversized = false
	depth := 0
	inStr := false
	esc := false
	started := false

	for {
		if cerr := checkCtx(ctx); cerr != nil {
			return nil, false, cerr
		}
		b, rerr := f.br.ReadByte()
		if rerr == io.EOF {
			f.done = true
			if started || f.oversized {
				// File ends mid-element: honest truncation, not silent drop.
				return nil, false, io.ErrUnexpectedEOF
			}
			return nil, false, nil
		}
		if rerr != nil {
			return nil, false, rerr
		}
		f.consumed++

		if inStr {
			f.appendByte(b)
			if esc {
				esc = false
			} else if b == '\\' {
				esc = true
			} else if b == '"' {
				inStr = false
			}
			continue
		}

		switch b {
		case '"':
			started = true
			f.appendByte(b)
			inStr = true
		case '{', '[':
			started = true
			depth++
			f.appendByte(b)
		case '}', ']':
			if depth > 0 {
				depth--
				f.appendByte(b)
				if depth == 0 {
					return f.finish()
				}
			} else if b == ']' {
				// Top-level closing bracket: array finished.
				f.done = true
				if started || f.oversized {
					return f.finish()
				}
				return nil, false, nil
			} else {
				// Stray '}' at depth 0: malformed; fold into element so the
				// downstream decode fails honestly.
				started = true
				f.appendByte(b)
			}
		case ',':
			if depth == 0 {
				if started || f.oversized {
					return f.finish()
				}
				// Stray separator before any element content: skip.
				continue
			}
			f.appendByte(b)
		default:
			if !started && (b == ' ' || b == '\t' || b == '\n' || b == '\r') {
				continue
			}
			started = true
			f.appendByte(b)
		}
	}
}

// finish materializes a completed element. Oversized elements are reported
// via errArrayElementTooLarge without retaining their bytes.
func (f *arrayFramer) finish() (json.RawMessage, bool, error) {
	if f.oversized {
		return nil, false, errArrayElementTooLarge
	}
	raw := make(json.RawMessage, len(f.buf))
	copy(raw, f.buf)
	return raw, true, nil
}

func isCtxErr(err error, ctx context.Context) bool {
	if err == context.Canceled || err == context.DeadlineExceeded {
		return true
	}
	if ctx.Err() != nil {
		return true
	}
	return false
}
