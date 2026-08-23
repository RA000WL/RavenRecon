package importer

import (
	"context"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// XML importers for v1.8 T7: Burp Suite (sitemap + issues shapes) and OWASP
// ZAP alerts. Each streams via the shared xml.Decoder token loop in
// xml_stream.go (NO DOM, DecodeElement per record), ignores unknown fields,
// uses only asset builders (single normalization point), preserves provenance
// sidecars, dedups via Sink.seen.
//
// Imported findings are passive observations: they are never re-executed and
// never submitted anywhere — they become asset.Finding records backed by
// MethodDetection Evidence, exactly like the nuclei JSON importer.

// XMLBurpImporter consumes Burp Suite XML exports in both shapes:
//
//	sitemap: <items><item><url>https://host/path</url></item>...</items>
//	issues:  <issues><issue><name/><severity/><host/><path/></issue>...</issues>
//
// Sitemap items become URL assets via ParseURL; issues become passive
// Findings with severity mapped onto the framework priority vocabulary (same
// mapping as nuclei: critical/high/medium/low/info). Both shapes may be mixed
// in one file — every <item> and <issue> element is handled.
type XMLBurpImporter struct{ importerBase }

func NewXMLBurpImporter() *XMLBurpImporter {
	return &XMLBurpImporter{importerBase{name: "xml-burp", version: "1.0.0", tool: "burpsuite"}}
}

func (x *XMLBurpImporter) CanImport(path string, peek []byte) (float64, bool) {
	return xmlConfidence(path, peek, xmlShapeBurp)
}

type burpItemRecord struct {
	URL string `xml:"url"`
}

type burpIssueRecord struct {
	Serial   string `xml:"serial"`
	Name     string `xml:"name"`
	Severity string `xml:"severity"`
	Host     string `xml:"host"`
	Path     string `xml:"path"`
}

func (x *XMLBurpImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	maxOut := env.Bounds.effectiveMaxOutput()
	filename := filepath.Base(path)
	recordNames := map[string]bool{"item": true, "issue": true}
	handle := func(dec *xml.Decoder, start xml.StartElement, recIndex int, tap *xmlRecordTap) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		now := env.now()
		if start.Name.Local != "issue" { // sitemap item → URL asset
			var rec burpItemRecord
			if err := dec.DecodeElement(&rec, &start); err != nil {
				return err
			}
			// Capture AFTER DecodeElement succeeded, clamped to the decoder
			// position: exactly [record start, record close), never a
			// read-ahead fragment ending mid-URL.
			raw := tap.raw(dec.InputOffset())
			uStr := strings.TrimSpace(rec.URL)
			if uStr == "" {
				return fmt.Errorf("burp item missing url")
			}
			prov, srec := buildProvenance(env, x.Name(), filename, raw, now)
			prov.Reference = fmt.Sprintf("%s:%d", filename, recIndex)
			srec.OriginalRecord = truncateOriginalRecord(raw)
			u, err := asset.ParseURL(uStr, prov)
			if err != nil {
				return err
			}
			key := u.Identity().String()
			if _, dup := out.seen[key]; dup {
				return errDuplicate
			}
			if totalAssets(out) >= maxOut {
				statsTruncatedSink(out)
				return errOutputTruncated
			}
			out.seen[key] = struct{}{}
			out.URLs = append(out.URLs, u)
			srec.Identity = key
			out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
			return nil
		}
		var rec burpIssueRecord
		if err := dec.DecodeElement(&rec, &start); err != nil {
			return err
		}
		// Same post-decode capture as the item path: window ends exactly at
		// </issue>, mirroring ZAP.
		raw := tap.raw(dec.InputOffset())
		name := sanitizeASCIILabel(rec.Name, 128)
		if name == "" {
			name = sanitizeASCIILabel("burp-issue-"+rec.Serial, 128)
		}
		if name == "" {
			return fmt.Errorf("burp issue missing name")
		}
		hostStr := strings.TrimSpace(rec.Host)
		pathStr := strings.TrimSpace(rec.Path)
		if hostStr == "" {
			return fmt.Errorf("burp issue missing host")
		}
		prov, srec := buildProvenance(env, x.Name(), filename, raw, now)
		prov.Reference = fmt.Sprintf("%s:%d", filename, recIndex)
		subject, observed, err := burpIssueSubject(hostStr, pathStr, prov)
		if err != nil {
			return err
		}
		metadata := map[string]string{
			"severity": sanitizeASCIILabel(strings.ToLower(strings.TrimSpace(rec.Severity)), 32),
			"host":     sanitizeASCIILabel(hostStr, 256),
		}
		if pathStr != "" {
			metadata["path"] = sanitizeASCIILabel(pathStr, 256)
		}
		if s := sanitizeASCIILabel(rec.Serial, 64); s != "" {
			metadata["serial"] = s
		}
		ev, err := asset.NewEvidence(asset.MethodDetection,
			sanitizeASCIILabel("burp-issue:"+name, 128),
			observed, subject, prov)
		if err != nil {
			return err
		}
		finding, err := asset.NewFinding(asset.Finding{
			RuleID:     name,
			RuleName:   sanitizeASCIILabel(name, 256),
			Category:   "burp",
			Subject:    subject,
			Confidence: 1.0,
			Evidence:   []asset.Evidence{ev},
			Priority:   burpSeverityToPriority(rec.Severity),
			Status:     "open",
			Created:    now,
			Updated:    now,
			Metadata:   metadata,
		})
		if err != nil {
			return err
		}
		key := finding.Identity().String()
		if _, dup := out.seen[key]; dup {
			return errDuplicate
		}
		if totalAssets(out) >= maxOut {
			statsTruncatedSink(out)
			return errOutputTruncated
		}
		out.seen[key] = struct{}{}
		out.Findings = append(out.Findings, finding)
		srec.Identity = key
		out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
		return nil
	}
	processed, failed, trunc, serr := streamXMLElements(ctx, env, path, recordNames, handle)
	return finishXMLStats(processed, failed, trunc, serr, out)
}

// burpIssueSubject resolves the finding subject for a Burp issue. When the
// host carries a scheme (typical Burp exports, e.g. "https://api.example.com")
// the joined host+path is normalized via ParseURL. Without a scheme the host
// alone becomes a Host identity — inventing "http://" would fabricate an
// assertion the tool never made. Returns the subject identity and the
// human-readable observed value for Evidence.
func burpIssueSubject(host, path string, prov asset.Provenance) (asset.Identity, string, error) {
	host = strings.TrimSpace(host)
	path = strings.TrimSpace(path)
	if strings.Contains(host, "://") {
		cand := host
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			cand = host + path
		}
		if u, err := asset.ParseURL(cand, prov); err == nil {
			return u.Identity(), cand, nil
		}
		if u, err := asset.ParseURL(host, prov); err == nil {
			return u.Identity(), host, nil
		}
	}
	h, err := asset.NewHost(host, prov)
	if err != nil {
		return asset.Identity{}, "", fmt.Errorf("burp issue subject not a valid URL/host: %q", sanitizeASCIILabel(host, 128))
	}
	val := host
	if path != "" {
		val = host + path
	}
	return h.Identity(), val, nil
}

// XMLZapImporter consumes OWASP ZAP XML reports:
//
//	<OWASPZAPReport version="...">
//	  <site name="https://host">
//	    <alerts><alertitem>
//	      <pluginid>10038</pluginid><alert>Scriptable alert</alert>
//	      <riskcode>2</riskcode><url>https://host/page</url>
//	    </alertitem>...</alerts>
//	  </site>
//	</OWASPZAPReport>
//
// Alerts become passive Findings/Evidence (never re-executed). ZAP riskcode
// maps onto the framework priority vocabulary as documented on
// zapRiskcodeToPriority ("3"→high … "0"→info; else "unknown").
type XMLZapImporter struct{ importerBase }

func NewXMLZapImporter() *XMLZapImporter {
	return &XMLZapImporter{importerBase{name: "xml-zap", version: "1.0.0", tool: "owaspzap"}}
}

func (x *XMLZapImporter) CanImport(path string, peek []byte) (float64, bool) {
	return xmlConfidence(path, peek, xmlShapeZap)
}

type zapAlertItemRecord struct {
	PluginID string `xml:"pluginid"`
	Alert    string `xml:"alert"`
	RiskCode string `xml:"riskcode"`
	URL      string `xml:"url"`
	Host     string `xml:"host"`
}

func (x *XMLZapImporter) Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error) {
	if out.seen == nil {
		out.seen = make(map[string]struct{})
	}
	if out.seenCIDR == nil {
		out.seenCIDR = make(map[string]struct{})
	}
	maxOut := env.Bounds.effectiveMaxOutput()
	filename := filepath.Base(path)
	recordNames := map[string]bool{"alertitem": true}
	handle := func(dec *xml.Decoder, start xml.StartElement, recIndex int, tap *xmlRecordTap) error {
		if err := checkCtx(ctx); err != nil {
			return err
		}
		var rec zapAlertItemRecord
		if err := dec.DecodeElement(&rec, &start); err != nil {
			return err
		}
		// Capture AFTER DecodeElement succeeded, clamped to the decoder
		// position: exactly [alertitem start, </alertitem>).
		raw := tap.raw(dec.InputOffset())
		now := env.now()
		alertName := sanitizeASCIILabel(rec.Alert, 128)
		pluginID := sanitizeASCIILabel(rec.PluginID, 32)
		if alertName == "" && pluginID != "" {
			alertName = "zap-plugin-" + pluginID
		}
		if alertName == "" {
			return fmt.Errorf("zap alert missing alert/pluginid")
		}
		ruleID := alertName
		if pluginID != "" {
			ruleID = sanitizeASCIILabel("zap-"+pluginID+"-"+alertName, 128)
		}
		urlStr := strings.TrimSpace(rec.URL)
		hostStr := strings.TrimSpace(rec.Host)
		if urlStr == "" && hostStr == "" {
			return fmt.Errorf("zap alert missing url/host")
		}
		prov, srec := buildProvenance(env, x.Name(), filename, raw, now)
		prov.Reference = fmt.Sprintf("%s:%d", filename, recIndex)
		var subject asset.Identity
		var observed string
		if urlStr != "" {
			u, err := asset.ParseURL(urlStr, prov)
			if err != nil {
				return err
			}
			subject = u.Identity()
			observed = urlStr
		} else {
			h, err := asset.NewHost(hostStr, prov)
			if err != nil {
				return err
			}
			subject = h.Identity()
			observed = hostStr
		}
		metadata := map[string]string{
			"riskcode": sanitizeASCIILabel(strings.TrimSpace(rec.RiskCode), 32),
			"pluginid": pluginID,
		}
		if hostStr != "" {
			metadata["host"] = sanitizeASCIILabel(hostStr, 256)
		}
		ev, err := asset.NewEvidence(asset.MethodDetection,
			sanitizeASCIILabel("zap-alert:"+ruleID, 128),
			observed, subject, prov)
		if err != nil {
			return err
		}
		finding, err := asset.NewFinding(asset.Finding{
			RuleID:     ruleID,
			RuleName:   sanitizeASCIILabel(alertName, 256),
			Category:   "zap",
			Subject:    subject,
			Confidence: 1.0,
			Evidence:   []asset.Evidence{ev},
			Priority:   zapRiskcodeToPriority(rec.RiskCode),
			Status:     "open",
			Created:    now,
			Updated:    now,
			Metadata:   metadata,
		})
		if err != nil {
			return err
		}
		key := finding.Identity().String()
		if _, dup := out.seen[key]; dup {
			return errDuplicate
		}
		if totalAssets(out) >= maxOut {
			statsTruncatedSink(out)
			return errOutputTruncated
		}
		out.seen[key] = struct{}{}
		out.Findings = append(out.Findings, finding)
		srec.Identity = key
		out.ProvenanceRecords = append(out.ProvenanceRecords, srec)
		return nil
	}
	processed, failed, trunc, serr := streamXMLElements(ctx, env, path, recordNames, handle)
	return finishXMLStats(processed, failed, trunc, serr, out)
}

// statsTruncatedSink records a tail-drop on the sink so callers merging
// multiple imports observe the sticky truncation even when their own stats
// copy predates the cap.
func statsTruncatedSink(out *Sink) {
	out.truncated = true
}

// burpSeverityToPriority maps Burp's textual severity onto the framework
// priority vocabulary, identical to nuclei: critical/high/medium/low/info;
// empty → unknown; unrecognized printable values pass through bounded to 32
// bytes by nucleiSeverityToPriority. Burp spells its lowest actionable level
// "Information", which maps onto the framework's "info".
func burpSeverityToPriority(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	if s == "information" {
		s = "info"
	}
	return nucleiSeverityToPriority(s)
}

// zapRiskcodeToPriority maps OWASP ZAP's numeric riskcode onto the framework
// priority vocabulary: "3"→high, "2"→medium, "1"→low, "0"→info. Anything else
// (missing, non-numeric) maps to "unknown" — ZAP's 0-3 scale has no critical
// level, so none is invented here.
func zapRiskcodeToPriority(riskcode string) string {
	switch strings.TrimSpace(riskcode) {
	case "3":
		return "high"
	case "2":
		return "medium"
	case "1":
		return "low"
	case "0":
		return "info"
	default:
		return "unknown"
	}
}
