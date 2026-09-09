package dnsrec

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// txtByHost groups dns:txt evidence values by source host identity string.
// Only MethodDNS records with the dns:txt indicator enter; every value is
// kept (clipped included) so negative-claim guards can see incompleteness.
func txtByHost(dctx *detect.Context) map[string][]string {
	out := make(map[string][]string)
	for _, ev := range dctx.Evidence {
		if ev.Method != asset.MethodDNS || ev.Indicator != dnsTXTIndicator {
			continue
		}
		if ev.Source.Kind != asset.KindHost {
			continue
		}
		out[ev.Source.String()] = append(out[ev.Source.String()], ev.Value)
	}
	return out
}

// srvByHost groups complete dns:srv evidence values by source host identity
// string. Clipped values are SKIPPED here (never cited as exposure detail);
// the caller treats a host with no complete values as silent. Guard: a
// clipped "target:port" prefix may hide the port or the full target, so
// citing it would misattribute the advertised service — fail open instead.
func srvCompleteByHost(dctx *detect.Context) map[string][]string {
	out := make(map[string][]string)
	for _, ev := range dctx.Evidence {
		if ev.Method != asset.MethodDNS || ev.Indicator != dnsSRVIndicator {
			continue
		}
		if ev.Source.Kind != asset.KindHost {
			continue
		}
		// Negative/positive-claim guard shared with the TXT channels:
		// clipped input never supports a finding. A host whose SRV values
		// are all clipped stays silent.
		if isClipped(ev.Value) {
			continue
		}
		out[ev.Source.String()] = append(out[ev.Source.String()], ev.Value)
	}
	return out
}

// isWeakSPF reports whether a COMPLETE SPF record value is a weak policy:
// it starts with "v=spf1" and carries neither "-all" nor "~all" among its
// whitespace-separated mechanisms. Callers must only pass unclipped values:
// absence of "-all"/"~all" derived from a "…"-clipped prefix is FORBIDDEN
// (the clipped tail may hide the very directive whose absence is claimed),
// so clipped values are skipped before this check and a host whose SPF
// records are all clipped stays silent. A complete value carrying "+all"
// is a positive claim on complete input and is correctly weak here.
func isWeakSPF(completeValue string) bool {
	if !strings.HasPrefix(completeValue, "v=spf1") {
		return false
	}
	for _, tok := range strings.Fields(completeValue) {
		if tok == "-all" || tok == "~all" {
			return false
		}
	}
	return true
}

// spfWeakDetector observes weak SPF policy per host: at least one complete
// (unclipped) dns:txt record starting "v=spf1" with neither "-all" nor
// "~all" among its whitespace-separated mechanisms. Informational only —
// never claims the host is spoofable.
func spfWeakDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleSPFWeak+".disabled"] == "true" {
		return nil, nil
	}
	txt := txtByHost(dctx)
	var subjects []asset.Identity
	metaFor := make(map[asset.Identity]map[string]string)
	for _, h := range hostAssets(dctx) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var weak []string
		for _, v := range txt[h.String()] {
			// Guard: skip every clipped value for SPF claims, positive
			// or negative. Deriving "no -all/~all" from a truncated
			// prefix would be a false negative-claim; deriving "+all"
			// from one would cite a torn mechanism. Fail open.
			if isClipped(v) {
				continue
			}
			if isWeakSPF(v) {
				weak = append(weak, v)
			}
		}
		if len(weak) == 0 {
			continue
		}
		sort.Strings(weak)
		subjects = append(subjects, h)
		metaFor[h] = map[string]string{
			"signal":   "dnsrec_spf_weak",
			"spf":      weak[0],
			"category": "weak_spf",
		}
	}
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := metaFor[s]
		m := make(map[string]string, len(meta)+2)
		for k, v := range meta {
			m[k] = v
		}
		if dropped > 0 {
			m["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			m["truncated"] = "true"
		}
		f, err := dnsrecFinding(dctx, ruleSPFWeak, "DNSRec SPF Weak", s, m)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleSPFWeak, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleSPFWeak)
	return out, nil
}

// dmarcMissingDetector observes absent DMARC records per host: a non-empty
// dns:txt set with no record starting "v=DMARC1" and no clipped values.
// Informational only — never claims the domain lacks DMARC protection.
//
// Negative-claim guard: if ANY dns:txt value for the host is clipped, the
// host's TXT set is incomplete (the clipped tail may hide a DMARC record),
// so the rule stays silent for that host. An empty TXT set is also silent:
// no evidence is not evidence of absence (fail-open).
//
// Scope note: DMARC records canonically live at _dmarc.<host>, not at the
// queried host itself. This rule reports only what the queried host's own
// observed TXT set shows ("no DMARC record observed in this host's TXT
// set") — an observed-corpus signal, never a standards-compliant DMARC
// evaluation. Correlating with MX edges or _dmarc.* queries is a consumer
// concern, deliberately out of scope here.
func dmarcMissingDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleDMARCMissing+".disabled"] == "true" {
		return nil, nil
	}
	txt := txtByHost(dctx)
	var subjects []asset.Identity
	metaFor := make(map[asset.Identity]map[string]string)
	for _, h := range hostAssets(dctx) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		vals, ok := txt[h.String()]
		if !ok || len(vals) == 0 {
			// No TXT evidence for this host: stay silent (fail-open).
			continue
		}
		clipped := false
		hasDMARC := false
		for _, v := range vals {
			if isClipped(v) {
				clipped = true
				break
			}
			if strings.HasPrefix(v, "v=DMARC1") {
				hasDMARC = true
				break
			}
		}
		// Guard: an incomplete TXT set (any clipped value) never
		// supports the "no DMARC observed" claim — stay silent.
		if clipped || hasDMARC {
			continue
		}
		subjects = append(subjects, h)
		metaFor[h] = map[string]string{
			"signal":      "dnsrec_dmarc_missing",
			"category":    "missing_dmarc",
			"txt_records": fmt.Sprintf("%d", len(vals)),
		}
	}
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := metaFor[s]
		m := make(map[string]string, len(meta)+2)
		for k, v := range meta {
			m[k] = v
		}
		if dropped > 0 {
			m["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			m["truncated"] = "true"
		}
		f, err := dnsrecFinding(dctx, ruleDMARCMissing, "DNSRec DMARC Missing", s, m)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleDMARCMissing, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleDMARCMissing)
	return out, nil
}

// maxServicesMetaBytes bounds the joined "services" metadata value so wide
// SRV sets cannot breach the finding metadata value bound (256 bytes).
const maxServicesMetaBytes = 256

// servicesMeta renders sorted complete "target:port" values as a bounded,
// deterministic citation. When the full join exceeds the bound it keeps the
// longest head whose exact rendering (head + ",+N more" marker) fits — the
// same honest-marker convention as the triage pack's reflectionMeta — so
// the metadata never breaches validation and the retained set is honestly
// marked as partial.
func servicesMeta(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	sorted := append([]string(nil), vals...)
	sort.Strings(sorted)
	joined := strings.Join(sorted, ",")
	if len(joined) <= maxServicesMetaBytes {
		return joined
	}
	const markerFmt = ",+%d more"
	for n := len(sorted); n >= 1; n-- {
		marker := fmt.Sprintf(markerFmt, len(sorted)-n)
		head := strings.Join(sorted[:n], ",")
		if len(head)+len(marker) <= maxServicesMetaBytes {
			return head + marker
		}
	}
	return fmt.Sprintf("+%d services", len(sorted))
}

// srvExposureDetector observes advertised services per host: at least one
// complete (unclipped) dns:srv evidence record citing "target:port".
// Informational only — never claims the service is reachable.
func srvExposureDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleSRVExposure+".disabled"] == "true" {
		return nil, nil
	}
	srv := srvCompleteByHost(dctx)
	var subjects []asset.Identity
	metaFor := make(map[asset.Identity]map[string]string)
	for _, h := range hostAssets(dctx) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		vals := srv[h.String()]
		if len(vals) == 0 {
			// No complete SRV evidence: silent (a host with only
			// clipped SRV values stays silent per the guard above).
			continue
		}
		subjects = append(subjects, h)
		metaFor[h] = map[string]string{
			"signal":        "dnsrec_srv_exposure",
			"category":      "srv_exposure",
			"services":      servicesMeta(vals),
			"service_count": fmt.Sprintf("%d", len(vals)),
		}
	}
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := metaFor[s]
		m := make(map[string]string, len(meta)+2)
		for k, v := range meta {
			m[k] = v
		}
		if dropped > 0 {
			m["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			m["truncated"] = "true"
		}
		f, err := dnsrecFinding(dctx, ruleSRVExposure, "DNSRec SRV Exposure", s, m)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleSRVExposure, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleSRVExposure)
	return out, nil
}
