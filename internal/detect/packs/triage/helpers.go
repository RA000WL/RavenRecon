package triage

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
)

// triageFinding builds one canonical triage-pack finding. Subject must be
// observed; evidence is a MethodDetection record on the subject with
// provenance Source "triage". Category is information, priority info,
// status open, timestamps from injected Clock for determinism. Confidence
// is 0.8 when live reflection evidence backs a flagged param (the probe
// saw the input come back — a second signal beyond the param name) and
// 0.6 for unenriched name-only matches (heuristic testing assignments,
// never vulnerability claims).
func triageFinding(dctx *detect.Context, ruleID, ruleName string, subject asset.Identity, confidence float64, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "triage pack signal: "+ruleID, subject, asset.Provenance{Source: "triage"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleName,
		Category:   detect.CategoryInformation.String(),
		Subject:    subject,
		Confidence: confidence,
		Evidence:   []asset.Evidence{ev},
		Metadata:   meta,
		Priority:   detect.PriorityInfo.String(),
		Status:     detect.StatusOpen.String(),
		Created:    dctx.Clock.Now().UTC(),
	})
}

// sortedKeys returns map keys in deterministic sorted order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// formatConfigKeys logs sorted config keys via Logger for deterministic handling.
func formatConfigKeys(dctx *detect.Context, ruleID string) {
	if len(dctx.Config) == 0 {
		return
	}
	keys := sortedKeys(dctx.Config)
	msg := fmt.Sprintf("config keys: %s", strings.Join(keys, ","))
	dctx.Logger.Log(detect.LevelInfo, ruleID, msg)
}

// extractParamNames extracts lowercased param names from an endpoint URL.
// Spec: split on ?& take key before =. We use the canonical Query string
// (already sorted, without leading ?) and split on & and =. Percent decoding
// is attempted for robustness; lowercasing ensures case-insensitive matching.
func extractParamNames(ep asset.Endpoint) []string {
	q := ep.URL.Query
	if q == "" {
		return nil
	}
	parts := strings.Split(q, "&")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		k, _, _ := strings.Cut(p, "=")
		if k == "" {
			continue
		}
		// Decode percent escapes for matching against lowercased wordlists.
		if decoded, err := url.QueryUnescape(k); err == nil {
			k = decoded
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

// triageClasses: canonical rule IDs for each vuln class in precedence order.
const (
	classRCE      = "triage.cmdi"
	classSSRF     = "triage.ssrf"
	classLFI      = "triage.lfi"
	classIDOR     = "triage.idor"
	classSQLi     = "triage.sqli"
	classRedirect = "triage.redirect"
	classSSTI     = "triage.ssti"
	classXSS      = "triage.xss_reflected"
)

// precedenceOrdered is highest → lowest (RCE>SSRF>LFI>IDOR>SQLi>Redirect>SSTI>XSS).
var precedenceOrdered = []string{
	classRCE, classSSRF, classLFI, classIDOR, classSQLi, classRedirect, classSSTI, classXSS,
}

// rawWordlists per class (exact research lists lowercased, sorted for determinism).
var (
	xssParams      = []string{"_hash", "api", "api_key", "begindate", "callback", "categoryid", "csrf_token", "dest", "email", "emailto", "enddate", "feed", "file", "folder", "fragment", "hash", "href", "id", "immagine", "item", "jsonp", "key", "keyword", "keywords", "l", "lang", "link", "list_type", "month", "name", "next", "p", "page", "page_id", "password", "path", "q", "query", "redirect", "return", "s", "search", "site", "src", "terms", "token", "type", "unsubscribe_token", "url", "username", "view", "year"}
	sqliParams     = []string{"column", "delete", "fetch", "field", "filter", "from", "id", "keyword", "name", "number", "order", "params", "process", "query", "report", "results", "role", "row", "search", "sel", "select", "sleep", "sort", "string", "table", "update", "user", "view", "where"}
	ssrfParams     = []string{"access", "adm", "admin", "alter", "callback", "cfg", "clone", "continue", "create", "data", "dbg", "debug", "delete", "dest", "dir", "disable", "doc", "document", "domain", "edit", "enable", "exec", "execute", "feed", "file", "filename", "folder", "grant", "host", "html", "img", "load", "make", "modify", "navigation", "next", "open", "out", "page", "path", "pg", "php_path", "port", "redirect", "reference", "rename", "reset", "return", "root", "shell", "show", "site", "style", "test", "to", "toggle", "uri", "url", "val", "validate", "view", "window"}
	lfiParams      = []string{"action", "board", "cat", "conf", "content", "date", "detail", "dir", "doc", "document", "download", "file", "folder", "inc", "include", "layout", "locate", "mod", "name", "page", "path", "pdf", "pg", "php_path", "prefix", "root", "show", "site", "style", "template", "type", "url", "view"}
	redirectParams = []string{"callback", "cgi-bin/redirect.cgi", "checkout", "checkout_url", "continue", "data", "dest", "destination", "dir", "domain", "feed", "file", "file_name", "file_url", "folder", "folder_url", "forward", "from_url", "go", "goto", "host", "html", "image_url", "img_url", "lmage_url", "load_file", "load_url", "login?to", "login_url", "logout", "navigation", "next", "next_page", "open", "out", "page", "page_url", "path", "port", "redir", "redirect", "redirect_to", "redirect_uri", "redirect_url", "reference", "return", "return_path", "return_to", "return_url", "returnto", "rt", "rurl", "show", "site", "target", "to", "uri", "url", "val", "validate", "view", "window"}
	idorParams     = []string{"account", "account_id", "booking", "client", "customer", "doc", "edit", "email", "employee", "group", "guid", "hash", "id", "invoice", "item_id", "key", "member", "no", "number", "order", "order_id", "patient", "post_id", "product_id", "profile", "profile_id", "report", "reservation", "scale", "session", "student", "token", "transaction", "uid", "user", "user_id", "uuid"}
	rceParams      = []string{"arg", "cli", "cmd", "code", "command", "daemon", "dir", "do", "download", "exe", "exec", "execute", "feature", "func", "function", "ip", "jump", "load", "log", "module", "option", "payload", "ping", "print", "process", "query", "read", "reg", "req", "run", "step", "upload"}
	sstiParams     = []string{"action", "activity", "blade", "block", "callback", "component", "config", "content", "controller", "data", "design", "display", "dust", "dustjs", "edge", "ejs", "file", "fn", "format", "fragment", "freemarker", "func", "function", "handlebars", "handler", "hbs", "id", "include", "jade", "lang", "latte", "layout", "liquid", "locale", "lodash", "module", "mustache", "name", "nette", "nunjucks", "output", "page", "partial", "path", "phptal", "plates", "preview", "pug", "redirect", "render", "resource", "savant", "section", "show", "skin", "smarty", "squirrelly", "style", "template", "theme", "thymeleaf", "tpl", "twig", "underscore", "velocity", "view", "vm", "widget"}
)

// paramSets maps ruleID -> set of param names.
var paramSets map[string]map[string]struct{}

// paramPrimary maps param name -> primary ruleID under precedence.
var paramPrimary map[string]string

// paramAllClasses maps param name -> sorted list of all matching ruleIDs.
var paramAllClasses map[string][]string

func init() {
	paramSets = map[string]map[string]struct{}{
		classXSS:      toSet(xssParams),
		classSQLi:     toSet(sqliParams),
		classSSRF:     toSet(ssrfParams),
		classLFI:      toSet(lfiParams),
		classRedirect: toSet(redirectParams),
		classIDOR:     toSet(idorParams),
		classRCE:      toSet(rceParams),
		classSSTI:     toSet(sstiParams),
	}
	paramPrimary = make(map[string]string)
	paramAllClasses = make(map[string][]string)
	// Collect all unique param names.
	all := make(map[string]struct{})
	for _, lst := range [][]string{xssParams, sqliParams, ssrfParams, lfiParams, redirectParams, idorParams, rceParams, sstiParams} {
		for _, p := range lst {
			all[p] = struct{}{}
		}
	}
	for p := range all {
		var matches []string
		for _, ruleID := range precedenceOrdered {
			if _, ok := paramSets[ruleID][p]; ok {
				matches = append(matches, ruleID)
			}
		}
		if len(matches) == 0 {
			continue
		}
		// Primary is first in precedenceOrdered.
		paramPrimary[p] = matches[0]
		sorted := append([]string(nil), matches...)
		sort.Strings(sorted)
		paramAllClasses[p] = sorted
	}
}

func toSet(list []string) map[string]struct{} {
	m := make(map[string]struct{}, len(list))
	for _, s := range list {
		m[s] = struct{}{}
	}
	return m
}

// classifyParam returns primary ruleID and sorted all matching ruleIDs for param.
func classifyParam(param string) (string, []string) {
	prim := paramPrimary[param]
	all := paramAllClasses[param]
	return prim, all
}

// shortName returns short class name for metadata (e.g., "xss_reflected").
func shortName(ruleID string) string {
	switch ruleID {
	case classXSS:
		return "xss_reflected"
	case classSQLi:
		return "sqli"
	case classSSRF:
		return "ssrf"
	case classLFI:
		return "lfi"
	case classRedirect:
		return "redirect"
	case classIDOR:
		return "idor"
	case classRCE:
		return "cmdi"
	case classSSTI:
		return "ssti"
	}
	return ruleID
}

// triageSubjects holds per-endpoint matching state for one rule.
type triageSubjects struct {
	params     map[string]struct{}
	allClasses map[string]struct{}
	multi      bool
}

// reflectionIndex groups canary-reflection verdicts (urllive evidence:
// MethodEndpoint + "reflect:<param>") by source URL identity string. Only
// decided verdicts ever enter the channel — unknown is fail-open at the
// reader — so every entry here is actionable.
func reflectionIndex(evs []asset.Evidence) map[string]map[string]string {
	out := make(map[string]map[string]string)
	for _, ev := range evs {
		param, verdict, ok := httpprobe.ParseReflectEvidence(ev)
		if !ok {
			continue
		}
		src := ev.Source.String()
		m := out[src]
		if m == nil {
			m = make(map[string]string)
			out[src] = m
		}
		if _, dup := m[param]; !dup {
			m[param] = string(verdict)
		}
	}
	return out
}

// reflectionPostIndex groups POST canary-reflection verdicts (urllive
// evidence: MethodEndpoint + "reflect-post-form:<param>" or
// "reflect-post-json:<param>") by source URL identity string. It resolves
// the channel via httpprobe.ReflectEvidenceScope and strips the
// scope-namespaced indicator to the param — it never parses POST as query,
// so GET and POST verdicts never conflate. Only decided verdicts enter
// (unknown claims no scope at the reader); every entry here is actionable.
func reflectionPostIndex(evs []asset.Evidence) map[string]map[string]string {
	out := make(map[string]map[string]string)
	for _, ev := range evs {
		scope, ok := httpprobe.ReflectEvidenceScope(ev)
		if !ok {
			continue
		}
		if scope != httpprobe.ReflectScopePostForm && scope != httpprobe.ReflectScopePostJSON {
			continue
		}
		var param string
		if p, ok := strings.CutPrefix(ev.Indicator, httpprobe.ReflectPostFormIndicatorPrefix); ok {
			param = p
		} else if p, ok := strings.CutPrefix(ev.Indicator, httpprobe.ReflectPostJSONIndicatorPrefix); ok {
			param = p
		} else {
			continue
		}
		if param == "" {
			continue
		}
		param = strings.ToLower(strings.TrimSpace(param))
		if param == "" {
			continue
		}
		src := ev.Source.String()
		m := out[src]
		if m == nil {
			m = make(map[string]string)
			out[src] = m
		}
		if _, dup := m[param]; !dup {
			m[param] = ev.Value
		}
	}
	return out
}

// reflectionPostScopes groups the POST body kinds observed per source URL
// identity string, for the reflection_post_scope citation. Keys are scope
// values ("post-form", "post-json"); the caller renders them sorted.
func reflectionPostScopes(evs []asset.Evidence) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{})
	for _, ev := range evs {
		scope, ok := httpprobe.ReflectEvidenceScope(ev)
		if !ok {
			continue
		}
		if scope != httpprobe.ReflectScopePostForm && scope != httpprobe.ReflectScopePostJSON {
			continue
		}
		src := ev.Source.String()
		m := out[src]
		if m == nil {
			m = make(map[string]struct{})
			out[src] = m
		}
		m[string(scope)] = struct{}{}
	}
	return out
}

// reflectionMeta renders the cited verdicts for one subject's flagged
// params as sorted "param:verdict" pairs, bounded to
// maxReflectionMetaBytes with an honest ",+N more" marker: finding
// metadata values must fit 256 bytes, and an unbounded join would fail
// finding validation on wide endpoints.
const maxReflectionMetaBytes = 256

func reflectionMeta(params []string, verdicts map[string]string) string {
	var pairs []string
	for _, p := range params {
		if v, ok := verdicts[p]; ok {
			pairs = append(pairs, p+":"+v)
		}
	}
	if len(pairs) == 0 {
		return ""
	}
	sort.Strings(pairs)
	joined := strings.Join(pairs, ",")
	if len(joined) <= maxReflectionMetaBytes {
		return joined
	}
	// Greedy deterministic fit: keep the longest head whose exact
	// rendering (head + exact remainder marker) fits the bound.
	const markerFmt = ",+%d more"
	for n := len(pairs); n >= 1; n-- {
		marker := fmt.Sprintf(markerFmt, len(pairs)-n)
		head := strings.Join(pairs[:n], ",")
		if len(head)+len(marker) <= maxReflectionMetaBytes {
			return head + marker
		}
	}
	// A single pair never fits (a >256-byte param name cannot happen —
	// reflection caps names at 64 bytes — so this is defensive): cite
	// the count honestly.
	return fmt.Sprintf("+%d verdicts", len(pairs))
}

// dropSilent reports whether a subject's flagged params are all
// verdict-ed not-reflected on the GET channel with no POST rescue: every
// flagged param carries a GET verdict, none is GET-reflected, and none is
// POST-reflected for the same source identity. Missing verdicts (no
// evidence, unknown probes, or params the reflection pass never covered)
// keep the subject — fail-open, so output without enrichment is unchanged.
// POST verdicts never parse as query (separate index); a POST reflected
// verdict rescues a GET-silent subject, cited under reflection_post.
func dropSilent(flagged map[string]struct{}, verdicts map[string]string, postVerdicts map[string]string) bool {
	if len(verdicts) == 0 && len(postVerdicts) == 0 {
		return false
	}
	considered := 0
	for p := range flagged {
		v, ok := verdicts[p]
		if !ok {
			return false
		}
		considered++
		if isReflected(v) {
			return false
		}
	}
	if considered == 0 {
		return false
	}
	// GET demands a drop (all flagged GET-absent): rescue when any flagged
	// param reflected via POST for the same source.
	for p := range flagged {
		if v, ok := postVerdicts[p]; ok {
			if isReflected(v) {
				return false
			}
		}
	}
	return true
}

// isReflected reports a decided reflected verdict on either channel: the
// canary came back unencoded or encoded. Absent/unknown verdicts are not
// reflected — and missing verdicts never reach here (fail-open upstream).
func isReflected(v string) bool {
	return v == string(httpprobe.ReflectUnencoded) || v == string(httpprobe.ReflectEncoded)
}

// reflectBacked reports whether live reflection evidence backs any flagged
// param on either the GET or the POST channel: the probe saw attacker-
// controlled input return, a second signal beyond the param name. Backed
// findings carry confidence 0.8; unenriched name-only matches stay 0.6.
func reflectBacked(params []string, verdicts, postVerdicts map[string]string) bool {
	for _, p := range params {
		if isReflected(verdicts[p]) || isReflected(postVerdicts[p]) {
			return true
		}
	}
	return false
}

// runTriage is the shared bounded, deterministic detector core for all
// eight triage rules. It extracts param names, applies overlap precedence
// (primary only), flags multi-class, sorts, caps at 256, and builds
// findings with MethodDetection evidence.
//
// Reflection gate (NEW-120, POST-aware NEW-127): subjects whose every
// flagged param verdicts not-reflected on GET with no POST rescue are
// dropped — an inert input is not worth a researcher's click. Any
// GET- or POST-reflected verdict keeps the subject and is cited in meta
// under a distinct key (reflection for GET, reflection_post for POST, so
// channels never conflate); missing or unknown verdicts keep it too
// (fail-open): without enrichment the output is byte-identical to the
// pre-gate behavior. Cited GET verdicts carry reflection_scope
// (query-get-only); cited POST verdicts carry reflection_post_scope
// (post-form and/or post-json). POST bodies, headers, and fragments
// outside the probed channels were not tested.
func runTriage(ctx context.Context, dctx *detect.Context, ruleID, ruleName string) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleID+".disabled"] == "true" {
		return nil, nil
	}
	refl := reflectionIndex(dctx.Evidence)
	postRefl := reflectionPostIndex(dctx.Evidence)
	postScopes := reflectionPostScopes(dctx.Evidence)
	seen := make(map[asset.Identity]*triageSubjects)
	// verdictsBySubject carries each kept subject's URL-identity verdict
	// map for meta rendering: the reflection index is keyed by URL
	// identity while findings are keyed by endpoint identity.
	verdictsBySubject := make(map[asset.Identity]map[string]string)
	postVerdictsBySubject := make(map[asset.Identity]map[string]string)
	postScopesBySubject := make(map[asset.Identity]map[string]struct{})
	var subjects []asset.Identity
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		params := extractParamNames(ep)
		if len(params) == 0 {
			continue
		}
		info := &triageSubjects{params: make(map[string]struct{}), allClasses: make(map[string]struct{})}
		matched := false
		for _, p := range params {
			prim, all := classifyParam(p)
			if prim != ruleID {
				continue
			}
			matched = true
			info.params[p] = struct{}{}
			for _, c := range all {
				info.allClasses[c] = struct{}{}
			}
			if len(all) > 1 {
				info.multi = true
			}
		}
		if !matched {
			continue
		}
		srcKey := ep.URL.Identity().String()
		if dropSilent(info.params, refl[srcKey], postRefl[srcKey]) {
			continue
		}
		id := ep.Identity()
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = info
		verdictsBySubject[id] = refl[srcKey]
		postVerdictsBySubject[id] = postRefl[srcKey]
		postScopesBySubject[id] = postScopes[srcKey]
		subjects = append(subjects, id)
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].String() < subjects[j].String() })
	dropped := 0
	if len(subjects) > 256 {
		dropped = len(subjects) - 256
		subjects = subjects[:256]
	}
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info := seen[s]
		plist := make([]string, 0, len(info.params))
		for p := range info.params {
			plist = append(plist, p)
		}
		sort.Strings(plist)
		meta := map[string]string{"signal": "triage_" + shortName(ruleID), "triage_class": shortName(ruleID), "params": strings.Join(plist, ",")}
		if rm := reflectionMeta(plist, verdictsBySubject[s]); rm != "" {
			meta["reflection"] = rm
			// Scope marker (NEW-127): cited verdicts cover GET query
			// parameters only — endpoints accepting POST bodies,
			// headers, or fragments were not tested, and silence
			// about them must never be read as clean. Silence itself
			// produces no finding, so the marker rides the verdicts
			// it scopes (absent without evidence, by construction).
			meta["reflection_scope"] = "query-get-only"
		}
		if rpm := reflectionMeta(plist, postVerdictsBySubject[s]); rpm != "" {
			meta["reflection_post"] = rpm
			// POST scope marker rides the POST verdicts it scopes, so
			// a POST-rescued finding never loses its channel claim.
			if sc, ok := postScopesBySubject[s]; ok && len(sc) > 0 {
				kinds := make([]string, 0, len(sc))
				for k := range sc {
					kinds = append(kinds, k)
				}
				sort.Strings(kinds)
				meta["reflection_post_scope"] = strings.Join(kinds, ",")
			} else {
				meta["reflection_post_scope"] = "post-body"
			}
		}
		if info.multi {
			meta["multi_class"] = "true"
			clist := make([]string, 0, len(info.allClasses))
			for c := range info.allClasses {
				clist = append(clist, shortName(c))
			}
			sort.Strings(clist)
			meta["all_classes"] = strings.Join(clist, ",")
		} else {
			meta["multi_class"] = "false"
		}
		// Reflection-backed confidence: a flagged param the probe saw
		// return carries 0.8; unenriched name-only matches stay 0.6.
		// The marker makes the promotion auditable in the finding itself.
		confidence := 0.6
		if reflectBacked(plist, verdictsBySubject[s], postVerdictsBySubject[s]) {
			confidence = 0.8
			meta["reflection_backed"] = "true"
		}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := triageFinding(dctx, ruleID, ruleName, s, confidence, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleID, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleID)
	return out, nil
}
