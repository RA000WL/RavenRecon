package triage

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// triageFinding builds one canonical triage-pack finding. Subject must be
// observed; evidence is a MethodDetection record on the subject with
// provenance Source "triage". Category is information, priority info,
// confidence 0.6 (heuristic testing assignment, not a vulnerability claim),
// status open, timestamps from injected Clock for determinism.
func triageFinding(dctx *detect.Context, ruleID, ruleName string, subject asset.Identity, meta map[string]string) (asset.Finding, error) {
	ev, err := asset.NewEvidence(asset.MethodDetection, ruleID, "triage pack signal: "+ruleID, subject, asset.Provenance{Source: "triage"})
	if err != nil {
		return asset.Finding{}, err
	}
	return asset.NewFinding(asset.Finding{
		RuleID:     ruleID,
		RuleName:   ruleName,
		Category:   detect.CategoryInformation.String(),
		Subject:    subject,
		Confidence: 0.6,
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

// runTriage is the shared bounded, deterministic detector core for all
// eight triage rules. It extracts param names, applies overlap precedence
// (primary only), flags multi-class, sorts, caps at 256, and builds
// findings with MethodDetection evidence.
func runTriage(ctx context.Context, dctx *detect.Context, ruleID, ruleName string) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleID+".disabled"] == "true" {
		return nil, nil
	}
	seen := make(map[asset.Identity]*triageSubjects)
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
		id := ep.Identity()
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = info
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
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := triageFinding(dctx, ruleID, ruleName, s, meta)
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
