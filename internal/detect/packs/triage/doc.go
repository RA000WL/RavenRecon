// Package triage is RavenRecon's URL triage detection pack (v2.0 Batch 6,
// most requested feature — URL triage like gf xss/sqli/ssrf etc).
//
// It follows the pack loader story established in Batch 1 (OPT-P1-2) and
// extended in Batches 2-5 (Web / JS / APIs / Cloud): packs are in-repo Go
// packages sibling to internal/detect/examples, exporting Rules()
// ([]Rule,error) starting with CheckAPIVersion(1,0), registered through
// ValidateRule → Registry.Register (deep copy) → Validate graph → Seal
// (startup confinement), never auto-discovered.
//
// Research wordlists (TRIAGE_RESEARCH.md, 2026-08-26, deduplicated,
// lowercased, sorted) source: 1ndianl33t/Gf-Patterns, geeknik/Gf-Patterns,
// rix4uni/gf-patterns, SecLists burp-parameter-names.txt, Assetnote,
// PortSwigger — 1ndianl33t/geeknik/rix4uni MIT, SecLists MIT, Assetnote
// Apache-2.0 (attribution here, not viral):
//
//	XSS  — reflected input 52 curated — _hash, api, api_key, begindate, callback, categoryid, csrf_token, dest, email, emailto, enddate, feed, file, folder, fragment, hash, href, id, immagine, item, jsonp, key, keyword, keywords, l, lang, link, list_type, month, name, next, p, page, page_id, password, path, q, query, redirect, return, s, search, site, src, terms, token, type, unsubscribe_token, url, username, view, year
//	SQLi — DB query core 29 — column, delete, fetch, field, filter, from, id, keyword, name, number, order, params, process, query, report, results, role, row, search, sel, select, sleep, sort, string, table, update, user, view, where
//	SSRF — attacker-controlled URL fetch 62 — access, adm, admin, alter, callback, cfg, clone, continue, create, data, dbg, debug, delete, dest, dir, disable, doc, document, domain, edit, enable, exec, execute, feed, file, filename, folder, grant, host, html, img, load, make, modify, navigation, next, open, out, page, path, pg, php_path, port, redirect, reference, rename, reset, return, root, shell, show, site, style, test, to, toggle, uri, url, val, validate, view, window
//	LFI  — file path 33 — action, board, cat, conf, content, date, detail, dir, doc, document, download, file, folder, inc, include, layout, locate, mod, name, page, path, pdf, pg, php_path, prefix, root, show, site, style, template, type, url, view
//	Redirect — open redirect 62 — callback, cgi-bin/redirect.cgi, checkout, checkout_url, continue, data, dest, destination, dir, domain, feed, file, file_name, file_url, folder, folder_url, forward, from_url, go, goto, host, html, image_url, img_url, lmage_url, load_file, load_url, login?to, login_url, logout, navigation, next, next_page, open, out, page, page_url, path, port, redir, redirect, redirect_to, redirect_uri, redirect_url, reference, return, return_path, return_to, return_url, returnto, rt, rurl, show, site, target, to, uri, url, val, validate, view, window
//	IDOR — object reference 37 — account, account_id, booking, client, customer, doc, edit, email, employee, group, guid, hash, id, invoice, item_id, key, member, no, number, order, order_id, patient, post_id, product_id, profile, profile_id, report, reservation, scale, session, student, token, transaction, uid, user, user_id, uuid
//	RCE  — command injection 32 — arg, cli, cmd, code, command, daemon, dir, do, download, exe, exec, execute, feature, func, function, ip, jump, load, log, module, option, payload, ping, print, process, query, read, reg, req, run, step, upload
//	SSTI — template render 68 curated — action, activity, blade, block, callback, component, config, content, controller, data, design, display, dust, dustjs, edge, ejs, file, fn, format, fragment, freemarker, func, function, handlebars, handler, hbs, id, include, jade, lang, latte, layout, liquid, locale, lodash, module, mustache, name, nette, nunjucks, output, page, partial, path, phptal, plates, preview, pug, redirect, render, resource, savant, section, show, skin, smarty, squirrelly, style, template, theme, thymeleaf, tpl, twig, underscore, velocity, view, vm, widget
//
// Overlap precedence (deterministic, flag multi-class but report under
// primary): RCE > SSRF > LFI > IDOR > SQLi > Redirect > SSTI > XSS —
// key overlaps: url (4 classes), file/path/folder (3), id (4),
// page/view/name (3), callback (2). A param matching multiple classes
// is reported once under its primary class; the finding's metadata
// carries multi_class=true and lists all matched classes deterministically.
// Endpoints with multiple params of distinct primary classes yield one
// finding per primary class (ruleID@subject isolates them).
//
// Rules (8, each <100 lines, deterministic fixtures):
//
//	triage.redirect      — information — endpoints — per-endpoint open-redirect triage assignment
//	triage.idor          — information — endpoints — per-endpoint IDOR triage assignment
//	triage.sqli          — information — endpoints — per-endpoint SQLi triage assignment
//	triage.lfi           — information — endpoints — per-endpoint LFI triage assignment
//	triage.ssrf          — information — endpoints — per-endpoint SSRF triage assignment
//	triage.cmdi          — information — endpoints — per-endpoint command-injection triage assignment
//	triage.ssti          — information — endpoints — per-endpoint SSTI triage assignment
//	triage.xss_reflected — information — endpoints — per-endpoint reflected XSS triage assignment
//
// Each rule honors context.Context, uses Detector
// func(context.Context,*Context)([]asset.Finding,error), builds findings via
// asset.NewFinding (CategoryInformation, PriorityInfo, MethodDetection
// evidence, observed endpoint subjects), respects RequiredAssetTypes
// (endpoint) for census skip, handles Config deterministically (sorted keys,
// explicit lookups for triage.<class>.disabled), extracts param names from
// endpoint URLs (split on ?& take key before =, lowercased), and respects the
// per-rule finding bound 256 via deterministic truncation.
//
// This pack produces TESTING ASSIGNMENTS, not vulnerability claims: every
// finding is CategoryInformation / PriorityInfo, StatusOpen, confidence 0.6
// for unenriched name-only matches or 0.8 when live reflection evidence
// backs a flagged param (reflection_backed marker, heuristic), with
// metadata naming the triage class and matched params.
// It is recon-only (AGENTS §0.1).
//
// Loading sketch (SDK-only, no core edits):
//
//	rules, err := triage.Rules() // CheckAPIVersion(1,0) first
//	if err != nil { return err }
//	reg := detect.NewRegistry()
//	for _, r := range rules {
//	    if err := reg.Register(r); err != nil { return err } // ValidateRule → deep copy
//	}
//	if err := reg.Validate(); err != nil { return err } // graph
//	reg.Seal() // startup confinement
//	cfg := detect.DefaultEngineConfig(reg)
//	rep, err := detect.Run(ctx, cfg, snap) // per-rule Context clone already proven
package triage
