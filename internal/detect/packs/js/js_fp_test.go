package js

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

// JS precision-harness location rationale — mirrors
// internal/detect/packs/triage/triage_fp_test.go: co-located with the
// pack it measures (hermetic, versioned with the pack, stdlib-only,
// synthetic values only, byte-stable). FP measurement is a pack-level
// quality gate, not a pipeline fixture.
//
// What it measures (NEW-123): the string-contains predicates decide on
// raw bodies, so comments, string literals, and dead code fire. This
// harness pins three things: (1) RECALL on labeled vulnerable bodies
// must stay 100% (gates future predicate tightening); (2) clean safe
// bodies stay quiet; (3) trap bodies (FP/FN classes) pin EXACT current
// counts — characterization baselines to beat, NOT zero gates: update
// them deliberately when predicates improve (token-aware filtering),
// never silently.

// vulnBodies are labeled-vulnerable scripts: every rule must fire on
// its own class (recall gate).
var vulnBodies = map[string]struct {
	rule string
	url  string
	body string
}{
	"xss-innerhtml": {ruleDomXSS, "https://www.example.com/fp_xss_innerhtml.js", "el.innerHTML = location.hash;\n"},
	"xss-outerhtml": {ruleDomXSS, "https://www.example.com/fp_xss_outerhtml.js", "el.outerHTML = userHtml;\n"},
	"xss-docwrite":  {ruleDomXSS, "https://www.example.com/fp_xss_docwrite.js", "document.write(title);\n"},
	"pm-unguarded":  {rulePostMessage, "https://www.example.com/fp_pm_unguarded.js", "window.addEventListener(\"message\", function(e){ console.log(e.data); });\n"},
	"proto-dunder":  {ruleProtoPollute, "https://www.example.com/fp_proto_dunder.js", "obj.__proto__.polluted = true;\n"},
	"proto-ctor":    {ruleProtoPollute, "https://www.example.com/fp_proto_ctor.js", "obj.constructor.prototype.x = 1;\n"},
}

// safeBodies are clean scripts: no rule may fire.
var safeBodies = map[string]struct {
	url  string
	body string
}{
	"textcontent":  {"https://www.example.com/fp_safe_text.js", "el.textContent = name;\n"},
	"guarded-pm":   {"https://www.example.com/fp_safe_pm.js", "window.addEventListener(\"message\", function(e){ if (e.origin !== \"https://example.com\") return; render(e.data); });\n"},
	"plain-assign": {"https://www.example.com/fp_safe_assign.js", "obj.normal = true;\na.b = 1;\n"},
	"jquery-like":  {"https://www.example.com/fp_safe_jq.js", "(function($){ var v = \"1.2.3\"; $(document).ready(function(){ var el = document.querySelector(\"#app\"); el.textContent = v; document.addEventListener(\"click\", function(){ track(\"open\"); }); }); })(jQuery);\n"},
}

// trapBodies are adversarial-to-the-heuristic scripts with KNOWN current
// verdicts: comment/string mentions that fire (FP traps) and guarded-
// looking-but-vulnerable shapes that stay quiet (FN traps). Each entry
// names the expected firing rules TODAY — update deliberately when the
// predicates change (that update IS the precision win).
var trapBodies = map[string]struct {
	body  string
	fires []string // rule IDs expected to fire today
}{
	// FP traps: no code sink — NEW-123 token-aware predicates keep all
	// four quiet (baseline beaten 4→0; each entry names its fix).
	"comment-innerhtml": {
		"// NOTE: we never use innerHTML here, only textContent\nel.textContent = name;\n",
		[]string{}, // FIXED by code-vs-comment: innerHTML only in the // comment, no code sink.
	},
	"string-docwrite": {
		"var doc = \"see document.write docs\";\nconsole.log(doc);\n",
		[]string{}, // FIXED by code-vs-string: document.write only in the "..." literal, no code call.
	},
	"click-with-message-string": {
		"var msg = \"message\";\nwindow.addEventListener(\"click\", function(){ ping(msg); });\n",
		[]string{}, // FIXED by handler scope (first-arg-is-message): the "message" literal is a var initializer; the handler listens for "click".
	},
	"comment-proto": {
		"// __proto__ pollution is dangerous; we use Object.create(null)\nvar o = Object.create(null);\n",
		[]string{}, // FIXED by code-vs-comment: __proto__ only in the // comment, no code write.
	},
	// FN traps: real sink, silenced by a misleading token.
	"guarded-looking-comment": {
		"window.addEventListener(\"message\", function(e){ doSomething(e.data); });\n// validated via e.origin upstream\n",
		[]string{rulePostMessage}, // NEW-123 MUST FIRE: origin-in-code check — the e.origin mention is comment-only and no longer suppresses the unguarded handler.
	},
}

func fpSnapshot(t testing.TB, bodies map[string]string, base string) detect.Snapshot {
	t.Helper()
	var scripts []asset.JavaScript
	var contents []detect.JavaScriptContent
	// Sorted keys: Go map iteration is random, and the body→URL
	// attachment must be deterministic across runs.
	names := make([]string, 0, len(bodies))
	for name := range bodies {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		js := mustJS(t, base+"/fp_case_"+fmt.Sprint(i)+".js")
		scripts = append(scripts, js)
		contents = append(contents, detect.JavaScriptContent{Identity: js.Identity(), Body: bodies[name]})
	}
	return detect.Snapshot{JavaScript: scripts, JavaScriptContent: contents}
}

func fpRun(t testing.TB, snap detect.Snapshot) map[string]int {
	t.Helper()
	reg := registerJSPack(t)
	cfg := detect.DefaultEngineConfig(reg)
	cfg.Clock = testClock
	rep, err := detect.Run(context.Background(), cfg, snap)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	counts := make(map[string]int)
	for _, f := range rep.Findings {
		counts[f.RuleID]++
	}
	return counts
}

// TestJSFPRecallOnLabeledVuln pins detection recall at 100%: every
// labeled vulnerable body must fire its rule. Predicate tightening that
// drops a true sink fails here — never trade recall silently.
func TestJSFPRecallOnLabeledVuln(t *testing.T) {
	for rule, want := range map[string]int{ruleDomXSS: 3, rulePostMessage: 1, ruleProtoPollute: 2} {
		total := 0
		i := 0
		for _, tc := range vulnBodies {
			if tc.rule != rule {
				continue
			}
			url := fmt.Sprintf("https://www.example.com/fp_recall_%d.js", i)
			i++
			got := fpRun(t, snapWithBody(t, url, tc.body))
			total += got[rule]
		}
		if total != want {
			t.Errorf("rule %s recall: %d/%d labeled vuln bodies fired", rule, total, want)
		}
	}
}

// TestJSFPSafeQuiet pins clean bodies silent across all rules.
func TestJSFPSafeQuiet(t *testing.T) {
	bodies := make(map[string]string)
	for name, tc := range safeBodies {
		bodies[name] = tc.body
	}
	snap := fpSnapshot(t, bodies, "https://www.example.com")
	counts := fpRun(t, snap)
	for rule, n := range counts {
		t.Errorf("safe corpus fired rule %s %d times, want 0", rule, n)
	}
}

// TestJSFPTrapBaseline pins EXACT current verdicts on trap bodies:
// characterization baselines to beat. A predicate change that alters
// any count must update these pins deliberately (that diff IS the
// precision-fix review).
func TestJSFPTrapBaseline(t *testing.T) {
	for name, tc := range trapBodies {
		snap := snapWithBody(t, "https://www.example.com/fp_trap_"+name+".js", tc.body)
		counts := fpRun(t, snap)
		var got []string
		for rule := range counts {
			got = append(got, rule)
		}
		if len(got) != len(tc.fires) {
			t.Errorf("trap %q fires %v, want %v (baseline; update deliberately with predicate work)", name, got, tc.fires)
			continue
		}
		for _, rule := range tc.fires {
			if counts[rule] != 1 {
				t.Errorf("trap %q: rule %s count %d, want 1", name, rule, counts[rule])
			}
		}
	}
}

// TestJSFPBenignBundleRate measures the FP rate on a wild-like benign
// bundle (framework-shaped code with trap words in comments) and pins
// the exact count: baseline to beat, not a zero gate.
func TestJSFPBenignBundleRate(t *testing.T) {
	body := `(function(){
"use strict";
// Fixes innerHTML XSS by using textContent everywhere (v2.1).
// postMessage protocol v2: handlers validate event.origin first.
// __proto__-free clone helper below (no prototype tricks).
var VERSION = "4.7.2";
function clone(o){ var n = {}; for (var k in o){ if (Object.prototype.hasOwnProperty.call(o, k)){ n[k] = o[k]; } } return n; }
function render(el, text){ el.textContent = text; }
document.addEventListener("DOMContentLoaded", function(){
  var el = document.querySelector("#app");
  render(el, VERSION);
  window.addEventListener("click", function(){ track("open"); });
});
})();
`
	snap := snapWithBody(t, "https://cdn.example.com/fw-4.7.2.min.js", body)
	counts := fpRun(t, snap)
	total := 0
	for rule, n := range counts {
		total += n
		t.Logf("benign bundle: rule %s fired %d", rule, n)
	}
	// Baseline pin (NEW-123 beaten 2→0): comment-awareness quiets both
	// former fires — the "innerHTML" // comment (domxss) and the
	// "__proto__" // comment (proto); postmessage stays quiet (no static
	// "message" handler arg anywhere). Nothing still fires: total 0.
	if total != 0 {
		t.Errorf("benign bundle findings = %d, want beaten baseline 0", total)
	}
	t.Logf("FP harness: %d findings over 1 benign bundle (baseline pinned; lower is better, see NEW-123)", total)
}

// TestJSFPCommentOnlySinkQuiet pins NEW-123's code-vs-comment contract: a
// sink name appearing ONLY in comments (line and block) must not fire its
// rule — the token-aware predicates decide on code spans, never raw
// substrings.
func TestJSFPCommentOnlySinkQuiet(t *testing.T) {
	cases := map[string]struct {
		rule string
		body string
	}{
		"dom-line-comment":   {ruleDomXSS, "// el.innerHTML = location.hash;\nvar ok = 1;\n"},
		"dom-block-comment":  {ruleDomXSS, "/* document.write(title); */\nvar ok = 1;\n"},
		"pm-line-comment":    {rulePostMessage, "// window.addEventListener(\"message\", function(e){});\nvar ok = 1;\n"},
		"proto-line-comment": {ruleProtoPollute, "// obj.__proto__.x = 1;\nvar ok = 1;\n"},
		"proto-block":        {ruleProtoPollute, "/* o.constructor.prototype.x = 1; */\nvar ok = 1;\n"},
	}
	for name, tc := range cases {
		snap := snapWithBody(t, "https://www.example.com/fp_commentonly_"+name+".js", tc.body)
		counts := fpRun(t, snap)
		if counts[tc.rule] != 0 {
			t.Errorf("comment-only %q fired rule %s, want quiet (sink only in comments)", name, tc.rule)
		}
		total := 0
		for _, n := range counts {
			total += n
		}
		if total != 0 {
			t.Errorf("comment-only %q fired %v, want total 0", name, counts)
		}
	}
}

// TestJSFPHostileChunkBounded pins NEW-123's bounded contract on hostile
// 512 KiB chunk windows (the NEW-129 window size): inputs are pre-bounded
// (snapshot bodies ≤2 MiB, chunks 512 KiB — far below the parser's 8 MiB
// hard cap), and codeMask is a single linear pass with capped nesting, so
// hostile shapes (megabyte identifiers, comment floods, unterminated
// constructs) complete in linear time under the rule's 2s Timeout with no
// pathological blowup vs the old substring scan (timing logged per case).
func TestJSFPHostileChunkBounded(t *testing.T) {
	const chunk = 512 * 1024 // 512 KiB chunk windows
	sinkTail := "el.innerHTML = x;\n"
	fireBody := strings.Repeat("a", chunk-len(sinkTail)) + sinkTail
	commentLine := "// innerHTML document.write __proto__ message\n"
	commentFlood := strings.Repeat(commentLine, chunk/len(commentLine)+1)[:chunk]
	cases := map[string]struct {
		body     string
		rule     string
		wantRule int
		wantAll  int
	}{
		// Filler abuts the sink into one long identifier; the dotted
		// write at the tail must still fire (the scan reaches the end).
		"tail-sink-fires": {fireBody, ruleDomXSS, 1, 1},
		// 512 KiB of sink words, all in // comments: quiet.
		"comment-flood-quiet": {commentFlood, ruleDomXSS, 0, 0},
		// Unterminated block comment swallows the trailing sink: quiet.
		"unterminated-comment-quiet": {"var setup = 1;\n/*\n" + strings.Repeat("innerHTML __proto__ document.write message\n", chunk/44) + "el.innerHTML = x;\n", ruleDomXSS, 0, 0},
		// Unterminated string holds the sink word (it ends at the newline
		// per spec recovery): quiet.
		"unterminated-string-quiet": {"var s = \"innerHTML tail\n" + strings.Repeat("a", chunk/2)[:chunk/2], ruleDomXSS, 0, 0},
	}
	for name, tc := range cases {
		if len(tc.body) > detect.MaxSnapshotJSContentBodyBytes {
			t.Fatalf("case %q body %d bytes over the 2 MiB snapshot bound", name, len(tc.body))
		}
		startSub := time.Now()
		low := strings.ToLower(tc.body)
		_ = domXSSCodeSink(low, codeMask(low))
		subElapsed := time.Since(startSub)
		startTok := time.Now()
		snap := snapWithBody(t, "https://www.example.com/fp_hostile_"+name+".js", tc.body)
		counts := fpRun(t, snap)
		tokElapsed := time.Since(startTok)
		t.Logf("hostile %q (%d bytes): token-aware predicate %v, full run %v", name, len(tc.body), subElapsed, tokElapsed)
		if tokElapsed > 5*time.Second {
			t.Errorf("hostile %q full run %v over 5s hang guard (linear scan violated)", name, tokElapsed)
		}
		if counts[tc.rule] != tc.wantRule {
			t.Errorf("hostile %q rule %s = %d, want %d", name, tc.rule, counts[tc.rule], tc.wantRule)
		}
		total := 0
		for _, n := range counts {
			total += n
		}
		if total != tc.wantAll {
			t.Errorf("hostile %q total = %d (%v), want %d", name, total, counts, tc.wantAll)
		}
	}
}

// TestJSFPProtoStmtTerminator pins MEDIUM-1: the proto assignment search
// terminates at `)`, `,`, `:` (plus `;{}`) within a 4 KiB window, so a
// comparison inside a condition cannot bleed into a later statement's `=`.
func TestJSFPProtoStmtTerminator(t *testing.T) {
	cases := map[string]struct {
		body      string
		wantProto int
		wantAll   int
	}{
		// Condition compares __proto__; the later `z = 1` is a different
		// statement past `)` — quiet.
		"comparison-then-assign-quiet": {"if (x.__proto__ == y) z = 1;\n", 0, 0},
		// Direct assignment inside for-parens fires before any terminator.
		"for-assign-fires": {"for(x.__proto__=y;;){break;}\n", 1, 1},
		// Dotted continuation reaches `=` before `;` — fires.
		"dotted-continuation-fires": {"obj.__proto__.polluted = true;\n", 1, 1},
	}
	for name, tc := range cases {
		snap := snapWithBody(t, "https://www.example.com/fp_stmt_"+name+".js", tc.body)
		counts := fpRun(t, snap)
		if counts[ruleProtoPollute] != tc.wantProto {
			t.Errorf("stmt %q proto = %d, want %d", name, counts[ruleProtoPollute], tc.wantProto)
		}
		total := 0
		for _, n := range counts {
			total += n
		}
		if total != tc.wantAll {
			t.Errorf("stmt %q total = %d (%v), want %d", name, total, counts, tc.wantAll)
		}
	}
}

// TestJSFPProtoHostileReadsBounded pins HIGH: N×`x.__proto__` reads with no
// statement terminators stay quiet in linear, interruptible time. Each
// occurrence scans at most one 4 KiB window (maxStmtScanBytes) with ctx
// checked every 128 occurrences — never to-EOF per occurrence.
func TestJSFPProtoHostileReadsBounded(t *testing.T) {
	const chunk = 512 * 1024
	unit := "x.__proto__ "
	body := strings.Repeat(unit, chunk/len(unit))
	if len(body) > detect.MaxSnapshotJSContentBodyBytes {
		t.Fatalf("hostile reads body %d bytes over the 2 MiB snapshot bound", len(body))
	}
	start := time.Now()
	snap := snapWithBody(t, "https://www.example.com/fp_hostile_proto_reads.js", body)
	counts := fpRun(t, snap)
	elapsed := time.Since(start)
	t.Logf("hostile proto-reads (%d bytes, %d occurrences): full run %v", len(body), chunk/len(unit), elapsed)
	if elapsed > 5*time.Second {
		t.Errorf("hostile proto-reads full run %v over 5s hang guard (quadratic scan)", elapsed)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total != 0 {
		t.Errorf("hostile proto-reads total = %d (%v), want 0 (reads, no assignment)", total, counts)
	}
	// Interruptible: a cancelled ctx aborts the finder promptly.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	low := strings.ToLower(body)
	if _, err := protoCodeSinkCtx(ctx, low, codeMask(low)); err == nil {
		t.Errorf("protoCodeSinkCtx with cancelled ctx = nil error, want cancellation")
	}
}

// TestJSFPPostMessageFileGlobalOriginLimitation pins MEDIUM-2 choice B
// (documented file-global origin scope as a known-FN limitation): any code
// `.origin` anywhere suppresses the rule, even when it guards a different
// handler. Both two-handler shapes stay quiet today; handler-scoped search
// would fire the unguarded handler (1). If handler scope is ever
// implemented, update these pins to 1 deliberately.
func TestJSFPPostMessageFileGlobalOriginLimitation(t *testing.T) {
	cases := map[string]string{
		"guarded-plus-unguarded": "window.addEventListener(\"message\", function(e){ if (e.origin !== \"https://example.com\") return; render(e.data); });\n" +
			"window.addEventListener(\"message\", function(e){ console.log(e.data); });\n",
		"click-with-origin-plus-unguarded-message": "document.addEventListener(\"click\", function(e){ console.log(e.origin); });\n" +
			"window.addEventListener(\"message\", function(e){ console.log(e.data); });\n",
	}
	for name, body := range cases {
		snap := snapWithBody(t, "https://www.example.com/fp_origin_global_"+name+".js", body)
		counts := fpRun(t, snap)
		total := 0
		for _, n := range counts {
			total += n
		}
		// Known-FN pin: file-global scope quiets the unguarded handler.
		if total != 0 {
			t.Errorf("origin-global %q total = %d (%v), want 0 quiet-as-known-FN (file-global suppresses)", name, total, counts)
		}
	}
}

// TestJSFPDocumentWriteSpacing pins LOW-2 (document.write): the gap between
// `document`, `.`, `write` resolves through nextCodeNonSpace + allCode like
// innerHTML, so spaced/commented calls fire while `mydocument.write` stays
// quiet.
func TestJSFPDocumentWriteSpacing(t *testing.T) {
	fires := map[string]string{
		"contiguous-control": "document.write(x);\n",
		"spaced-dot":         "document .write(x);\n",
		"comment-gap":        "document /*c*/.write(x);\n",
	}
	for name, body := range fires {
		snap := snapWithBody(t, "https://www.example.com/fp_docwrite_"+name+".js", body)
		counts := fpRun(t, snap)
		if counts[ruleDomXSS] != 1 {
			t.Errorf("docwrite %q domxss = %d, want 1", name, counts[ruleDomXSS])
		}
	}
	quiet := map[string]string{
		"longer-ident": "mydocument.write(x);\n",
	}
	for name, body := range quiet {
		snap := snapWithBody(t, "https://www.example.com/fp_docwrite_"+name+".js", body)
		counts := fpRun(t, snap)
		if counts[ruleDomXSS] != 0 {
			t.Errorf("docwrite %q domxss = %d, want 0 (longer identifier)", name, counts[ruleDomXSS])
		}
	}
}

// TestJSFPConstructorPrototypeSpacing pins LOW-2 (constructor.prototype):
// the gap between `constructor`, `.`, `prototype` uses the same spacing
// logic as `__proto__`.
func TestJSFPConstructorPrototypeSpacing(t *testing.T) {
	fires := map[string]string{
		"contiguous-control": "obj.constructor.prototype.x = 1;\n",
		"spaced-dot":         "obj.constructor .prototype.x = 1;\n",
		"comment-gap":        "obj.constructor /*c*/.prototype.x = 1;\n",
	}
	for name, body := range fires {
		snap := snapWithBody(t, "https://www.example.com/fp_ctor_"+name+".js", body)
		counts := fpRun(t, snap)
		if counts[ruleProtoPollute] != 1 {
			t.Errorf("ctor %q proto = %d, want 1", name, counts[ruleProtoPollute])
		}
	}
	snap := snapWithBody(t, "https://www.example.com/fp_ctor_object_prototype.js", "Object.prototype.x = 1;\n")
	if counts := fpRun(t, snap); counts[ruleProtoPollute] != 0 {
		t.Errorf("Object.prototype proto = %d, want 0 (no constructor qualifier)", counts[ruleProtoPollute])
	}
}

// TestJSFPParseFirstStringArgParen pins LOW-4: one parenthesized layer
// around the event type unwraps (`("message")` fires); var aliases stay
// quiet (statically unknown, documented alongside the paren limit).
func TestJSFPParseFirstStringArgParen(t *testing.T) {
	fire := "window.addEventListener((\"message\"), function(e){ console.log(e.data); });\n"
	if counts := fpRun(t, snapWithBody(t, "https://www.example.com/fp_paren_message.js", fire)); counts[rulePostMessage] != 1 {
		t.Errorf("paren-message postmessage = %d, want 1 (one paren layer unwraps)", counts[rulePostMessage])
	}
	alias := "var t = \"message\";\nwindow.addEventListener(t, function(e){ console.log(e.data); });\n"
	if counts := fpRun(t, snapWithBody(t, "https://www.example.com/fp_alias_message.js", alias)); counts[rulePostMessage] != 0 {
		t.Errorf("alias-message postmessage = %d, want 0 (var alias statically unknown)", counts[rulePostMessage])
	}
}

// TestJSFPIdentByteNonASCII pins LOW-3: bytes >= 0x80 are identifier
// continuation, so a non-ASCII byte adjacent to a sink name keeps it one
// identifier (fewer fires, conservative).
func TestJSFPIdentByteNonASCII(t *testing.T) {
	if !isIdentByte(0x80) || !isIdentByte(0xff) {
		t.Errorf("isIdentByte(>=0x80) = false, want true (ident-continuation)")
	}
	if isIdentByte(' ') || isIdentByte('.') || isIdentByte('(') {
		t.Errorf("isIdentByte ASCII punctuation = true, want false")
	}
	// End-to-end: U+00E9 directly before `document` reads as a longer
	// identifier — quiet. Without the fix this fires (boundary split).
	body := "édocument.write(x);\n"
	if counts := fpRun(t, snapWithBody(t, "https://www.example.com/fp_nonascii_docwrite.js", body)); counts[ruleDomXSS] != 0 {
		t.Errorf("nonascii-docwrite domxss = %d, want 0 (non-ASCII ident continuation)", counts[ruleDomXSS])
	}
}

// TestJSFPPostMessageHostileReadsBounded pins HIGH: single-line N×
// `x.addEventListener("` unterminated stays quiet in linear,
// interruptible time. Each occurrence scans at most one 4 KiB literal
// window (maxStaticStringScanBytes) — never to EOF per occurrence — with
// ctx checked every 128 occurrences.
func TestJSFPPostMessageHostileReadsBounded(t *testing.T) {
	const chunk = 512 * 1024
	unit := `x.addEventListener("`
	body := strings.Repeat(unit, chunk/len(unit))
	if len(body) > detect.MaxSnapshotJSContentBodyBytes {
		t.Fatalf("hostile reads body %d bytes over the 2 MiB snapshot bound", len(body))
	}
	if strings.Contains(body, "\n") {
		t.Fatalf("hostile reads body contains a newline, want a single line")
	}
	start := time.Now()
	snap := snapWithBody(t, "https://www.example.com/fp_hostile_pm_reads.js", body)
	counts := fpRun(t, snap)
	elapsed := time.Since(start)
	t.Logf("hostile pm-reads (%d bytes, %d occurrences): full run %v", len(body), chunk/len(unit), elapsed)
	if elapsed > 5*time.Second {
		t.Errorf("hostile pm-reads full run %v over 5s hang guard (quadratic scan)", elapsed)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total != 0 {
		t.Errorf("hostile pm-reads total = %d (%v), want 0 (no static message arg, no delimiter)", total, counts)
	}
	// Over-cap literal stays static-unknown without scanning to EOF: a
	// single opening quote followed by 32 KiB with no closer reports
	// ok=false (quiet, conservative FN past the 4 KiB window).
	longBody := `x.addEventListener("` + strings.Repeat("a", 32*1024)
	lowLong := strings.ToLower(longBody)
	qIdx := strings.Index(lowLong, `"`)
	if qIdx < 0 {
		t.Fatalf("over-cap fixture has no quote")
	}
	if _, _, ok := parseStaticString(lowLong, qIdx); ok {
		t.Errorf("over-cap parseStaticString ok = true, want false (static-unknown past 4 KiB)")
	}
	// Interruptible: a cancelled ctx aborts the finder promptly.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	low := strings.ToLower(body)
	if _, err := postMessageCodeHandlerCtx(ctx, low, codeMask(low)); err == nil {
		t.Errorf("postMessageCodeHandlerCtx with cancelled ctx = nil error, want cancellation")
	}
}

// TestJSFPParseFirstStringArgDelimiter pins LOW-2: the non-paren branch
// requires the next code byte after the static string to be `,` or `)`
// (so `"message"+x` — a concatenation expression — stays quiet), while
// `"message",` and `"message")` fire.
func TestJSFPParseFirstStringArgDelimiter(t *testing.T) {
	quiet := `window.addEventListener("message"+suffix, function(e){ console.log(e.data); });` + "\n"
	if counts := fpRun(t, snapWithBody(t, "https://www.example.com/fp_pm_concat.js", quiet)); counts[rulePostMessage] != 0 {
		t.Errorf("concat-message postmessage = %d, want 0 (first arg is a concatenation, not static)", counts[rulePostMessage])
	}
	fires := map[string]string{
		"comma": `window.addEventListener("message", function(e){ console.log(e.data); });` + "\n",
		"close": `window.addEventListener("message")` + "\n",
	}
	for name, body := range fires {
		if counts := fpRun(t, snapWithBody(t, "https://www.example.com/fp_pm_delim_"+name+".js", body)); counts[rulePostMessage] != 1 {
			t.Errorf("delim %q postmessage = %d, want 1 (static message followed by , or ))", name, counts[rulePostMessage])
		}
	}
}

// TestJSFPHasCodeOriginCtxCadence pins LOW-1: the .origin scan checks ctx
// every 128 occurrences (finderCtxCheckEvery, like every other finder),
// so a cancelled run aborts promptly even when occurrence offsets never
// align to a byte multiple.
func TestJSFPHasCodeOriginCtxCadence(t *testing.T) {
	body := strings.Repeat("e.origin;", 1000)
	low := strings.ToLower(body)
	mask := codeMask(low)
	if v, err := hasCodeOriginCtx(context.Background(), low, mask); err != nil || !v {
		t.Errorf("hasCodeOriginCtx background = (%v, %v), want (true, nil)", v, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hasCodeOriginCtx(ctx, low, mask); err == nil {
		t.Errorf("hasCodeOriginCtx with cancelled ctx = nil error, want cancellation (every-128 cadence)")
	}
	// Short body with no origin still honors cancellation via the final
	// check (prompt abort even under the 128-occurrence window).
	shortLow := strings.ToLower("var ok = 1;\n")
	if _, err := hasCodeOriginCtx(ctx, shortLow, codeMask(shortLow)); err == nil {
		t.Errorf("hasCodeOriginCtx short cancelled = nil error, want cancellation (final check)")
	}
}

// TestJSFPPostMessageCtxCancelledShortBody pins LOW-1:
// postMessageCodeHandlerCtx honors cancellation even on short bodies (<128
// occurrences) via trailing ctx.Err checks before each success return
// (mirroring hasCodeOriginCtx) — a cancelled ctx reports error, never
// silent success.
func TestJSFPPostMessageCtxCancelledShortBody(t *testing.T) {
	body := "window.addEventListener(\"message\", function(e){ console.log(e.data); });\n"
	low := strings.ToLower(body)
	mask := codeMask(low)
	if got, err := postMessageCodeHandlerCtx(context.Background(), low, mask); err != nil || got < 0 {
		t.Fatalf("background short firing body = (%d, %v), want (offset>=0, nil)", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := postMessageCodeHandlerCtx(ctx, low, mask); err == nil {
		t.Errorf("postMessageCodeHandlerCtx short firing cancelled = nil error, want cancellation (trailing check before success return)")
	}
	quietLow := strings.ToLower("var ok = 1;\n")
	if _, err := postMessageCodeHandlerCtx(ctx, quietLow, codeMask(quietLow)); err == nil {
		t.Errorf("postMessageCodeHandlerCtx short quiet cancelled = nil error, want cancellation (final check)")
	}
}

// TestJSFPParseFirstStringArgParenOuterDelimiter pins LOW-2: the paren
// branch requires the outer next-code byte after the close to be `,` or
// `)` — `("message")+suffix` stays quiet (first argument is a
// concatenation, not the static event type) while `("message"))` fires.
func TestJSFPParseFirstStringArgParenOuterDelimiter(t *testing.T) {
	quiet := "window.addEventListener((\"message\")+suffix, function(e){ console.log(e.data); });\n"
	if counts := fpRun(t, snapWithBody(t, "https://www.example.com/fp_paren_concat.js", quiet)); counts[rulePostMessage] != 0 {
		t.Errorf("paren-concat postmessage = %d, want 0 (outer +suffix is a concatenation, not static)", counts[rulePostMessage])
	}
	fire := "window.addEventListener((\"message\"))\n"
	if counts := fpRun(t, snapWithBody(t, "https://www.example.com/fp_paren_close.js", fire)); counts[rulePostMessage] != 1 {
		t.Errorf("paren-close postmessage = %d, want 1 (outer ) accepts)", counts[rulePostMessage])
	}
}
