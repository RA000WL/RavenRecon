// Package jsintel implements the JavaScript intelligence pipeline (roadmap
// v0.8): discovering script URLs from raw lines and HTML observations,
// fetching them over HTTP with bounded, honest truncation, parsing script
// bodies into typed observations — module imports and exports, string and
// template literals, and source map references — and extracting endpoint
// candidates, secret candidates (detection only, never verification),
// technologies, and per-marker evidence from the parsed content. Everything
// is deterministic, stdlib-only, and bounded; the Phase 2 JavaScript model
// lives in internal/asset. The parser layer is a pure, deterministic,
// error-tolerant extraction pass: it never builds an AST, never executes
// code, and never rewrites code; it is stdlib-only (the tokenizer is
// hand-rolled — no external parser library). The fetch layer performs NO
// analysis and NO pool orchestration — it delivers the per-URL fetch
// operation and its cache operation only; the discovery seams
// (discover.go), the bounded analysis pipeline (engine.go), and the
// extraction passes (extract.go, secrets.go, detect.go, sourcemap.go) build
// on it.
//
// # The parser abstraction
//
//	type Parser interface { Parse(src []byte) (Parsed, error) }
//
// NewParser returns the single stdlib implementation: a hand-rolled,
// error-tolerant JavaScript tokenizer (lex.go) plus an extraction walk over
// its tokens (parse.go). Later passes consume ONLY the interface and the
// Parsed model — the architecture is deliberately NOT tied to any parser
// implementation. Parse is deterministic and safe for concurrent use on one
// Parser instance (all state is per-call); the same input always yields the
// same Parsed.
//
// # Error tolerance
//
// Malformed JavaScript NEVER fails Parse. The scanner recovers from
// unterminated strings, comments, templates, and regexes (at EOL or EOF),
// stray bytes, and invalid UTF-8, counting each recovery on Parsed.Malformed
// while still extracting valid constructs before and after the damage.
// Parse returns an error ONLY for input over the hard defense cap
// maxParseInputBytes (8 MiB): the future fetch layer's own body cap bounds
// normal inputs; this is defense in depth. Empty input is a valid parse
// yielding an empty Parsed.
//
// # Limits
//
// Fixed caps (constants in parser.go, honored in every Parse):
//
//	maxParserTokens      1 Mi tokens (comments included) — a cap hit stops
//	                     tokenizing; the results are an honest prefix
//	maxParserStringBytes 4096 bytes per retained literal value — longer
//	                     literals are still tokenized and counted toward the
//	                     string budget, but not retained
//	maxParserStrings     8192 string/template literals processed
//	maxParserImports     1024 imports (static and dynamic)
//	maxParserExports     1024 distinct export names
//	maxParserIdentBytes  1024 bytes per identifier — longer identifiers are
//	                     split and counted malformed
//	maxSourceMapRefBytes 4096 bytes per sourceMappingURL reference — longer
//	                     references are dropped and counted malformed
//	maxParseInputBytes   8 MiB of input — beyond this Parse errors
//
// Any token/string/import/export cap hit marks Parsed.Truncated: the
// results are partial and never treated as complete.
//
// # Extraction scope
//
// The parser extracts observations: static imports (side-effect, binding
// forms, and export re-exports), dynamic imports (statically unresolvable
// specifiers are honestly reported as empty), exported names, string and
// template literal VALUES (escapes decoded), and the last sourceMappingURL
// reference. It does NOT resolve specifiers, deduplicate script content, or
// scan for secrets — those are later passes.
//
// # The fetch layer
//
// Fetch (fetch.go) performs ONE bounded HTTP GET of a canonical asset URL:
// a fixed RavenRecon user agent, no cookies or custom headers, up to
// MaxRedirects redirect hops (each hop gated on the central limiter), a
// per-attempt deadline, bounded header capture, and content retention
// bounded by FetchConfig.MaxJSBytes (default 2 MiB, clamped to 64 KiB .. 8
// MiB). Redirect policy: cross-host http(s) redirects ARE followed — jsintel
// has no declared-scope concept, fetch targets come from the operator's own
// corpus — but a redirect to a NON-http(s) scheme (ftp:, file:, ...) is
// observed, never followed: the walk ends with the redirect response as the
// final observation, so one scheme-incompatible redirect can never wedge the
// URL into permanent failures. Every outcome is classified with a typed
// FetchStatus and FetchReason; failures are retried immediately up to
// cfg.Retries times (bounded 1..3); completed negative observations
// (conn_refused, tls) are legitimate observations, never failures. The
// transport is a seam: nil means a bounded production transport
// (header-block cap, header timeout, direct-only, transparent gzip
// decompression); tests inject hermetic loopback transports.
//
// # Truncation honesty
//
// A response whose content exceeds MaxJSBytes — whether declared up front by
// Content-Length (the body is closed without reading a byte) or discovered
// while streaming — is truncated: Content stays nil, Size 0, Truncated
// true, Status FetchTruncated ("incomplete"). A partial prefix is NEVER
// retained: it would be a misleading partial observation, and the pipeline
// must never serve partial content as if it were the file. Truncated
// observations are stored as cache.StatusIncomplete records (never served
// as hits; a later run re-fetches), and a re-fetch under a lowered cap
// simply truncates again — cap changes never invalidate entries.
//
// # Content retention (T3d)
//
// Config.RetainContent (default false) opts a run into retaining the
// fully-retained body bytes: every entry whose fetch retained complete
// content carries it on JSEntry.Content (bounded per entry by MaxJSBytes),
// and Report.RetainedContent() exposes the run-wide set — deterministic
// canonical-URL order, one entry per URL, never a truncated prefix. The
// pipeline's jsintel stage always enables retention: its document channel
// (pipeline.Document) is produced from RetainedContent (T3d, adapt/doc.go).
// With the flag off the memory profile is unchanged (entries carry no
// content).
//
// # The js.fetch cache operation
//
// record_fetch.go implements the cache-before-execute sides: the key
// (operation + canonical URL identity only — timings, retries, caps, and
// concurrency NEVER enter a key), the stored record shape (storedFetch:
// metadata, content with recomputed hash, sources, first/last-seen), decode
// re-validation (every field re-checked, content hash verified, so a
// tampered record is discarded and recomputed — self-healing), and the
// lookup/store sides. The engine performs the lookup BEFORE any limiter
// token wait, so a cache hit performs zero token waits and zero network
// requests. Only completed observations with fully retained content are
// stored completed and served as hits; completed negatives (conn_refused /
// tls) are stored completed with their reason; truncated observations are
// stored incomplete; failed and cancelled observations are never stored.
//
// # Adapters (external JavaScript-discovery tools)
//
// internal/jsintel/adapt presents three external commands as jsintel.Source
// streams (roadmap v0.8, Phase 7): subjs, LinkFinder, and SecretFinder.
// The adapters are ACTIVE: all three tools fetch the target themselves, so
// every adapter run performs the tool's own network activity — bounded only
// by the runner's limits (the caller's context deadline and the per-stream
// output cap) — and the tools' traffic is the tools' own responsibility,
// never re-limited by RavenRecon.
//
//   - subjs (github.com/lc/subjs; MIT): discovers script URLs from a page.
//     Invocation: subjs -c 1 -t 15 -i <tmpfile>, where the tmpfile (0600,
//     created and removed by the adapter) holds exactly the target URL.
//     Detection: version probe "subjs -version".
//   - LinkFinder (github.com/GerbenJavado/LinkFinder; MIT): endpoint
//     discovery. Invocation: linkfinder.py -i <target> -o cli. Detection:
//     existence-only (no version flag). It requires jsbeautifier. Output
//     lines are HTML-escaped and may carry relative references; the
//     engine's line seam owns normalization (below).
//   - SecretFinder (github.com/m4ll0k/SecretFinder; GPL-3.0): secret
//     candidate discovery. Invocation: SecretFinder.py -i <target> -o cli.
//     Detection: existence-only (no version flag). Its progress lines
//     ("[ + ] URL: <u>") and match lines ("name\t->\tvalue") pass through
//     the adapter raw and are recognized by the engine's line seam.
//
// Executable + wrapper contract: for the python pair the SCRIPT IS the
// executable — the command's Path is "linkfinder.py" / "SecretFinder.py",
// never "python3 <script>". The documented install contract is a PATH
// wrapper with a shebang (or a symlink to the real script), or a per-run
// path override. There is no interpreter split, and the adapter NEVER
// resolves executables itself: a bare-name Path is resolved by the
// discovery Runner, which classifies a missing executable as
// discovery.ErrExecutableNotFound (wrapped with context), never a panic.
// The adapter's override map is keyed by the executable NAME — "subjs",
// "linkfinder.py", "SecretFinder.py" — and a value replaces that name as
// the command's Path, executed verbatim.
//
// Detection semantics: subjs is version-probed (a broken, garbled, or
// timing-out probe is at worst a WARN — never MISSING); the python pair is
// existence-probed (the tool's executable — the script, possibly a wrapper
// — must resolve; no probe can misreport an installed tool).
//
// The seam: every adapter wraps its bounded stdout capture as one
// Item{Kind: ItemLine, Line: <raw line>} per output line; lines over
// maxRawLineBytes (32 KiB, adapter-side) are skipped and counted. The
// ENGINE owns all normalization: URL canonicalization, relative-reference
// resolution against Config.Base, the "[ + ] URL: <u>" progress form, and
// the "name\t->\tvalue" secret-line form (parseLine in discover.go).
//
// Line-secret ingestion (the D2 contract): "[ + ] URL:" lines set the
// line seam's current URL context; every later secret line becomes a typed
// candidate attributed to that URL (the mapping table in discover.go —
// google_api/google_api_key → google, json_web_token → jwt,
// amazon_aws_access_key_id/aws_access_key_id/aws_secret_access_key → aws,
// firebase/firebase_api_key → firebase, stripe/stripe_secret_key → stripe,
// github/github_token → github, private_key → private_key, bearer →
// bearer, and everything else → generic) with the value bounded to 4096
// bytes. Pending line-secrets are retained per URL in a bounded map (32
// URL contexts × 64 secrets each); beyond either cap, or for an empty or
// overlong value, the line is counted (Skipped) and dropped. At the end of
// the run the pending secrets are attached to their URL's entry — source
// identity is the URL's JavaScript identity, so they deduplicate with the
// content-derived candidates by candidate identity — while secrets for
// URLs never admitted (cap-dropped targets) or for lines before any URL
// context are counted and dropped. SecretLines counts every raw secret
// line, ingested or not. Tool stderr is never parsed for content.
//
// Katana's JS output is deliberately DEFERRED (documented future work),
// consistent with urlintel's katana deferral: katana is a crawling tool with
// a heavier invocation shape; the three tools above cover this phase's
// JS-discovery scope.
//
// Known limitations and follow-ups:
//   - LinkFinder lines may carry HTML entities (the tool HTML-escapes its
//     output); parseLine does not unescape them in this pass — unescaping at
//     the line seam is a documented follow-up for a later pass.
//   - The 32 KiB line cap lives in the adapter (maxRawLineBytes); the engine
//     seam has no line cap of its own. The overlong count is exposed on the
//     adapter source so the future orchestration can fold it into the
//     engine's Malformed accounting.
package jsintel
