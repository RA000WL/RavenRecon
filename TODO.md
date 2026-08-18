# RavenRecon — Agent Coordination TODO

Cross-agent work board. Agents record open issues, required fixes, and
suggestions here so that work survives session boundaries and no reviewed
finding is lost between orchestrations. Maintained by the master
orchestrator; every agent may append or update its own entries.

## Conventions

- **One entry per issue.** Keep it small and actionable.
- **IDs:** continue the existing sequences — audit findings (H-/M-/L-),
  review follow-ups (NEW-n), info/doc skew (NF-n). New entries take the
  next free `NEW-n` (currently NEW-4).
- **Statuses:**
  - `OPEN` — needs work; reporter recorded it.
  - `IN PROGRESS` — owner claimed it (owner sets this).
  - `VERIFIED` — implementation + tests exist, gates run, orchestrator confirmed.
  - `DEFERRED` — acknowledged, deliberately not doing now (reason required).
  - `WON'T FIX` — decision recorded (reason required).
- **Closing:** the orchestrator (not the implementer) moves entries to
  VERIFIED and archives them under "Recently closed". Implementers never
  claim work that was not actually run (AGENTS.md §0.9).
- **Reporter duties:** include file:line evidence, severity, and the
  concrete fix to do — not just the problem.
- **Suggestions vs. mandates:** any agent may add ideas/notes (builder
  refactor ideas, reviewer hardening notes, researcher tooling
  suggestions) — tag them `(note)` in the title so they are not mistaken
  for mandated fixes.

## Role guidance

- **Reviewer:** files findings as entries (severity + evidence + required
  fix), status OPEN. Never fixes.
- **Builder:** claims entries (IN PROGRESS), implements, reports gates;
  may add `(note)` suggestions for future work.
- **Tester:** files coverage gaps, flaky tests, missing race coverage.
- **Researcher:** files tooling/architecture suggestions with trade-offs.
- **Docs:** files doc-drift entries (comments, README/ARCHITECTURE skew).
- **Master:** assigns owners, verifies closures against acceptance
  criteria, archives completed entries, keeps this file honest.

## Entry template

    ### NEW-n (SEVERITY) — short title (package)
    - Status: OPEN | IN PROGRESS | DEFERRED
    - Reporter: reviewer | builder | tester | researcher | docs
    - Owner: (unassigned) | builder | docs | ...
    - Problem: <one or two lines, file:line evidence>
    - Fix: <actionable steps>
    - Verification: <tests/gates that prove it done>

## Open items

### M-1 (tests) (HIGH) — spoof regression tests missing (internal/httpprobe)
- Status: OPEN
- Reporter: reviewer
- Owner: (unassigned)
- Problem: the M-1 classification code is verified correct (structural-only,
  sentinel-tagged at the dial boundary, no `"tls:"` text fallback), but the
  two audit-mandated spoof regressions are not in the suite, and
  `rawResponder`/`newRawResponder` (fake_test.go:436-470) is dead code built
  exactly for them.
- Fix: wire rawResponder into two end-to-end loopback tests (real transport,
  hostile bytes as header lines): (a) malformed no-colon line containing
  `tls:` must NOT classify ProbeCompleted/ReasonTLS (→ ProbeFailed/ReasonOther);
  (b) malformed line containing `server response headers exceeded` must NOT
  classify ProbeTruncated (→ ProbeFailed/ReasonOther). Both must fail on
  pre-fix text-matching code. Positive controls exist
  (TestProbeHeaderByteCapTruncates, TestProbeTLSHandshakeErrorClassifiedReasonTLS) — keep.
- Verification: `go test ./internal/httpprobe/...`

### M-2 (tests) (MED) — scope-boundary regression tests missing (internal/httpprobe)
- Status: OPEN
- Reporter: reviewer
- Owner: (unassigned)
- Problem: probeKey now includes the declared domain (code verified), but no
  test pins it — every current test passes with the pre-fix key shape.
- Fix: (a) key inequality — same target under two different declared domains →
  different keys; identical domains → identical keys. (b) behavioral —
  narrow-scope run (domain `a.example.com`) probes a target whose redirect
  walks out of scope → record stored; then a broader-scope run
  (`example.com`) against the same target must NOT be served a cache hit
  (Executed=true/Cached=false, redirect chain contains the followed hop).
- Verification: `go test ./internal/httpprobe/...`

### NEW-1 (LOW) — urlintel decode serves userinfo-bearing stored endpoint URLs (internal/urlintel)
- Status: OPEN
- Reporter: reviewer
- Owner: (unassigned)
- Problem: decodeStoredURL (record.go ~110-136) re-validates stored endpoints
  only via String()-based identity checks; identity excludes userinfo, so a
  tampered cache record whose `Endpoints[0].URL.Original` carries `user:pass@`
  passes decode and storedToEntry (~230-240) serves it into the report.
- Fix: mirror httpprobe's decode-time refusal (internal/httpprobe/cache.go:274-282):
  refuse any stored URL asset (record URL and every endpoint URL) whose
  Original is non-empty and parses with userinfo (or whose Original !=
  canonical String(); first verify no legitimate path stores non-canonical
  Originals). Add a descriptive decode error.
- Verification: regression test plants a tampered record → decode rejects →
  lookup deletes + falls through to fresh extraction (self-heal); the entry
  never carries the userinfo. `go test ./internal/urlintel/...`

### NF-1 (INFO) — admin/openapi.yaml User-Agent example still 0.5.0 (docs)
- Status: OPEN
- Reporter: reviewer
- Owner: docs
- Problem: admin/openapi.yaml (~line 56) default `User-Agent` example value
  is still `RavenRecon/0.5.0`.
- Fix: update to `RavenRecon/1.0.0`.
- Verification: grep for stale `0.5.0`/`v0.5.0` refs — clean.

### NF-2 (INFO) — techintel key-shape comment stale (internal/techintel/doc.go)
- Status: OPEN
- Reporter: reviewer
- Owner: docs
- Problem: doc.go (~25-34) describes the cache key as
  "operation + identity + schema version"; the actual key also carries
  `db_digest` and `sources` parts.
- Fix: refresh the comment to match techKey (record.go:15-32).
- Verification: comment matches code; `go test ./internal/techintel/...`

### NF-3 (INFO) — httpprobe header-cap comment stale (internal/httpprobe/run.go)
- Status: OPEN
- Reporter: reviewer
- Owner: docs
- Problem: run.go (~40-45) describes the header-cap abort error text without
  acknowledging the exact-equality classification.
- Fix: refresh the comment.
- Verification: comment matches code.

### NEW-3 (INFO) — Set-Cookie retained verbatim in boundedHeaders (internal/httpprobe)
- Status: DEFERRED
- Reporter: reviewer
- Owner: (none)
- Problem: boundedHeaders retains Set-Cookie verbatim; session cookies could
  be stored in probe records. Pre-existing behavior, outside the audit
  scope — documented here only, per AGENTS.md §5.
- Fix (if ever scoped): redact Set-Cookie values like Location userinfo;
  requires a scoped milestone decision first.
- Verification: n/a while deferred.

## Operational warnings (all agents)

- **Never run `go test ./...` while internal/discovery's tests hang**
  (deterministic hang in the foreign in-flight work). Run package-scoped
  tests only until resolved.
- Tests must stay hermetic (loopback servers, fake transports, temp dirs —
  no public internet).
- Stdlib only; go.mod must not gain dependencies. No real secrets in tests
  (synthetic values only).
- External tools are adapters behind interfaces; core pipelines never branch
  on tool names.

## Recently closed — v1.0 audit changeset (committed)

All 14 audit findings closed; senior review APPROVE with 12/14 fully closed
and failing-on-pre-fix regressions. M-1 and M-2 are code-verified (reviewer
traced the sentinel wiring and the domain key plumbing) but their
audit-mandated regression tests are missing — tracked above as
"M-1 (tests)" / "M-2 (tests)". Summary:

- H-1 credential echo — sanitizeLocation covers both raw-echo branches;
  terminal-response Location also redacted in observe.go.
- H-2 outcome-vocabulary amendment — AGENTS.md §0 item 6, verified against
  the techintel/urlintel sticky flag chains end-to-end.
- M-1 classification — tlsHandshakeError sentinel at DialTLSContext, typed
  TLS set incl. tls.RecordHeaderError, exact-equality header-cap abort,
  no text fallback.
- M-2 cache key — declared domain in probeKey; narrow records unreachable
  by broader-scope runs.
- M-3 urlintel userinfo — redacted at the single ingest construction point.
- M-4 secrentel diagnostics — redactedCandidateID at all four rejection sites.
- M-5 jsintel content binding — AnalyzedHash cross-validated; stale never
  served; silent self-heal.
- M-6 jsintel redirects — non-http(s) targets observed-not-followed.
- M-7 detect fingerprints — full field coverage + provenance, SchemaVersion 2,
  old records self-invalidate.
- M-8 techintel NaN — rejected at load and decode, neutralized in
  deriveConfidence.
- M-9 techintel digest — fingerprint-DB content digest in cache keys,
  computed once per run.
- L-10 report — zero-byte render parts rejected + self-heal.
- L-11 report — mdEscape doubles backslashes before pipes.
- L-20 version 1.0.0 + UA bump; L-21 CI pinned to go.mod; README/
  ARCHITECTURE/AGENTS synced.
