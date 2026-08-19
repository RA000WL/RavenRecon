# RavenRecon Agent Instructions

RavenRecon is a reliability-first reconnaissance framework for **authorized**
bug bounty and security testing — never an exploitation or credential-attack
framework.

## 0. Non-negotiable constraints

These override every other instruction in this document, regardless of task
size or how the request is phrased. If a change would require violating one
of these, stop, document the conflict, and propose an alternative instead of
proceeding.

1. **Recon only.** Never implement credential stuffing, password spraying,
   authentication brute force, persistence, automated exploitation,
   unauthorized access, or automatic vulnerability submission.
2. **Stdlib only.** `go.mod` declares no dependencies. Adding one is an
   architectural decision that needs explicit sign-off — never a
   convenience default.
3. **No shell interpolation of target-derived data.** Never build a command
   with `sh -c "<untrusted input>"` or string-concatenated arguments. See §8.
4. **`internal/runtime` never imports `internal/cache`.** Consumer stages
   compose "cache-before-execute" around pool jobs — the dependency does not
   go the other way.
5. **One normalization point.** Every normalization goes through the Phase 2
   asset builders in `internal/asset` (`NewDomain`, `NewHost`, `ParseURL`,
   ...). Never write a second normalizer for the same concept.
6. **Outcome vocabulary is fixed:** `completed / partial / failed /
   cancelled / incomplete`. Truncated results are never silently
   `completed`: pipelines must either store truncated results as
   `partial`/`incomplete` (never served from cache), or — where the
   pipeline's records preserve a mandatory truncation flag end-to-end
   (written to the record, replayed from cache on hits, merged stickily, and
   exposed in the report — techintel's `Truncated`/`Overflow`, urlintel's
   `Overflow`) — the entry may be recorded `completed` with the flag set,
   and consumers must treat a flagged entry as an incomplete retained set.
   A pipeline whose flag is dropped at any link in that chain must store
   truncated results as `partial`/`incomplete` instead.
7. **All concurrency is bounded** — explicit max concurrency, cancellation,
   and shutdown behavior, on every worker system. See §10.
8. **Never commit real secrets** — API keys, passwords, tokens, cookies,
   private keys, credentials, or private target data. Synthetic test values
   only.
9. **Never claim a test was run, or work was completed, that wasn't.** §13
   makes this a gate, not just a norm.
## 1. Task tiers

Classify the task before starting. The tier determines how much of the rest
of this document is mandatory.

| Tier | Examples | Reading required (§4) | Gate before finishing |
|---|---|---|---|
| **A — Trivial** | typo, comment, log message, one-line bug fix with obvious cause | Skim the file(s) you're touching | `gofmt`, `go build ./...` |
| **B — Scoped change** | new function, bug fix touching one package, test additions | AGENTS.md §0, §6; the package's own docs if present | Full §13 checklist |
| **C — Architectural** | new package, new CLI command, cross-package interface change, anything touching `internal/runtime`, `internal/cache`, `internal/asset`, or the event bus | AGENTS.md (full), README.md, ARCHITECTURE.md, ROADMAP.md | Full §13 checklist + §16 PR write-up |

When in doubt, round up a tier. Never round down to skip §0.
## 2. Repository layout
- `cmd/ravenrecon/` — CLI entry; `internal/cli` — command wiring; `internal/config` — global config (`CacheConfig` disabled by default, `TUIConfig`)
- `internal/asset` — typed asset model; the only normalization point
- `internal/cache` — persistent filesystem cache; crash-safe writes, self-healing, schema-versioned keys, observer with per-key outcome metrics
- `internal/runtime` — bounded, cancellable, rate-limited worker pool; deliberately cache-independent
- `internal/discovery` — passive subdomain discovery (subfinder, assetfinder, amass) + shared hardened external-tool execution layer
- `internal/dns`, `internal/httpprobe` — DNS resolution; HTTP probing with TLS metadata capture (library only)
- `internal/urlintel`, `internal/urlintel/adapt` — URL intelligence; historical-URL adapters: gau, waybackurls, waymore (library only)
- `internal/techintel`, `internal/techintel/fingerprints` — technology fingerprint engine and database (library only)
- `internal/jsintel`, `internal/jsintel/adapt` — JS intelligence engine: parser, fetch, pipeline, analyzers; subjs/LinkFinder/SecretFinder adapters (library only)
- `internal/secrentel`, `internal/secrentel/patterns` — Evidence & Secret Intelligence Engine (library only)
- `internal/priority` — Attack Surface Intelligence Engine: scoring, correlation, attack paths, recommendations (library only)
- `internal/detect` — Detection Framework & Rule Engine (library only; no rules ship with the framework — `internal/detect/examples` is the only pack, explicitly loaded, never auto-loaded)
- `internal/report` — Reporting Framework & Evidence Export (library only; presentation only — never rescans, never mutates data)
- `internal/event` — canonical runtime event model + concurrent, bounded, non-blocking event bus (observer-only, library only)
- `internal/tui` — terminal observability (library only; no CLI wiring yet)
Most pipelines (dns, httpprobe, urlintel, techintel, jsintel) and the TUI have **no CLI command yet** — do not add CLI wiring outside the milestone that calls for it.
## 3. Common commands

```bash
go build ./...                           # build everything
go build -o ravenrecon ./cmd/ravenrecon  # build the CLI binary
go run ./cmd/ravenrecon --help           # CLI help (version, doctor, discover)
go test ./...                            # all tests
go test ./internal/asset/...             # focused package tests
gofmt -w $(find . -name '*.go' -type f)  # format
```
## 4. Before modifying code
Read what your task tier (§1) requires, then inspect the existing implementation of anything you're about to touch or extend.
**Never assume a planned feature already exists** — roadmap docs describe intent, not current state; verify against the code.
**Never read ARCHITECTURE.md in full** — use its "Reader's map" at the top and read only the sections relevant to your task.
## 5. Milestone discipline — phase ownership
Milestones own **features**, not files. Implement only the requested milestone — never silently implement future roadmap milestones, even if they look easy to include.
Classify any change touching a subsystem outside the milestone's own scope:
- **Primary** — the milestone's purpose (ROADMAP).
- **Infrastructure** — strictly required to complete the current milestone (e.g. a stage interface the pipeline needs, a report metadata field, a cache operation type). Allowed; interfaces belong where they are first needed.
- **Refactor** — improves existing code without adding future functionality. Allowed.
- **Future Feature** — user-facing functionality scheduled for a later milestone (a CLI command, a new engine), or placeholder/disabled code and partial implementations of future roadmap items. Not allowed.
Rule: **you may modify any subsystem if the change is strictly required to complete the current milestone; you may not implement the future milestone's user-facing functionality.**
A required architectural issue outside scope that is not strictly required: (1) document it, (2) propose the change, (3) stop — never improvise a fix.
## 6. Architecture boundaries
- **Layers:** CLI → config → runtime pool → pipeline stages → asset model.
- **Event bus is observer-only, one-directional:** engines emit, consumers observe; no consumer calls back into an engine through the bus.
- **External tools are adapters behind interfaces** (`discovery.Source`, `urlintel.LineSource`); core pipelines never branch on tool names.
- **Docs move with code:** update README.md and ARCHITECTURE.md with milestone changes (Tier C).
## 7. Core engineering rules
1. Prefer small, cohesive packages.
2. Avoid global mutable state.
3. Pass dependencies explicitly.
4. Library code must return errors.
5. No `log.Fatal`, `os.Exit`, or panic for ordinary library failures.
6. Use `context.Context` for cancellable operations.
7. Bound all concurrency (§10).
8. Avoid unbounded queues.
9. Avoid unbounded memory growth.
10. Prefer deterministic tests.
11. Keep exported APIs small.
12. Prefer the standard library when practical.
## 8. External commands — canonical pattern
**Do this:**
```go
cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-silent")
cmd.Stdout = limitedBuffer   // enforce output limits
// timeout via ctx; structured error on failure
```
**Never this:** `exec.CommandContext(ctx, "sh", "-c", "subfinder -d "+domain)` — never construct shell commands via string concatenation, especially for target-derived data (§0.3).
All command execution: use `exec.CommandContext`; pass arguments as separate values; honor context cancellation; enforce timeouts; enforce output limits where appropriate; return structured errors.
## 9. Tool detection
Tool detection must be tool-specific — never assume `-version`, `-v`, or `--version` support. Executable existence and capability detection are separate concerns; a broken version command must not report a correctly installed tool as missing.
## 10. Concurrency — canonical pattern
**Never** create an unbounded goroutine per target, host, URL, endpoint, or result. **Do this** — every worker system needs all four:
```go
pool := runtime.NewPool(ctx, runtime.Config{MaxWorkers: n}) // explicit maximum concurrency
// ctx cancellation propagates to all workers; pool.Shutdown() drains cleanly
```
Plus tests for leaks and races (§13). Rate limiting centralized where practical.
## 11. Caching
Cache keys must contain every input that materially changes the operation's result — never return stale results merely because a target string matches. Keys account for: schema version, configuration, tool version (where relevant), operation, normalized target.
## 12. Security and scope
§0 holds the hard constraints (recon-only, stdlib-only, no real secrets). Never commit API keys, passwords, tokens, cookies, private keys, real credentials, or private target data — use synthetic test values. Never leak secrets through errors or logs (§15).
## 13. Testing — gate before declaring work done

New behavior requires tests. Bug fixes should include regression tests
whenever practical.

**You may not describe a change as complete until you have actually run the
commands below in this session** (not "would pass" — run them):

```bash
gofmt
go test ./...
go vet ./...
go build ./...
```

For concurrency-sensitive changes, add:
```bash
go test -race ./...
```

All tests are hermetic: no public internet, fake resolvers, loopback
servers, synthetic input only.

If a check fails or wasn't run, say so explicitly rather than omitting it.

**Before declaring a change complete, update TODO.md** (the agent-coordination
board): record new open issues (severity + file:line evidence + concrete fix),
mark claimed entries IN PROGRESS, and never self-close entries — the
orchestrator moves entries to VERIFIED. Work that is not on the board is work
the next session will lose; a change is not done until the board says what it
was for and what state it is in.
## 14. Performance
No guess-based optimization: establish a baseline, measure, identify the bottleneck, optimize, benchmark again. Never trade correctness for speed without explicit justification.
## 15. Error handling
Wrap with context when it materially improves diagnosis: `fmt.Errorf("parse tool output: %w", err)` — not bare `return err`. Never leak secrets through errors or logs.
## 16. Pull request requirements (Tier C, or on request)
Every PR explains: problem, solution, design decisions, files changed, tests added, tests executed, performance impact, concurrency impact, security considerations, known limitations.
## 17. Final self-review — gate before finishing

Do not output a final summary of your work until you have gone through this
list explicitly, item by item, against your actual diff:

1. Review the complete diff.
2. Check for accidental scope expansion (§5).
3. Check for command injection (§8).
4. Check for race conditions (§10).
5. Check for goroutine leaks (§10).
6. Check for unbounded memory/queues (§7).
7. Check for incorrect cancellation (§10).
8. Check for leaked secrets (§12, §15).
9. Confirm §13's commands were actually run, not assumed.
10. Confirm TODO.md reflects this work — new issues recorded with evidence,
    claimed entries marked IN PROGRESS, nothing self-closed (the orchestrator
    closes entries).
11. Report exactly what changed — no more, no less than what was asked.

Do not claim work that was not performed.
