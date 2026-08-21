# RavenRecon Agent Instructions

RavenRecon is a reliability-first reconnaissance framework for **authorized**
bug bounty and security testing — never an exploitation or credential-attack
framework.

This file is loaded into every session automatically — never spend turns
re-reading it or other top-level docs wholesale. Treat it as guardrails, not
procedure: it marks the cliffs (§0), the load-bearing patterns (§7–§11), and
the honesty rules (§13, §17). How you explore, plan, and build is yours.
Where judgment and this document conflict, judgment wins everywhere except
§0 — there, the constraint wins and you escalate instead.

## 0. Non-negotiable constraints

These override everything else, regardless of task size or phrasing. If a
change would violate one: stop, document the conflict, propose an
alternative — never improvise around §0.

1. **Recon only.** Never implement credential stuffing, password spraying,
   authentication brute force, persistence, automated exploitation,
   unauthorized access, or automatic vulnerability submission.
2. **Stdlib only.** `go.mod` declares no dependencies. Adding one is an
   architectural decision needing explicit sign-off — never a convenience
   default.
3. **No shell interpolation of target-derived data.** Never build commands
   with `sh -c "<untrusted input>"` or string-concatenated arguments. See §8.
4. **`internal/runtime` never imports `internal/cache`.** Consumer stages
   compose cache-before-execute around pool jobs; the dependency does not
   point back.
5. **One normalization point.** Every normalization goes through the asset
   builders in `internal/asset` (`NewDomain`, `NewHost`, `ParseURL`, ...).
   Never write a second normalizer for the same concept.
6. **Outcome vocabulary is fixed:** `completed / partial / failed /
   cancelled / incomplete`. Truncated results are never silently
   `completed`: either store them `partial`/`incomplete` (never served from
   cache), or — where the pipeline preserves a mandatory truncation flag
   end-to-end (written to the record, replayed from cache, merged stickily,
   exposed in the report; techintel `Truncated`/`Overflow`, urlintel
   `Overflow`) — record `completed` with the flag set, and consumers treat
   flagged entries as an incomplete retained set. If the flag drops at any
   link in that chain, store `partial`/`incomplete`.
7. **All concurrency is bounded** — explicit max concurrency, cancellation,
   and shutdown behavior, on every worker system. See §10.
8. **Never commit real secrets** — API keys, passwords, tokens, cookies,
   private keys, credentials, private target data. Synthetic test values
   only.
9. **Never claim a test was run, or work was completed, that wasn't.**
   §13 makes this a gate, not a norm.

## 1. Rigor scales with blast radius, not ceremony

Calibrate once, then work — no reading requirements are attached to any
size (this file is already in your context; read code, not process):

- **Trivial** (typo, comment, log line): format + build what you touched.
- **Scoped** (behavior change within one package): full §13 gate.
- **Architectural** (new package, CLI command, cross-package interface, or
  anything touching `internal/runtime`, `internal/cache`,
  `internal/asset`, or the event bus): §13 gate, docs move with code (§6),
  written design rationale when asked.

When unsure, round up. Never round down out of §0.

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
- `internal/tui` — terminal observability (library only; wired into the CLI by `ravenrecon scan --tui`)
- `internal/pipeline`, `internal/pipeline/adapt` — end-to-end pipeline orchestration (runner, stages, params, events) and the adapters that wrap each engine as a stage (library only; wired into the CLI by `ravenrecon scan`)
Most pipelines (dns, httpprobe, urlintel, techintel, jsintel) have **no standalone CLI command yet** — do not add CLI wiring outside the milestone that calls for it. (The pipeline as a whole IS reachable via `ravenrecon scan`, and the TUI IS wired into scan via `--tui`; those engines still have no standalone commands.)

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
Inspect the existing implementation of anything you touch or extend.
Roadmap docs describe intent, not current state — verify against the code;
never assume a planned feature already exists. For architecture context,
use ARCHITECTURE.md's Reader's map and read only the section your task
needs — never the whole file.

## 5. Milestone discipline
Milestones own **features**, not files. Implement the requested milestone —
never silently implement future roadmap milestones, however easy they look.

Touching another subsystem is fine when strictly required to complete the
current milestone (a stage interface the pipeline needs, a cache operation
type, a report metadata field); interfaces belong where first needed.
Refactors that add no future functionality are fine. Placeholder or partial
implementations of future features are not.

An architectural issue you notice but that isn't required here: document
it, propose the change, move on — never fold it into the current work.

## 6. Architecture boundaries
- **Layers:** CLI → config → runtime pool → pipeline stages → asset model.
- **Event bus is observer-only, one-directional:** engines emit, consumers observe; no consumer calls back into an engine through the bus.
- **External tools are adapters behind interfaces** (`discovery.Source`, `urlintel.LineSource`); core pipelines never branch on tool names.
- **Docs move with code:** milestone-level changes update README.md and ARCHITECTURE.md.

## 7. Core engineering rules
1. Prefer small, cohesive packages.
2. Avoid global mutable state.
3. Pass dependencies explicitly.
4. Library code returns errors — no `log.Fatal`, `os.Exit`, or panic for ordinary failures.
5. Use `context.Context` for cancellable operations.
6. Bound all concurrency (§10); avoid unbounded queues and memory growth.
7. Prefer deterministic tests.
8. Keep exported APIs small.
9. Prefer the standard library when practical.

## 8. External commands — canonical pattern
**Do this:**
```go
cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-silent")
cmd.Stdout = limitedBuffer   // enforce output limits
// timeout via ctx; structured error on failure
```
**Never this:** `exec.CommandContext(ctx, "sh", "-c", "subfinder -d "+domain)` — never construct shell commands via string concatenation, especially for target-derived data (§0.3).
All command execution: `exec.CommandContext`; arguments as separate values; context cancellation honored; timeouts enforced; output limits where appropriate; structured errors returned.

## 9. Tool detection
Tool detection must be tool-specific — never assume `-version`, `-v`, or `--version` support. Executable existence and capability detection are separate concerns; a broken version command must not report a correctly installed tool as missing.

## 10. Concurrency — canonical pattern
**Never** create an unbounded goroutine per target, host, URL, endpoint, or result. Every worker system needs all four properties:
```go
pool := runtime.NewPool(ctx, runtime.Config{MaxWorkers: n}) // explicit maximum concurrency
// ctx cancellation propagates to all workers; pool.Shutdown() drains cleanly
```
Plus leak/race coverage (§13). Rate limiting centralized where practical.

## 11. Caching
Cache keys must contain every input that materially changes the operation's result — never return stale results merely because a target string matches. Keys account for: schema version, configuration, tool version (where relevant), operation, normalized target.

## 12. Security and scope
§0.1, §0.2, and §0.8 carry the hard lines. Beyond them: synthetic test data only, and never leak secrets through errors or logs (§15).

## 13. Testing — know, don't assume
New behavior requires tests; bug fixes include regression tests whenever practical. Tests are hermetic: loopback servers, fake resolvers, synthetic input — no public internet.

Before calling work done, run these in this session:

```bash
gofmt
go test ./...
go vet ./...
go build ./...
```

Add `go test -race ./...` for concurrency-sensitive changes. If a check fails — or cannot run (missing toolchain, broken environment) — say so plainly. An honest "not verified" beats a silent assumption.

Keep the board honest: record new open issues in TODO.md (severity + file:line evidence + concrete fix), mark claimed entries IN PROGRESS, and never self-close — the orchestrator moves entries to VERIFIED. Work not on the board is work the next session loses.

## 14. Performance
No guess-based optimization: baseline, measure, fix the bottleneck, measure again. Never trade correctness for speed without explicit justification.

## 15. Error handling
Wrap errors with context when it materially improves diagnosis: `fmt.Errorf("parse tool output: %w", err)` — not bare `return err`. Never leak secrets through errors or logs.

## 16. Change write-ups
On request, or for architectural changes, cover: problem, approach, design decisions, files changed, tests executed (with results), known limitations. Skip ceremony beyond that.

## 17. Before you call it done
A habit, not a ritual — against your actual diff:

- Diff reviewed end to end; scope is exactly what was asked (§5).
- §0 clean: no injection paths (§8), unbounded concurrency (§10), or secret leaks (§12, §15).
- §13 gates actually ran; results reported as they happened.
- TODO.md reflects the work; nothing self-closed.
- Your summary states exactly what changed — no more, no less.

Do not claim work that was not performed.
