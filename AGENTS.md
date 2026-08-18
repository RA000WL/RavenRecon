# RavenRecon Agent Instructions

RavenRecon is a reliability-first reconnaissance framework for authorized bug
bounty and security testing. It helps researchers discover, correlate,
prioritize, and report attack surface — it is not an exploitation or
credential-attack framework.

---

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

---

## 1. Task tiers

Classify the task before starting. The tier determines how much of the rest
of this document is mandatory.

| Tier | Examples | Reading required (§4) | Gate before finishing |
|---|---|---|---|
| **A — Trivial** | typo, comment, log message, one-line bug fix with obvious cause | Skim the file(s) you're touching | `gofmt`, `go build ./...` |
| **B — Scoped change** | new function, bug fix touching one package, test additions | AGENTS.md §0, §6; the package's own docs if present | Full §13 checklist |
| **C — Architectural** | new package, new CLI command, cross-package interface change, anything touching `internal/runtime`, `internal/cache`, `internal/asset`, or the event bus | AGENTS.md (full), README.md, ARCHITECTURE.md, ROADMAP.md | Full §13 checklist + §16 PR write-up |

When in doubt, round up a tier. Never round down to skip §0.

---

## 2. Repository layout

- `cmd/ravenrecon/` — CLI entry point
- `internal/cli` — command wiring; current commands: `version`, `doctor`, `discover <domain>`
- `internal/config` — global configuration: `CacheConfig` (disabled by default), `TUIConfig`
- `internal/asset` — typed asset model; the only normalization point
- `internal/cache` — persistent filesystem cache; crash-safe writes, self-healing, schema-versioned keys, observer with per-key outcome metrics
- `internal/runtime` — bounded, cancellable, rate-limited worker pool with an optional observer bridge; deliberately cache-independent
- `internal/discovery` — passive subdomain discovery (subfinder, assetfinder, amass) + shared hardened external-tool execution layer
- `internal/dns` — DNS resolution pipeline (library only)
- `internal/httpprobe` — HTTP probing with TLS metadata capture (library only)
- `internal/urlintel`, `internal/urlintel/adapt` — URL intelligence, historical-URL adapters: gau, waybackurls, waymore (library only)
- `internal/techintel`, `internal/techintel/fingerprints` — technology fingerprint engine and database (library only)
- `internal/jsintel`, `internal/jsintel/adapt` — JS intelligence engine: parser, fetch, pipeline, analyzers, subjs/LinkFinder/SecretFinder adapters (library only)
- `internal/secrentel`, `internal/secrentel/patterns` — Evidence & Secret Intelligence Engine (library only)
- `internal/priority` — Attack Surface Intelligence Engine: scoring, correlation, attack paths, recommendations (library only)
- `internal/detect` — Detection Framework & Rule Engine (library only; no rules ship with the framework)
- `internal/report` — Reporting Framework & Evidence Export (library only; presentation only — never rescans, never mutates data)
- `internal/event` — canonical runtime event model + concurrent, bounded, non-blocking event bus (observer-only, library only)
- `internal/tui` — terminal observability (library only; no CLI wiring yet)

Most pipelines (dns, httpprobe, urlintel, techintel, jsintel) and the TUI are
library capabilities with **no CLI command yet** — do not add CLI wiring
outside the milestone that calls for it.

---

## 3. Common commands

```bash
go build ./...                           # build everything
go build -o ravenrecon ./cmd/ravenrecon  # build the CLI binary
go run ./cmd/ravenrecon --help           # CLI help (version, doctor, discover)
go test ./...                            # all tests
go test ./internal/asset/...             # focused package tests
gofmt -w $(find . -name '*.go' -type f)  # format
```

---

## 4. Before modifying code

Read what your task tier (§1) requires, then inspect the existing
implementation of anything you're about to touch or extend.

**Never assume a planned feature already exists.** Roadmap docs describe
intent, not current state — verify against the code.

---

## 5. Milestone discipline

Implement only the requested milestone or task. Do not silently implement
future roadmap milestones, even if they look easy to include.

If a task exposes a required architectural issue outside its scope, follow
this exact procedure — do not improvise a fix:

1. Document the issue (what it is, where, why it blocks or affects the task).
2. Propose the change (what you'd do, what it touches).
3. Stop. Do not implement the proposed change as part of the current task.

---

## 6. Architecture boundaries

- **Layers:** CLI → config → runtime pool → pipeline stages → asset model.
- **Event bus is observer-only and one-directional.** Engines emit,
  consumers observe. No consumer calls back into an engine through the bus.
- **External tools are adapters behind interfaces**
  (`discovery.Source`, `urlintel.LineSource`). Core pipelines never branch
  on tool names.
- **Docs move with code.** `README.md` and `ARCHITECTURE.md` document each
  landed phase in detail — update them together with the code when a
  milestone changes behavior (Tier C).

---

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

---

## 8. External commands — canonical pattern

External tools are adapters, not the architecture.

**Do this:**
```go
cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-silent")
cmd.Stdout = limitedBuffer   // enforce output limits
// timeout via ctx; structured error on failure
```

**Never this:**
```go
// Never construct shell commands through string concatenation,
// and never do this for target-derived data:
exec.CommandContext(ctx, "sh", "-c", "subfinder -d "+domain)
```

All command execution must:
- use `exec.CommandContext`
- pass arguments as separate values
- honor context cancellation
- enforce timeouts
- enforce output limits where appropriate
- return structured errors

---

## 9. Tool detection

Do not assume every external security tool supports `-version`, `-v`, or
`--version` — tool detection must be tool-specific. Executable existence and
capability detection are separate concerns. A broken version command must
not cause a correctly installed tool to be reported as missing.

---

## 10. Concurrency — canonical pattern

**Never** create an unbounded goroutine per target, host, URL, endpoint, or
result.

**Do this** — every worker system needs all four:
```go
pool := runtime.NewPool(ctx, runtime.Config{
    MaxWorkers: n,        // explicit maximum concurrency
})
// ctx cancellation propagates to all workers
// pool.Shutdown() drains cleanly
```
Plus tests for leaks and tests for races (§13). Rate limiting should be
centralized where practical.

---

## 11. Caching

Cache keys must contain every input that materially changes the operation's
result. Never return stale results merely because a target string matches.

Cache implementations must account for: schema version, configuration, tool
version (where relevant), operation, and normalized target.

---

## 12. Security and scope

See §0 for the hard constraints (recon-only, stdlib-only, no real secrets).
This section is the detail behind item 8:

- Never commit API keys, passwords, tokens, cookies, private keys, real
  credentials, or private target data — use synthetic test values.
- Do not leak secrets through errors or logs (§15).

---

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

---

## 14. Performance

Do not optimize based on guesses:

1. establish a baseline
2. measure
3. identify the bottleneck
4. optimize
5. benchmark again

Do not trade correctness for speed without explicit justification.

---

## 15. Error handling

**Do this** — wrap with context when it materially improves diagnosis:
```go
fmt.Errorf("parse tool output: %w", err)
```

**Not this:**
```go
return err
```

Do not leak secrets through errors or logs.

---

## 16. Pull request requirements (Tier C, or on request)

Every PR should explain: problem, solution, design decisions, files
changed, tests added, tests executed, performance impact, concurrency
impact, security considerations, known limitations.

---

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
10. Report exactly what changed — no more, no less than what was asked.

Do not claim work that was not performed.