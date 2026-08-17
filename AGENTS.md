# RavenRecon Agent Instructions

## Mission

RavenRecon is a reliability-first reconnaissance framework for authorized bug bounty and security testing.

It should help researchers discover, correlate, prioritize, and report attack surface without becoming an exploitation or credential-attack framework.

## Repository layout

- `cmd/ravenrecon/` — CLI entry point
- `internal/cli` — command wiring; current commands: `version`, `doctor`, `discover <domain>`
- `internal/config` — global configuration, including `CacheConfig` (cache disabled by default) and `TUIConfig` (terminal observability)
- `internal/asset` — typed asset model; the only normalization point (`NewDomain`, `NewHost`, `ParseURL`, ...)
- `internal/cache` — persistent filesystem cache; crash-safe writes, self-healing, schema-versioned keys, and an observer with honest per-key outcome metrics
- `internal/runtime` — bounded, cancellable, rate-limited worker pool with an optional observer bridge (lifecycle, progress, and phase events); deliberately cache-independent
- `internal/discovery` — passive subdomain discovery (subfinder, assetfinder, amass) and the shared hardened external-tool execution layer
- `internal/dns` — DNS resolution pipeline (library only)
- `internal/httpprobe` — HTTP probing with TLS metadata capture (library only)
- `internal/urlintel`, `internal/urlintel/adapt` — URL intelligence and historical-URL adapters: gau, waybackurls, waymore (library only)
- `internal/techintel`, `internal/techintel/fingerprints` — technology fingerprint engine and database (library only)
- `internal/jsintel`, `internal/jsintel/adapt` — JavaScript intelligence engine: parser, fetch, pipeline, analyzers, and subjs/LinkFinder/SecretFinder adapters (library only)
- `internal/secrentel`, `internal/secrentel/patterns` — Evidence & Secret Intelligence Engine: document seam, scan/correlation/confidence pipeline, offline verification queue, and the compile-once pattern database (library only)
- `internal/priority` — Attack Surface Intelligence Engine: indicator catalogs, deterministic scoring, correlation, attack paths, recommendations, runtime-pool engine, and cache integration with strict decode re-validation (library only)
- `internal/detect` — Detection Framework & Rule Engine: rule registration and validation, dependency level scheduling, the fixed detection context, canonical findings, the `detect.rule` cache record, execution metrics, and detector benchmarking (library only; no rules ship with the framework)
- `internal/report` — Reporting Framework & Evidence Export: the canonical report model (a normalize-once Context validated, merged, identity-sorted, with statistics, run/error summaries, and a digest), the validated report registry, JSON/CSV/Markdown/HTML exporters, export validation before exposure, atomic crash-safe file writes with deterministic sanitized filenames, and the engine on the shared runtime pool with an optional `report.render` cache record (library only; presentation only — never rescans, never mutates data)
- `internal/event` — the canonical runtime event model and the concurrent, bounded, non-blocking event bus: typed, validated, severity-marked, clock-stamped events with sealed payloads projected from the Phase 2 asset model; observer-only (library only)
- `internal/tui` — terminal observability: full-screen TUI driven purely by the event stream (phases, progress, workers, queue, throughput, resources, interesting items, error groups, run summary) (library only; no CLI wiring yet)

## Common commands

```bash
go build ./...                           # build everything
go build -o ravenrecon ./cmd/ravenrecon  # build the CLI binary
go run ./cmd/ravenrecon --help           # CLI help (version, doctor, discover)
go test ./...                            # all tests
go test ./internal/asset/...             # focused package tests
gofmt -w $(find . -name '*.go' -type f)  # format
```

## Before modifying code

Always read:

1. `AGENTS.md`
2. `README.md`
3. `ARCHITECTURE.md`
4. `ROADMAP.md`

Then inspect the existing implementation.

Never assume a planned feature already exists.

## Milestone discipline

Implement only the requested milestone or task.

Do not silently implement future roadmap milestones.

If a task exposes a required architectural issue outside its scope:

1. document it
2. propose the change
3. do not silently expand the implementation

## Architecture boundaries

- Layers: CLI → config → runtime pool → pipeline stages → asset model.
- The event bus is observer-only and cross-cutting: engines emit, consumers observe; data flows one way, and no consumer can call back into an engine through the bus.
- External tools are adapters behind interfaces (`discovery.Source`, `urlintel.LineSource`); core pipelines never branch on tool names.
- `internal/runtime` never imports `internal/cache`: consumer stages compose "cache-before-execute" around pool jobs.
- Every normalization goes through the Phase 2 asset builders in `internal/asset`; never write a second normalization of the same concept.
- Most pipelines (dns, httpprobe, urlintel, techintel, jsintel) and the TUI (`internal/tui`) are library capabilities with no CLI command yet; do not add CLI wiring outside the milestone that calls for it.
- Outcome vocabulary is fixed: completed / partial / failed / cancelled / incomplete. Truncated results are never `completed` and never served from cache.
- All tests are hermetic: no public Internet, fake resolvers, loopback servers, synthetic input.
- The project is stdlib-only (`go.mod` declares no dependencies); adding an external dependency is an architectural decision, not a convenience.
- `README.md` and `ARCHITECTURE.md` document each landed phase in detail; update them together with the code when a milestone changes behavior.

## Core engineering rules

1. Prefer small, cohesive packages.
2. Avoid global mutable state.
3. Pass dependencies explicitly.
4. Library code must return errors.
5. Do not use `log.Fatal`, `os.Exit`, or panic for ordinary library failures.
6. Use `context.Context` for cancellable operations.
7. Bound all concurrency.
8. Avoid unbounded queues.
9. Avoid unbounded memory growth.
10. Prefer deterministic tests.
11. Keep exported APIs small.
12. Prefer the standard library when practical.

## External commands

External tools are adapters.

They are not the architecture.

All command execution must:

- use `exec.CommandContext`
- pass arguments as separate values
- honor context cancellation
- enforce timeouts
- enforce output limits where appropriate
- return structured errors

Never construct shell commands through string concatenation.

Never use:

```text
sh -c "<untrusted input>"
```

for target-derived data.

## Tool detection

Do not assume every external security tool supports:

```text
-version
-v
--version
```

Tool detection must be tool-specific.

Executable existence and capability detection are separate concerns.

A broken version command must not cause a correctly installed tool to be reported as missing.

## Concurrency

All concurrency must be bounded.

Never create an unbounded goroutine per:

* target
* host
* URL
* endpoint
* result

Every worker system must have:

* explicit maximum concurrency
* cancellation
* shutdown behavior
* tests for leaks
* tests for races

## Rate limiting

Respect configured rate limits.

Do not bypass or silently override:

* global rate limits
* per-target limits
* per-origin limits
* tool-specific limits
* concurrency limits

Rate limiting should be centralized where practical.

## Caching

Cache keys must contain every input that materially changes the operation's result.

Never return stale results merely because a target string matches.

Cache implementations must consider:

* schema version
* configuration
* tool version where relevant
* operation
* normalized target

## Security

Never commit:

* API keys
* passwords
* tokens
* cookies
* private keys
* real credentials
* private target data

Use synthetic test values.

## Recon scope

RavenRecon is reconnaissance-focused.

Do not implement:

* credential stuffing
* password spraying
* authentication brute force
* persistence
* automated exploitation
* unauthorized access
* automatic vulnerability submission

## Testing

New behavior requires tests.

Bug fixes should include regression tests whenever practical.

Before declaring work complete, run the appropriate checks.

At minimum for Go changes:

```bash
gofmt
go test ./...
go vet ./...
go build ./...
```

For concurrency-sensitive changes:

```bash
go test -race ./...
```

Never claim a test was run if it wasn't.

## Performance

Do not optimize based on guesses.

When performance matters:

1. establish a baseline
2. measure
3. identify the bottleneck
4. optimize
5. benchmark again

Do not trade correctness for speed without explicit justification.

## Error handling

Errors should contain useful context.

Prefer:

```go
fmt.Errorf("parse tool output: %w", err)
```

over:

```go
return err
```

when additional context materially improves diagnosis.

Do not leak secrets through errors or logs.

## Pull request requirements

Every PR should explain:

* problem
* solution
* design decisions
* files changed
* tests added
* tests executed
* performance impact
* concurrency impact
* security considerations
* known limitations

## Final self-review

Before finishing:

1. Review the complete diff.
2. Look for accidental scope expansion.
3. Look for command injection.
4. Look for race conditions.
5. Look for goroutine leaks.
6. Look for unbounded memory/queues.
7. Look for incorrect cancellation.
8. Look for leaked secrets.
9. Run tests.
10. Report exactly what changed.

Do not claim work that was not performed.
