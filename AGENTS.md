# RavenRecon Agent Instructions

## Mission

RavenRecon is a reliability-first reconnaissance framework for authorized bug bounty and security testing.

It should help researchers discover, correlate, prioritize, and report attack surface without becoming an exploitation or credential-attack framework.

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
