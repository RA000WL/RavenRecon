# Contributing to RavenRecon

## Before changing code

Read:

1. `AGENTS.md`
2. `ARCHITECTURE.md`
3. `ROADMAP.md`

Understand the current milestone before writing code.

## Development

Format Go code:

```bash
gofmt -w $(find . -name '*.go' -type f)
```

Test:

```bash
go test ./...
```

Race detection:

```bash
go test -race ./...
```

Static analysis:

```bash
go vet ./...
```

Build:

```bash
go build ./...
```

## Pull requests

Every PR should explain:

* problem
* solution
* affected packages
* tests added
* tests executed
* performance impact
* concurrency impact
* security implications
* compatibility implications

## Scope

Do not mix unrelated refactoring with feature work.

Keep PRs small enough to review.

## Tests

New functionality requires tests.

Bug fixes should include a regression test whenever practical.

Never claim a test passed unless it was actually executed.

## Dependencies

Prefer the Go standard library.

A dependency should have a clear reason to exist and should be evaluated for:

* maintenance
* licensing
* security
* size
* performance
* API stability
