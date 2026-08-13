## Summary

Describe the problem and the proposed solution.

## Scope

- [ ] Implements only the requested milestone/task.
- [ ] No unrelated refactoring included.
- [ ] No future roadmap features silently implemented.

## Tests

Commands actually executed:

```text
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

## Review checklist

* [ ] `gofmt` applied
* [ ] Tests added/updated
* [ ] Errors handled appropriately
* [ ] Context cancellation considered
* [ ] Concurrency bounded
* [ ] No goroutine leaks
* [ ] No unsafe shell command construction
* [ ] No secrets committed
* [ ] No unauthorized/exploitation functionality
* [ ] Documentation updated where necessary
* [ ] Performance impact considered
