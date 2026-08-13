# RavenRecon Roadmap

## v0.1 — Foundation

Status: current

- [x] Go module
- [x] CLI
- [x] `--help`
- [x] version command
- [x] doctor command
- [x] configuration foundation
- [x] unit-test baseline
- [x] CI baseline
- [x] agent instructions
- [x] architecture documentation

## v0.2 — Runtime Engine

- [ ] Context-aware scheduler
- [ ] Bounded worker pool
- [ ] Configurable concurrency
- [ ] Central rate limiter
- [ ] Graceful shutdown
- [ ] Progress events
- [ ] Structured errors
- [ ] Cancellation tests
- [ ] Concurrency tests
- [ ] Race tests

## v0.3 — Asset Graph

- [ ] Domain model
- [ ] Host model
- [ ] IP model
- [ ] Service model
- [ ] URL model
- [ ] Relationships
- [ ] Deduplication
- [ ] Serialization

## v0.4 — Cache and Resume

- [ ] Persistent cache
- [ ] Cache schema versioning
- [ ] Resume support
- [ ] Cache invalidation
- [ ] Deterministic cache keys

## v0.5 — Passive Discovery

Initial adapters:

- [ ] subfinder
- [ ] assetfinder
- [ ] amass

Requirements:

- [ ] normalized output
- [ ] timeout
- [ ] cancellation
- [ ] tool detection
- [ ] parser tests
- [ ] integration fixtures

## v0.6 — DNS / HTTP

- [ ] DNS pipeline
- [ ] HTTP probing
- [ ] TLS metadata
- [ ] HTTP metadata normalization
- [ ] technology detection

## v0.7 — URL Intelligence

- [ ] Historical URLs
- [ ] URL normalization
- [ ] parameter extraction
- [ ] deduplication
- [ ] endpoint classification

## v0.8 — JavaScript Intelligence

- [ ] JS discovery
- [ ] JS retrieval
- [ ] endpoint extraction
- [ ] source-map detection
- [ ] secret candidate detection
- [ ] third-party library identification

## v0.9 — Prioritization

- [ ] asset scoring
- [ ] technology-aware prioritization
- [ ] API/admin classification
- [ ] confidence scoring
- [ ] interesting-asset ranking

## v0.10 — Reporting

- [ ] JSON
- [ ] CSV
- [ ] Markdown
- [ ] HTML
- [ ] run summaries
- [ ] error summaries

## v0.11 — Terminal UI

- [ ] live progress
- [ ] worker status
- [ ] throughput
- [ ] ETA
- [ ] errors
- [ ] interesting assets

## v1.0 — Production Foundation

- [ ] comprehensive integration tests
- [ ] race-tested concurrency
- [ ] benchmark suite
- [ ] stable configuration format
- [ ] compatibility policy
- [ ] release automation
- [ ] documentation

## Future

Native implementations may replace external tools where that produces a meaningful improvement in:

- reliability
- performance
- portability
- observability
- control

Do not replace a tool merely for novelty.
