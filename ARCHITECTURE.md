# RavenRecon Architecture

## Purpose

RavenRecon is designed as a reconnaissance framework rather than a collection of shell commands.

The architecture separates:

- CLI
- configuration
- scheduling
- execution
- rate limiting
- caching
- asset modeling
- tool adapters
- pipeline stages
- output

External tools are adapters.

They are not the architecture.

## Planned architecture

The following describes the target architecture. Not all components exist yet.

```text
CLI
 |
 v
Configuration
 |
 v
Scheduler
 |
 +--> Worker Pool
 |
 +--> Rate Limiter
 |
 +--> Cache
 |
 v
Pipeline
 |
 +--> Discovery
 +--> DNS
 +--> HTTP
 +--> TLS
 +--> Crawling
 +--> JavaScript
 +--> Technology
 +--> Secret Analysis
 |
 v
Asset Graph
 |
 v
Scoring
 |
 v
Reports
```

## Asset model

The asset model (implemented in `internal/asset`) provides normalized types
for reconnaissance data:

* Domain
* Host
* IP
* Port
* Service
* URL
* Endpoint
* JavaScript

Deferred to later phases: Technology, SecretCandidate, Finding.

Every implemented asset has:

* a canonical, normalized representation
* a deterministic, namespaced identity for deduplication
* provenance (source, discovery time, optional reference and confidence)
* deterministic merge primitives that refuse to merge distinct assets
* JSON serialization

Identity values are namespaced by asset kind (`domain:example.com` vs
`host:example.com`), so different asset kinds can never collide.

Relationships are represented by the typed `Relationship` primitive
(Host -> IP, IP -> Port, Port -> Service, Host -> URL, URL -> Endpoint,
URL -> JavaScript). This phase provides the representation only; the graph
store, traversal, and correlation engine are planned for a later phase.

## Pipeline requirements

Major pipeline stages should support:

* cancellation
* bounded concurrency
* timeouts
* rate limiting
* deduplication
* caching
* structured errors
* deterministic behavior where practical
* resumability

## External tools

External tools must be isolated behind adapters.

An adapter should:

1. Validate configuration.
2. Build structured arguments.
3. Execute with context cancellation.
4. Capture output safely.
5. Parse the result.
6. Normalize it into RavenRecon types.
7. Return structured errors.

Never construct shell commands by concatenating untrusted strings.

## Concurrency

RavenRecon must use bounded concurrency.

Do not create an unbounded goroutine for every:

* target
* domain
* host
* URL
* endpoint
* result

Long-running operations must support `context.Context`.

## Rate limiting

Rate limiting must be centralized where practical.

Individual adapters should not independently invent incompatible rate-limit behavior.

The runtime should eventually support:

* global limits
* per-origin limits
* per-tool limits
* concurrency limits
* request delays
* cancellation

## Cache

Cache keys must include every input that materially changes an operation's result.

Future cache metadata should include:

* operation
* normalized target
* relevant options
* tool/version where applicable
* timestamp
* schema version

## Configuration precedence

Future configuration should follow:

```text
CLI flags
   ↓
Environment
   ↓
Config file
   ↓
Defaults
```

## Safety boundary

RavenRecon is reconnaissance-focused.

Do not add:

* credential stuffing
* password spraying
* authentication brute force
* persistence
* automated exploitation
* automatic vulnerability submission

## v0.2 boundary

Implemented:

* CLI foundation
* configuration defaults
* version metadata
* basic tests
* normalized asset model (see "Asset model" above)

Planned, not yet implemented:

* runtime scheduler and worker pool
* discovery engines (DNS, HTTP, TLS, URL, JS)
* cache and resume
* asset store, graph, and correlation engine
* reporting and terminal UI
