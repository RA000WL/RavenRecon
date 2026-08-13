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

The following describes the target architecture. Not all components exist in v0.1.

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

Future domain objects may include:

* Program
* Domain
* Host
* IP
* Service
* Port
* URL
* Endpoint
* JavaScript
* Technology
* Secret
* Finding

Relationships should be explicit.

Example:

```text
Domain
  |
  +--> Host
         |
         +--> Service
                |
                +--> URL
                       |
                       +--> JavaScript
```

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

## v0.1 boundary

v0.1 contains only:

* CLI foundation
* configuration defaults
* version metadata
* basic tests

Do not implement discovery engines during v0.1.
