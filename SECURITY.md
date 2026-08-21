# Security Policy

## Intended use

RavenRecon is intended for authorized security research, bug bounty programs, and security assessments where the operator has permission to test the target.

## Reporting vulnerabilities

Security issues in RavenRecon should be reported privately to the project maintainers rather than immediately publishing exploit details.

Contact: security@ravenrecon.local or open a GitHub Security Advisory.

## Security requirements

Contributors must consider:

- command injection
- path traversal
- unsafe temporary files
- secret leakage
- uncontrolled resource consumption
- race conditions
- unsafe deserialization
- malformed external-tool output
- denial-of-service through unbounded input

## Recon safety

RavenRecon should remain reconnaissance-focused.

Do not add functionality for:

- credential stuffing
- password spraying
- authentication brute force
- persistence
- automated exploitation
- unauthorized access
- automatic vulnerability submission

Users are responsible for complying with the authorization and rules governing every target they scan.
