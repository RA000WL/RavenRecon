// Package patterns is the secret pattern database for the Phase 8 secret
// intelligence engine: structured, data-only fingerprint definitions plus the
// compile-once compiler.
//
// The package is DATA ONLY, mirroring internal/techintel/fingerprints: the
// production tables describe every known secret shape (provider, type, family,
// regex, capture group, validators, entropy rules, length bounds, negative and
// positive indicators, and context hints) and Load validates and compiles
// every regular expression exactly once. The engine NEVER compiles its own
// regexes and consumes the database only through the compile-once accessor.
// Extension is a data-only change: add a table entry and Load validates it;
// duplicate IDs, malformed regexes, and out-of-range fields fail the load.
//
// Bump SchemaVersion when the data model or any table's matching semantics
// change: the version enters every secret-scan cache key, so a bump
// invalidates every cached scan by construction.
package patterns
