# Committed benchmark baselines (v1.7 batch D — TODO.md NEW-56, decision D4)

One file per baselined package: `<pkg>.txt`, the verbatim stdout of ONE
recording session of:

    go test -run '^$' -bench=. -benchmem -count=10 ./internal/<pkg>/ \
      > testdata/bench/<pkg>.txt

Files are committed unmodified so `cmd/benchgate` parses exactly what
`go test` printed — no post-processing step to drift.

Regenerate a baseline only when hardware changes or a deliberate,
reviewed optimization lands; state the reason and date in the PR.
Compare a fresh run against a baseline with:

    go test -run '^$' -bench=. -benchmem -count=10 ./internal/<pkg>/ \
      > /tmp/opencode/<pkg>-new.txt
    go run ./cmd/benchgate testdata/bench/<pkg>.txt /tmp/opencode/<pkg>-new.txt

The gate fails (exit 1) only when the median B/op or allocs/op exceeds the
baseline median by more than 25%; ns/op is printed advisory-only.
Baselines are machine-dependent by nature (recorded 2026-08-21 on this
workspace's machine); they are regression signals, not absolute numbers.

## Exclusions

- `urlintel.txt` excludes `BenchmarkIngestMillion` (recorded with
  `-bench='Ingest(Cold|Hit)|Normalize|MergeParams'`): at recording time
  it failed its own full-cold-pass assertion (`Stored:981506`, want 1M) —
  a pre-existing urlintel issue unrelated to the baseline work, reported
  separately (see TODO.md NEW-57). Re-include it once fixed;
  note it takes ≈1 min per iteration on this machine even when passing.

## importer (v1.8 T14)

- `importer.txt` covers all five benchmarks with no filter: the full
  `-bench=.` set was stable across three recording sessions on this
  machine (medians of B/op and allocs/op within <0.1% across sessions;
  `cmd/benchgate` passes run↔run in both directions). Recorded
  2026-08-23.
- `BenchmarkIngestCold`/`BenchmarkIngestHit` include real fsync'd cache
  writes/reads/deletes over a filesystem-backed cache, so their ns/op is
  machine-noisy (±~5% here, more on shared CI runners). The gateable
  metrics are allocation-shaped and deterministic for these workloads;
  ns/op stays advisory-only per D4.
