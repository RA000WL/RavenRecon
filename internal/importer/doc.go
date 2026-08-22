// Package importer implements RavenRecon's Universal Asset Ingestion Framework
// (ROADMAP v1.8, Phase 1).
//
// Importers are adapters behind one interface (Importer: Name/Version/CanImport/Import).
// Every imported record becomes a canonical Phase 2 asset through the single
// normalization point (asset.NewDomain/NewHost/ParseURL/NewIP/NewJavaScript —
// no second normalizer). Import is passive evidence only, never re-executed.
//
// Design rules locked for Phase 1:
//
//   - Format detection waterfall: signature (<?xml/json.Valid/gzip magic) →
//     structure probe (json.Decoder/xml.Decoder on peek) → MIME + extension
//     tie-break → line-shape classifier for plain-text family. Peek = first
//     32 KiB via io.LimitReader, buffered once, then Seek(0,0). Registry
//     returns ordered matches by confidence desc, Name asc; generic fallback
//     last.
//   - Streaming: incremental line parsing with bounded memory — bufio.Reader
//     (8 KiB buffer) and ReadSlice with an effectiveMaxLine()+1 cap; oversized
//     lines are counted as failed+truncated and drained in bounded 8 KiB chunks
//     with per-chunk ctx checks. Gzip is transparent via openStream; total
//     decompressed bytes are capped at effectiveMaxDecompressed() (default
//     100 MiB, see MaxDecompressedBytes) and abort with Truncated=true when
//     exceeded, preventing gzip bombs from OOM. Progress via event.Observer
//     every 64 KiB or 10k records.
//   - Cache: per-file key via content sha256 + config (max_output,
//     max_line_bytes, max_decompressed_bytes) + schema + importer version
//     (helpers in cache.go expose the parts for cache.NewKey without
//     importing internal/cache inside this package, preserving layering §0.4).
//
// This package imports only stdlib, internal/asset, and internal/event
// (never internal/cache, internal/runtime, internal/pipeline, internal/report).
package importer
