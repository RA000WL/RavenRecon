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
// Registration checklist — every importer below must be registered together
// at the future ingest composition point (registration is caller-side; there
// is deliberately no production compose point before that milestone, see
// TestXMLRegistryDeterminism / newFullRegistry for the canonical set):
//
//	plain ×7   NewPlainDomainsImporter, NewPlainSubdomainsImporter,
//	           NewPlainURLsImporter, NewPlainAliveImporter, NewPlainJSImporter,
//	           NewPlainIPsImporter, NewPlainCIDRsImporter
//	json ×5    NewJSONHttpxImporter, NewJSONDnsxImporter, NewJSONNaabuImporter,
//	           NewJSONKatanaImporter, NewJSONNucleiImporter
//	xml ×2     NewXMLBurpImporter (sitemap + issues shapes), NewXMLZapImporter
//	fallbacks  NewJSONGenericImporter then NewPlainGenericImporter — always LAST
//	           (registry sorts confidence desc, Name asc within a tier)
//
// Do not wire a subset: Detect's generic-last fallback only behaves as tested
// when this exact 14-specific-importer set (+2 generic fallbacks = 16 total)
// is registered.
//
// This package imports only stdlib, internal/asset, and internal/event
// (never internal/cache, internal/runtime, internal/pipeline, internal/report).
package importer
