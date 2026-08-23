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
//     structure probe (json.Decoder/xml.Decoder on peek) → archive content
//     probes (WARC version marker / CDX line shape, gzip peeks inflated
//     in-memory ≤32 KiB) → MIME + extension tie-break → line-shape
//     classifier for plain-text family. Peek = first
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
//	plain ×7     NewPlainDomainsImporter, NewPlainSubdomainsImporter,
//	             NewPlainURLsImporter, NewPlainAliveImporter,
//	             NewPlainJSImporter, NewPlainIPsImporter, NewPlainCIDRsImporter
//	json ×5      NewJSONHttpxImporter, NewJSONDnsxImporter,
//	             NewJSONNaabuImporter, NewJSONKatanaImporter,
//	             NewJSONNucleiImporter
//	xml ×2       NewXMLBurpImporter (sitemap + issues shapes),
//	             NewXMLZapImporter
//	archive ×2   NewArchiveCDXImporter (wayback CDX lines, .cdx/.cdx.gz),
//	             NewArchiveWARCImporter (WARC 0.x/1.x records, .warc/.warc.gz)
//	fallbacks    NewJSONGenericImporter then NewPlainGenericImporter —
//	             always LAST (registry sorts confidence desc, Name asc
//	             within a tier)
//
// Do not wire a subset: Detect's generic-last fallback only behaves as tested
// when this exact 16-specific-importer set (+2 generic fallbacks = 18 total)
// is registered.
//
// ROADMAP v1.8 row "Crawl-output importers: katana, hakrawler, gospider,
// waymore, gau" — disposition (verified against each tool's documented output
// formats; no redundant importers were added for one-URL-per-line output):
//
//   - katana text/stdout and -output files are bare crawled URLs, one per
//     line → ingested by the plain URL family (content-shape detection claims
//     them). katana -jsonl is claimed by json-katana in both shapes: flat
//     {"url":...,"method":...} objects and modern exports nesting the
//     endpoint under "request"."endpoint" (json-katana reads whichever
//     field carries the URL).
//   - hakrawler stdout is bare URLs → plain family. hakrawler -json emits
//     flat {"url":...} NDJSON objects → classified through the existing JSON
//     url-key shape and ingested as URLs by the JSON family.
//   - gospider quiet mode (-q, "only show URL") and its per-category output
//     files are bare URL lists → plain family. Decorated console lines
//     ([robots]/[js] prefixes) fall through honestly as unparseable.
//   - waymore URL mode (-mode U) writes deduplicated bare links
//     (waymore.txt / -oU file), plain text without headers/footers → plain
//     family, in both uncompressed and gzipped form: plainConfidence inflates
//     a gzipped peek once (bounded, ≤PeekSize) and classifies the inner
//     lines, so a waymore.txt.gz link list is detected by content while the
//     streaming path stays gzip-transparent (openStream/readLines). Corrupt
//     gzip declines honestly; inflated JSON/XML signatures are never claimed
//     by the plain family.
//   - gau prints bare URLs to stdout/--o file → plain family; gau --json
//     emits flat url-key objects → JSON family.
//   - Archive sources: archive-cdx and archive-warc above cover local
//     wayback CDX exports and WARC files. Remote Common Crawl index
//     ingestion is explicitly OUT OF SCOPE for this milestone — local files
//     only; no network fetches happen in this package.
//
// This package imports only stdlib, internal/asset, and internal/event
// (never internal/cache, internal/runtime, internal/pipeline, internal/report).
package importer
