package importer

import (
	"context"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// SchemaVersion is the ingestion record schema version. It enters the cache
// key (Config["schema"]) and the cache record's Data, so a bump invalidates
// every previous import.
const SchemaVersion = 1

// MaxLineBytes is the bounded line buffer for plain-text importers (32 KiB).
// A line longer than this is truncated and counted as failed — never loaded
// unbounded.
const MaxLineBytes = 32 * 1024

// MaxOutput is the default retained-set cap per import. When the number of
// distinct assets would exceed it, the import truncates (tail-drop) and
// reports Truncated=true with the sticky flag "import_truncated".
const MaxOutput = 100000

// MaxDecompressedBytes is the default cap for decompressed gzip payloads
// streamed through openStream/readLines. A gzip file whose decompressed
// size exceeds this limit aborts the import with Truncated=true (sticky
// flag "import_truncated") instead of OOM. The value is 100 MiB, chosen to
// accommodate legitimate large plain-text imports (MaxOutput 100k × ~1 KiB
// avg line) while bounding gzip bombs (e.g., 10 KiB → 10 GiB). Override via
// Bounds.MaxDecompressedBytes; the effective value enters the cache key
// (Config["max_decompressed_bytes"]) so a limit change invalidates prior
// cached imports.
const MaxDecompressedBytes = 100 << 20 // 100 MiB

// MaxOriginalRecordBytes bounds the OriginalRecord provenance field (first
// 4 KiB of the raw line).
const MaxOriginalRecordBytes = 4 * 1024

// ProgressBytesInterval and ProgressRecordsInterval bound progress emissions.
const ProgressBytesInterval = 64 * 1024
const ProgressRecordsInterval = 10000

// ImportStats is the honest outcome of one Import invocation.
type ImportStats struct {
	ItemsProcessed int
	ItemsFailed    int
	Truncated      bool
	StickyFlags    map[string]bool
}

// Bounds enforces output bounding per AGENTS §0.7, §10 and C-4.
type Bounds struct {
	// MaxOutput caps distinct assets retained; 0 means Default.
	MaxOutput int
	// MaxLineBytes caps a single line's buffered bytes; 0 means default.
	MaxLineBytes int
	// MaxDecompressedBytes caps decompressed gzip bytes streamed via
	// openStream/readLines; 0 means Default (MaxDecompressedBytes = 100 MiB).
	// Exceeding the cap aborts with Truncated=true instead of OOM.
	MaxDecompressedBytes int
}

func (b Bounds) effectiveMaxOutput() int {
	if b.MaxOutput <= 0 {
		return MaxOutput
	}
	return b.MaxOutput
}

func (b Bounds) effectiveMaxLine() int {
	if b.MaxLineBytes <= 0 {
		return MaxLineBytes
	}
	return b.MaxLineBytes
}

func (b Bounds) effectiveMaxDecompressed() int {
	if b.MaxDecompressedBytes <= 0 {
		return MaxDecompressedBytes
	}
	return b.MaxDecompressedBytes
}

// ImportEnv carries the per-import environment. Every field is optional;
// zero values resolve to deterministic defaults. Clock==nil means time.Now.
// Observer==nil means no progress events (the off switch). ProvenanceBase
// supplies Source/Confidence seed; importer, filename, and time are layered
// on top. Bounds controls caps.
type ImportEnv struct {
	Clock          func() time.Time
	Observer       event.Observer
	ProvenanceBase asset.Provenance
	Bounds         Bounds
}

func (e ImportEnv) now() time.Time {
	if e.Clock != nil {
		return e.Clock().UTC()
	}
	return time.Now().UTC()
}

// Sink is the bounded, deduplicating collection an importer writes into.
// It is not safe for concurrent use — Import is streaming and single-goroutine
// per file, so no synchronization is needed. Every Add* method validates
// through the single normalization point (asset builders) and deduplicates by
// canonical Identity.String(). CIDRs are validated via netip.ParsePrefix and
// deduplicated by canonical prefix string (no asset kind — they are stored as
// strings). JS is stored via asset.NewJavaScript. Findings are stored via
// asset.NewFinding and deduped by Finding.Identity().
//
// The Sink also preserves provenance sidecar data without mutating asset
// Identity — provenance is stored in the asset's Prov field plus the sidecar
// ProvenanceRecord slice.
type Sink struct {
	seen map[string]struct{}

	Domains  []asset.Domain
	Hosts    []asset.Host
	URLs     []asset.URL
	IPs      []asset.IP
	CIDRs    []string
	JS       []asset.JavaScript
	Findings []asset.Finding

	// ProvenanceRecords preserves per-asset provenance sidecar: importer,
	// original tool, filename, import time, original record (first 4 KiB), and
	// confidence. It is parallel to the asset slices (index-aligned via identity).
	ProvenanceRecords []ProvenanceRecord

	// seenCIDR dedup for CIDR strings
	seenCIDR map[string]struct{}

	// stats helpers
	truncated bool
}

// ProvenanceRecord is the first-class provenance preserved per imported asset.
type ProvenanceRecord struct {
	Importer       string
	OriginalTool   string
	Filename       string
	ImportTime     time.Time
	OriginalRecord string
	Confidence     float64
	Metadata       map[string]string
	Identity       string
}

// NewSink returns an empty Sink ready for Add* calls.
func NewSink() *Sink {
	return &Sink{
		seen:     make(map[string]struct{}),
		seenCIDR: make(map[string]struct{}),
	}
}

// Importer is the single generic adapter interface. No importer owns runtime,
// cache, reporting, or asset identities — everything is reused from existing
// frameworks.
type Importer interface {
	// Name returns the stable importer name, e.g. "plain-domains", "plain-urls".
	Name() string
	// Version returns the importer version that enters the cache key.
	Version() string
	// CanImport reports whether this importer claims the file at path with the
	// given peek (first 32 KiB of content). It must not open the file itself
	// beyond the peek slice. Confidence is 0..1; ok==false means "no claim".
	CanImport(path string, peek []byte) (confidence float64, ok bool)
	// Import streams the file at path, validating each record through the
	// single normalization point and writing deduplicated canonical assets into
	// out. It is streaming with bounded memory (32 KiB buffers), checks
	// ctx.Err() per record, emits progress via env.Observer, and respects
	// cancellation (returning partial stats with a cancelled error).
	Import(ctx context.Context, env ImportEnv, path string, out *Sink) (ImportStats, error)
}

// importerBase is a helper for plain importers to build provenance.
type importerBase struct {
	name    string
	version string
	tool    string
}

func (b importerBase) Name() string    { return b.name }
func (b importerBase) Version() string { return b.version }
func (b importerBase) Tool() string    { return b.tool }
