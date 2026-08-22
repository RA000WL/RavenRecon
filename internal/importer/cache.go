package importer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// CacheKeyParts describes the deterministic inputs that must enter a cache key
// for an import. The importer package does not import internal/cache (layering
// §0.4), so it exposes these parts and the caller composes cache.NewKey
// externally (see importer/cache_test.go for the hermetic hit test).
//
// Operation is always "ingest.import". Target is "import:<hex-sha256-content>".
// Config contains schema, importer_version, and max_output. Tool is the importer
// Name/Version pair.
type CacheKeyParts struct {
	Operation   string
	Target      string
	Config      map[string]string
	ToolName    string
	ToolVersion string
}

// ContentHash computes the lowercase hex SHA-256 of the file at path via
// streaming (bounded memory, 32 KiB buffer). It never loads the whole file.
func ContentHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 32*1024)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CacheKeyForFile builds the CacheKeyParts for path and importer. It streams
// the file for the content hash (bounded), so a 1 GiB file does not spike
// memory. Config's schema and importer_version are frozen by SchemaVersion and
// the importer's Version().
func CacheKeyForFile(path string, imp Importer, bounds Bounds) (CacheKeyParts, error) {
	hash, err := ContentHash(path)
	if err != nil {
		return CacheKeyParts{}, fmt.Errorf("import cache key %s: hash: %w", imp.Name(), err)
	}
	cfg := map[string]string{
		"schema":                 fmt.Sprintf("%d", SchemaVersion),
		"importer_version":       imp.Version(),
		"max_output":             fmt.Sprintf("%d", bounds.effectiveMaxOutput()),
		"max_line_bytes":         fmt.Sprintf("%d", bounds.effectiveMaxLine()),
		"max_decompressed_bytes": fmt.Sprintf("%d", bounds.effectiveMaxDecompressed()),
	}
	return CacheKeyParts{
		Operation:   "ingest.import",
		Target:      "import:" + hash,
		Config:      cfg,
		ToolName:    imp.Name(),
		ToolVersion: imp.Version(),
	}, nil
}

// ImportCacheData is the structured Data stored under an ingest.import record.
// It carries normalized identities + stats, never raw bytes (MaxRecordSize
// guard). Stored as JSON via json.Marshal in the caller (see cache_test).
type ImportCacheData struct {
	SchemaVersion int         `json:"schema_version"`
	Importer      string      `json:"importer"`
	Target        string      `json:"target"`
	Identities    []string    `json:"identities"`
	Stats         ImportStats `json:"stats"`
}
