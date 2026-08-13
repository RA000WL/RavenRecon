package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SchemaVersion is the version of the cache record structure and key
// derivation. Bump it when the Record layout or the key payload semantics
// change: a bump makes every previously written key unreachable through
// NewKey, and records carrying an older version are reported as
// schema-incompatible instead of being interpreted with the new structure.
const SchemaVersion = 1

// ToolInfo identifies an external tool whose identity (name and version)
// materially changes the meaning of an operation's results. Leave it empty
// for operations that do not depend on an external tool.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// keyConfigPair is one configuration entry inside the canonical key payload.
// Configuration is hashed as sorted pairs so the key is independent of map
// iteration order.
type keyConfigPair struct {
	K string `json:"k"`
	V string `json:"v"`
}

// keyPayload is the canonical, deterministic form of a cache key. The field
// names, their ordering, and the encoding rules are frozen by SchemaVersion;
// changing them requires a schema bump.
type keyPayload struct {
	Schema int `json:"schema"`

	// Op is the stable namespaced capability name, e.g. "dns.resolve".
	Op string `json:"op"`

	// Target is the canonical normalized asset identity, e.g.
	// "host:example.com".
	Target string `json:"target"`

	// Config is the result-relevant configuration as sorted pairs. emit only
	// values that materially change the meaning of the operation's result.
	Config []keyConfigPair `json:"config,omitempty"`

	// Tool is present only when the operation's results depend on a specific
	// external tool and version.
	Tool *ToolInfo `json:"tool,omitempty"`
}

// KeyParts are the semantic inputs that determine a cache key. Two logically
// equivalent inputs must produce identical parts and therefore the same key;
// meaningfully different inputs must produce different keys.
//
// The Target must be the canonical Phase 2 asset identity string: the output
// of asset normalization, e.g.
// asset.Identity{Kind: asset.KindHost, Value: "example.com"}.String() which
// is "host:example.com". Cache keys never wrap raw, unnormalized user input;
// normalization is the asset layer's job and happens before KeyParts is
// built.
type KeyParts struct {
	// Operation is a stable, namespaced capability name ("passive-discovery",
	// "dns.resolve", "http.probe", ...). Leading/trailing whitespace is
	// ignored; otherwise the value is hashed exactly as given.
	Operation string

	// Target is the canonical asset identity (see the type documentation).
	Target string

	// Config holds the option values that materially change the meaning of
	// the operation's result. Only values that change results belong here:
	// timings, rate limits, and other non-semantic settings must not be
	// included. Keys are hashed sorted, so nil and an empty map produce the
	// same key.
	Config map[string]string

	// Tool is included only when the operation's results depend on which
	// external tool (and version) produced them.
	Tool ToolInfo
}

// NewKey derives the deterministic cache key for parts.
//
// The computed key is a 64-character lowercase hex SHA-256 digest. It is
// collision-resistant, contains no input-derived bytes, and is therefore safe
// to embed in filesystem paths: no user-controlled string ever reaches a
// path.
//
// The cache indexes by key only and cannot verify that the Record later
// stored under the key carries matching identity fields; store the record
// with the same trimmed Operation and Target values used here (see Put).
func NewKey(parts KeyParts) (Key, error) {
	op := strings.TrimSpace(parts.Operation)
	if op == "" {
		return "", fmt.Errorf("cache key: operation must not be empty")
	}
	target := strings.TrimSpace(parts.Target)
	if target == "" {
		return "", fmt.Errorf("cache key: target must not be empty")
	}

	payload := keyPayload{
		Schema: SchemaVersion,
		Op:     op,
		Target: target,
	}
	if len(parts.Config) > 0 {
		payload.Config = make([]keyConfigPair, 0, len(parts.Config))
		for k, v := range parts.Config {
			payload.Config = append(payload.Config, keyConfigPair{K: k, V: v})
		}
		sort.Slice(payload.Config, func(i, j int) bool {
			return payload.Config[i].K < payload.Config[j].K
		})
	}
	if parts.Tool.Name != "" || parts.Tool.Version != "" {
		tool := parts.Tool
		payload.Tool = &tool
	}

	buf, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("cache key: marshal key payload: %w", err)
	}
	sum := sha256.Sum256(buf)
	return Key(hex.EncodeToString(sum[:])), nil
}

// Key is an opaque, deterministic cache key: the lowercase hex SHA-256 digest
// of the canonical key payload. Keys contain no input-derived bytes and are
// safe for use as filesystem path components.
type Key string
