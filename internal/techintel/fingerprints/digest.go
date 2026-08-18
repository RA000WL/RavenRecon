package fingerprints

import (
	"hash/fnv"
	"math"
	"sort"
	"strconv"
)

// Digest returns a stable hexadecimal content digest of the database's
// complete detection data. It is computed over every fingerprint's name,
// category, and full indicator payload — kind, match, weight, and version
// spec — serialized in canonical order (fingerprints sorted by name, then
// category; indicators in their declared order), so ANY data-only edit to
// any table changes the digest while equivalent loads never do.
//
// The digest is the content-addressing half of the cache-key contract:
// technology detection cache keys MUST include it alongside SchemaVersion,
// so a table edit that never bumps the schema still invalidates every
// cached detection by construction. SchemaVersion remains the LAYOUT
// version; the digest is the content version.
//
// The digest is computed fresh on every call — the database is immutable,
// so callers may call it freely, but the engine computes it exactly once
// per run at environment construction.
func (d *DB) Digest() string {
	return digestEntries(d.fingerprints)
}

// digestEntries hashes a canonical serialization of fingerprint entries.
// The input order does not matter: entries are sorted by name, then
// category, before hashing (fingerprint names are unique across the
// database, so the sort is total). Mirroring the priority catalog digest
// pattern: FNV-1a 64-bit with \x1f (unit separator) between fields and \n
// between entries. The weight is hashed as its exact IEEE-754 bit pattern
// (strconv.FormatUint(math.Float64bits(w), 16)), so no rounding, locale,
// or formatting difference can ever alias two distinct values — including
// NaN, which serializes to its canonical quiet-NaN bit pattern.
func digestEntries(entries []Fingerprint) string {
	sorted := make([]Fingerprint, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Category < sorted[j].Category
	})

	h := fnv.New64a()
	for _, fp := range sorted {
		h.Write([]byte(fp.Name))
		h.Write([]byte{0x1f})
		h.Write([]byte(fp.Category))
		h.Write([]byte{0x1f})
		for _, ind := range fp.Indicators {
			h.Write([]byte(ind.Kind))
			h.Write([]byte{0x1f})
			h.Write([]byte(ind.Match))
			h.Write([]byte{0x1f})
			h.Write([]byte(strconv.FormatUint(math.Float64bits(ind.Weight), 16)))
			h.Write([]byte{0x1f})
			if ind.Version == nil {
				h.Write([]byte{'0'})
			} else {
				h.Write([]byte{'1'})
				h.Write([]byte{0x1f})
				h.Write([]byte(ind.Version.Pattern))
				h.Write([]byte{0x1f})
				h.Write([]byte(strconv.Itoa(ind.Version.Group)))
			}
			h.Write([]byte{0x1f})
		}
		h.Write([]byte{'\n'})
	}
	return strconv.FormatUint(h.Sum64(), 16)
}
