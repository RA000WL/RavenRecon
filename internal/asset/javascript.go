package asset

import (
	"fmt"
	"strings"
	"time"
)

// Bounds applied by the JavaScript observation setters.
const (
	// maxJavaScriptContentHashChars is the exact length of a canonical
	// content hash: the lowercase hex SHA-256 of the script body. Empty
	// means "not observed".
	maxJavaScriptContentHashChars = 64
	// maxJavaScriptContentTypeBytes bounds an observed Content-Type value.
	maxJavaScriptContentTypeBytes = 128
	// maxJavaScriptETagBytes bounds an observed ETag value.
	maxJavaScriptETagBytes = 256
	// maxJavaScriptDiscoverySourceBytes bounds an observed discovery-source
	// label (the capability that surfaced the script observation).
	maxJavaScriptDiscoverySourceBytes = 128
	// minJavaScriptStatusCode and maxJavaScriptStatusCode bound an observed
	// HTTP status code (the 1xx..5xx range); zero means "not observed".
	minJavaScriptStatusCode = 100
	maxJavaScriptStatusCode = 599
)

// JavaScript is a script resource observed at a URL.
//
// The identity is the canonical URL — KindJavaScript + URL.String() — and
// every other field is an OBSERVATION of that resource, never part of the
// identity: a changed or dropped observation never changes the asset. The
// URL asset's own Original field carries the raw form as first observed.
type JavaScript struct {
	// URL is the canonical URL of the script resource.
	URL URL `json:"url"`

	// Hash is an optional content hash, kept for later content-level
	// deduplication. It is not part of the identity.
	Hash string `json:"hash,omitempty"`

	// Host is the host the script resource was observed on, as a canonical
	// Host asset. The zero Host (no name) means "not observed".
	Host Host `json:"host"`

	// ContentHash is the lowercase hex SHA-256 of the script body — exactly
	// maxJavaScriptContentHashChars characters when observed. Empty means
	// "not observed". Not part of the identity.
	ContentHash string `json:"content_hash,omitempty"`

	// Size is the observed script body size in bytes; zero means "not
	// observed".
	Size int64 `json:"size,omitempty"`

	// ContentType is the observed Content-Type header value of the script
	// response, bounded printable ASCII. Empty means "not observed".
	ContentType string `json:"content_type,omitempty"`

	// ETag is the observed ETag header value of the script response, bounded
	// printable ASCII. Empty means "not observed".
	ETag string `json:"etag,omitempty"`

	// LastModified is the observed Last-Modified header time of the script
	// response. The zero time means "not observed".
	LastModified time.Time `json:"last_modified,omitempty"`

	// DiscoverySource is a generic label for the capability that surfaced
	// this script observation (e.g. "html-scan"), bounded printable ASCII.
	// Empty means "not observed".
	DiscoverySource string `json:"discovery_source,omitempty"`

	// StatusCode is the observed HTTP status code of the script response,
	// 100..599 when observed; zero means "not observed".
	StatusCode int `json:"status_code,omitempty"`

	// FinalURL is the canonical URL the script response was actually served
	// from after redirects. The zero URL means "no redirect observed" — the
	// resource was served from URL itself.
	FinalURL URL `json:"final_url"`

	// Prov records where and when this observation came from.
	Prov Provenance `json:"provenance,omitempty"`
}

// NewJavaScript parses rawURL into a JavaScript asset.
func NewJavaScript(rawURL string, p Provenance) (JavaScript, error) {
	u, err := ParseURL(rawURL, p)
	if err != nil {
		return JavaScript{}, fmt.Errorf("invalid javascript URL: %w", err)
	}
	return JavaScript{URL: u, Prov: p}, nil
}

// Identity returns the deterministic identity used for deduplication.
//
// The identity is exactly the canonical URL of the script resource
// (KindJavaScript + URL.String()); the URL asset's own Original field carries
// the raw form. Observations never enter the identity.
func (j JavaScript) Identity() Identity {
	return Identity{Kind: KindJavaScript, Value: j.URL.String()}
}

// Chunk identity (NEW-129 Slice 1): one deterministic overlapped window of a
// truncated script prefix.
//
// Format (exact, single normalization point — all chunk-string parsing lives
// here; parsing the same strings anywhere else is forbidden):
//
//	javascript:<file-url>#rr-chunk=i/n/span=start-end/ph=<8hex>/t=<tag>
//
// where <file-url> is the canonical file URL string (URL.String(), which
// never carries a fragment — file identities never contain '#', verified by
// TestNewJavaScriptIdentity), i/n are the window index/count, span=start-end
// are byte offsets in the retained prefix, ph is the first 8 lowercase hex
// digits of the window's SHA-256, and t is the tiling tag supplied by the
// producer (jsintel's fetchTilingTag, e.g. "w512-o8-v1") carried opaquely.
//
// ChunkJavaScriptIdentity is the ONLY constructor of chunk identities and
// ParseChunkIdentity the ONLY parser: every other package must build and
// read chunk identities through these two functions, never by formatting or
// splitting the strings itself.
func ChunkJavaScriptIdentity(file URL, index, total int, start, end int64, chunkPrefixHash, tilingTag string) (Identity, error) {
	if file.IsZero() {
		return Identity{}, fmt.Errorf("chunk identity: file URL must not be zero")
	}
	if file.Fragment != "" {
		return Identity{}, fmt.Errorf("chunk identity: file URL must not carry a fragment")
	}
	fileStr := file.String()
	if fileStr == "" {
		return Identity{}, fmt.Errorf("chunk identity: file URL string must not be empty")
	}
	if strings.Contains(fileStr, "#") {
		return Identity{}, fmt.Errorf("chunk identity: file URL %q must not contain '#'", fileStr)
	}
	if total <= 0 || total > 1024 {
		return Identity{}, fmt.Errorf("chunk identity: total %d out of range [1,1024]", total)
	}
	if index < 0 || index >= total {
		return Identity{}, fmt.Errorf("chunk identity: index %d out of range [0,%d)", index, total)
	}
	if start < 0 || end <= start {
		return Identity{}, fmt.Errorf("chunk identity: span %d-%d is not a positive range", start, end)
	}
	if end > 8<<20 {
		return Identity{}, fmt.Errorf("chunk identity: span end %d exceeds 8 MiB", end)
	}
	if end-start > 1<<20 {
		return Identity{}, fmt.Errorf("chunk identity: span length %d exceeds 1 MiB", end-start)
	}
	if len(chunkPrefixHash) != 8 {
		return Identity{}, fmt.Errorf("chunk identity: prefix hash must be 8 hex digits, got %q", chunkPrefixHash)
	}
	for i := 0; i < 8; i++ {
		c := chunkPrefixHash[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return Identity{}, fmt.Errorf("chunk identity: prefix hash %q is not lowercase hex", chunkPrefixHash)
		}
	}
	if err := validateChunkTilingTag(tilingTag); err != nil {
		return Identity{}, err
	}
	value := fileStr + "#rr-chunk=" + itoa(index) + "/" + itoa(total) + "/span=" + itoa64(start) + "-" + itoa64(end) + "/ph=" + chunkPrefixHash + "/t=" + tilingTag
	return Identity{Kind: KindJavaScript, Value: value}, nil
}

// validateChunkTilingTag checks the opaque tiling-tag shape w<N>-o<M>-v<K>
// (e.g. "w512-o8-v1"): 'w' + decimal KiB window, "-o" + decimal KiB overlap,
// "-v" + decimal version. The producer owns the exact value; this layer only
// enforces the shape so malformed tags never enter an identity.
func validateChunkTilingTag(tag string) error {
	if tag == "" || len(tag) > 32 {
		return fmt.Errorf("chunk identity: tiling tag %q out of range", tag)
	}
	// Expected shape: w<digits>-o<digits>-v<digits>.
	i := 0
	if i >= len(tag) || tag[i] != 'w' {
		return fmt.Errorf("chunk identity: tiling tag %q must start with 'w'", tag)
	}
	i++
	s := i
	for i < len(tag) && tag[i] >= '0' && tag[i] <= '9' {
		i++
	}
	if i == s {
		return fmt.Errorf("chunk identity: tiling tag %q lacks window digits", tag)
	}
	if i+1 >= len(tag) || tag[i] != '-' || tag[i+1] != 'o' {
		return fmt.Errorf("chunk identity: tiling tag %q must carry '-o'", tag)
	}
	i += 2
	s = i
	for i < len(tag) && tag[i] >= '0' && tag[i] <= '9' {
		i++
	}
	if i == s {
		return fmt.Errorf("chunk identity: tiling tag %q lacks overlap digits", tag)
	}
	if i+1 >= len(tag) || tag[i] != '-' || tag[i+1] != 'v' {
		return fmt.Errorf("chunk identity: tiling tag %q must carry '-v'", tag)
	}
	i += 2
	s = i
	for i < len(tag) && tag[i] >= '0' && tag[i] <= '9' {
		i++
	}
	if i == s || i != len(tag) {
		return fmt.Errorf("chunk identity: tiling tag %q must end with version digits", tag)
	}
	return nil
}

// ParseChunkIdentity parses a chunk identity built by ChunkJavaScriptIdentity
// and returns the file URL plus the window parameters. It is the ONLY legal
// reader of chunk strings: callers must never split or match on the
// "#rr-chunk=" marker themselves.
//
// The file part must re-parse canonically through ParseURL (the same
// re-parse check normalizeSnapshot applies to snapshot scripts): the stored
// file string must equal its own canonical form and carry no fragment, so a
// chunk always cites a canonical file.
func ParseChunkIdentity(id Identity) (file URL, index, total int, start, end int64, chunkPrefixHash, tilingTag string, err error) {
	if id.Kind != KindJavaScript {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: kind %q is not javascript", id.Kind)
	}
	fileStr, rest, ok := strings.Cut(id.Value, "#rr-chunk=")
	if !ok {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: missing '#rr-chunk=' marker")
	}
	if fileStr == "" || strings.Contains(fileStr, "#") {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: file part is not a fragment-free URL")
	}
	re, rerr := ParseURL(fileStr, Provenance{})
	if rerr != nil {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: file part does not parse: %w", rerr)
	}
	if re.String() != fileStr {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: file part %q is not canonical (normalizes to %q)", fileStr, re.String())
	}
	if re.Fragment != "" {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: file part must not carry a fragment")
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 5 {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: chunk part must have 5 '/'-separated fields, got %d", len(parts))
	}
	index, err = atoiBounded(parts[0], "index", 0, 1023)
	if err != nil {
		return URL{}, 0, 0, 0, 0, "", "", err
	}
	total, err = atoiBounded(parts[1], "total", 1, 1024)
	if err != nil {
		return URL{}, 0, 0, 0, 0, "", "", err
	}
	if index >= total {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: index %d out of range [0,%d)", index, total)
	}
	span, ok := strings.CutPrefix(parts[2], "span=")
	if !ok {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: chunk part %q must start with 'span='", parts[2])
	}
	s0, s1, ok := strings.Cut(span, "-")
	if !ok {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: span %q must be start-end", span)
	}
	start, err = atoi64Bounded(s0, "span start", 0, 8<<20)
	if err != nil {
		return URL{}, 0, 0, 0, 0, "", "", err
	}
	end, err = atoi64Bounded(s1, "span end", 0, 8<<20)
	if err != nil {
		return URL{}, 0, 0, 0, 0, "", "", err
	}
	if end <= start || end-start > 1<<20 {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: span %d-%d is not a positive range within 1 MiB", start, end)
	}
	ph, ok := strings.CutPrefix(parts[3], "ph=")
	if !ok || len(ph) != 8 {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: ph field must be 'ph=<8hex>'")
	}
	for i := 0; i < 8; i++ {
		c := ph[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: prefix hash %q is not lowercase hex", ph)
		}
	}
	tag, ok := strings.CutPrefix(parts[4], "t=")
	if !ok {
		return URL{}, 0, 0, 0, 0, "", "", fmt.Errorf("chunk identity: tag field must start with 't='")
	}
	if verr := validateChunkTilingTag(tag); verr != nil {
		return URL{}, 0, 0, 0, 0, "", "", verr
	}
	return re, index, total, start, end, ph, tag, nil
}

// atoiBounded parses a decimal integer with an exact digit shape and range.
func atoiBounded(s, field string, min, max int) (int, error) {
	if s == "" || len(s) > 10 {
		return 0, fmt.Errorf("chunk identity: %s %q is not a decimal integer", field, s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("chunk identity: %s %q is not a decimal integer", field, s)
		}
	}
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
		if n > max {
			return 0, fmt.Errorf("chunk identity: %s %d exceeds %d", field, n, max)
		}
	}
	if n < min {
		return 0, fmt.Errorf("chunk identity: %s %d below %d", field, n, min)
	}
	return n, nil
}

// atoi64Bounded parses a decimal int64 with range.
func atoi64Bounded(s, field string, min, max int64) (int64, error) {
	if s == "" || len(s) > 10 {
		return 0, fmt.Errorf("chunk identity: %s %q is not a decimal integer", field, s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("chunk identity: %s %q is not a decimal integer", field, s)
		}
	}
	var n int64
	for i := 0; i < len(s); i++ {
		n = n*10 + int64(s[i]-'0')
		if n > max {
			return 0, fmt.Errorf("chunk identity: %s %d exceeds %d", field, n, max)
		}
	}
	if n < min {
		return 0, fmt.Errorf("chunk identity: %s %d below %d", field, n, min)
	}
	return n, nil
}

// itoa formats a small non-negative int without importing strconv (stdlib
// only, single normalization point stays in this package).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// itoa64 formats a non-negative int64.
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ID returns the canonical identity string.
func (j JavaScript) ID() string { return j.Identity().String() }

// WithHost returns a copy of j carrying the host the script was observed on.
// It never mutates j. The name is normalized through NewHost, so the stored
// Host is always canonical. An empty (or blank) name clears the observation
// to the zero Host ("not observed").
func WithHost(j JavaScript, name string) (JavaScript, error) {
	if strings.TrimSpace(name) == "" {
		out := j
		out.Host = Host{}
		return out, nil
	}
	h, err := NewHost(name, Provenance{})
	if err != nil {
		return JavaScript{}, fmt.Errorf("set javascript host: %w", err)
	}
	out := j
	out.Host = h
	return out, nil
}

// WithContentHash returns a copy of j carrying the observed content hash of
// the script body. It never mutates j.
//
// A set value must be in canonical form — exactly
// maxJavaScriptContentHashChars lowercase hex characters (the SHA-256 digest
// of the body); uppercase or otherwise non-canonical input is rejected, never
// coerced, so identity-adjacent inputs are never silently rewritten. Empty
// means "not observed" and is always accepted.
func WithContentHash(j JavaScript, hash string) (JavaScript, error) {
	if err := validateJavaScriptContentHash(hash); err != nil {
		return JavaScript{}, fmt.Errorf("set javascript content hash: %w", err)
	}
	out := j
	out.ContentHash = hash
	return out, nil
}

// validateJavaScriptContentHash enforces the canonical content-hash form:
// empty (unobserved) or exactly maxJavaScriptContentHashChars lowercase hex
// characters. Uppercase hex is rejected (the canonical form boundary), never
// lowercased.
func validateJavaScriptContentHash(hash string) error {
	if hash == "" {
		return nil
	}
	if len(hash) != maxJavaScriptContentHashChars {
		return fmt.Errorf("content hash must be exactly %d lowercase hex characters, got %d", maxJavaScriptContentHashChars, len(hash))
	}
	for i := 0; i < len(hash); i++ {
		c := hash[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("content hash must contain only lowercase hex characters [0-9a-f], got %q at index %d", c, i)
		}
	}
	return nil
}

// WithSize returns a copy of j carrying the observed script body size in
// bytes. It never mutates j. Size must be non-negative; zero means "not
// observed".
func WithSize(j JavaScript, size int64) (JavaScript, error) {
	if size < 0 {
		return JavaScript{}, fmt.Errorf("set javascript size: size %d must not be negative", size)
	}
	out := j
	out.Size = size
	return out, nil
}

// WithContentType returns a copy of j carrying the observed Content-Type
// header value of the script response. It never mutates j. The value must be
// at most maxJavaScriptContentTypeBytes bytes of printable ASCII; empty means
// "not observed".
func WithContentType(j JavaScript, contentType string) (JavaScript, error) {
	if err := validateJavaScriptString("content type", contentType, maxJavaScriptContentTypeBytes); err != nil {
		return JavaScript{}, fmt.Errorf("set javascript content type: %w", err)
	}
	out := j
	out.ContentType = contentType
	return out, nil
}

// WithETag returns a copy of j carrying the observed ETag header value of the
// script response. It never mutates j. The value must be at most
// maxJavaScriptETagBytes bytes of printable ASCII; empty means "not
// observed".
func WithETag(j JavaScript, etag string) (JavaScript, error) {
	if err := validateJavaScriptString("etag", etag, maxJavaScriptETagBytes); err != nil {
		return JavaScript{}, fmt.Errorf("set javascript etag: %w", err)
	}
	out := j
	out.ETag = etag
	return out, nil
}

// WithLastModified returns a copy of j carrying the observed Last-Modified
// header time of the script response. It never mutates j. Any time is
// accepted; the zero time means "not observed".
func WithLastModified(j JavaScript, lastModified time.Time) (JavaScript, error) {
	out := j
	out.LastModified = lastModified
	return out, nil
}

// WithDiscoverySource returns a copy of j carrying the generic label of the
// capability that surfaced this script observation. It never mutates j. The
// label must be at most maxJavaScriptDiscoverySourceBytes bytes of printable
// ASCII; empty means "not observed".
func WithDiscoverySource(j JavaScript, source string) (JavaScript, error) {
	if err := validateJavaScriptString("discovery source", source, maxJavaScriptDiscoverySourceBytes); err != nil {
		return JavaScript{}, fmt.Errorf("set javascript discovery source: %w", err)
	}
	out := j
	out.DiscoverySource = source
	return out, nil
}

// WithStatusCode returns a copy of j carrying the observed HTTP status code
// of the script response. It never mutates j. A set value must lie in
// minJavaScriptStatusCode..maxJavaScriptStatusCode (the 1xx..5xx range); zero
// means "not observed".
func WithStatusCode(j JavaScript, status int) (JavaScript, error) {
	if status != 0 && (status < minJavaScriptStatusCode || status > maxJavaScriptStatusCode) {
		return JavaScript{}, fmt.Errorf("set javascript status code: %d is outside %d..%d", status, minJavaScriptStatusCode, maxJavaScriptStatusCode)
	}
	out := j
	out.StatusCode = status
	return out, nil
}

// WithFinalURL returns a copy of j carrying the canonical URL the script
// response was served from after redirects. It never mutates j.
//
// The value is canonicalized through ParseURL and must re-parse canonically
// to its own identity — the stored FinalURL is always a canonical URL asset,
// never a raw redirect string. An empty (or blank) value clears the
// observation to the zero URL ("no redirect observed").
func WithFinalURL(j JavaScript, rawURL string) (JavaScript, error) {
	if strings.TrimSpace(rawURL) == "" {
		out := j
		out.FinalURL = URL{}
		return out, nil
	}
	u, err := ParseURL(rawURL, Provenance{})
	if err != nil {
		return JavaScript{}, fmt.Errorf("set javascript final url: %w", err)
	}
	re, err := ParseURL(u.String(), Provenance{})
	if err != nil {
		return JavaScript{}, fmt.Errorf("set javascript final url: %w", err)
	}
	if !re.Identity().Equal(u.Identity()) {
		return JavaScript{}, fmt.Errorf("set javascript final url: %q does not re-parse canonically to its own identity", u.String())
	}
	out := j
	out.FinalURL = u
	return out, nil
}

// validateJavaScriptString enforces the shared bounds for bounded observed
// string fields: at most max bytes of printable ASCII. Empty values are
// allowed: they mean "not observed", and the merge treats them as unset.
func validateJavaScriptString(field, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("javascript %s is %d bytes, longer than the %d maximum", field, len(s), max)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return fmt.Errorf("javascript %s %q contains a non-printable character", field, s)
		}
	}
	return nil
}
