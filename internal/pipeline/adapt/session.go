package adapt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Operator session headers (NEW-125): an opt-in authenticated surface.
// The operator supplies session material out-of-band (a headers file —
// never CLI args, never acquired by the framework: no login, no token
// endpoints, no credential handling of any kind, per §0.1); stages add
// the headers to their own requests and bind a digest (never values)
// into cache keys so authed and anonymous runs never share records.
//
// Residual (accepted, documented): an authed response that echoes the
// bearer (a debug endpoint reflecting Cookie/Authorization, a JS bundle
// embedding the token) is retained verbatim into cache records and
// reports like any other response body — the framework cannot
// distinguish secret bytes from content bytes on the wire. Operators
// should scan with low-privilege test sessions only and rotate (or
// expire) the session after authed runs; values never enter logs,
// errors, or cache keys regardless.
const (
	// maxSessionHeaders bounds header entries per file.
	maxSessionHeaders = 32
	// maxSessionHeaderNameBytes bounds one header name.
	maxSessionHeaderNameBytes = 256
	// maxSessionHeaderValueBytes bounds one header value (cookies
	// included — session cookies are long, but bounded).
	maxSessionHeaderValueBytes = 8 << 10
	// maxSessionHeaderValues bounds the total number of header values
	// across all names (one name may carry many values).
	maxSessionHeaderValues = 64
	// maxSessionHeaderTotalBytes bounds the total session header value
	// bytes across all names (Σ len(values)).
	maxSessionHeaderTotalBytes = 64 << 10
	// maxSessionFileBytes bounds the session file itself.
	maxSessionFileBytes = 64 << 10
)

// forbiddenSessionHeader reports whether the canonical header name must
// never arrive via the session file: Host (the transport would ignore
// it — silent confusion), the framing headers Content-Length /
// Transfer-Encoding / Connection (the transport owns framing — an
// operator value would desync or smuggle requests), and User-Agent (the
// engines set their own fixed identifier; a session override would
// silently impersonate a different client rather than authenticate
// this one).
func forbiddenSessionHeader(canon string) bool {
	switch canon {
	case "Host", "Content-Length", "Transfer-Encoding", "Connection", "User-Agent":
		return true
	}
	return false
}

// ReadSessionFile reads operator session headers from path: "Name:
// value" lines, "#" comments and blank lines skipped, duplicate names
// merged in file order. Names canonicalize via CanonicalMIMEHeaderKey.
// It fails CLOSED on every anomaly — missing/unreadable/oversized
// file, zero headers, malformed lines, empty names or values,
// non-token names, over-long entries, the Host / framing / User-Agent
// headers (see forbiddenSessionHeader), control bytes in values
// (header injection), over-count names, over-count total values, and
// over-budget total value bytes. An enabled-but-unusable session file
// must abort the run, never degrade to an anonymous scan the operator
// did not ask for.
func ReadSessionFile(path string) (http.Header, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// Basename only (mirrors the importer): a full path would leak
		// the operator's directory layout into report error summaries.
		if pe, ok := err.(*fs.PathError); ok {
			err = pe.Err
		}
		return nil, fmt.Errorf("adapt: read session file %s: %v", filepath.Base(path), err)
	}
	if len(raw) > maxSessionFileBytes {
		return nil, fmt.Errorf("adapt: session file is %d bytes over bound %d", len(raw), maxSessionFileBytes)
	}
	out := make(http.Header)
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		name, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return nil, fmt.Errorf("adapt: session file line %d is not Name: value", i+1)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			return nil, fmt.Errorf("adapt: session file line %d has an empty name or value", i+1)
		}
		canon := textproto.CanonicalMIMEHeaderKey(name)
		if !validSessionHeaderName(name) {
			return nil, fmt.Errorf("adapt: session file line %d has an invalid header name", i+1)
		}
		if len(name) > maxSessionHeaderNameBytes {
			return nil, fmt.Errorf("adapt: session file line %d name over bound %d", i+1, maxSessionHeaderNameBytes)
		}
		if forbiddenSessionHeader(canon) {
			if strings.EqualFold(canon, "host") {
				return nil, fmt.Errorf("adapt: session file line %d sets Host (the transport would ignore it)", i+1)
			}
			return nil, fmt.Errorf("adapt: session file line %d sets %s (the transport owns it)", i+1, canon)
		}
		if len(value) > maxSessionHeaderValueBytes {
			return nil, fmt.Errorf("adapt: session file line %d value over bound %d", i+1, maxSessionHeaderValueBytes)
		}
		for j := 0; j < len(value); j++ {
			if value[j] < 0x20 || value[j] > 0x7e {
				return nil, fmt.Errorf("adapt: session file line %d value carries control bytes", i+1)
			}
		}
		out[canon] = append(out[canon], value)
		if len(out) > maxSessionHeaders {
			return nil, fmt.Errorf("adapt: session file carries over bound %d headers", maxSessionHeaders)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("adapt: session file carries no headers")
	}
	totalValues := 0
	totalBytes := 0
	for _, vs := range out {
		totalValues += len(vs)
		for _, v := range vs {
			totalBytes += len(v)
		}
	}
	if totalValues > maxSessionHeaderValues {
		return nil, fmt.Errorf("adapt: session file carries %d values over bound %d", totalValues, maxSessionHeaderValues)
	}
	if totalBytes > maxSessionHeaderTotalBytes {
		return nil, fmt.Errorf("adapt: session file carries %d value bytes over bound %d", totalBytes, maxSessionHeaderTotalBytes)
	}
	return out, nil
}

// validSessionHeaderName reports whether name is an HTTP token:
// letters, digits, and "!#$%&'*+-.^_`|~" — no spaces, colons, or
// controls. CanonicalMIMEHeaderKey passes most garbage through, so the
// token check (not the canonicalization) is the gate.
func validSessionHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

// sessionHeadersParam is the StageParams key carrying the session file
// path (NEW-125). The value is a filesystem path — never secret
// material — so it is safe in dry-run output and help text.
const sessionHeadersParam = "session_headers"

// sessionHeadersFromParams resolves StageParams["session_headers"] into
// validated headers for the httpprobe/jsintel/urllive stages. Absent key
// means anonymous probing (nil, nil). A present key must parse or the
// caller fails the stage: an enabled-but-unusable session file aborts
// the run rather than scanning anonymously when authentication was
// asked for (fail-closed).
//
// Each stage reads the file independently at its own start (no shared
// header state flows between stages), so the file must not change
// mid-run: a stage that starts later re-reads whatever is on disk then,
// and two stages could otherwise authenticate as different sessions
// within one run.
func sessionHeadersFromParams(params map[string]string) (http.Header, error) {
	path, ok := params[sessionHeadersParam]
	if !ok {
		return nil, nil
	}
	h, err := ReadSessionFile(path)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// SessionDigest binds session headers into cache keys WITHOUT carrying
// values: the hex SHA-256 over sorted "name\x00value" lines. Empty
// (nil or zero headers) digests to "" — callers OMIT the key component
// then, so anonymous runs keep byte-identical keys (no cache
// invalidation on upgrade). Key order is normalized (sorted):
// distinct keys in any file order digest identically. Value order
// within one key is significant (duplicate values in different orders
// digest differently — a miss, never stale).
func SessionDigest(h http.Header) string {
	if len(h) == 0 {
		return ""
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sum := sha256.New()
	for _, k := range keys {
		for _, v := range h[k] {
			sum.Write([]byte(k))
			sum.Write([]byte{0})
			sum.Write([]byte(v))
			sum.Write([]byte{0})
		}
	}
	return hex.EncodeToString(sum.Sum(nil))
}
