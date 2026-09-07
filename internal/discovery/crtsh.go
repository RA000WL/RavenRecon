package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

const (
	// crtshEndpoint is the crt.sh Certificate Transparency search endpoint.
	// The query value "%.<domain>" is the crt.sh wildcard idiom: the literal
	// % matches any left-hand label set, so one request returns every
	// certificate logged for the domain and its subdomains.
	crtshEndpoint = "https://crt.sh/"

	// crtshMaxBody caps the crt.sh response body held in memory. A response
	// larger than this is truncated and the result carries Truncated, so a
	// huge certificate corpus can never balloon the run past its memory
	// budget. The cap vocabulary (completed/partial/failed/cancelled /
	// Truncated flag) matches the runner-backed sources.
	crtshMaxBody = 1 << 20 // 1 MiB

	// crtshClientTimeout bounds the whole crt.sh HTTP exchange (connect,
	// redirects, body read) for the production client. The request also
	// carries the caller's context, so pipeline cancellation and stage
	// deadlines apply on top; the client is never unbounded.
	crtshClientTimeout = 30 * time.Second

	// crtshVersion is the synthetic stable cache identity for this adapter.
	// crt.sh exposes no version (it is a live remote dataset, not a binary),
	// so Detect binds this constant: the pipeline's cache gate keys on a
	// non-empty version (pipeline.go runSource), which keeps crt.sh's
	// rate-limited public API from being re-queried on every cached run.
	// The string versions the adapter's query+parse contract, not upstream:
	// bump it when the endpoint, query shape, consumed fields, or filtering
	// change. Upstream CT-data drift inside the cache TTL is accepted
	// staleness (the cache is opt-in and disabled by default).
	crtshVersion = "crtsh-json-v1"
)

// httpDoer is the minimal HTTP exchange seam: *http.Client satisfies it, and
// tests inject a fake returning canned crt.sh JSON. Only Do is needed —
// redirects, pooling, and TLS stay inside net/http.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// crtshClientNew builds the bounded production HTTP client. It is a
// package-level variable solely as a hermetic test seam (mirroring
// encodeResult): production always uses the 30s-timeout client, and the
// pipeline-level opt-in test overrides it with a fake transport so no test
// ever touches live crt.sh.
var crtshClientNew = func() httpDoer {
	return &http.Client{Timeout: crtshClientTimeout}
}

// crtsh is the crt.sh Certificate Transparency adapter (opt-in network
// source, no executable).
//
// Discovery is a single bounded request:
//
//	GET https://crt.sh/?q=%25.<domain>&output=json   (Accept: application/json)
//
// crt.sh returns a JSON array of {"name_value":"..."} objects where each
// name_value may itself hold several newline-separated names (one
// certificate covering many SANs) and may carry a "*." wildcard prefix
// (matched case-insensitively — crt.sh mirrors back mixed-case names).
// Every candidate is stripped ("*."), trimmed, reconstructed into a line
// set, and normalized only through parseHostLines — so the NEW-130
// dot-guard (bare words are malformed, never subdomains) and the
// asset.NewHost single-normalization path behave exactly as for the
// runner-backed sources — then filtered to names in-domain of the target.
//
// There is no binary to detect: Detect reports the source usable
// (Exists:true, StatusOK) with a Reason noting it is a network source whose
// reachability is proven at Discover time — mirroring how chaos reports
// Exists:true once keyed — and binds crtshVersion as the cache identity
// (see the crtshVersion rationale above).
type crtsh struct {
	env    toolEnv
	client httpDoer // nil means the bounded production client
}

// Name implements Source.
func (c crtsh) Name() string { return "crtsh" }

// httpClient returns the injected fake, or the bounded production client
// built by crtshClientNew (overridable only by same-package tests).
func (c crtsh) httpClient() httpDoer {
	if c.client != nil {
		return c.client
	}
	return crtshClientNew()
}

// Detect implements Source. No executable exists for a network source, so
// detection is a static usable report: the operator opted in via --sources,
// and reachability is proven when Discover runs.
func (c crtsh) Detect(ctx context.Context) Detection {
	_ = ctx // no I/O: usability is static, reachability is proven at Discover
	e := c.env.sanitized()
	name := e.name
	if name == "" {
		name = c.Name()
	}
	return Detection{
		Source:  name,
		Status:  StatusOK,
		Reason:  "network source (crt.sh certificate transparency); no executable required, reachability proven at Discover time",
		Exists:  true,
		Capable: true,
		Version: crtshVersion,
	}
}

// Discover implements Source.
func (c crtsh) Discover(ctx context.Context, target asset.Domain) (DiscoverResult, error) {
	e := c.env.sanitized()
	if e.name == "" {
		e.name = c.Name()
	}
	u := crtshEndpoint + "?q=" + url.QueryEscape("%."+target.Name) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("%s: build request: %w", c.Name(), err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("%s: GET crt.sh: %w", c.Name(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return DiscoverResult{}, fmt.Errorf("%s: crt.sh returned status %s", c.Name(), resp.Status)
	}
	body, truncated, rerr := readCapped(resp.Body, crtshMaxBody)
	hosts, malformed, perr := parseCrtshJSON(body, target.Name, e.provenance())
	dres := DiscoverResult{Hosts: hosts, Malformed: malformed, Truncated: truncated}
	if rerr != nil {
		return dres, fmt.Errorf("%s: read response: %w", c.Name(), rerr)
	}
	if perr != nil {
		return dres, fmt.Errorf("%s: %w", c.Name(), perr)
	}
	return dres, nil
}

// readCapped reads r up to cap bytes, reporting whether the stream held
// more. The returned slice never exceeds cap.
func readCapped(r io.Reader, cap int) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r, int64(cap)+1))
	if err != nil {
		// Keep the honest prefix: callers parse what arrived and report
		// both the hosts and the error, mirroring runAndParse.
		if len(body) > cap {
			body = body[:cap]
			return body, true, err
		}
		return body, false, err
	}
	if len(body) > cap {
		return body[:cap], true, nil
	}
	return body, false, nil
}

// crtshEntry is the one crt.sh field consumed: the certificate's names,
// possibly several newline-separated (SAN list) and possibly wildcarded.
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// parseCrtshJSON converts a crt.sh JSON body — untrusted input — into
// normalized Phase 2 hosts in-domain of domain.
//
// The body must be an array (strict array-only: crt.sh always returns one,
// and a lone object is rejected rather than special-cased, so there is a
// single decode path to reason about). Decoding streams the array so a body
// that breaks mid-way — mid-array or mid-object (truncation, cut
// connection) — still yields the parsed prefix alongside an error — never
// silently empty, never silently complete. Candidate names are split on
// newlines, trimmed, wildcard-stripped, and normalized only through
// parseHostLines (NEW-130 dot-guard included); survivors outside the target
// domain are dropped and counted as malformed — they normalized, but are
// not usable for this target, and a separate out-of-scope counter would add
// vocabulary for no diagnostic gain.
func parseCrtshJSON(body []byte, domain string, prov asset.Provenance) ([]asset.Host, int, error) {
	t := bytes.TrimSpace(body)
	if len(t) == 0 {
		return nil, 0, fmt.Errorf("crtsh: empty response body")
	}
	var entries []crtshEntry
	var perr error
	complete := true
	dec := json.NewDecoder(bytes.NewReader(t))
	tok, err := dec.Token()
	if err != nil {
		return nil, 0, fmt.Errorf("crtsh: decode response: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, 0, fmt.Errorf("crtsh: unexpected response shape")
	}
	for dec.More() {
		var en crtshEntry
		if err := dec.Decode(&en); err != nil {
			complete = false
			perr = err
			break
		}
		entries = append(entries, en)
	}
	if complete {
		// A clean prefix of a cut body must not pass as complete:
		// the closing bracket has to be there.
		if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
			complete = false
			if perr == nil {
				if err != nil {
					perr = err
				} else {
					perr = fmt.Errorf("unexpected end of JSON array")
				}
			}
		}
	}
	var sb strings.Builder
	for _, en := range entries {
		for _, part := range strings.Split(en.NameValue, "\n") {
			p := strings.TrimSpace(part)
			// Wildcard match is case-insensitive (crt.sh mirrors back
			// mixed-case names such as "*.Example.COM"); the "*. " prefix
			// is ASCII, so slicing 2 bytes off the original is safe.
			if len(p) > 2 && strings.HasPrefix(strings.ToLower(p), "*.") {
				p = p[2:]
			}
			p = strings.TrimSpace(p)
			if p == "" {
				continue // empty SAN slot: blank, not malformed
			}
			sb.WriteString(p)
			sb.WriteByte('\n')
		}
	}
	hosts, malformed := parseHostLines([]byte(sb.String()), prov)
	kept := hosts[:0]
	for _, h := range hosts {
		// Single-check rule: domain-scope membership lives only in
		// asset.InDomain (see internal/asset/scope.go) — no private copy.
		if asset.InDomain(h.Name, domain) {
			kept = append(kept, h)
			continue
		}
		malformed++ // normalized, but outside this target: not usable here
	}
	hosts = kept
	if !complete {
		return hosts, malformed, fmt.Errorf("crtsh: decode response: %w", perr)
	}
	return hosts, malformed, nil
}
