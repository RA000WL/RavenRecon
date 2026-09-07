package httpprobe

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
)

// takeoverHandlerTransport is a hermetic RoundTripper for confirmation
// tests: it records requests and answers through a handler, never dialing.
type takeoverHandlerTransport struct {
	mu       sync.Mutex
	requests []string
	handle   func(req *http.Request) (*http.Response, error)
}

func (t *takeoverHandlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requests = append(t.requests, req.URL.String())
	t.mu.Unlock()
	return t.handle(req)
}

func (t *takeoverHandlerTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.requests)
}

func takeoverTestResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{"text/html"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func mustTakeoverHost(t testing.TB, name string) asset.Host {
	t.Helper()
	h, err := asset.NewHost(name, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewHost %q: %v", name, err)
	}
	return h
}

func confirmOne(t testing.TB, ctx context.Context, tr *takeoverHandlerTransport, host string) TakeoverVerdict {
	t.Helper()
	domain := mustDomainProbe(t, "example.com")
	cfg := Config{Concurrency: 2, QueueSize: 4, Transport: tr}
	rep, err := ConfirmTakeoverHosts(ctx, domain, []asset.Host{mustTakeoverHost(t, host)}, cfg)
	if err != nil {
		t.Fatalf("ConfirmTakeoverHosts: %v", err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("records = %d, want 1", len(rep.Results))
	}
	return rep.Results[0]
}

func TestTakeoverProviderTable(t *testing.T) {
	if len(takeoverFingerprints) < 3 {
		t.Fatalf("provider table = %d entries, want >= 3 curated providers", len(takeoverFingerprints))
	}
	seen := make(map[string]bool)
	for _, fp := range takeoverFingerprints {
		if fp.Provider == "" {
			t.Fatal("provider with empty id")
		}
		if seen[fp.Provider] {
			t.Fatalf("duplicate provider %q", fp.Provider)
		}
		seen[fp.Provider] = true
		if len(fp.Substrings) == 0 {
			t.Fatalf("provider %q has no fingerprint strings", fp.Provider)
		}
		for _, s := range fp.Substrings {
			if s == "" {
				t.Fatalf("provider %q has an empty fingerprint string", fp.Provider)
			}
		}
	}
}

func TestConfirmTakeoverGithub(t *testing.T) {
	tr := &takeoverHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return takeoverTestResponse(404, "<html><body><h1>There isn't a GitHub Pages site here.</h1></body></html>"), nil
	}}
	rec := confirmOne(t, context.Background(), tr, "docs.example.com")
	if !rec.Confirmed {
		t.Fatal("confirmed = false, want true (GitHub fingerprint page)")
	}
	if rec.Provider != "github-pages" {
		t.Errorf("provider = %q, want github-pages", rec.Provider)
	}
	if rec.Fingerprint == "" {
		t.Error("fingerprint empty: the matched substring must be cited")
	}
	if rec.Status != 404 {
		t.Errorf("status = %d, want 404 (provider error pages are non-2xx)", rec.Status)
	}
	if rec.Err != nil {
		t.Errorf("err = %v, want nil (a matched page is a completed observation)", rec.Err)
	}
	if tr.count() != 2 {
		t.Errorf("requests = %d, want 2 (both schemes probed, mirrors root probing)", tr.count())
	}
}

func TestConfirmTakeoverNoMatch(t *testing.T) {
	tr := &takeoverHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return takeoverTestResponse(200, "<html><body>legitimate site, no fingerprints</body></html>"), nil
	}}
	rec := confirmOne(t, context.Background(), tr, "www.example.com")
	if rec.Confirmed {
		t.Fatal("confirmed = true on a clean page (false positive)")
	}
	if rec.Provider != "" || rec.Fingerprint != "" {
		t.Errorf("provider/fingerprint = %q/%q, want empty on no-match", rec.Provider, rec.Fingerprint)
	}
	if rec.Err != nil {
		t.Errorf("err = %v, want nil (a fully-read clean page is completed)", rec.Err)
	}
	if rec.Truncated {
		t.Error("truncated = true on a small body")
	}
}

func TestConfirmTakeoverTimeout(t *testing.T) {
	block := make(chan struct{})
	tr := &takeoverHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		select {
		case <-block:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		return takeoverTestResponse(200, "late"), nil
	}}
	cfgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	domain := mustDomainProbe(t, "example.com")
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr, RequestTimeout: 50 * time.Millisecond}
	rep, err := ConfirmTakeoverHosts(cfgCtx, domain, []asset.Host{mustTakeoverHost(t, "slow.example.com")}, cfg)
	if err != nil {
		t.Fatalf("ConfirmTakeoverHosts: %v", err)
	}
	rec := rep.Results[0]
	if rec.Confirmed {
		t.Fatal("confirmed = true on timeout (must never confirm without bytes)")
	}
	if rec.Err == nil {
		t.Error("err = nil, want the timeout cause (no verdict was reachable)")
	}
	close(block)
}

func TestConfirmTakeoverTruncation(t *testing.T) {
	big := strings.Repeat("x", maxTakeoverBodyBytes+1024)
	tr := &takeoverHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return takeoverTestResponse(200, big), nil
	}}
	rec := confirmOne(t, context.Background(), tr, "big.example.com")
	if rec.Confirmed {
		t.Fatal("confirmed = true without an observed fingerprint")
	}
	if !rec.Truncated {
		t.Fatal("truncated = false, want true (over-cap body)")
	}
}

func TestConfirmTakeoverMatchDespiteTruncation(t *testing.T) {
	// Found is found: a fingerprint observed before the cap confirms even
	// though the record carries the honest truncation flag.
	fp := takeoverFingerprints[0].Substrings[0]
	body := "prefix " + fp + " " + strings.Repeat("y", maxTakeoverBodyBytes+1024)
	tr := &takeoverHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return takeoverTestResponse(404, body), nil
	}}
	rec := confirmOne(t, context.Background(), tr, "docs.example.com")
	if !rec.Confirmed {
		t.Fatal("confirmed = false, want true (fingerprint observed before the cap)")
	}
	if !rec.Truncated {
		t.Error("truncated = false, want true (the body still exceeded the cap)")
	}
}

func TestConfirmTakeoverScopeRejects(t *testing.T) {
	tr := &takeoverHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return takeoverTestResponse(200, "x"), nil
	}}
	domain := mustDomainProbe(t, "example.com")
	evil, err := asset.NewHost("evil.com", asset.Provenance{})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	cfg := Config{Concurrency: 1, QueueSize: 4, Transport: tr}
	if _, err := ConfirmTakeoverHosts(context.Background(), domain, []asset.Host{evil}, cfg); err == nil {
		t.Fatal("out-of-scope host accepted, want rejection before any request")
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %d, want 0", tr.count())
	}
}

func TestConfirmTakeoverSortedDeterministic(t *testing.T) {
	tr := &takeoverHandlerTransport{handle: func(req *http.Request) (*http.Response, error) {
		return takeoverTestResponse(200, "clean"), nil
	}}
	domain := mustDomainProbe(t, "example.com")
	cfg := Config{Concurrency: 2, QueueSize: 4, Transport: tr}
	hosts := []asset.Host{mustTakeoverHost(t, "z.example.com"), mustTakeoverHost(t, "a.example.com")}
	rep, err := ConfirmTakeoverHosts(context.Background(), domain, hosts, cfg)
	if err != nil {
		t.Fatalf("ConfirmTakeoverHosts: %v", err)
	}
	if len(rep.Results) != 2 || rep.Results[0].Host.Name != "a.example.com" || rep.Results[1].Host.Name != "z.example.com" {
		t.Fatalf("records not hostname-sorted: %+v", rep.Results)
	}
}

func TestTakeoverEvidenceContract(t *testing.T) {
	src := mustTakeoverHost(t, "docs.example.com").Identity()
	ev, err := TakeoverEvidence(src, "github-pages", "There isn't a GitHub Pages site here.")
	if err != nil {
		t.Fatalf("TakeoverEvidence: %v", err)
	}
	provider, ok := ParseTakeoverEvidence(ev)
	if !ok {
		t.Fatalf("ParseTakeoverEvidence refused its own contract record: %+v", ev)
	}
	if provider != "github-pages" {
		t.Errorf("provider = %q, want github-pages", provider)
	}
	// Unknown provider values never parse (tamper guard).
	bad, err := asset.NewEvidence(asset.MethodHTML, "takeover_page:evil-provider", "x", src, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if _, ok := ParseTakeoverEvidence(bad); ok {
		t.Error("ParseTakeoverEvidence accepted an uncurated provider")
	}
	// Foreign methods never parse (no cross-talk with techintel HTML evidence).
	other, err := asset.NewEvidence(asset.MethodEndpoint, "takeover_page:github-pages", "x", src, asset.Provenance{Source: "test"})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if _, ok := ParseTakeoverEvidence(other); ok {
		t.Error("ParseTakeoverEvidence accepted a non-HTML method record")
	}
}
