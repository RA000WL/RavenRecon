package adapt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// writeSessionFile materializes one session file for tests (0600,
// hermetic temp dir — synthetic credential-shaped values only).
func writeSessionFile(t testing.TB, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session_headers.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestReadSessionFileHappyPath(t *testing.T) {
	path := writeSessionFile(t, "# operator session for authed scan\nCookie: session=synthetic-abc123\nX-Custom-Token: tok-456\n\n")
	h, err := ReadSessionFile(path)
	if err != nil {
		t.Fatalf("ReadSessionFile: %v", err)
	}
	if got := h.Get("Cookie"); got != "session=synthetic-abc123" {
		t.Errorf("Cookie = %q, want the session value", got)
	}
	if got := h.Get("X-Custom-Token"); got != "tok-456" {
		t.Errorf("X-Custom-Token = %q, want tok-456", got)
	}
	if len(h) != 2 {
		t.Errorf("headers = %d entries, want 2 (comments/blanks skipped)", len(h))
	}
	// Canonical key form regardless of input case.
	path2 := writeSessionFile(t, "cookie: session=synthetic-abc123\n")
	h2, err := ReadSessionFile(path2)
	if err != nil {
		t.Fatalf("ReadSessionFile: %v", err)
	}
	if _, ok := h2["Cookie"]; !ok {
		t.Errorf("keys = %v, want canonical Cookie form", h2)
	}
}

func TestReadSessionFileFailClosed(t *testing.T) {
	for name, content := range map[string]string{
		"missing file":     "",
		"empty file":       "",
		"comments only":    "# just a comment\n\n",
		"no colon":         "Cookie session without separator\n",
		"empty name":       ": value\n",
		"empty value":      "X-Token:\n",
		"space in name":    "X Bad: v\n",
		"control in value": "X-Token: a\x01b\n",
		"host header":      "Host: evil.example.com\n",
	} {
		t.Run(name, func(t *testing.T) {
			var path string
			if name == "missing file" {
				path = filepath.Join(t.TempDir(), "does-not-exist.txt")
			} else {
				path = writeSessionFile(t, content)
			}
			if _, err := ReadSessionFile(path); err == nil {
				t.Fatalf("ReadSessionFile accepted %s (want fail-closed error)", name)
			}
		})
	}
}

func TestReadSessionFileBounds(t *testing.T) {
	// Over-count: distinct names past the bound.
	var sb strings.Builder
	for i := 0; i < maxSessionHeaders+1; i++ {
		fmt.Fprintf(&sb, "X-Cap-%04d: v\n", i)
	}
	if _, err := ReadSessionFile(writeSessionFile(t, sb.String())); err == nil {
		t.Fatalf("ReadSessionFile accepted headers over bound %d", maxSessionHeaders)
	}
	// Over-long value.
	if _, err := ReadSessionFile(writeSessionFile(t, "X-Token: "+strings.Repeat("v", maxSessionHeaderValueBytes+1)+"\n")); err == nil {
		t.Fatal("ReadSessionFile accepted an over-long value")
	}
	// Oversized file.
	if _, err := ReadSessionFile(writeSessionFile(t, "X-Token: v\n"+strings.Repeat("# pad\n", maxSessionFileBytes))); err == nil {
		t.Fatal("ReadSessionFile accepted an oversized file")
	}
}

// TestReadSessionFileColonInValue pins the ambiguity resolution: the
// split is on the FIRST colon (HTTP field semantics), so values may
// contain colons ("12:30:00"). A "name:bad: v" line parses as name +
// colon-bearing value — legal per RFC 9110, indistinguishable from two
// headers once split across lines (CRLF files list headers line by
// line by design); wire-level smuggling is the Go transport's
// enforcement (it rejects control bytes), not the parser's.
func TestReadSessionFileColonInValue(t *testing.T) {
	h, err := ReadSessionFile(writeSessionFile(t, "X-Time: 12:30:00\n"))
	if err != nil {
		t.Fatalf("ReadSessionFile: %v", err)
	}
	if got := h.Get("X-Time"); got != "12:30:00" {
		t.Fatalf("X-Time = %q, want the colon-bearing value intact", got)
	}
}

func TestSessionDigest(t *testing.T) {
	a := writeSessionFile(t, "Cookie: session=one\nX-T: v\n")
	b := writeSessionFile(t, "X-T: v\nCookie: session=one\n")
	ha, err := ReadSessionFile(a)
	if err != nil {
		t.Fatalf("ReadSessionFile: %v", err)
	}
	hb, err := ReadSessionFile(b)
	if err != nil {
		t.Fatalf("ReadSessionFile: %v", err)
	}
	da, db := SessionDigest(ha), SessionDigest(hb)
	if da == "" || db == "" {
		t.Fatal("digest empty for non-empty headers")
	}
	if da != db {
		t.Fatal("digest differs for same headers in different file order (must be order-independent)")
	}
	c := writeSessionFile(t, "Cookie: session=two\nX-T: v\n")
	hc, err := ReadSessionFile(c)
	if err != nil {
		t.Fatalf("ReadSessionFile: %v", err)
	}
	if SessionDigest(hc) == da {
		t.Fatal("digest unchanged for different values (cache keys would collide across sessions)")
	}
	if got := SessionDigest(nil); got != "" {
		t.Fatalf("nil digest = %q, want empty (anonymous keys stay byte-identical)", got)
	}
}

// TestSessionHeadersFromParams pins the StageParams contract:
// absent key = anonymous (nil, nil); present key = parsed file;
// present-but-broken key = error (fail-closed, the stage aborts
// rather than scanning anonymously when auth was asked for).
func TestSessionHeadersFromParams(t *testing.T) {
	h, err := sessionHeadersFromParams(nil)
	if h != nil || err != nil {
		t.Fatalf("nil params = %v/%v, want nil/nil (anonymous)", h, err)
	}
	h, err = sessionHeadersFromParams(map[string]string{})
	if h != nil || err != nil {
		t.Fatalf("empty params = %v/%v, want nil/nil", h, err)
	}
	path := writeSessionFile(t, "Cookie: session=synthetic-abc123\n")
	h, err = sessionHeadersFromParams(map[string]string{"session_headers": path})
	if err != nil {
		t.Fatalf("valid file: %v", err)
	}
	if h.Get("Cookie") != "session=synthetic-abc123" {
		t.Fatalf("Cookie = %q, want the session value", h.Get("Cookie"))
	}
	if _, err := sessionHeadersFromParams(map[string]string{"session_headers": filepath.Join(t.TempDir(), "missing.txt")}); err == nil {
		t.Fatal("missing file accepted (want fail-closed error)")
	}
	if _, err := sessionHeadersFromParams(map[string]string{"session_headers": writeSessionFile(t, "Bad Name: v\n")}); err == nil {
		t.Fatal("invalid file accepted (want fail-closed error)")
	}
}

// headerCaptureStageTransport records request headers per URL for
// stage wiring tests.
type headerCaptureStageTransport struct {
	mu  sync.Mutex
	got map[string]http.Header
}

func (t *headerCaptureStageTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	if t.got == nil {
		t.got = make(map[string]http.Header)
	}
	cp := make(http.Header, len(req.Header))
	for k, vs := range req.Header {
		cp[k] = append([]string(nil), vs...)
	}
	t.got[req.URL.String()] = cp
	t.mu.Unlock()
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/javascript"}},
		Body:       io.NopCloser(strings.NewReader("var wired = 1;\n")),
		Request:    req,
	}, nil
}

func (t *headerCaptureStageTransport) cookieFor(url string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.got[url].Get("Cookie")
}

// TestStageSessionHeadersWired pins NEW-125 end to end at stage level:
// a session_headers param file flows into requests on all three
// fetching stages, and anonymous runs send nothing extra.
func TestStageSessionHeadersWired(t *testing.T) {
	path := writeSessionFile(t, "Cookie: session=synthetic-stage\n")
	params := map[string]string{"session_headers": path}

	t.Run("httpprobe", func(t *testing.T) {
		tr := &headerCaptureStageTransport{}
		stage := &HTTPProbeStage{transport: tr}
		in := httpProbeStageInput(t, "example.com",
			[]asset.Host{httpProbeMustHost(t, "www.example.com")}, params, nil)
		if _, err := httpProbeRunBounded(t, stage, context.Background(), in); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := tr.cookieFor("http://www.example.com/"); got != "session=synthetic-stage" {
			t.Errorf("Cookie on probe = %q, want the session value", got)
		}
	})

	t.Run("jsintel", func(t *testing.T) {
		tr := &headerCaptureStageTransport{}
		stage := NewJSIntelStage(tr)
		in := pipeline.StageInput{
			Target: mustDomain(t, "example.com"),
			URLs:   []asset.URL{mustURL(t, "https://www.example.com/app.js")},
			Bounds: pipeline.DefaultStageConfig(),
			Config: params,
			Clock:  fixedClock{now: fixedTime},
		}
		res, err := stage.Run(context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Outcome != pipeline.OutcomeCompleted {
			t.Fatalf("outcome = %q, want completed", res.Outcome)
		}
		if got := tr.cookieFor("https://www.example.com/app.js"); got != "session=synthetic-stage" {
			t.Errorf("Cookie on fetch = %q, want the session value", got)
		}
	})

	t.Run("urllive", func(t *testing.T) {
		tr := &headerCaptureStageTransport{}
		stage := NewUrlliveStage(tr)
		in := pipeline.StageInput{
			Target: mustDomain(t, "example.com"),
			URLs:   []asset.URL{mustURL(t, "http://www.example.com/app.js")},
			Bounds: pipeline.DefaultStageConfig(),
			Config: params,
			Clock:  fixedClock{now: fixedTime},
		}
		if _, err := stage.Run(context.Background(), in); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := tr.cookieFor("http://www.example.com/app.js"); got != "session=synthetic-stage" {
			t.Errorf("Cookie on live probe = %q, want the session value", got)
		}
	})

	t.Run("anonymous sends nothing", func(t *testing.T) {
		tr := &headerCaptureStageTransport{}
		stage := &HTTPProbeStage{transport: tr}
		in := httpProbeStageInput(t, "example.com",
			[]asset.Host{httpProbeMustHost(t, "www.example.com")}, nil, nil)
		if _, err := httpProbeRunBounded(t, stage, context.Background(), in); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := tr.cookieFor("http://www.example.com/"); got != "" {
			t.Errorf("Cookie on anonymous probe = %q, want none", got)
		}
	})
}

// TestReadSessionFileRejectsFramingHeaders pins F4 (review wave
// 2026-09): the framing headers and User-Agent must never arrive via
// the session file — the transport owns framing and the engines set
// their own fixed identifier.
func TestReadSessionFileRejectsFramingHeaders(t *testing.T) {
	for _, name := range []string{
		"Content-Length", "Transfer-Encoding", "Connection", "User-Agent",
		"content-length", "transfer-encoding", "connection", "user-agent",
		"HOST",
	} {
		path := writeSessionFile(t, name+": synthetic-value\n")
		if _, err := ReadSessionFile(path); err == nil {
			t.Errorf("ReadSessionFile accepted %q (want fail-closed rejection)", name)
		}
	}
}

// TestReadSessionFileRejectsManyValues pins F6 (review wave 2026-09):
// a single name carrying 65 values exceeds the total-values bound.
func TestReadSessionFileRejectsManyValues(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < maxSessionHeaderValues+1; i++ {
		fmt.Fprintf(&sb, "X-Multi: synthetic-value-%04d\n", i)
	}
	if _, err := ReadSessionFile(writeSessionFile(t, sb.String())); err == nil {
		t.Fatalf("ReadSessionFile accepted %d values on one name (bound %d)",
			maxSessionHeaderValues+1, maxSessionHeaderValues)
	}
}

// TestTakeoverConfirmationAnonymous pins F1 (review wave 2026-09):
// takeover confirmation probes assert what a stranger sees, so they
// carry no session credentials even when the run is authed.
func TestTakeoverConfirmationAnonymous(t *testing.T) {
	tr := &headerCaptureStageTransport{}
	stage := &HTTPProbeStage{transport: tr}
	ghost := httpProbeMustHost(t, "ghost.example.com")
	in := httpProbeStageInput(t, "example.com", []asset.Host{ghost}, nil, nil)
	cfg := httpprobe.Config{
		Concurrency:    2,
		QueueSize:      4,
		Transport:      tr,
		RequestHeaders: http.Header{"Cookie": []string{"session=synthetic-takeover"}},
	}
	if _, _, err := stage.confirmTakeover(context.Background(), in, []asset.Host{ghost}, cfg); err != nil {
		t.Fatalf("confirmTakeover: %v", err)
	}
	tr.mu.Lock()
	n := len(tr.got)
	tr.mu.Unlock()
	if n != 2 {
		t.Fatalf("confirmation requests = %d, want 2 (http + https roots, non-vacuous)", n)
	}
	for _, url := range []string{"http://ghost.example.com/", "https://ghost.example.com/"} {
		if got := tr.cookieFor(url); got != "" {
			t.Errorf("Cookie on takeover confirmation %s = %q, want none (anonymous evidence)", url, got)
		}
	}
}

// TestSessionStagesFailClosedOnEmptyCorpus pins F2 (review wave
// 2026-09): a broken session file fails the jsintel/urllive stages
// even on an empty corpus — never a silent anonymous completed run.
func TestSessionStagesFailClosedOnEmptyCorpus(t *testing.T) {
	params := map[string]string{"session_headers": filepath.Join(t.TempDir(), "missing.txt")}

	t.Run("jsintel", func(t *testing.T) {
		stage := NewJSIntelStage(&headerCaptureStageTransport{})
		res, err := stage.Run(context.Background(), pipeline.StageInput{
			Target: mustDomain(t, "example.com"),
			Bounds: pipeline.DefaultStageConfig(),
			Config: params,
			Clock:  fixedClock{now: fixedTime},
		})
		if err == nil || res.Outcome != pipeline.OutcomeFailed {
			t.Errorf("jsintel empty corpus + missing file: err=%v outcome=%q, want error + failed", err, res.Outcome)
		}
	})

	t.Run("urllive", func(t *testing.T) {
		stage := NewUrlliveStage(&headerCaptureStageTransport{})
		res, err := stage.Run(context.Background(), pipeline.StageInput{
			Target: mustDomain(t, "example.com"),
			Bounds: pipeline.DefaultStageConfig(),
			Config: params,
			Clock:  fixedClock{now: fixedTime},
		})
		if err == nil || res.Outcome != pipeline.OutcomeFailed {
			t.Errorf("urllive empty corpus + missing file: err=%v outcome=%q, want error + failed", err, res.Outcome)
		}
	})
}

// TestStageSessionHeadersMissingFile pins fail-closed wiring: a
// session_headers param pointing nowhere fails the stage (never an
// anonymous run).
func TestStageSessionHeadersMissingFile(t *testing.T) {
	params := map[string]string{"session_headers": filepath.Join(t.TempDir(), "missing.txt")}
	tr := &headerCaptureStageTransport{}

	httpStage := &HTTPProbeStage{transport: tr}
	hres, herr := httpProbeRunBounded(t, httpStage, context.Background(),
		httpProbeStageInput(t, "example.com", []asset.Host{httpProbeMustHost(t, "www.example.com")}, params, nil))
	if herr == nil || hres.Outcome != pipeline.OutcomeFailed {
		t.Errorf("httpprobe missing file: err=%v outcome=%q, want error + failed", herr, hres.Outcome)
	}

	jsStage := NewJSIntelStage(tr)
	jres, jerr := jsStage.Run(context.Background(), pipeline.StageInput{
		Target: mustDomain(t, "example.com"),
		URLs:   []asset.URL{mustURL(t, "https://www.example.com/app.js")},
		Bounds: pipeline.DefaultStageConfig(),
		Config: params,
		Clock:  fixedClock{now: fixedTime},
	})
	if jerr == nil || jres.Outcome != pipeline.OutcomeFailed {
		t.Errorf("jsintel missing file: err=%v outcome=%q, want error + failed", jerr, jres.Outcome)
	}

	urlStage := NewUrlliveStage(tr)
	ures, uerr := urlStage.Run(context.Background(), pipeline.StageInput{
		Target: mustDomain(t, "example.com"),
		URLs:   []asset.URL{mustURL(t, "http://www.example.com/app.js")},
		Bounds: pipeline.DefaultStageConfig(),
		Config: params,
		Clock:  fixedClock{now: fixedTime},
	})
	if uerr == nil || ures.Outcome != pipeline.OutcomeFailed {
		t.Errorf("urllive missing file: err=%v outcome=%q, want error + failed", uerr, ures.Outcome)
	}
}
