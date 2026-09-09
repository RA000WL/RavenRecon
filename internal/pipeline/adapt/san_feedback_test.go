package adapt

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/cache"
	"github.com/RA000WL/RavenRecon/internal/httpprobe"
	"github.com/RA000WL/RavenRecon/internal/pipeline"
)

// sanFeedbackParams enables SAN→target feedback and nothing else.
func sanFeedbackParams() map[string]string {
	return map[string]string{"probe_san": "true"}
}

// TestProbeSANKnobParsing pins the dedicated knob: OFF by default
// (absent, nil, or any non-truthy value), ON for the probe_ports
// truthy spellings.
func TestProbeSANKnobParsing(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]string
		want   bool
	}{
		{"nil", nil, false},
		{"absent", map[string]string{}, false},
		{"false", map[string]string{"probe_san": "false"}, false},
		{"empty", map[string]string{"probe_san": ""}, false},
		{"zero", map[string]string{"probe_san": "0"}, false},
		{"true", map[string]string{"probe_san": "true"}, true},
		{"one", map[string]string{"probe_san": "1"}, true},
		{"yes", map[string]string{"probe_san": "yes"}, true},
		{"on", map[string]string{"probe_san": "on"}, true},
		{"case-insensitive", map[string]string{"probe_san": "TRUE"}, true},
		{"space-insensitive", map[string]string{"probe_san": " on "}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := probeSANEnabled(tc.params); got != tc.want {
				t.Fatalf("probeSANEnabled(%v) = %v, want %v", tc.params, got, tc.want)
			}
		})
	}
}

// sanFeedbackFixture builds the cert-only-host fixture: www serves a
// synthetic leaf naming hidden (in-domain, unlisted), api (already in
// the corpus), an out-of-scope name, and a wildcard. Every served host
// answers 200 on both schemes.
func sanFeedbackFixture(t *testing.T, tr *cannedTransport) {
	t.Helper()
	cert := syntheticTLSCert(t, "www.example.com",
		"www.example.com", "hidden.example.com", "api.example.com",
		"evil.example.net", "*.example.com")
	registerHTTPSWithTLS(tr, "www.example.com", cannedResponse{status: 200, body: "ok", tlsState: tlsStateFor(cert)})
	cannedHost(tr, "api.example.com", cannedResponse{status: 200, body: "ok"})
	cannedHost(tr, "hidden.example.com", cannedResponse{status: 200, body: "ok"})
}

// TestHTTPProbeStageSANFeedbackProbesCertOnlyHost is the NEW-136
// acceptance proof: the cert-only SAN host gets probed through the
// standard path (its root URLs join the corpus), while the corpus dup,
// the out-of-scope name, and the wildcard never cost an extra request.
func TestHTTPProbeStageSANFeedbackProbesCertOnlyHost(t *testing.T) {
	tr := &cannedTransport{}
	sanFeedbackFixture(t, tr)

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
		httpProbeMustHost(t, "api.example.com"),
	}, sanFeedbackParams(), nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	// Merged report: 2 corpus hosts + 1 SAN host.
	if res.ItemsProcessed != 3 || res.ItemsFailed != 0 {
		t.Fatalf("counters = %d/%d, want 3/0", res.ItemsProcessed, res.ItemsFailed)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("Truncated/flags = %v/%v, want false/empty (no cap hit)", res.Truncated, res.StickyFlags)
	}
	// The SAN host was probed: its root URLs join the corpus additions.
	httpProbeRequireStrings(t, "Additions.URLs", httpProbeURLStrings(res.Additions.URLs),
		[]string{
			"http://api.example.com/",
			"http://hidden.example.com/",
			"http://www.example.com/",
			"https://api.example.com/",
			"https://hidden.example.com/",
			"https://www.example.com/",
		})
	if !tr.served("http", "hidden.example.com") || !tr.served("https", "hidden.example.com") {
		t.Fatal("cert-only SAN host was not probed on both schemes")
	}
	// Request budget: 2 roots x 3 hosts, no more — the corpus dup
	// (api), the out-of-scope name, and the wildcard cost nothing extra.
	if got := tr.requestCount(); got != 6 {
		t.Fatalf("requests = %d, want 6 (2 roots x 3 probed hosts)", got)
	}
	if tr.served("http", "evil.example.net") || tr.served("https", "evil.example.net") {
		t.Fatal("out-of-scope SAN was probed: the scope wall is absolute")
	}
}

// TestHTTPProbeStageSANFeedbackDisabledParity pins byte-identical off
// behavior: without the knob (or with an explicit "false") the SAN host
// is never probed and both param shapes produce DeepEqual results.
func TestHTTPProbeStageSANFeedbackDisabledParity(t *testing.T) {
	run := func(params map[string]string) (pipeline.StageResult, int) {
		t.Helper()
		tr := &cannedTransport{}
		sanFeedbackFixture(t, tr)
		in := httpProbeStageInput(t, "example.com", []asset.Host{
			httpProbeMustHost(t, "www.example.com"),
			httpProbeMustHost(t, "api.example.com"),
		}, params, nil)
		res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res, tr.requestCount()
	}
	resAbsent, nAbsent := run(nil)
	resFalse, nFalse := run(map[string]string{"probe_san": "false"})
	if nAbsent != 4 || nFalse != 4 {
		t.Fatalf("requests = %d/%d, want 4/4 (2 roots x 2 corpus hosts, SAN host untouched)",
			nAbsent, nFalse)
	}
	// The fixture mints a fresh synthetic certificate per run (new ECDSA
	// key), so only the fingerprint-identified material differs between
	// runs by construction. Scrub it before the parity comparison: the
	// pin is that the KNOB changes nothing, not that two random keys
	// collide.
	scrubCertIdentity := func(res pipeline.StageResult) pipeline.StageResult {
		res.Results.TLSCertificates = nil
		kept := res.Results.Relationships[:0]
		for _, r := range res.Results.Relationships {
			if r.Kind == asset.RelationshipHostToTLSCertificate ||
				r.Kind == asset.RelationshipPortToTLSCertificate {
				continue
			}
			kept = append(kept, r)
		}
		res.Results.Relationships = kept
		return res
	}
	if !reflect.DeepEqual(scrubCertIdentity(resAbsent), scrubCertIdentity(resFalse)) {
		t.Fatalf("absent vs false differ:\nabsent: %+v\nfalse: %+v", resAbsent, resFalse)
	}
	// The passive expansion still names the SAN host for later stages —
	// the knob gates probing, not inventory.
	found := false
	for _, h := range resAbsent.Additions.Hosts {
		if h.Name == "hidden.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Additions.Hosts = %v, want the passive tls-san inventory intact",
			httpProbeHostStrings(resAbsent.Additions.Hosts))
	}
	for _, u := range resAbsent.Additions.URLs {
		if u.String() == "http://hidden.example.com/" || u.String() == "https://hidden.example.com/" {
			t.Fatalf("SAN host URL joined additions without the knob: %s", u)
		}
	}
}

// TestHTTPProbeStageSANFeedbackCapAndFlag pins the bound: beyond the
// engine cap only the sorted head is probed, and the cut sets Truncated
// with the named sticky flag (never silent, §0.6).
func TestHTTPProbeStageSANFeedbackCapAndFlag(t *testing.T) {
	tr := &cannedTransport{}
	var names []string
	for i := 0; i < 20; i++ {
		names = append(names, fmt.Sprintf("h%02d.example.com", i))
	}
	names = append(names, "www.example.com")
	cert := syntheticTLSCert(t, "www.example.com", names...)
	registerHTTPSWithTLS(tr, "www.example.com", cannedResponse{status: 200, body: "ok", tlsState: tlsStateFor(cert)})
	// Serve every potential SAN host so all probes complete.
	for i := 0; i < 20; i++ {
		cannedHost(tr, fmt.Sprintf("h%02d.example.com", i), cannedResponse{status: 200, body: "ok"})
	}

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
	}, sanFeedbackParams(), nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed (all probed hosts completed)", res.Outcome)
	}
	if res.ItemsProcessed != 17 {
		t.Fatalf("ItemsProcessed = %d, want 17 (1 root + 16 SAN)", res.ItemsProcessed)
	}
	if !res.Truncated || !res.StickyFlags[httpprobeSANTargetsTruncatedFlag] {
		t.Fatalf("Truncated=%v StickyFlags=%v, want the cut flagged, never silent",
			res.Truncated, res.StickyFlags)
	}
	// Sorted head probed (h00..h15), tail never touched.
	if !tr.served("https", "h00.example.com") || !tr.served("https", "h15.example.com") {
		t.Fatal("sorted head of the SAN set was not probed")
	}
	if tr.served("http", "h16.example.com") || tr.served("https", "h19.example.com") {
		t.Fatal("SAN hosts beyond the cap were probed")
	}
	if got := tr.requestCount(); got != 2+32 {
		t.Fatalf("requests = %d, want 34 (2 roots + 16 SAN x 2)", got)
	}
}

// TestHTTPProbeStageSANFeedbackInertWithoutCerts pins the no-op: with
// the knob on but no captured certificates, behavior is root-only with
// no flag.
func TestHTTPProbeStageSANFeedbackInertWithoutCerts(t *testing.T) {
	tr := &cannedTransport{}
	cannedHost(tr, "www.example.com", cannedResponse{status: 200, body: "ok"})

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
	}, sanFeedbackParams(), nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("Outcome = %q, want completed", res.Outcome)
	}
	if res.Truncated || len(res.StickyFlags) != 0 {
		t.Fatalf("Truncated/flags = %v/%v, want false/empty", res.Truncated, res.StickyFlags)
	}
	if got := tr.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

// TestHTTPProbeStageSANFeedbackCache pins cache honesty: the SAN pass
// rides cache-before-execute under its own URL identities, so a warm run
// issues zero requests — and a different session digest misses, proving
// the binding is preserved through the feedback join.
func TestHTTPProbeStageSANFeedbackCache(t *testing.T) {
	c, err := cache.Open(t.TempDir(), cache.WithClock(httpProbeFixedClock{}.Now))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	tr := &cannedTransport{}
	sanFeedbackFixture(t, tr)

	hosts := []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
		httpProbeMustHost(t, "api.example.com"),
	}
	run := func(params map[string]string) pipeline.StageResult {
		t.Helper()
		in := httpProbeStageInput(t, "example.com", hosts, params, c)
		res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}

	res1 := run(sanFeedbackParams())
	if res1.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("first run Outcome = %q, want completed", res1.Outcome)
	}
	if got := tr.requestCount(); got != 6 {
		t.Fatalf("first run requests = %d, want 6 (one miss per probe target)", got)
	}

	res2 := run(sanFeedbackParams())
	if res2.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("second run Outcome = %q, want completed (served from cache)", res2.Outcome)
	}
	if got := tr.requestCount(); got != 6 {
		t.Fatalf("second run requests = %d, want 6 unchanged (SAN pass hits under its URL identities)", got)
	}
	httpProbeRequireStrings(t, "second run Additions.URLs",
		httpProbeURLStrings(res2.Additions.URLs), httpProbeURLStrings(res1.Additions.URLs))

	// A different operator session re-probes: the digest binds every key,
	// including the SAN pass's, so anonymity can never be served
	// authenticated results (or the reverse).
	writeSession := func(value string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "session.txt")
		if err := os.WriteFile(path, []byte("X-Session: "+value+"\n"), 0o600); err != nil {
			t.Fatalf("write session file: %v", err)
		}
		return path
	}
	authed := sanFeedbackParams()
	authed["session_headers"] = writeSession("alpha")
	run(authed)
	if got := tr.requestCount(); got <= 6 {
		t.Fatalf("authed run requests = %d, want more than 6 (a new session digest misses)", got)
	}
	before := tr.requestCount()
	res4 := run(authed)
	if res4.Outcome != pipeline.OutcomeCompleted {
		t.Fatalf("authed rerun Outcome = %q, want completed", res4.Outcome)
	}
	if got := tr.requestCount(); got != before {
		t.Fatalf("authed rerun requests = %d, want %d unchanged (same session hits)", got, before)
	}
}

// TestHTTPProbeStageSANFeedbackSANHostFailurePartial pins the refold when
// a SAN host fails while the corpus completes: the run folds partial (not
// failed — completed hosts exist), ItemsProcessed counts the union, and
// ItemsFailed counts exactly the SAN host. Both per-host failure flavors —
// a DNS failure (unserved host) and a timeout (timeout DNSError) — fold
// the same way.
func TestHTTPProbeStageSANFeedbackSANHostFailurePartial(t *testing.T) {
	cases := []struct {
		name  string
		serve func(tr *cannedTransport)
	}{
		{"dns failure", func(tr *cannedTransport) {
			// Unserved: every SAN probe fails DNS (ReasonDNS).
		}},
		{"timeout", func(tr *cannedTransport) {
			cannedHost(tr, "hidden.example.com", cannedResponse{err: &net.DNSError{
				Err: "timeout", Name: "hidden.example.com", IsTimeout: true,
			}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &cannedTransport{}
			cert := syntheticTLSCert(t, "www.example.com",
				"www.example.com", "api.example.com", "hidden.example.com")
			registerHTTPSWithTLS(tr, "www.example.com", cannedResponse{status: 200, body: "ok", tlsState: tlsStateFor(cert)})
			cannedHost(tr, "api.example.com", cannedResponse{status: 200, body: "ok"})
			tc.serve(tr)

			in := httpProbeStageInput(t, "example.com", []asset.Host{
				httpProbeMustHost(t, "www.example.com"),
				httpProbeMustHost(t, "api.example.com"),
			}, sanFeedbackParams(), nil)
			res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.Outcome != pipeline.OutcomePartial {
				t.Fatalf("Outcome = %q, want partial (corpus completed, SAN host failed)", res.Outcome)
			}
			// The union is pinned: 2 corpus hosts + 1 SAN host, with
			// exactly the SAN host failed.
			if res.ItemsProcessed != 3 || res.ItemsFailed != 1 {
				t.Fatalf("counters = %d/%d, want 3/1", res.ItemsProcessed, res.ItemsFailed)
			}
			if res.Truncated || len(res.StickyFlags) != 0 {
				t.Fatalf("Truncated/flags = %v/%v, want false/empty (no cap hit)", res.Truncated, res.StickyFlags)
			}
			// The failed SAN host's probed target URLs are retained as
			// observations, and the host stays listed in Additions.Hosts.
			httpProbeRequireStrings(t, "Additions.URLs", httpProbeURLStrings(res.Additions.URLs),
				[]string{
					"http://api.example.com/",
					"http://hidden.example.com/",
					"http://www.example.com/",
					"https://api.example.com/",
					"https://hidden.example.com/",
					"https://www.example.com/",
				})
			found := false
			for _, h := range res.Additions.Hosts {
				if h.Name == "hidden.example.com" {
					found = true
				}
			}
			if !found {
				t.Fatalf("Additions.Hosts = %v, want the failed SAN host listed",
					httpProbeHostStrings(res.Additions.Hosts))
			}
			// Both SAN probes were attempted (2 roots x 3 hosts).
			if got := tr.requestCount(); got != 6 {
				t.Fatalf("requests = %d, want 6 (2 roots x 3 probed hosts)", got)
			}
		})
	}
}

// TestHTTPProbeStageSANFeedbackUnionFailureFoldsFailed pins the refold when
// no host in the union completed: the root is incomplete (its http side
// fails DNS while its https side completes and captures the SAN
// certificate — failed+completed folds incomplete with the observations
// retained) and every synthesized SAN host fails, so the run folds failed
// with the first-pass observations merged. The SAN set exceeds the cap, so
// the sanCut flag rides the failed outcome too (never swallowed, §0.6).
func TestHTTPProbeStageSANFeedbackUnionFailureFoldsFailed(t *testing.T) {
	tr := &cannedTransport{}
	names := []string{"www.example.com"}
	for i := 0; i < 20; i++ {
		names = append(names, fmt.Sprintf("h%02d.example.com", i))
	}
	cert := syntheticTLSCert(t, "www.example.com", names...)
	// https-only: the http side fails DNS, so the root folds incomplete
	// (failed + completed) while still capturing the certificate that
	// drives the SAN pass.
	cannedHostScheme(tr, "www.example.com", "https",
		cannedResponse{status: 200, body: "ok", tlsState: tlsStateFor(cert)})
	// Every SAN host is unserved: the SAN pass retains no observations.

	in := httpProbeStageInput(t, "example.com", []asset.Host{
		httpProbeMustHost(t, "www.example.com"),
	}, sanFeedbackParams(), nil)
	res, err := httpProbeRunBounded(t, testStage(tr), context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != pipeline.OutcomeFailed {
		t.Fatalf("Outcome = %q, want failed (no completed host in the union)", res.Outcome)
	}
	// The union is pinned: 1 root + 16 synthesized SAN hosts, with exactly
	// the SAN hosts failed.
	if res.ItemsProcessed != 17 || res.ItemsFailed != 16 {
		t.Fatalf("counters = %d/%d, want 17/16", res.ItemsProcessed, res.ItemsFailed)
	}
	// The cut flag survives the failed fold; no probe cap fired, so it is
	// the only flag.
	if !res.Truncated || !res.StickyFlags[httpprobeSANTargetsTruncatedFlag] {
		t.Fatalf("Truncated=%v StickyFlags=%v, want the SAN cut flagged, never silent",
			res.Truncated, res.StickyFlags)
	}
	if len(res.StickyFlags) != 1 {
		t.Fatalf("StickyFlags = %v, want only the SAN cut flag", res.StickyFlags)
	}
	// First-pass observations merged: every probed target URL — the root's
	// and the SAN pass's, failed or not — joins the corpus additions even
	// though the run failed. Built in the canonical sorted order the
	// adapter emits (all http targets, then all https targets).
	var wantURLs []string
	for _, scheme := range []string{"http", "https"} {
		for i := 0; i < 16; i++ {
			wantURLs = append(wantURLs, fmt.Sprintf("%s://h%02d.example.com/", scheme, i))
		}
		wantURLs = append(wantURLs, scheme+"://www.example.com/")
	}
	httpProbeRequireStrings(t, "Additions.URLs", httpProbeURLStrings(res.Additions.URLs), wantURLs)
	// Sorted head probed (h00..h15), tail never touched.
	if !tr.served("https", "h00.example.com") || !tr.served("http", "h15.example.com") {
		t.Fatal("sorted head of the SAN set was not probed")
	}
	if tr.served("http", "h16.example.com") || tr.served("https", "h19.example.com") {
		t.Fatal("SAN hosts beyond the cap were probed")
	}
	if got := tr.requestCount(); got != 2+32 {
		t.Fatalf("requests = %d, want 34 (2 roots + 16 SAN x 2)", got)
	}
}

// httpProbeReportFor builds a one-host engine report for merge tests.
func httpProbeReportFor(t testing.TB, target asset.Domain, name string) httpprobe.Report {
	t.Helper()
	return httpprobe.Report{
		Target: target,
		Results: []httpprobe.HostResult{{
			Host:   httpProbeMustHost(t, name),
			Status: httpprobe.StatusCompleted,
		}},
	}
}

// httpProbeReportEmpty builds an engine report with no host results.
func httpProbeReportEmpty(target asset.Domain) httpprobe.Report {
	return httpprobe.Report{Target: target}
}

// TestMergeProbeReportsDeterminism pins the join: reports concatenate
// and sort by host regardless of pass order, and an empty second report
// is an identity.
func TestMergeProbeReportsDeterminism(t *testing.T) {
	target := httpProbeMustDomain(t, "example.com")
	// Build two single-host engine reports through the real types.
	repA := httpProbeReportFor(t, target, "www.example.com")
	repB := httpProbeReportFor(t, target, "api.example.com")
	merged := mergeProbeReports(repA, repB)
	if len(merged.Results) != 2 ||
		merged.Results[0].Host.Name != "api.example.com" ||
		merged.Results[1].Host.Name != "www.example.com" {
		t.Fatalf("merged order = %v, want [api www] sorted", merged.Results)
	}
	if merged.Target.Name != "example.com" {
		t.Fatalf("merged target = %q, want example.com", merged.Target.Name)
	}
	identity := mergeProbeReports(repA, httpProbeReportEmpty(target))
	if len(identity.Results) != 1 || identity.Results[0].Host.Name != "www.example.com" {
		t.Fatalf("empty second report did not preserve the first: %+v", identity)
	}
}
