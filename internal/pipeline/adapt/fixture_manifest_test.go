package adapt

// Parser and loader coverage for the v1.7 acceptance fixture-manifest
// format (NEW-56 batch E; review findings HIGH-2 and LOW-2). These tests
// pin EVERY validation branch the code implements:
//
//   - parseFixtureManifest: empty profile, empty target, discovery object
//     without detections/runs, empty http, http status range, http
//     body/body_file mutual exclusion, http body_oversized exclusion,
//     js file/body/oversized mutual exclusion and requirement, js status
//     range, empty stage_params sets, unknown fields (top level and
//     nested, via DisallowUnknownFields), malformed JSON;
//   - loadFixtureManifest: happy-path load of the committed clean-baseline
//     profile (including eager body-file resolution), profile/directory
//     mismatch, missing manifest, missing referenced js/body files, and
//     the LOW-2 path-containment hardening: a manifest-referenced path
//     that escapes the profile directory ("../..") is rejected with a
//     clear error BEFORE any read happens, and absolute paths are treated
//     as profile-relative (never resolved against the filesystem root).
//
// All fixture data below is strictly synthetic (AGENTS §0.8): the
// example.com corpus and the placeholder key shapes mirror the committed
// clean-baseline profile, which is itself synthetic end to end.

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// fixturesDir resolves the repository's fixtures/ directory relative to
// this source file, independent of the test process's working directory
// (the same pattern as detect's surface snapshot test).
func fixturesDir(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures")
}

// writeFixtureRoot builds a temporary fixtures root with one profile
// directory holding the given manifest bytes plus optional extra files
// keyed by slash-separated relative paths.
func writeFixtureRoot(t *testing.T, profile string, manifest []byte, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, profile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestName), manifest, 0o644); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}
	for rel, content := range files {
		fp := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", filepath.Dir(rel), err)
		}
		if err := os.WriteFile(fp, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", rel, err)
		}
	}
	return root
}

// TestParseFixtureManifestValidRoundTrip pins the accepted document space:
// a full document carrying every section decodes into the exact struct
// shape, and the documented minimal forms (no discovery; detections-only;
// runs-only) parse cleanly.
func TestParseFixtureManifestValidRoundTrip(t *testing.T) {
	const fullDoc = `{
	  "profile": "full-profile",
	  "target": "example.com",
	  "discovery": {
	    "detections": {
	      "subfinder -version": {"stdout": "Current Version: v2.6.3\n"},
	      "assetfinder -h": {"stderr": "Usage\n", "exit_code": 2}
	    },
	    "runs": {
	      "subfinder -d example.com -silent": {"stdout": "api.example.com\nwww.example.com\n"}
	    }
	  },
	  "dns": {
	    "www.example.com": {"A": ["93.184.216.34"], "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"], "CNAME": []}
	  },
	  "dns_poison": {
	    "www.example.com": {"A": ["203.0.113.10"]}
	  },
	  "http": {
	    "www.example.com": {"status": 200, "headers": {"Content-Type": "text/html"}, "body": "<html></html>"},
	    "api.example.com": {"status": 404, "body_file": "api-body.txt"}
	  },
	  "urlintel": [
	    "http://www.example.com/app.js",
	    "http://api.example.com/lib.js?v=2"
	  ],
	  "js": {
	    "/app.js": {"file": "app.js"},
	    "/lib.js": {"body": "const x = 1;\n", "status": 200, "headers": {"Content-Type": "application/javascript"}}
	  },
	  "stage_params": {
	    "discover": {"min_quality": "0.5"}
	  }
	}`

	m, err := parseFixtureManifest([]byte(fullDoc))
	if err != nil {
		t.Fatalf("parseFixtureManifest(full document): %v", err)
	}
	if m.Profile != "full-profile" || m.Target != "example.com" {
		t.Errorf("Profile/Target = %q/%q, want full-profile/example.com", m.Profile, m.Target)
	}
	if len(m.Detections) != 2 || len(m.Runs) != 1 {
		t.Errorf("Detections/Runs = %d/%d, want 2/1", len(m.Detections), len(m.Runs))
	}
	if d := m.Detections["assetfinder -h"]; d.Stderr != "Usage\n" || d.ExitCode != 2 || d.Stdout != "" {
		t.Errorf("detection assetfinder -h = %+v, want stderr+exit_code only", d)
	}
	if r := m.Runs["subfinder -d example.com -silent"]; r.Stdout != "api.example.com\nwww.example.com\n" {
		t.Errorf("run subfinder = %+v", r)
	}
	wantDNS := fixtureDNSRecords{
		A:     []string{"93.184.216.34"},
		AAAA:  []string{"2606:2800:220:1:248:1893:25c8:1946"},
		CNAME: []string{},
	}
	if got := m.DNS["www.example.com"]; !reflect.DeepEqual(got, wantDNS) {
		t.Errorf("DNS www = %+v, want %+v", got, wantDNS)
	}
	if got := m.DNSPoison["www.example.com"]; !reflect.DeepEqual(got.A, []string{"203.0.113.10"}) {
		t.Errorf("DNSPoison www = %+v, want A [203.0.113.10]", got)
	}
	www := m.HTTP["www.example.com"]
	if www.Status != 200 || www.Body != "<html></html>" || www.Headers["Content-Type"] != "text/html" ||
		www.BodyFile != "" || www.BodyOversized {
		t.Errorf("http www = %+v, want the canned 200 html response", www)
	}
	if got := m.HTTP["api.example.com"].BodyFile; got != "api-body.txt" {
		t.Errorf("http api BodyFile = %q, want api-body.txt (unresolved until load)", got)
	}
	if got := m.URLIntel; !reflect.DeepEqual(got, []string{
		"http://www.example.com/app.js",
		"http://api.example.com/lib.js?v=2",
	}) {
		t.Errorf("URLIntel = %v", got)
	}
	app := m.JS["/app.js"]
	if app.File != "app.js" || app.Body != "" || app.Oversized || app.Status != 0 {
		t.Errorf("js /app.js = %+v, want file reference only", app)
	}
	lib := m.JS["/lib.js"]
	if lib.Body != "const x = 1;\n" || lib.Status != 200 || lib.Headers["Content-Type"] != "application/javascript" {
		t.Errorf("js /lib.js = %+v, want inline body with status+headers", lib)
	}
	if got := m.StageParams["discover"]; !reflect.DeepEqual(got, map[string]string{"min_quality": "0.5"}) {
		t.Errorf("StageParams discover = %v", got)
	}

	// Minimal form: no discovery section at all.
	minimal := `{"profile":"mini","target":"example.com","http":{"www.example.com":{"status":200}}}`
	m2, err := parseFixtureManifest([]byte(minimal))
	if err != nil {
		t.Fatalf("parseFixtureManifest(minimal): %v", err)
	}
	if m2.Detections != nil || m2.Runs != nil {
		t.Errorf("minimal Detections/Runs = %v/%v, want nil/nil", m2.Detections, m2.Runs)
	}

	// Detections-only and runs-only are both valid discovery forms.
	detOnly := `{"profile":"p","target":"example.com",
	             "discovery":{"detections":{"subfinder -version":{"stdout":"v"}}},
	             "http":{"h":{"status":200}}}`
	if _, err := parseFixtureManifest([]byte(detOnly)); err != nil {
		t.Fatalf("parseFixtureManifest(detections-only): %v", err)
	}
	runsOnly := `{"profile":"p","target":"example.com",
	             "discovery":{"runs":{"subfinder -d example.com":{"stdout":"a.example.com"}}},
	             "http":{"h":{"status":200}}}`
	if _, err := parseFixtureManifest([]byte(runsOnly)); err != nil {
		t.Fatalf("parseFixtureManifest(runs-only): %v", err)
	}
}

// TestParseFixtureManifestRejections walks every structural validation
// branch in parseFixtureManifest. Each entry names the branch it pins;
// the assertion is that parsing fails with an error carrying the listed
// fragment (or any error for the decoder-level cases where Go owns the
// message).
func TestParseFixtureManifestRejections(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantErr string // "" = any error (decoder-owned messages)
	}{
		{name: "empty profile", doc: `{"target":"example.com","http":{"h":{"status":200}}}`,
			wantErr: "profile must not be empty"},
		{name: "empty target", doc: `{"profile":"p","http":{"h":{"status":200}}}`,
			wantErr: "target must not be empty"},
		{name: "discovery without detections or runs", doc: `{"profile":"p","target":"example.com","discovery":{},"http":{"h":{"status":200}}}`,
			wantErr: "discovery must set detections and/or runs"},
		{name: "discovery with explicitly empty maps", doc: `{"profile":"p","target":"example.com","discovery":{"detections":{},"runs":{}},"http":{"h":{"status":200}}}`,
			wantErr: "discovery must set detections and/or runs"},
		{name: "http absent", doc: `{"profile":"p","target":"example.com"}`,
			wantErr: "http responses must not be empty"},
		{name: "http empty object", doc: `{"profile":"p","target":"example.com","http":{}}`,
			wantErr: "http responses must not be empty"},
		{name: "http status below range", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":99}}}`,
			wantErr: `http h: status 99 out of range`},
		{name: "http status above range", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":600}}}`,
			wantErr: `http h: status 600 out of range`},
		{name: "http body and body_file together", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200,"body":"a","body_file":"b.txt"}}}`,
			wantErr: `http h: body and body_file are mutually exclusive`},
		{name: "http body_oversized with body", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200,"body_oversized":true,"body":"a"}}}`,
			wantErr: `http h: body_oversized excludes body/body_file`},
		{name: "http body_oversized with body_file", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200,"body_oversized":true,"body_file":"b.txt"}}}`,
			wantErr: `http h: body_oversized excludes body/body_file`},
		{name: "js two of file/body/oversized", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200}},"js":{"/a.js":{"file":"a.js","body":"x"}}}`,
			wantErr: `js /a.js: file, body, and oversized are mutually exclusive`},
		{name: "js all three of file/body/oversized", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200}},"js":{"/a.js":{"file":"a.js","body":"x","oversized":true}}}`,
			wantErr: `js /a.js: file, body, and oversized are mutually exclusive`},
		{name: "js none of file/body/oversized", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200}},"js":{"/a.js":{}}}`,
			wantErr: `js /a.js: one of file, body, oversized is required`},
		{name: "js status below range", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200}},"js":{"/a.js":{"body":"x","status":99}}}`,
			wantErr: `js /a.js: status 99 out of range`},
		{name: "js status above range", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200}},"js":{"/a.js":{"body":"x","status":600}}}`,
			wantErr: `js /a.js: status 600 out of range`},
		{name: "stage_params empty parameter set", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200}},"stage_params":{"discover":{}}}`,
			wantErr: "stage_params discover: empty parameter set"},
		{name: "unknown top-level field", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200}},"bogus":1}`,
			wantErr: `unknown field "bogus"`},
		{name: "unknown nested field", doc: `{"profile":"p","target":"example.com","http":{"h":{"status":200,"bogus":true}}}`,
			wantErr: `unknown field "bogus"`},
		{name: "malformed json", doc: `{"profile":"p",`,
			wantErr: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFixtureManifest([]byte(tc.doc))
			if err == nil {
				t.Fatalf("parseFixtureManifest accepted an invalid document:\n%s", tc.doc)
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not carry %q", err, tc.wantErr)
			}
		})
	}
}

// TestLoadFixtureManifestCleanBaseline loads the committed clean-baseline
// profile — the consumer side of HIGH-2 — and pins that referenced .js
// files are eagerly materialized into inline bodies.
func TestLoadFixtureManifestCleanBaseline(t *testing.T) {
	m, err := loadFixtureManifest(fixturesDir(t), "clean-baseline")
	if err != nil {
		t.Fatalf("loadFixtureManifest(clean-baseline): %v", err)
	}
	if m.Profile != "clean-baseline" || m.Target != "example.com" {
		t.Errorf("Profile/Target = %q/%q", m.Profile, m.Target)
	}
	if len(m.Detections) != 4 || len(m.Runs) != 4 {
		t.Errorf("Detections/Runs = %d/%d, want 4/4 (subfinder, assetfinder, amass, chaos)", len(m.Detections), len(m.Runs))
	}
	if len(m.DNS) != 3 || len(m.HTTP) != 3 {
		t.Errorf("DNS/HTTP = %d/%d, want 3/3 hosts", len(m.DNS), len(m.HTTP))
	}
	if len(m.URLIntel) != 4 {
		t.Errorf("URLIntel = %d lines, want 4", len(m.URLIntel))
	}
	app := m.JS["/app.js"]
	if app.File == "" || !strings.Contains(app.Body, awsKey(7)) {
		t.Errorf("js /app.js not materialized from its file: file=%q body carries the synthetic key=%v",
			app.File, strings.Contains(app.Body, awsKey(7)))
	}
	if m.JS["/shared.js"].Body == "" {
		t.Errorf("js /shared.js body = %q, want the inline body", m.JS["/shared.js"].Body)
	}
	if len(m.StageParams) != 0 || len(m.DNSPoison) != 0 {
		t.Errorf("clean baseline StageParams/DNSPoison = %v/%v, want empty", m.StageParams, m.DNSPoison)
	}
}

// TestLoadFixtureManifestRejections covers the loader-only branches:
// profile/directory mismatch, missing manifest, missing referenced files,
// and the LOW-2 path-containment hardening.
func TestLoadFixtureManifestRejections(t *testing.T) {
	const validHead = `{"profile":"p","target":"example.com","http":{"www.example.com":{"status":200}}`

	t.Run("profile directory mismatch", func(t *testing.T) {
		root := writeFixtureRoot(t, "dir-a", []byte(`{"profile":"other","target":"example.com","http":{"h":{"status":200}}}`), nil)
		_, err := loadFixtureManifest(root, "dir-a")
		if err == nil || !strings.Contains(err.Error(), `profile "other" does not match directory "dir-a"`) {
			t.Fatalf("error = %v, want the mismatch message", err)
		}
	})

	t.Run("missing manifest", func(t *testing.T) {
		_, err := loadFixtureManifest(t.TempDir(), "absent")
		if err == nil || !strings.Contains(err.Error(), "read fixture manifest") {
			t.Fatalf("error = %v, want the read-failure wrapper", err)
		}
	})

	// The loader-only parse wrap: a manifest that EXISTS but fails
	// validation surfaces the parse error wrapped with the manifest's full
	// path (the loader branch, not the bare parser error).
	t.Run("existing manifest fails parsing", func(t *testing.T) {
		root := writeFixtureRoot(t, "p", []byte(`{"profile":"p","target":"example.com","http":{"h":{"status":200}},"bogus":1}`), nil)
		_, err := loadFixtureManifest(root, "p")
		if err == nil || !strings.Contains(err.Error(), `unknown field "bogus"`) {
			t.Fatalf("error = %v, want the wrapped parse failure naming the unknown field", err)
		}
		wantWrap := "parse " + filepath.Join(root, "p", manifestName)
		if !strings.Contains(err.Error(), wantWrap) {
			t.Fatalf("error %q does not carry the manifest path wrapper %q", err, wantWrap)
		}
	})

	t.Run("missing js file", func(t *testing.T) {
		doc := validHead + `,"js":{"/app.js":{"file":"missing.js"}}}`
		root := writeFixtureRoot(t, "p", []byte(doc), nil)
		_, err := loadFixtureManifest(root, "p")
		if err == nil || !strings.Contains(err.Error(), "missing.js") {
			t.Fatalf("error = %v, want the missing-file failure naming missing.js", err)
		}
	})

	t.Run("missing http body file", func(t *testing.T) {
		doc := `{"profile":"p","target":"example.com","http":{"h":{"status":404,"body_file":"missing.txt"}}}`
		root := writeFixtureRoot(t, "p", []byte(doc), nil)
		_, err := loadFixtureManifest(root, "p")
		if err == nil || !strings.Contains(err.Error(), "missing.txt") {
			t.Fatalf("error = %v, want the missing-file failure naming missing.txt", err)
		}
	})

	// LOW-2: a referenced path whose cleaned location leaves the profile
	// directory must be rejected with a clear containment error BEFORE any
	// read is attempted. The outside file exists and carries a marker: a
	// regression back to the absorbing filepath.Join would read it (and
	// fail differently), never produce the containment error.
	escapes := []struct {
		name   string
		jsRef  string
		httpFn func(doc string) string
	}{
		{name: "js parent escape", jsRef: "../../outside.js"},
		{name: "js deep nested escape", jsRef: "sub/../../outside.js"},
	}
	for _, esc := range escapes {
		t.Run(esc.name, func(t *testing.T) {
			outside := filepath.Join(t.TempDir(), "outside.js")
			if err := os.WriteFile(outside, []byte("MARKER"), 0o644); err != nil {
				t.Fatalf("seed outside file: %v", err)
			}
			// The escape must climb out of the profile directory, which sits
			// one level below its own temp root: place the profile root so
			// ../../outside.js resolves next to it.
			root := t.TempDir() // the outside file's parent directory
			dir := filepath.Join(root, "p")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			doc := validHead + `,"js":{"/app.js":{"file":"` + esc.jsRef + `"}}}`
			if err := os.WriteFile(filepath.Join(dir, manifestName), []byte(doc), 0o644); err != nil {
				t.Fatalf("WriteFile manifest: %v", err)
			}
			m, err := loadFixtureManifest(root, "p")
			if err == nil {
				t.Fatalf("loadFixtureManifest accepted the escaping reference %q (body %q)", esc.jsRef, m.JS["/app.js"].Body)
			}
			if !strings.Contains(err.Error(), "resolves outside the profile directory") {
				t.Fatalf("error = %v, want the path-containment error", err)
			}
			b, rerr := os.ReadFile(outside)
			if rerr != nil || string(b) != "MARKER" {
				t.Fatalf("the outside file was disturbed: %q (%v)", b, rerr)
			}
		})
	}

	t.Run("http body file parent escape", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "p")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		outside := filepath.Join(root, "outside.txt")
		if err := os.WriteFile(outside, []byte("MARKER"), 0o644); err != nil {
			t.Fatalf("seed outside file: %v", err)
		}
		doc := `{"profile":"p","target":"example.com","http":{"h":{"status":200,"body_file":"../outside.txt"}}}`
		if err := os.WriteFile(filepath.Join(dir, manifestName), []byte(doc), 0o644); err != nil {
			t.Fatalf("WriteFile manifest: %v", err)
		}
		_, err := loadFixtureManifest(root, "p")
		if err == nil || !strings.Contains(err.Error(), "resolves outside the profile directory") {
			t.Fatalf("error = %v, want the path-containment error", err)
		}
	})

	// An absolute-looking reference is treated as profile-relative by
	// filepath.Join semantics and must stay CONTAINED: it fails as a
	// missing file inside the profile directory, never reads the absolute
	// location.
	t.Run("absolute reference stays contained", func(t *testing.T) {
		root := writeFixtureRoot(t, "p", []byte(validHead+`,"js":{"/app.js":{"file":"/etc/passwd"}}}`), nil)
		_, err := loadFixtureManifest(root, "p")
		if err == nil {
			t.Fatal("loadFixtureManifest accepted an absolute file reference")
		}
		if strings.Contains(err.Error(), "resolves outside the profile directory") {
			t.Fatalf("absolute reference escaped containment semantics: %v", err)
		}
		if !strings.Contains(err.Error(), filepath.Join("p", "etc", "passwd")) &&
			!strings.Contains(err.Error(), "no such file") {
			t.Fatalf("error = %v, want a read failure for the CONTAINED profile-relative path", err)
		}
	})
}
