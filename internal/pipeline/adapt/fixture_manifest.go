package adapt

// fixtureManifest is the JSON manifest format for the v1.7 acceptance
// fixture profiles (NEW-56 D1: hybrid weighted static fixtures). One
// manifest per profile directory under fixtures/<profile>/manifest.json;
// JS bodies may be separate .js files referenced by "file" and served
// through the loopback server exactly as the T4 harness does.
//
// This file is deliberately NON-test code: parsing and validating the
// manifest format is pure data handling with no test doubles involved, so
// it compiles into the production package without changing production
// behavior (the materialization of a manifest into the hermetic T4 seams —
// fake runners, fake resolver, canned transports — lives in the package's
// acceptance test-support file, because the seam types themselves are
// test-file-local).
//
// Manifest schema (all keys required unless marked optional; unknown keys
// are rejected at decode time so typos fail loudly):
//
//	profile      string  — must equal the manifest's directory name
//	target       string  — the declared scan target (canonical domain)
//	discovery    object  — discovery tool scripting:
//	  detections   map[argvKey]{stdout,stderr,exit_code} — tool-detection probes
//	  runs         map[argvKey]{stdout,stderr,exit_code} — discovery executions
//	             (argvKey is "path arg1 arg2 ...", the fakeRunner key form)
//	dns          map[host]{A:[], AAAA:[], CNAME:[]} — canned answers
//	dns_poison   optional, same shape — answers used ONLY by the seeding
//	             run of the cache-poisoning scenario (messy profile); the
//	             warm runs then serve the poisoned records from cache
//	http         map[key]{status,headers,body,body_file,body_oversized} —
//	             canned HTTP responses; key forms tried in order:
//	             "scheme://host/path" (exact), "scheme://host", "host"
//	urlintel     []string — raw gau output lines for the target
//	js           map[path]{file|body|oversized,status?,headers?} — loopback-
//	             served script bodies keyed by URL path ("/app.js")
//	stage_params optional map[stageName]map[string]string — pipeline
//	             StageParams passed through ScanConfig (e.g. the discovery
//	             quality-gate keys)
import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// manifestName is the manifest file every profile directory must contain.
const manifestName = "manifest.json"

// fixtureToolResult scripts one fake-runner invocation (a detection probe
// or a discovery execution).
type fixtureToolResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

// fixtureDNSRecords are one host's canned DNS answers. Absent record types
// resolve as legitimate empty answers (NODATA), matching fakeResolver.
type fixtureDNSRecords struct {
	A     []string `json:"A"`
	AAAA  []string `json:"AAAA"`
	CNAME []string `json:"CNAME"`
}

// fixtureHTTPResponse is one canned probe response.
type fixtureHTTPResponse struct {
	Status        int               `json:"status"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	BodyFile      string            `json:"body_file"`
	BodyOversized bool              `json:"body_oversized"`
}

// fixtureJSBody is one loopback-served script body.
type fixtureJSBody struct {
	File      string            `json:"file"`
	Body      string            `json:"body"`
	Oversized bool              `json:"oversized"`
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
}

// fixtureManifest is the decoded, validated manifest document.
type fixtureManifest struct {
	Profile     string
	Target      string
	Detections  map[string]fixtureToolResult
	Runs        map[string]fixtureToolResult
	DNS         map[string]fixtureDNSRecords
	DNSPoison   map[string]fixtureDNSRecords
	HTTP        map[string]fixtureHTTPResponse
	URLIntel    []string
	JS          map[string]fixtureJSBody
	StageParams map[string]map[string]string
}

// fixtureDiscovery is the manifest's "discovery" object.
type fixtureDiscovery struct {
	Detections map[string]fixtureToolResult `json:"detections"`
	Runs       map[string]fixtureToolResult `json:"runs"`
}

// fixtureRaw mirrors the on-disk JSON shape of a manifest.
type fixtureRaw struct {
	Profile     string                         `json:"profile"`
	Target      string                         `json:"target"`
	Discovery   *fixtureDiscovery              `json:"discovery"`
	DNS         map[string]fixtureDNSRecords   `json:"dns"`
	DNSPoison   map[string]fixtureDNSRecords   `json:"dns_poison"`
	HTTP        map[string]fixtureHTTPResponse `json:"http"`
	URLIntel    []string                       `json:"urlintel"`
	JS          map[string]fixtureJSBody       `json:"js"`
	StageParams map[string]map[string]string   `json:"stage_params"`
}

// resolveProfilePath resolves one manifest-referenced relative path
// (slash-separated, e.g. "app.js" or "bodies/lib.js") inside the profile
// directory and REJECTS directory escapes: the joined path must stay
// within fixtures/<dir>. filepath.Join would silently absorb "../.."
// (joining cleans the result), so containment is verified with
// filepath.Rel — any result at or above the profile directory is an
// error, never a read outside the fixture tree.
//
// Containment is LEXICAL ONLY: symlinks inside the profile directory are
// followed. That is acceptable for repo-committed fixtures and test temp
// roots; harden this path with filepath.EvalSymlinks if profiles ever
// become externally supplied.
func resolveProfilePath(fixturesRoot, dir, slashPath string) (string, error) {
	profileDir := filepath.Join(fixturesRoot, dir)
	joined := filepath.Join(profileDir, filepath.FromSlash(slashPath))
	rel, err := filepath.Rel(profileDir, joined)
	if err != nil {
		return "", fmt.Errorf("fixture path %q: %w", slashPath, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("fixture path %q resolves outside the profile directory %q", slashPath, dir)
	}
	return joined, nil
}

// loadFixtureManifest reads and validates fixtures/<dir>/manifest.json.
// The returned manifest references no filesystem handles; body files are
// resolved later by the caller (which owns the error reporting policy).
func loadFixtureManifest(fixturesRoot, dir string) (fixtureManifest, error) {
	path := filepath.Join(fixturesRoot, dir, manifestName)
	data, err := os.ReadFile(path)
	if err != nil {
		return fixtureManifest{}, fmt.Errorf("read fixture manifest: %w", err)
	}
	m, err := parseFixtureManifest(data)
	if err != nil {
		return fixtureManifest{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if m.Profile != dir {
		return fixtureManifest{}, fmt.Errorf("parse %s: profile %q does not match directory %q", path, m.Profile, dir)
	}
	// Resolve relative file references eagerly so a missing .js fixture
	// fails at load time, not mid-run. Every reference is confined to the
	// profile directory (resolveProfilePath) — a "../.." escape fails
	// loudly instead of reading outside the fixture tree.
	for p, jb := range m.JS {
		if jb.File == "" {
			continue
		}
		fp, err := resolveProfilePath(fixturesRoot, dir, jb.File)
		if err != nil {
			return fixtureManifest{}, fmt.Errorf("parse %s: js %s: %w", path, p, err)
		}
		b, err := os.ReadFile(fp)
		if err != nil {
			return fixtureManifest{}, fmt.Errorf("parse %s: js %s: %w", path, p, err)
		}
		jb.Body = string(b)
		m.JS[p] = jb
	}
	for k, hr := range m.HTTP {
		if hr.BodyFile == "" {
			continue
		}
		fp, err := resolveProfilePath(fixturesRoot, dir, hr.BodyFile)
		if err != nil {
			return fixtureManifest{}, fmt.Errorf("parse %s: http %s: %w", path, k, err)
		}
		b, err := os.ReadFile(fp)
		if err != nil {
			return fixtureManifest{}, fmt.Errorf("parse %s: http %s: %w", path, k, err)
		}
		hr.Body = string(b)
		m.HTTP[k] = hr
	}
	return m, nil
}

// parseFixtureManifest decodes and structurally validates one manifest
// document. Unknown fields are rejected so a schema typo fails loudly
// instead of silently materializing an empty fixture.
func parseFixtureManifest(data []byte) (fixtureManifest, error) {
	var raw fixtureRaw
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return fixtureManifest{}, err
	}
	m := fixtureManifest{
		Profile:     raw.Profile,
		Target:      raw.Target,
		DNS:         raw.DNS,
		DNSPoison:   raw.DNSPoison,
		HTTP:        raw.HTTP,
		URLIntel:    raw.URLIntel,
		JS:          raw.JS,
		StageParams: raw.StageParams,
	}
	if raw.Profile == "" {
		return fixtureManifest{}, fmt.Errorf("profile must not be empty")
	}
	if raw.Target == "" {
		return fixtureManifest{}, fmt.Errorf("target must not be empty")
	}
	if raw.Discovery != nil {
		m.Detections = raw.Discovery.Detections
		m.Runs = raw.Discovery.Runs
		if len(m.Detections) == 0 && len(m.Runs) == 0 {
			return fixtureManifest{}, fmt.Errorf("discovery must set detections and/or runs")
		}
	}
	if len(m.HTTP) == 0 {
		return fixtureManifest{}, fmt.Errorf("http responses must not be empty")
	}
	for k, hr := range m.HTTP {
		switch {
		case hr.Status < 100 || hr.Status > 599:
			return fixtureManifest{}, fmt.Errorf("http %s: status %d out of range", k, hr.Status)
		case hr.BodyFile != "" && hr.Body != "":
			return fixtureManifest{}, fmt.Errorf("http %s: body and body_file are mutually exclusive", k)
		case hr.BodyOversized && (hr.Body != "" || hr.BodyFile != ""):
			return fixtureManifest{}, fmt.Errorf("http %s: body_oversized excludes body/body_file", k)
		}
	}
	for p, jb := range m.JS {
		n := 0
		for _, s := range []bool{jb.File != "", jb.Body != "", jb.Oversized} {
			if s {
				n++
			}
		}
		if n > 1 {
			return fixtureManifest{}, fmt.Errorf("js %s: file, body, and oversized are mutually exclusive", p)
		}
		if n == 0 {
			return fixtureManifest{}, fmt.Errorf("js %s: one of file, body, oversized is required", p)
		}
		if jb.Status != 0 && (jb.Status < 100 || jb.Status > 599) {
			return fixtureManifest{}, fmt.Errorf("js %s: status %d out of range", p, jb.Status)
		}
	}
	for stage, params := range m.StageParams {
		if len(params) == 0 {
			return fixtureManifest{}, fmt.Errorf("stage_params %s: empty parameter set", stage)
		}
	}
	return m, nil
}
