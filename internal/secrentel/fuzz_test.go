package secrentel

import (
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// fuzzDocKinds indexes the document kinds exercised by FuzzScanDocument.
var fuzzDocKinds = []DocumentKind{
	KindJS, KindSourceMap, KindHTML, KindJSON, KindEnv,
	KindConfig, KindYAML, KindXML, KindGraphQL, KindOpenAPI, KindHTTP,
}

// FuzzScanDocument drives scanDocument — the engine's pure content-scan
// boundary (pattern matching → validation → dedup → correlation) — with
// arbitrary bytes through prepareDocument, the single normalization point.
// The production pattern DB (patterns.Load) backs every match. Invariants
// under hostile input:
//
//   - no panic and no hang (every per-document cap is fixed);
//   - candidates never exceed limits.maxCandidates (the overflow counter
//     accounts for the rest — nothing silently unbounded);
//   - dedup by (type, value) holds: no two candidates share both;
//   - every stored value is non-empty and within the asset-layer 512-byte
//     bound (see secret.go scannedCandidate.value).
func FuzzScanDocument(f *testing.F) {
	db, err := patterns.Load()
	if err != nil {
		f.Fatalf("load production patterns: %v", err)
	}

	seeds := []string{
		"",
		"\n",
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", // canonical documented example value
		`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
		`token = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789ABCD"`, // ghp_ + 36 alnum shape
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"-----BEGIN PRIVATE KEY-----\nMIIBsynthetic\n-----END PRIVATE KEY-----",
		strings.Repeat("AKIAABCDEFGHIJKLMNOP", 64), // repeated identical candidate: dedup path
		"\x00\x01\xff binary junk \xc3\x28 bytes",
		strings.Repeat("password=hunter2\n", 500),
		"secret=\u00e9\u00e1 multibyte \u4e2d\u6587 value",
		`{"api_key":"sk_test_synthetic_placeholder_value_1234567890abcdef"}`,
	}
	for i, s := range seeds {
		f.Add([]byte(s), int8(i%len(fuzzDocKinds)), "config_"+strings.Repeat("x", i%3)+".js")
	}

	f.Fuzz(func(t *testing.T, content []byte, kind int8, filename string) {
		docKind := fuzzDocKinds[int(uint8(kind))%len(fuzzDocKinds)]
		sd, err := prepareDocument(Document{
			Kind:     docKind,
			Content:  content,
			Filename: filename,
		}, fixedTime(0))
		if err != nil {
			// Honest rejection of over-bound metadata is correct behavior.
			return
		}

		limits := defaultScanLimits()
		out := scanDocument(sd, db, limits)

		if len(out.candidates) > limits.maxCandidates {
			t.Fatalf("%d candidates exceed maxCandidates %d", len(out.candidates), limits.maxCandidates)
		}

		type candKey struct{ typ, value string }
		seen := make(map[candKey]struct{}, len(out.candidates))
		for _, c := range out.candidates {
			k := candKey{typ: string(c.typ), value: c.value}
			if _, dup := seen[k]; dup {
				t.Fatalf("duplicate candidate for (type,value)=(%q,%q)", c.typ, c.value)
			}
			seen[k] = struct{}{}
			if c.value == "" {
				t.Fatalf("candidate of type %q has an empty stored value", c.typ)
			}
			if len(c.value) > 512 { // asset-layer stored-value bound (scannedCandidate.value)
				t.Fatalf("stored value is %d bytes, over the 512-byte asset-layer bound", len(c.value))
			}
		}
	})
}
