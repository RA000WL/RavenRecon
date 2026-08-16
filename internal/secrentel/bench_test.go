package secrentel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/RA000WL/RavenRecon/internal/secrentel/patterns"
)

// syntheticBundle builds a deterministic minified-JS bundle of the given
// size seeded with a configurable number of secrets.
func syntheticBundle(size int, secrets int) []byte {
	var b strings.Builder
	b.WriteString("/*! synthetic bundle */")
	i := 0
	for b.Len() < size {
		var embed string
		if i < secrets {
			switch i % 4 {
			case 0:
				embed = fmt.Sprintf(`,k%d="%s"`, i, "AKIA"+detRand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 7, i))
			case 1:
				embed = fmt.Sprintf(`,aws_secret_access_key="%s"`, detRand(40, alnumMixed+"/+=", 17, i))
			case 2:
				embed = fmt.Sprintf(`,t%d="%s"`, i, "ghp_"+detRand(36, alnumMixed, 11, i))
			default:
				embed = fmt.Sprintf(`,j%d="%s"`, i, jwtValue)
			}
		}
		fmt.Fprintf(&b, `function f%d(){var x%d="%s"%s;return x%d};`, i, i, detRand(24, alnumMixed, 7, i%37), embed, i)
		i++
	}
	return []byte(b.String())
}

func benchDoc(b *testing.B, size, secrets int) scannedDocument {
	b.Helper()
	sd, err := prepareDocument(Document{Kind: KindJS, Content: syntheticBundle(size, secrets)}, fixedTime(0))
	if err != nil {
		b.Fatal(err)
	}
	return sd
}

func BenchmarkScanPatternEngine512K(b *testing.B) {
	db, err := patterns.Load()
	if err != nil {
		b.Fatal(err)
	}
	sd := benchDoc(b, 512<<10, 0)
	limits := defaultScanLimits()
	b.SetBytes(int64(len(sd.content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := scanDocument(sd, db, limits)
		if len(out.candidates) != 0 {
			b.Fatal("unexpected candidates")
		}
	}
}

func BenchmarkScanLargeBundle2M(b *testing.B) {
	db, err := patterns.Load()
	if err != nil {
		b.Fatal(err)
	}
	sd := benchDoc(b, 2<<20, 8)
	limits := defaultScanLimits()
	b.SetBytes(int64(len(sd.content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 2 AKIA + 2 AWS secrets + 2 GitHub tokens + 1 deduplicated JWT.
		if out := scanDocument(sd, db, limits); len(out.candidates) != 7 {
			b.Fatalf("candidates = %d, want 7", len(out.candidates))
		}
	}
}

func BenchmarkScanHugeJSON(b *testing.B) {
	db, err := patterns.Load()
	if err != nil {
		b.Fatal(err)
	}
	var bld strings.Builder
	bld.WriteString("{")
	for i := 0; i < 10000; i++ {
		if i > 0 {
			bld.WriteString(",")
		}
		fmt.Fprintf(&bld, `"k%d":"%s"`, i, detRand(32, alnumMixed, 7, i%61))
	}
	bld.WriteString("}")
	sd, err := prepareDocument(Document{Kind: KindJSON, Content: []byte(bld.String())}, fixedTime(0))
	if err != nil {
		b.Fatal(err)
	}
	limits := defaultScanLimits()
	b.SetBytes(int64(len(sd.content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanDocument(sd, db, limits)
	}
}

func BenchmarkEntropyAssess(b *testing.B) {
	values := make([]string, 0, 256)
	for i := 0; i < 256; i++ {
		values = append(values, detRand(40, alnumMixed, 7, i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AssessEntropy(values[i%len(values)])
	}
}

func BenchmarkEntropyMemoized(b *testing.B) {
	c := newEntropyCache()
	value := detRand(40, alnumMixed, 7, 3)
	c.assess(value)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.assess(value)
	}
}

func BenchmarkCorrelateSignals(b *testing.B) {
	db, err := patterns.Load()
	if err != nil {
		b.Fatal(err)
	}
	content := syntheticBundle(256<<10, 4)
	correlations := db.Correlations()
	tech := []string{"aws-sdk", "stripe.js"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanSignals(content, correlations, tech)
	}
}

func BenchmarkIngestEndToEnd(b *testing.B) {
	db, err := patterns.Load()
	if err != nil {
		b.Fatal(err)
	}
	docs := make([]Document, 0, 32)
	for i := 0; i < 32; i++ {
		docs = append(docs, Document{Kind: KindJS, Content: syntheticBundle(64<<10, 2)})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := SliceDocumentSource(append([]Document(nil), docs...))
		if _, err := Ingest(b.Context(), Config{Concurrency: 4, QueueSize: 32, Timeout: 0, DB: db}, &src); err != nil {
			b.Fatal(err)
		}
	}
}
