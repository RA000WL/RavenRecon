package secrentel

import (
	"strings"
	"testing"
)

func TestExtractContextNames(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		offset   int
		variable string
		jsonKey  string
	}{
		{"js assignment", `const awsAccessKey = "AKIAIOSFODNN7REALKEY";`, 21, "awsAccessKey", ""},
		{"js quoted key", `config["apiKey"] = "a1b2c3"`, 15, "", ""}, // bracket form is not extracted
		{"json", `{"apiKey": "a1b2c3d4e5f6a7b8c9d0"}`, 11, "", "apiKey"},
		{"yaml", `aws_secret_access_key: wJalr...`, 22, "aws_secret_access_key", ""},
		{"env", `AWS_SECRET_ACCESS_KEY=wJalr...`, 22, "AWS_SECRET_ACCESS_KEY", ""},
		{"no shape", `AKIAIOSFODNN7REALKEY`, 0, "", ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v, k := extractName([]byte(tt.content), tt.offset)
			if v != tt.variable || k != tt.jsonKey {
				t.Errorf("extractName = (%q, %q), want (%q, %q)", v, k, tt.variable, tt.jsonKey)
			}
		})
	}
}

func TestExtractContextCommentDetection(t *testing.T) {
	content := []byte("var a = 1; // token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\nvar b = 2; /* secret=AKIAABCDEFGHIJKLMNOP */\nvar c = \"AKIAABCDEFGHIJKLMNOP\";")
	idx := buildStateIndex(content)
	if !inComment(content, len("var a = 1; // token="), idx) {
		t.Error("line comment content must be detected")
	}
	if !inComment(content, len("var a = 1; // token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\nvar b = 2; /* secret="), idx) {
		t.Error("block comment content must be detected")
	}
	if inComment(content, len("var a = 1; // token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\nvar b = 2; /* secret=AKIAABCDEFGHIJKLMNOP */\nvar c=\""), idx) {
		t.Error("code after a closed block comment is not a comment")
	}
	if inComment(content, 0, idx) {
		t.Error("document start is not a comment")
	}
}

func TestInCommentStringAware(t *testing.T) {
	// Comment markers inside string literals are quoted material, not
	// comment openers; unquoted markers later on the same line still count.
	cases := []struct {
		name    string
		content string
		offset  int
		want    bool
	}{
		{
			"double-quoted // is data",
			`const s = "// not a comment";`,
			len(`const s = "`),
			false,
		},
		{
			"single-quoted // is data",
			`const s = '// not a comment';`,
			len(`const s = '`),
			false,
		},
		{
			"quoted URL then real comment",
			`const u = "https://example.com/x"; // real`,
			len(`const u = "https://example.com/x"; // `),
			true,
		},
		{
			"quoted # then unquoted # on the same line",
			`const s = "a#b"; # hash comment`,
			len(`const s = "a#b"; # `),
			true,
		},
		{
			"quoted # alone is not a comment",
			`const s = "a#b";`,
			len(`const s = "a`),
			false,
		},
		{
			"block comment wins over quote-shaped text inside it",
			`/* const s = "AKIAIOSFODNN7REALKEY"; */`,
			len(`/* const s = "`),
			true,
		},
		{
			"escaped quote keeps the string open",
			`const s = "a\"; // still inside the string`,
			len(`const s = "a\"; // `),
			false,
		},
		{
			"backtick string spans lines",
			"const tpl = `line1\n// inside template\nline2`;\n// real comment",
			len("const tpl = `line1\n"),
			false,
		},
		{
			"backtick string closed, later comment counts",
			"const tpl = `a`;\n// real comment",
			len("const tpl = `a`;\n// "),
			true,
		},
		{
			"quoted google key in a hash comment is still a comment",
			`# apiKey: "AIzaSyA1234567890abcdefghijklmnopqrstuvwxyz"`,
			len(`# apiKey: "AIza`),
			true,
		},
		{
			"quoted env value in a hash comment is still a comment",
			`# AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
			len(`# AWS_SECRET_ACCESS_KEY="wJalr`),
			true,
		},
		{
			"unterminated quote inside a hash comment is still a comment",
			`# example: "old aws_access_key_id=AKIAIOSFODNN7REALKEY`,
			len(`# example: "old aws_`),
			true,
		},
		{
			"// comment with a quoted secret is still a comment",
			`// secret="AKIAIOSFODNN7REALKEY"`,
			len(`// secret="`),
			true,
		},
		{
			"quoted URL never opens a comment for the next assignment",
			"const url = \"https://api.example.com/x\"\nconst k = \"AKIAIOSFODNN7REALKEY\";",
			len("const url = \"https://api.example.com/x\"\nconst k = \""),
			false,
		},
		{
			"closed block comment with # inside does not comment the rest of the line",
			// The forward pass consumed /* ... */, so the # left no line
			// interval; the fallback must not re-read it as a comment opener.
			`/* #1 */ k=AKIAIOSFODNN7REALKEY`,
			len(`/* #1 */ k=`),
			false,
		},
		{
			"closed block comment with // inside does not comment the rest of the line",
			`/* a // b */ k=AKIAIOSFODNN7REALKEY`,
			len(`/* a // b */ k=`),
			false,
		},
		{
			"markers inside an open block comment are still comment material",
			`/* # secret="AKIAIOSFODNN7REALKEY" */`,
			len(`/* # secret="`),
			true,
		},
		{
			"real line comment after a closed block comment still counts",
			`/* x */ # real comment`,
			len(`/* x */ # `),
			true,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			content := []byte(tt.content)
			idx := buildStateIndex(content)
			if got := inComment(content, tt.offset, idx); got != tt.want {
				t.Errorf("inComment(%q@%d) = %v, want %v", tt.content, tt.offset, got, tt.want)
			}
		})
	}
}

func TestInCommentCappedFallsBackToLegacy(t *testing.T) {
	// A document whose string intervals exceed the cap falls back to the
	// legacy line scan: bounded, deterministic, still detecting plain
	// comments.
	var b strings.Builder
	for i := 0; i < maxTrackedIntervals+64; i++ {
		b.WriteString(`"x";`)
	}
	b.WriteString("// real comment")
	content := []byte(b.String())
	idx := buildStateIndex(content)
	if !idx.capped {
		t.Fatal("state index must report the cap")
	}
	off := len(b.String()) - len("real comment")
	if !inComment(content, off, idx) {
		t.Error("legacy fallback must still detect a plain line comment")
	}
}

func TestExtractContextNearbyAndHint(t *testing.T) {
	content := []byte(`const cfg = {region: "us-east-1", accessKey: "AKIAIOSFODNN7REALKEY"}; // aws sdk`)
	start := len(`const cfg = {region: "us-east-1", accessKey: "`)
	idx := buildStateIndex(content)
	ctx := extractContext(content, start, start+20, "aws", []string{"aws_access_key_id", "access_key"}, []string{"aws", "amazon", "sdk"}, idx)
	if ctx.Variable != "" && ctx.JSONKey != "" {
		t.Errorf("variable and JSON key are mutually exclusive: %v", ctx)
	}
	if ctx.NameHint == "" {
		t.Errorf("accessKey should match the aws hint/provider: %+v", ctx)
	}
	if len(ctx.Nearby) == 0 {
		t.Error("nearby positive indicators must be matched in the window")
	}

	// No hint in the name → weak context only.
	content2 := []byte(`const blob = "AKIAIOSFODNN7REALKEY";`)
	ctx2 := extractContext(content2, len(`const blob = "`), len(`const blob = "`)+20, "aws", nil, nil, buildStateIndex(content2))
	if ctx2.NameHint != "" {
		t.Errorf("no hints configured, no hint expected: %+v", ctx2)
	}
}

func TestLineIndexLocate(t *testing.T) {
	content := []byte("first\nsecond\nthird\n")
	idx := buildLineIndex(content)
	cases := []struct {
		offset int
		line   int
		column int
	}{
		{0, 1, 1},
		{3, 1, 4},
		{6, 2, 1},
		{8, 2, 3},
		{13, 3, 1},
		{18, 3, 6}, // the final newline itself belongs to line 3
	}
	for _, tt := range cases {
		loc := idx.locate(tt.offset)
		if loc.Line != tt.line || loc.Column != tt.column {
			t.Errorf("locate(%d) = line %d col %d, want line %d col %d", tt.offset, loc.Line, loc.Column, tt.line, tt.column)
		}
	}

	// Hostile newline soup: the index is bounded and lookups beyond the cap
	// report line 0.
	big := make([]byte, maxTrackedLines+2048)
	for i := range big {
		big[i] = '\n'
	}
	idx = buildLineIndex(big)
	if len(idx.starts) > maxTrackedLines+1 {
		t.Errorf("index grew to %d starts", len(idx.starts))
	}
	loc := idx.locate(len(big) - 1)
	if loc.Column < 1 {
		t.Errorf("column must be >= 1 even beyond the cap, got %d", loc.Column)
	}
}
