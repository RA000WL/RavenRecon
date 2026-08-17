package report

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// validateLineBytes bounds one line the text validators buffer (fixed
// constant): an HTML row or Markdown line larger than this is suspicious of
// a corrupted render.
const validateLineBytes = 1 << 20

// openValidated opens a rendered part file for validation, transparently
// decompressing it when compressed.
func openValidated(path string, compressed bool) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("report: validate: open: %w", err)
	}
	if !compressed {
		return f, nil
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("report: validate: gzip: %w", err)
	}
	return &closeBoth{gz, f}, nil
}

// closeBoth closes the gzip reader and the underlying file.
type closeBoth struct {
	gz io.ReadCloser
	f  io.ReadCloser
}

func (c *closeBoth) Read(p []byte) (int, error) { return c.gz.Read(p) }
func (c *closeBoth) Close() error {
	err := c.gz.Close()
	if ferr := c.f.Close(); err == nil {
		err = ferr
	}
	return err
}

// validateJSONFile checks a rendered JSON export: it decodes as exactly one
// JSON value, its schema version matches the framework's, and nothing
// follows the document.
func validateJSONFile(path string, compressed bool) error {
	r, err := openValidated(path, compressed)
	if err != nil {
		return err
	}
	defer r.Close()
	dec := json.NewDecoder(r)
	var head struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := dec.Decode(&head); err != nil {
		return fmt.Errorf("report: validate json: decode: %w", err)
	}
	if head.SchemaVersion != SchemaVersion {
		return fmt.Errorf("report: validate json: schema version %d does not match %d", head.SchemaVersion, SchemaVersion)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("report: validate json: trailing content after the document")
	}
	return nil
}

// validateCSVFile checks a rendered CSV table: it parses completely as CSV
// with a non-empty header row and a uniform field count on every row.
func validateCSVFile(path string, compressed bool) error {
	r, err := openValidated(path, compressed)
	if err != nil {
		return err
	}
	defer r.Close()
	cr := csv.NewReader(r)
	header, err := cr.Read()
	if err != nil {
		return fmt.Errorf("report: validate csv: header: %w", err)
	}
	if len(header) == 0 {
		return fmt.Errorf("report: validate csv: empty header row")
	}
	cr.FieldsPerRecord = len(header)
	for {
		if _, err := cr.Read(); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("report: validate csv: %w", err)
		}
	}
}

// validateMarkdownFile checks a rendered Markdown report: non-empty, the
// first non-empty line is a heading, and code fences are balanced.
func validateMarkdownFile(path string, compressed bool) error {
	r, err := openValidated(path, compressed)
	if err != nil {
		return err
	}
	defer r.Close()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), validateLineBytes)
	sawContent := false
	sawHeading := false
	fences := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		sawContent = true
		if !sawHeading {
			if !strings.HasPrefix(line, "# ") {
				return fmt.Errorf("report: validate markdown: first non-empty line is not a heading")
			}
			sawHeading = true
		}
		if strings.HasPrefix(line, "```") {
			fences++
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("report: validate markdown: %w", err)
	}
	if !sawContent {
		return fmt.Errorf("report: validate markdown: document is empty")
	}
	if fences%2 != 0 {
		return fmt.Errorf("report: validate markdown: unbalanced code fences (%d)", fences)
	}
	return nil
}

// validateHTMLFile checks a rendered HTML report: non-empty, carries the
// closing html tag, and every opened <details> section is closed.
func validateHTMLFile(path string, compressed bool) error {
	r, err := openValidated(path, compressed)
	if err != nil {
		return err
	}
	defer r.Close()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), validateLineBytes)
	sawContent := false
	sawClose := false
	open := 0
	closed := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		sawContent = true
		if strings.Contains(line, "</html>") {
			sawClose = true
		}
		open += strings.Count(line, "<details")
		closed += strings.Count(line, "</details>")
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("report: validate html: %w", err)
	}
	if !sawContent {
		return fmt.Errorf("report: validate html: document is empty")
	}
	if !sawClose {
		return fmt.Errorf("report: validate html: missing closing html tag")
	}
	if open != closed {
		return fmt.Errorf("report: validate html: unbalanced details sections (%d opened, %d closed)", open, closed)
	}
	return nil
}

// validateNonEmpty is the default check for custom reporters that declare
// no Validate function: the rendered part must be non-empty (and must
// decompress when compressed).
func validateNonEmpty(path string, compressed bool) error {
	r, err := openValidated(path, compressed)
	if err != nil {
		return err
	}
	defer r.Close()
	buf := make([]byte, 1)
	n, err := r.Read(buf)
	if err == io.EOF || n == 0 {
		return fmt.Errorf("report: validate: %s is empty", path)
	}
	if err != nil {
		return fmt.Errorf("report: validate: read %s: %w", path, err)
	}
	return nil
}
