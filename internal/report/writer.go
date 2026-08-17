package report

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

// Output-writing constants (fixed).
const (
	// sinkBufferSize is the buffered writer size for every output part.
	sinkBufferSize = 64 << 10
	// maxBaseNameBytes bounds the sanitized report base name.
	maxBaseNameBytes = 64
	// tmpPrefix prefixes every temporary output file so aborted renders
	// can be identified and never look like reports.
	tmpPrefix = ".ravenrecon-report-"
)

// sanitizeBaseName derives a safe, deterministic file base name from a
// caller-provided or target-derived string: lowercase; every character
// outside [a-z0-9.-] becomes '-'; runs collapse; leading separators are
// stripped; the result is bounded at maxBaseNameBytes and must be non-empty.
// No path separator, dot-dot, or untrusted byte ever survives into a
// filesystem path through this function.
func sanitizeBaseName(s string) (string, error) {
	lowered := strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(lowered))
	last := byte(0)
	for i := 0; i < len(lowered); i++ {
		c := lowered[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
			last = c
		case c == '.' || c == '-':
			if last == '.' || last == '-' || last == 0 {
				continue // no leading separators, no runs
			}
			b.WriteByte(c)
			last = c
		default:
			if last == '-' {
				continue
			}
			b.WriteByte('-')
			last = '-'
		}
		if b.Len() >= maxBaseNameBytes {
			break
		}
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "", fmt.Errorf("report: base name %q sanitizes to empty", s)
	}
	return out, nil
}

// validPartName reports whether part is a legal sink part name: the
// default part (""), or 1..32 bytes of [a-z0-9-]. Part names are
// framework/reporter vocabulary that enter FILENAMES (pathFor), and on
// the cache-hit path they arrive from a decoded cache record — so the
// sink enforces the character class at the single choke point every
// file-creating path goes through, and a path separator, dot-dot, or any
// other byte outside the class is rejected outright, never sanitized
// into a collision.
func validPartName(part string) bool {
	if part == "" {
		return true
	}
	if len(part) > 32 {
		return false
	}
	for i := 0; i < len(part); i++ {
		c := part[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// sinkPart is one part file managed by a fileSink.
type sinkPart struct {
	part   string
	final  string
	tmp    *os.File
	bw     *bufio.Writer
	gw     *gzip.Writer
	wrote  int64
	closed bool
}

// partWriteCloser is the writer handed to a renderer for one part. Close
// flushes the whole chain (gzip, buffer), fsyncs the temp file, and closes
// it — after which the bytes are durably on disk in the temp file, ready
// for the sink's atomic rename.
type partWriteCloser struct {
	sp *sinkPart
	mu sync.Mutex
}

// Write implements io.Writer.
func (w *partWriteCloser) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sp.tmp == nil {
		return 0, fmt.Errorf("report: write to closed part %q", w.sp.part)
	}
	var n int
	var err error
	if w.sp.gw != nil {
		n, err = w.sp.gw.Write(p)
	} else {
		n, err = w.sp.bw.Write(p)
	}
	w.sp.wrote += int64(n)
	return n, err
}

// Close flushes and fsyncs the part's temp file. Double Close is an error.
func (w *partWriteCloser) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	sp := w.sp
	if sp.closed {
		return fmt.Errorf("report: part %q already closed", sp.part)
	}
	sp.closed = true
	if sp.gw != nil {
		if err := sp.gw.Close(); err != nil {
			sp.tmp.Close()
			return fmt.Errorf("report: close gzip stream for part %q: %w", sp.part, err)
		}
	}
	if err := sp.bw.Flush(); err != nil {
		sp.tmp.Close()
		return fmt.Errorf("report: flush part %q: %w", sp.part, err)
	}
	if err := sp.tmp.Sync(); err != nil {
		sp.tmp.Close()
		return fmt.Errorf("report: fsync part %q: %w", sp.part, err)
	}
	if err := sp.tmp.Close(); err != nil {
		return fmt.Errorf("report: close part %q: %w", sp.part, err)
	}
	return nil
}

// fileSink is the engine's Sink: every part renders into a unique
// temporary file in the output directory (created as needed), and Commit
// atomically renames each validated temp file over its final name. A
// reader therefore never observes a partially written report, a cancelled
// or failed render leaves no final file behind, and a report that fails
// validation never overwrites the previous good one.
type fileSink struct {
	mu       sync.Mutex
	dir      string
	compress bool
	pathFor  func(part string) string
	parts    map[string]*sinkPart
	order    []string
	aborted  bool
}

// newFileSink creates the output directory (as needed) and returns a sink
// that renders parts into temporary files there. Directories are created
// with 0700 and files with 0600: reconnaissance output is target data and
// is deliberately private.
func newFileSink(dir string, compress bool, pathFor func(part string) string) (*fileSink, error) {
	if dir == "" {
		return nil, fmt.Errorf("report: output directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("report: create output directory: %w", err)
	}
	return &fileSink{
		dir:      dir,
		compress: compress,
		pathFor:  pathFor,
		parts:    make(map[string]*sinkPart),
	}, nil
}

// Writer implements Sink: the part renders through the sink's
// compression layer when the sink is compressed.
func (s *fileSink) Writer(part string) (io.WriteCloser, error) {
	return s.writer(part, s.compress)
}

// RawWriter returns a part writer that skips the sink's compression
// layer: bytes are written to the temp file exactly as given, with every
// other sink semantic kept (unique temp file, fsync, close, abort with
// partial-part removal, validation, atomic rename). It exists for the
// cache-hit commit path, where the stored part bytes ARE the final file
// bytes (gzip-compressed for compressed reporters) and must not be
// compressed a second time.
func (s *fileSink) RawWriter(part string) (io.WriteCloser, error) {
	return s.writer(part, false)
}

// writer is the shared part-writer implementation; compress selects
// whether the returned writer wraps the part in a gzip stream.
func (s *fileSink) writer(part string, compress bool) (io.WriteCloser, error) {
	if !validPartName(part) {
		return nil, fmt.Errorf("report: invalid sink part name %q", part)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted {
		return nil, fmt.Errorf("report: sink is aborted")
	}
	if _, ok := s.parts[part]; ok {
		return nil, fmt.Errorf("report: sink part %q already opened", part)
	}
	tmp, err := os.CreateTemp(s.dir, tmpPrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("report: create temp file for part %q: %w", part, err)
	}
	sp := &sinkPart{part: part, final: s.pathFor(part), tmp: tmp, bw: bufio.NewWriterSize(tmp, sinkBufferSize)}
	if compress {
		sp.gw = gzip.NewWriter(sp.bw)
	}
	s.parts[part] = sp
	s.order = append(s.order, part)
	return &partWriteCloser{sp: sp}, nil
}

// closeAll closes any still-open parts (best effort; used by Abort).
func (s *fileSink) closeAll() {
	for _, part := range s.order {
		sp := s.parts[part]
		if !sp.closed {
			if sp.gw != nil {
				sp.gw.Close()
			}
			sp.bw.Flush()
			sp.tmp.Close()
			sp.closed = true
		}
	}
}

// Abort tears the sink down: every temp file is closed and removed and no
// final file is ever created. The sink is unusable afterwards.
func (s *fileSink) Abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted {
		return
	}
	s.aborted = true
	s.closeAll()
	for _, part := range s.order {
		os.Remove(s.parts[part].tmp.Name())
	}
}

// sinkPartInfo describes one rendered part for validation and commit.
type sinkPartInfo struct {
	// Part is the part name ("" for single-part reports).
	Part string
	// Tmp is the validated temp file path.
	Tmp string
	// Final is the committed (renamed) path.
	Final string
	// Bytes is the number of bytes written through the part's writer:
	// the uncompressed count on a compressed fresh render (the file on
	// disk is smaller), or the exact file size when the part was written
	// raw (the cache-hit commit path).
	Bytes int64
	// Compressed reports whether the file is gzip-compressed.
	Compressed bool
}

// Parts returns every opened part sorted by part name. Every part must be
// closed before Validate/Commit.
func (s *fileSink) Parts() ([]sinkPartInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.partsLocked()
}

// partsLocked is Parts without locking (callers must hold s.mu).
func (s *fileSink) partsLocked() ([]sinkPartInfo, error) {
	out := make([]sinkPartInfo, 0, len(s.order))
	names := append([]string(nil), s.order...)
	sort.Strings(names)
	for _, name := range names {
		sp := s.parts[name]
		if !sp.closed {
			return nil, fmt.Errorf("report: sink part %q is still open", name)
		}
		// A part without a compression layer that rendered no bytes is a
		// genuinely empty file (a gzip-wrapped part would still carry its
		// header); the per-part check covers the raw-writer path too.
		if sp.wrote == 0 && sp.gw == nil {
			return nil, fmt.Errorf("report: sink part %q rendered no bytes", name)
		}
		out = append(out, sinkPartInfo{
			Part:       sp.part,
			Final:      sp.final,
			Tmp:        sp.tmp.Name(),
			Bytes:      sp.wrote,
			Compressed: s.compress,
		})
	}
	return out, nil
}

// Commit atomically renames every validated temp file over its final name
// (sorted by part name — the deterministic commit order). Each rename is
// atomic; a multi-part commit is therefore atomic per file, never
// transactional across files.
func (s *fileSink) Commit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted {
		return fmt.Errorf("report: sink is aborted")
	}
	parts, err := s.partsLocked()
	if err != nil {
		return err
	}
	for _, info := range parts {
		if err := os.Rename(info.Tmp, info.Final); err != nil {
			return fmt.Errorf("report: commit part %q: %w", info.Part, err)
		}
	}
	return nil
}

// memSink is an in-memory Sink for tests and previews. Parts are retained
// as byte buffers; it applies the same open-each-part-once contract.
type memSink struct {
	mu     sync.Mutex
	parts  map[string]*bytes.Buffer
	opened map[string]bool
	closed map[string]bool
}

// newMemSink returns an empty memory sink.
func newMemSink() *memSink {
	return &memSink{
		parts:  make(map[string]*bytes.Buffer),
		opened: make(map[string]bool),
		closed: make(map[string]bool),
	}
}

// Writer implements Sink.
func (s *memSink) Writer(part string) (io.WriteCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.opened[part] {
		return nil, fmt.Errorf("report: sink part %q already opened", part)
	}
	buf := &bytes.Buffer{}
	s.parts[part] = buf
	s.opened[part] = true
	return &memWriteCloser{sink: s, part: part, buf: buf}, nil
}

// buffer returns a copy of one part's bytes.
func (s *memSink) buffer(part string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf, ok := s.parts[part]
	if !ok {
		return nil, fmt.Errorf("report: no such part %q", part)
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

// memWriteCloser wraps one memory part.
type memWriteCloser struct {
	sink *memSink
	part string
	buf  *bytes.Buffer
	once bool
}

// Write implements io.Writer.
func (w *memWriteCloser) Write(p []byte) (int, error) {
	if w.once {
		return 0, fmt.Errorf("report: write to closed part %q", w.part)
	}
	return w.buf.Write(p)
}

// Close marks the part closed.
func (w *memWriteCloser) Close() error {
	if w.once {
		return fmt.Errorf("report: part %q already closed", w.part)
	}
	w.once = true
	w.sink.mu.Lock()
	w.sink.closed[w.part] = true
	w.sink.mu.Unlock()
	return nil
}
