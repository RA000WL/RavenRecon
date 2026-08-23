package importer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// PeekSize is the first 32 KiB buffered once for format detection, then Seek(0,0).
const PeekSize = 32 * 1024

// peekFile reads at most PeekSize bytes from path without interpreting them.
// It uses io.LimitReader and does not load the whole file. Caller must not
// mutate the returned slice.
func peekFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var buf bytes.Buffer
	buf.Grow(PeekSize)
	_, err = io.Copy(&buf, io.LimitReader(f, PeekSize))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ext returns the lowercase extension without dot, e.g. "txt", "xml", "json", "dat".
func ext(path string) string {
	e := strings.ToLower(filepath.Ext(path))
	if len(e) > 0 && e[0] == '.' {
		return e[1:]
	}
	return ""
}

// gzipMagic is the gzip header magic bytes.
var gzipMagic = []byte{0x1f, 0x8b}

// isGzipped reports whether peek starts with gzip magic.
func isGzipped(peek []byte) bool {
	return len(peek) >= 2 && peek[0] == gzipMagic[0] && peek[1] == gzipMagic[1]
}

// openStream opens path for streaming import, handling gzip transparently.
// Caller must Close the returned io.ReadCloser. The file is opened with
// O_RDONLY and no shell interpolation (AGENTS §0.3, §8). Decompressed byte
// limiting is not done here; readLines caps total decompressed bytes at
// effectiveMaxDecompressed() (default MaxDecompressedBytes = 100 MiB) and
// aborts with truncated=true before OOM (see readLines).
func openStream(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Peek magic without consuming stream for caller.
	peek := make([]byte, 2)
	n, _ := io.ReadFull(f, peek)
	if n == 2 && peek[0] == gzipMagic[0] && peek[1] == gzipMagic[1] {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
		gr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		// gzip reader closes underlying file when closed via wrapper
		return struct {
			io.Reader
			io.Closer
		}{Reader: gr, Closer: closeBoth{gr, f}}, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

type closeBoth struct {
	a io.Closer
	b io.Closer
}

func (c closeBoth) Close() error {
	_ = c.a.Close()
	return c.b.Close()
}

// progressEmitter emits event.KindProgress every ProgressBytesInterval or
// ProgressRecordsInterval, bounded and non-blocking via Observer contract.
type progressEmitter struct {
	obs       event.Observer
	clock     func() time.Time
	phase     string
	bytes     int
	records   int
	lastBytes int
	lastRecs  int
}

func newProgressEmitter(obs event.Observer, clock func() time.Time, phase string) *progressEmitter {
	if clock == nil {
		clock = time.Now
	}
	return &progressEmitter{obs: obs, clock: clock, phase: phase}
}

func (p *progressEmitter) add(n int) {
	p.bytes += n
	p.records++
	if p.obs == nil {
		return
	}
	if p.bytes-p.lastBytes >= ProgressBytesInterval || p.records-p.lastRecs >= ProgressRecordsInterval {
		p.flush()
	}
}

func (p *progressEmitter) flush() {
	if p.obs == nil {
		return
	}
	ev := event.New(event.KindProgress, p.clock(), event.Progress{
		Phase:      p.phase,
		Completed:  p.records,
		Total:      0,
		TotalKnown: false,
	})
	// Observe must be safe for concurrent use and not panic; we rely on event bus containment.
	// Recover here as well to avoid importer crash on hostile observer.
	func() {
		defer func() { _ = recover() }()
		p.obs.Observe(ev)
	}()
	p.lastBytes = p.bytes
	p.lastRecs = p.records
}

// checkCtx returns ctx.Err() if cancelled, else nil. It is called per record.
func checkCtx(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// errDuplicate is returned by importers when a line is a duplicate that
// should not be counted as processed nor failed.
var errDuplicate = errors.New("duplicate")

// errOutputTruncated is returned when MaxOutput cap caused a tail-drop.
var errOutputTruncated = errors.New("output truncated")

// importPathError redacts full filesystem paths, exposing only Base (LOW fix).
// It preserves the underlying error for errors.Is/As via Unwrap, but Error()
// replaces the full path with the base name to avoid disclosure.
type importPathError struct {
	base string
	full string
	op   string
	err  error
}

func (e *importPathError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("import %s: %s", e.base, e.op)
	}
	msg := e.err.Error()
	if e.full != "" && e.full != e.base {
		msg = strings.ReplaceAll(msg, e.full, e.base)
	}
	return fmt.Sprintf("import %s: %s: %s", e.base, e.op, msg)
}

func (e *importPathError) Unwrap() error { return e.err }

func newImportError(base, full, op string, err error) error {
	return &importPathError{base: base, full: full, op: op, err: err}
}

// readLines streams path line-by-line with bounded memory, per-record ctx
// check, and progress emission. It is the shared helper for plain importers.
// Each non-empty line (trimmed) is handed to handle; handle must not retain
// the line slice beyond the call. The file at path is opened with openStream
// (gzip-aware). Empty files yield zero calls and no error.
//
// Bounded-memory contract: never allocate > effectiveMaxLine()+1 bytes for a
// single line. Uses bufio.Reader.ReadSlice with an 8 KiB buffer and a
// maxLine+1 cap; oversized lines are detected, counted as failed+truncated,
// and drained in bounded 8 KiB chunks without unbounded allocation. The drain
// loop checks ctx per chunk. Total decompressed bytes (bytesRead via
// progressEmitter) are capped at effectiveMaxDecompressed() (default
// MaxDecompressedBytes = 100 MiB); exceeding the cap aborts with
// truncated=true (tail-drop, sticky flag "import_truncated" in callers)
// instead of OOM, preventing gzip bombs from exhausting memory. The cap is
// configurable via Bounds.MaxDecompressedBytes and participates in the cache
// key (Config["max_decompressed_bytes"]).
func readLines(ctx context.Context, env ImportEnv, path string, handle func(line string, raw string) error) (int, int, bool, error) {
	maxLine := env.Bounds.effectiveMaxLine()
	limit := maxLine + 1
	if limit <= 0 {
		limit = maxLine
	}
	maxDecomp := env.Bounds.effectiveMaxDecompressed()
	base := filepath.Base(path)
	rc, err := openStream(path)
	if err != nil {
		return 0, 0, false, newImportError(base, path, "open", err)
	}
	defer rc.Close()

	br := bufio.NewReaderSize(rc, 8192)
	progress := newProgressEmitter(env.Observer, env.now, "import")
	processed := 0
	failed := 0
	truncated := false
	var bytesRead int

	for {
		if err := checkCtx(ctx); err != nil {
			progress.flush()
			return processed, failed, truncated, err
		}
		var lineBuf []byte
		oversized := false
		logicalDone := false
		eof := false

		// Assemble one logical line (until '\n' or EOF) bounded to limit.
		for !logicalDone {
			if err := checkCtx(ctx); err != nil {
				progress.flush()
				return processed, failed, truncated, err
			}
			fragment, readErr := br.ReadSlice('\n')
			if readErr != nil && readErr != io.EOF && readErr != bufio.ErrBufferFull {
				progress.flush()
				return processed, failed, truncated, newImportError(base, path, "read", readErr)
			}
			isEOF := readErr == io.EOF
			isBufferFull := readErr == bufio.ErrBufferFull
			fragLen := len(fragment)
			if fragLen > 0 {
				bytesRead += fragLen
				progress.add(fragLen)
				// Decompressed-byte cap (gzip bomb guard). Count is
				// post-decompression (ReadSlice returns decompressed bytes).
				// Exceeding MaxDecompressedBytes aborts truncated, not OOM.
				if bytesRead > maxDecomp {
					truncated = true
					progress.flush()
					return processed, failed, truncated, nil
				}
			}
			if !oversized {
				if len(lineBuf)+fragLen > limit {
					oversized = true
					remaining := limit - len(lineBuf)
					if remaining > 0 {
						lineBuf = append(lineBuf, fragment[:remaining]...)
					}
				} else {
					lineBuf = append(lineBuf, fragment...)
				}
			}
			hasNewline := fragLen > 0 && fragment[fragLen-1] == '\n'
			if isEOF {
				eof = true
				logicalDone = true
			} else if isBufferFull {
				// need more fragments for this logical line
			} else if hasNewline {
				logicalDone = true
			} else {
				logicalDone = true
			}
			if eof && fragLen == 0 && len(lineBuf) == 0 && !oversized {
				logicalDone = true
			}
		}
		if eof && len(lineBuf) == 0 && !oversized {
			break
		}
		if oversized {
			failed++
			truncated = true
			if eof {
				break
			}
			continue
		}
		raw := string(lineBuf)
		trimmed := strings.TrimSpace(raw)
		if len(trimmed) > maxLine {
			failed++
			truncated = true
			if eof {
				break
			}
			continue
		}
		if trimmed == "" {
			if eof {
				break
			}
			continue
		}
		if err := handle(trimmed, raw); err != nil {
			if errors.Is(err, errDuplicate) || errors.Is(err, errOutputTruncated) {
				if errors.Is(err, errOutputTruncated) {
					truncated = true
				}
			} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				// A record whose handler bailed on cancellation was never
				// processed — it is neither completed nor failed. The run is
				// aborting: surface the cause instead of counting a phantom
				// failure (cancellation is never reported as a record
				// failure, mirroring the runtime pool's terminal
				// classification).
				return processed, failed, truncated, err
			} else {
				failed++
			}
		} else {
			processed++
		}
		if eof {
			break
		}
	}
	progress.flush()
	_ = bytesRead
	return processed, failed, truncated, nil
}
