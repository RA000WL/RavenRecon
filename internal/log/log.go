package log

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/RA000WL/RavenRecon/internal/event"
)

// subscriberBuffer is the bounded buffer for the logger's subscriber.
const subscriberBuffer = 64

// Logger is a bounded, non-blocking bus consumer that writes every event
// as one JSON line to a file. See doc.go for the full contract.
type Logger struct {
	bus  *event.Bus
	sub  *event.Subscriber
	path string
	dir  string
	file *os.File
	bw   *bufio.Writer

	mu     sync.Mutex
	closed bool
	err    error

	done chan struct{}
	wg   sync.WaitGroup
}

// NewLogger creates a logger that subscribes to bus with a bounded buffer
// of 64 and writes JSONL to path. The file is created with 0600, the
// parent directory with 0700. A nil bus is the off switch: it returns
// (nil, nil) and Close is a no-op (zero behavior change).
func NewLogger(bus *event.Bus, path string) (*Logger, error) {
	if bus == nil {
		return nil, nil
	}
	if path == "" {
		return nil, fmt.Errorf("log: path must not be empty")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("log: create dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("log: open %s: %w", path, err)
	}
	sub, err := bus.Subscribe(subscriberBuffer)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("log: subscribe: %w", err)
	}
	bw := bufio.NewWriterSize(f, 64<<10)
	l := &Logger{
		bus:  bus,
		sub:  sub,
		path: path,
		dir:  dir,
		file: f,
		bw:   bw,
		done: make(chan struct{}),
	}
	l.wg.Add(1)
	go l.run()
	return l, nil
}

// run is the single-consumer loop: it reads the subscriber and writes
// JSONL. Panics are contained per event and at the top level.
func (l *Logger) run() {
	defer l.wg.Done()
	defer close(l.done)
	defer func() {
		_ = recover()
	}()
	for {
		select {
		case ev := <-l.sub.Events():
			func() {
				defer func() {
					_ = recover()
				}()
				data, err := marshalEvent(ev)
				if err != nil {
					return
				}
				_, _ = l.bw.Write(data)
				_, _ = l.bw.Write([]byte("\n"))
			}()
		case <-l.sub.Done():
			// Drain whatever remains buffered (non-blocking) and exit.
			for {
				select {
				case ev := <-l.sub.Events():
					func() {
						defer func() { _ = recover() }()
						data, err := marshalEvent(ev)
						if err != nil {
							return
						}
						_, _ = l.bw.Write(data)
						_, _ = l.bw.Write([]byte("\n"))
					}()
				default:
					return
				}
			}
		}
	}
}

// Close shuts the logger down: it closes the subscriber (which drains the
// loop), waits for the loop to finish, flushes and syncs the file, closes
// it, and fsyncs the parent directory best-effort. It is idempotent.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		err := l.err
		l.mu.Unlock()
		return err
	}
	l.closed = true
	l.mu.Unlock()

	l.sub.Close()
	<-l.done

	var firstErr error
	if err := l.bw.Flush(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("log: flush: %w", err)
	}
	if err := l.file.Sync(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("log: sync: %w", err)
	}
	if err := l.file.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("log: close: %w", err)
	}
	if l.dir != "" && l.dir != "." {
		if err := syncDirBestEffort(l.dir); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("log: sync dir: %w", err)
		}
	}
	l.mu.Lock()
	l.err = firstErr
	l.mu.Unlock()
	l.wg.Wait()
	return firstErr
}

// Drops reports the subscriber's dropped count (full buffer).
func (l *Logger) Drops() uint64 {
	if l == nil || l.sub == nil {
		return 0
	}
	return l.sub.Drops()
}

// envelope is the JSONL line shape. Payload is raw JSON of the concrete
// payload type, keyed by Kind.
type envelope struct {
	Kind     string          `json:"kind"`
	Sequence uint64          `json:"sequence"`
	At       time.Time       `json:"at"`
	Severity int             `json:"severity"`
	Phase    string          `json:"phase,omitempty"`
	Category string          `json:"category,omitempty"`
	Identity string          `json:"identity,omitempty"`
	Value    string          `json:"value,omitempty"`
	Payload  json.RawMessage `json:"payload"`
}

func marshalEvent(ev event.Event) ([]byte, error) {
	var payload json.RawMessage
	if ev.Payload != nil {
		b, err := json.Marshal(ev.Payload)
		if err != nil {
			return nil, err
		}
		payload = b
	} else {
		payload = json.RawMessage("null")
	}
	env := envelope{
		Kind:     string(ev.Kind),
		Sequence: ev.Sequence,
		At:       ev.At,
		Severity: int(ev.Severity),
		Phase:    ev.Phase,
		Category: ev.Category,
		Identity: ev.Identity,
		Value:    ev.Value,
		Payload:  payload,
	}
	return json.Marshal(env)
}

// syncDirBestEffort fsyncs a directory so a just-completed write into it
// is durable. Mirrors internal/report/writer.go and internal/cache/cache.go.
func syncDirBestEffort(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s for directory sync: %w", dir, err)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil && !isUnsupportedDirSync(syncErr) {
		return fmt.Errorf("fsync %s: %w", dir, syncErr)
	}
	if closeErr != nil && !isUnsupportedDirSync(closeErr) {
		return fmt.Errorf("close %s: %w", dir, closeErr)
	}
	return nil
}

func isUnsupportedDirSync(err error) bool {
	return errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL)
}
