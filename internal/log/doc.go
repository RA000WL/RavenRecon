// Package log provides RavenRecon's JSONL bus consumer: it subscribes to
// the canonical event bus (internal/event) and writes every event as one
// JSON line to a file.
//
// # Observer-only contract
//
// The logger is observer-only: it consumes the bus, never calls an engine,
// never mutates execution state, and cannot change what a run does. There
// is no inbound path from the logger to the pool, the cache, or any pipeline
// stage. The file is a pure function of the events consumed so far.
//
// # Architecture
//
//	instrumented code (pool, cache, stages)
//		-> Bus (internal/event)
//		-> Subscriber (bounded 64)
//		-> Logger.Run (select on Events/Done, marshal, buffered write)
//		-> JSONL file (0600, fsync(dir) on close)
//
// The logger is single-consumer: exactly one goroutine (its internal run
// loop) reads the subscriber. The subscriber is single-consumer by
// contract, so the logger owns it.
//
// # Bounds and durability
//
// The subscriber buffer is 64 (the bus drops and counts on a full buffer).
// The file is opened 0600 (recon output is private), written through a
// 64 KiB bufio.Writer, and closed with Flush + Sync + Close + fsync(dir)
// (best-effort, ENOSYS/EINVAL ignored) per the report writer precedent
// (internal/report/writer.go syncDirBestEffort). A nil Bus is the off
// switch: NewLogger(nil, ...) returns (nil, nil) and Close is a no-op.
//
// # Panic containment
//
// A panicking marshal or write is contained: the event is dropped and the
// logger continues, mirroring the Deriving bridge's Deriver panic
// containment (internal/event/derive.go). The run loop itself is also
// recovered at the top level so a hostile event cannot crash the logger
// goroutine.
//
// # Replay symmetry
//
// Every line is one JSON object with kind, sequence, at (RFC3339Nano),
// severity, phase/category/identity/value, and payload (typed by kind).
// The payload is marshaled with the same struct tags the event package
// uses, so internal/replay can unmarshal it deterministically and re-derive
// an identical summary.
package log
