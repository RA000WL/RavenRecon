// Package replay provides deterministic replay from a recorded event stream.
//
// It reads the JSONL file produced by internal/log (one JSON object per
// line, each carrying kind, sequence, at, severity, phase/category/identity/
// value, and payload typed by kind) and replays events through the same
// Observer contract the live run used.
//
// # Observer-only contract
//
// Replay is observer-only: it never calls an engine, never mutates
// execution state, and cannot change what a run did. It is a pure function
// of the recorded file: the same JSONL always produces the same events in
// the same order, and a replay through the TUI state machine produces a
// byte-identical summary frame (via tui.RenderFinal) to the live run's
// final frame at the same clock.
//
// Panic containment mirrors the logger and the Deriving bridge: a panicking
// Observer does not crash replay — the event is dropped and replay
// continues.
//
// Persistence is the logger layer's concern; replay never touches the cache.
package replay
