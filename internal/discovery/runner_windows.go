//go:build windows

package discovery

import "os/exec"

// configureProcessGroup is a no-op on Windows: there is no POSIX process
// group to create, so cancellation can only kill the direct child (via
// exec.CommandContext). The waitGrace bound in waitCommand still guarantees
// the caller cannot hang on a descendant holding the output pipes; the
// descendant itself may outlive the run. This limitation is documented in
// ARCHITECTURE.md.
func configureProcessGroup(*exec.Cmd) {}

// killProcessGroup is a no-op on Windows: no POSIX process groups exist.
// exec.CommandContext's own watcher kills the direct child.
func killProcessGroup(*exec.Cmd) {}
