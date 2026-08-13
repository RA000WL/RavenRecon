//go:build windows

package discovery

import "os/exec"

// configureProcessGroup is a no-op on Windows: there is no POSIX process
// group to create, so cancellation can only kill the direct child (via
// exec.CommandContext). Run's own pipe teardown (force-closing the read ends
// and joining the copy goroutines, see pipeCopies) still guarantees that a
// wrapper-spawned child holding the output pipes cannot pin any goroutine or
// descriptor past Run's return, and that Run never blocks waiting for such a
// child; the descendant itself may outlive the run. This limitation is
// documented in ARCHITECTURE.md.
func configureProcessGroup(*exec.Cmd) {}

// killProcessGroup is a no-op on Windows: no POSIX process groups exist.
// exec.CommandContext's own watcher kills the direct child.
func killProcessGroup(*exec.Cmd) {}
