//go:build unix

package discovery

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup makes the child the leader of its own process group,
// so a cancelled run can kill the child AND any descendants that inherited
// its stdout/stderr pipes. Without this, a wrapper script or PATH shim (both
// documented configuration features) that spawned a background child holding
// the pipe write-ends would leave that descendant running after the direct
// child was killed: Run's own pipe teardown (see pipeCopies) still bounds
// Run's return, but only the group kill actually terminates the descendant.
func configureProcessGroup(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup kills the child's entire process group. It is called only
// after ctx.Done; exec.CommandContext's own watcher kills the direct child
// (the group leader) at the same time. A negative pid targets the process
// group. Errors other than ESRCH fall back to killing the direct child; the
// group kill is best-effort and Run's own pipe teardown (force-closing the
// read ends and joining the copy goroutines, see pipeCopies) covers the case
// where a descendant survives the kill anyway — for example by escaping into
// its own session with setsid — so such a descendant can pin no goroutine or
// descriptor past Run's return. The pid-reuse hazard of kill(-pid) is
// accepted as negligible here, as it is for every process-group killer: the
// pid can only be recycled after Wait reaps the child, and Wait is still in
// flight when this runs.
func killProcessGroup(c *exec.Cmd) {
	if c.Process == nil {
		return
	}
	if err := syscall.Kill(-c.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		_ = c.Process.Kill() // best effort; the watcher may have killed it already
	}
}
