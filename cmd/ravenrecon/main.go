package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/RA000WL/RavenRecon/internal/cli"
)

func main() {
	// Signal handling, two stages:
	//
	// The FIRST signal — Ctrl-C (os.Interrupt) or SIGTERM from a supervisor —
	// cancels the run context instead of killing the process outright: the
	// discovery pool then cancels in-flight tool processes (on unix the whole
	// child process group is killed, so wrapper-spawned descendants cannot
	// wedge the drain) and finishes with a bounded shutdown. Partial results
	// are still printed, and cli.Run reports the interruption, so the process
	// exits 1. The raw signal is deliberately not re-raised. On Windows only
	// os.Interrupt can be delivered; syscall.SIGTERM is registered for POSIX
	// semantics and is a compile-time no-op there.
	//
	// The SECOND signal — while the graceful shutdown is still draining —
	// force-exits immediately with the conventional 128+SIGINT status, so a
	// user who wants out now always gets out now, regardless of how bounded
	// the drain is.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		first := true
		for range sigCh {
			if first {
				first = false
				cancel()
				continue
			}
			os.Exit(130) // 128 + SIGINT; also used for a forced SIGTERM exit
		}
	}()

	if err := cli.Run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ravenrecon: %v\n", err)
		os.Exit(1)
	}
}
