package main

import (
	"context"
	"fmt"
	"os"

	"github.com/RA000WL/RavenRecon/internal/cli"
)

func main() {
	ctx := context.Background()

	if err := cli.Run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ravenrecon: %v\n", err)
		os.Exit(1)
	}
}
