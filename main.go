package main

import (
	"context"
	"os"

	"github.com/RA000WL/RavenRecon/internal/cli"
)

func main() {
	ctx := context.Background()

	if err := cli.Run(ctx, os.Args[1:]); err != nil {
		os.Exit(1)
	}
}