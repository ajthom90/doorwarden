package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ajthom90/doorwarden/internal/app"
)

var version = "dev"

func run(args []string, out io.Writer) int {
	for _, a := range args {
		if a == "--version" || a == "-version" {
			fmt.Fprintf(out, "doorwarden %s\n", version)
			return 0
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, args); err != nil {
		fmt.Fprintf(os.Stderr, "doorwarden: %v\n", err)
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}
