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

// subcommands is the registration hook for subcommand files (see
// import_npm.go, healthcheck.go): each init() adds its handler here.
var subcommands = map[string]func(args []string, out io.Writer) int{}

func run(args []string, out io.Writer) int {
	if len(args) > 0 {
		if h, ok := subcommands[args[0]]; ok {
			return h(args[1:], out)
		}
	}
	for _, a := range args {
		if a == "--version" || a == "-version" {
			fmt.Fprintf(out, "doorwarden %s\n", version)
			return 0
		}
	}
	app.Version = version
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
