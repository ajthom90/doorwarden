package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func init() { subcommands["healthcheck"] = runHealthcheck }

// runHealthcheck GETs the health URL and exits 0 on a 2xx, else 1. It exists
// so the distroless image can have a HEALTHCHECK without a shell or curl.
func runHealthcheck(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	def := os.Getenv("DOORWARDEN_HEALTH_URL")
	if def == "" {
		def = "http://127.0.0.1:8080/healthz"
	}
	url := fs.String("url", def, "health endpoint URL (env DOORWARDEN_HEALTH_URL)")
	timeout := fs.Duration("timeout", 3*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	fmt.Fprintln(out, "ok")
	return 0
}
