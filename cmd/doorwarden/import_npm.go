package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/importer/npm"
	"github.com/ajthom90/doorwarden/internal/model"
)

func init() { subcommands["import-npm"] = runImportNPM }

// runImportNPM implements `doorwarden import-npm`. It only reads and prints;
// nothing is applied. Flags in the output are not errors (exit 0).
func runImportNPM(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("import-npm", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dbPath := fs.String("db", "", "path to NPM database.sqlite (required)")
	_ = fs.Bool("copy", true, "snapshot-copy the database to a private temp dir (default; flag kept for compatibility)")
	noCopy := fs.Bool("no-copy", false, "UNSAFE: read the database in place; SQLite may create -wal/-shm next to NPM's files. Refused when sidecars exist or the directory is not writable")
	cfgPath := fs.String("config", "", "doorwarden config file (for zones)")
	disc := fs.String("discovered", "", `JSON file of discovered services: [{"key":"truenas:app","name":"app","host":"192.0.2.10","port":8080}]`)
	asYAML := fs.Bool("yaml", false, "emit only suggested static: entries")
	_ = fs.Bool("table", false, "print the human table (default)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(os.Stderr, "doorwarden import-npm: %v\n", err)
		return 1
	}
	if *dbPath == "" {
		return fail(fmt.Errorf("--db is required"))
	}
	var cfg *config.Config
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath, nil)
		if err != nil {
			return fail(err)
		}
		cfg = c
	}
	var found []model.Service
	if *disc != "" {
		d, err := npm.LoadDiscovered(*disc)
		if err != nil {
			return fail(err)
		}
		found = d
	}
	// Install the signal handler before the snapshot copy starts so an
	// interrupt removes the temp dir.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r, err := npm.Open(*dbPath, npm.Options{NoCopy: *noCopy, Context: ctx})
	if err != nil {
		return fail(err)
	}
	defer r.Close()
	snap, err := r.Read(ctx)
	if err != nil {
		return fail(err)
	}
	ms := npm.Plan(snap, found, cfg)
	if *asYAML {
		if err := npm.RenderYAML(out, ms); err != nil {
			return fail(err)
		}
		return 0
	}
	npm.Render(out, ms)
	for _, n := range npm.Notes(snap) {
		fmt.Fprintln(out, "note:", n)
	}
	fmt.Fprint(out, "\n", npm.CertGuidance(snap))
	fmt.Fprintln(out, "\nNothing was applied. Review the table; use --yaml for paste-ready static entries.")
	return 0
}
