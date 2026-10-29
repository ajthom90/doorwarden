package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/acme"
	"github.com/ajthom90/doorwarden/internal/app"
	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/ajthom90/doorwarden/internal/store"
)

func init() { subcommands["certs"] = runCerts }

const certsUsage = `usage: doorwarden certs import-npm -npm-dir PATH [-config PATH] [-env-file PATH]
                                  [-db PATH] [-certs-dir PATH] [-dry-run]

Imports Nginx Proxy Manager's certificates (wildcards included) as
imported certificates, so the cutover needs no re-issuance. Works directly
on the database and the certificate directory, also while the server runs
(it picks them up on its next cycle).

  -npm-dir PATH    NPM's letsencrypt directory, its live/ directory, or one
                   live/npm-N directory (each npm-N holds fullchain.pem and
                   privkey.pem)
  -config PATH     doorwarden config, for the zones (default
                   $DOORWARDEN_CONFIG or /config/doorwarden.yaml)
  -env-file PATH   KEY=VALUE file for the config's ${VAR}s (the process
                   environment wins; unset variables expand to empty)
  -db PATH         SQLite database (default $DOORWARDEN_DB or /data/doorwarden.db)
  -certs-dir PATH  certificate directory (default: the config's acme.certs_dir)
  -dry-run         check and list what would be imported; nothing is written
  -allow-owner-mismatch
                   run although the database belongs to another user

DOORWARDEN_MASTER_KEY must be set (not needed with -dry-run).
`

func runCerts(args []string, out io.Writer) int {
	if len(args) == 0 || args[0] != "import-npm" {
		fmt.Fprint(stderr, certsUsage)
		return 2
	}
	return runCertsImportNPM(args[1:], out)
}

func runCertsImportNPM(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("certs import-npm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	npmDir := fs.String("npm-dir", "", "NPM letsencrypt, live/ or live/npm-N directory (required)")
	defCfg := "/config/doorwarden.yaml"
	if v := os.Getenv("DOORWARDEN_CONFIG"); v != "" {
		defCfg = v
	}
	cfgPath := fs.String("config", defCfg, "doorwarden config (env DOORWARDEN_CONFIG)")
	envFile := fs.String("env-file", "", "KEY=VALUE file for the config's ${VAR}s")
	dbPath, allowOwner := dbFlags(fs)
	certsDir := fs.String("certs-dir", "", "certificate directory (default: acme.certs_dir from the config)")
	dry := fs.Bool("dry-run", false, "check and list only; nothing is written")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "doorwarden certs import-npm: %v\n", err)
		return 1
	}
	if fs.NArg() > 0 {
		return fail(fmt.Errorf("unexpected arguments %q", fs.Args()))
	}
	if *npmDir == "" {
		return fail(errors.New("-npm-dir is required"))
	}
	cfg, unset, err := cliConfig(*cfgPath, *envFile)
	if err != nil {
		return fail(err)
	}
	noteUnset(unset)
	dir := *certsDir
	if dir == "" {
		// An unset ${VAR} in acme.certs_dir would silently fall back to
		// the default directory, which the server may not use.
		if cfg.ACME.CertsDir == "" && len(unset) > 0 {
			return fail(fmt.Errorf("acme.certs_dir is empty and config variable(s) %s are unset; pass -certs-dir or -env-file", strings.Join(unset, ", ")))
		}
		dir = cfg.CertsRoot()
	}
	src, err := npmLiveDir(*npmDir)
	if err != nil {
		return fail(err)
	}

	var st *store.Store
	var box *secrets.Box
	if *dry {
		// The real run's database checks, without opening it.
		if _, err := os.Stat(*dbPath); err != nil {
			return fail(fmt.Errorf("database %s: %w", *dbPath, err))
		}
		if err := checkOwner("database", *dbPath, *allowOwner); err != nil {
			return fail(err)
		}
		// Run the real import into a throwaway store and directory: every
		// check is the same, nothing real is touched.
		tmp, err := os.MkdirTemp("", "doorwarden-import-dry-")
		if err != nil {
			return fail(err)
		}
		defer os.RemoveAll(tmp)
		if st, err = store.Open(filepath.Join(tmp, "dry.db")); err != nil {
			return fail(err)
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return fail(err)
		}
		if box, err = secrets.NewBox(base64.RawStdEncoding.EncodeToString(k)); err != nil {
			return fail(err)
		}
		dir = filepath.Join(tmp, "certs")
	} else {
		mk := os.Getenv("DOORWARDEN_MASTER_KEY")
		if mk == "" {
			return fail(errors.New("DOORWARDEN_MASTER_KEY is not set: it must be the server's master key"))
		}
		if box, err = secrets.NewBox(mk); err != nil {
			return fail(err)
		}
		if st, err = openExistingStore(*dbPath, *allowOwner); err != nil {
			return fail(err)
		}
		if _, err := os.Stat(dir); err == nil {
			if err := checkOwner("certificate directory", dir, *allowOwner); err != nil {
				st.Close()
				return fail(err)
			}
		}
	}
	defer st.Close()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(fmt.Errorf("creating the certificate directory: %w", err))
	}
	sec := &app.SecretStore{KV: st, Box: box}
	// DeferStartupCleanup, and StartupCleanup is never called: it removes
	// certificate directories this store does not know about, and the
	// server may be running.
	mgr, err := acme.NewManager(acme.ManagerConfig{
		Config: cfg, Store: st, Box: box, CertsDir: dir, SettingValue: sec.SettingValue,
		Logger:              slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		DeferStartupCleanup: true,
	})
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rs, err := mgr.ImportNPMDir(ctx, src)
	if err != nil {
		return fail(err)
	}
	return printImport(out, cfg, rs, *dry)
}

// npmLiveDir maps -npm-dir to what acme.ImportNPMDir takes: one npm-N
// directory or a live/ directory. NPM's letsencrypt directory (holding
// live/) is accepted too.
func npmLiveDir(d string) (string, error) {
	fi, err := os.Stat(d)
	if err != nil {
		return "", fmt.Errorf("-npm-dir: %w", err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("-npm-dir %s is not a directory", d)
	}
	if _, err := os.Stat(filepath.Join(d, acme.FullchainFile)); err == nil {
		return d, nil
	}
	live := filepath.Join(d, "live")
	if fi, err := os.Stat(live); err == nil && fi.IsDir() {
		if m, _ := filepath.Glob(filepath.Join(d, "npm-*")); len(m) == 0 {
			return live, nil
		}
	}
	return d, nil
}

func printImport(out io.Writer, cfg *config.Config, rs []acme.ImportResult, dry bool) int {
	verb := "imported"
	if dry {
		verb = "would import"
	}
	failed, ok, staged := 0, 0, false
	zones := map[string]bool{}
	for _, r := range rs {
		if r.Err != nil {
			failed++
			fmt.Fprintf(out, "FAILED  %s: %v\n", r.Source, r.Err)
			continue
		}
		ok++
		b := r.Bundle
		zones[b.Zone] = true
		issuer := "unknown"
		if leaf := leafOf(b.ChainPEM); leaf != nil {
			issuer = leaf.Issuer.CommonName
			if issuer == "" && len(leaf.Issuer.Organization) > 0 {
				issuer = leaf.Issuer.Organization[0]
			}
			if leafIsStaging(leaf) {
				staged = true
			}
		}
		state := ""
		if r.Expired {
			state = "  EXPIRED"
		}
		fmt.Fprintf(out, "%s  %s\n  id:        %s\n  zone:      %s\n  names:     %s\n  not after: %s\n  issuer:    %s%s\n",
			verb, r.Source, b.ID, b.Zone, strings.Join(b.Names, ", "), b.NotAfter.UTC().Format(time.RFC3339), issuer, state)
	}
	fmt.Fprintf(out, "\n%d certificate(s) %s, %d failed.\n", ok, verb, failed)
	if dry {
		fmt.Fprintln(out, "Dry run: nothing was written. Run again without -dry-run to import.")
	}
	if ok > 0 {
		fmt.Fprint(out, `
Next steps:
  - Imported certificates are served as they are (status "imported") and
    are never renewed while their zone has no certificate issuer.
  - With an issuer, a due imported certificate is adopted: Doorwarden
    issues its own replacement through that issuer before it expires.
  - A staging issuer never replaces an imported certificate (renewal is
    refused with "imported certificate is due but the issuer is a staging
    CA"): switch the zone's issuer to production before the imported
    certificates expire. Trial with staging is safe meanwhile.
  - The running server picks the certificates up on its next cycle (or
    restart it).
`)
		for z := range zones {
			if n := zoneIssuer(cfg, z); n != "" {
				fmt.Fprintf(out, "  zone %s: issuer %s (directory %s)\n", z, n, cfg.Issuers[n].Directory)
			} else {
				fmt.Fprintf(out, "  zone %s: no certificate issuer; imported certificates are not renewed\n", z)
			}
		}
	}
	if staged {
		fmt.Fprintln(out, "WARNING: at least one imported certificate was issued by a staging CA (not trusted by browsers).")
	}
	if failed > 0 {
		return 1
	}
	return 0
}

func zoneIssuer(cfg *config.Config, zone string) string {
	for _, z := range cfg.Zones {
		if strings.EqualFold(strings.TrimRight(z.Name, "."), zone) {
			return z.Certificate.Issuer
		}
	}
	return ""
}

func leafOf(chain []byte) *x509.Certificate {
	b, _ := pem.Decode(chain)
	if b == nil {
		return nil
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil
	}
	return c
}

// leafIsStaging reports a Let's Encrypt staging issuer ("(STAGING) ..."
// or the older "Fake LE ..." names).
func leafIsStaging(c *x509.Certificate) bool {
	n := strings.ToUpper(c.Issuer.CommonName + " " + strings.Join(c.Issuer.Organization, " "))
	return strings.Contains(n, "STAGING") || strings.Contains(n, "FAKE LE")
}
