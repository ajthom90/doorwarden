package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/ajthom90/doorwarden/internal/app"
	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/ajthom90/doorwarden/internal/store"
)

const adminSecretUsage = `usage: doorwarden admin secret set <name> [-force] [-db PATH]
       doorwarden admin secret list [-db PATH]
       doorwarden admin secret delete <name> [-db PATH]

Stores the values that config "secret:<name>" references resolve to,
encrypted (AES-256-GCM) under DOORWARDEN_MASTER_KEY, in the database. Works
directly on the database; restart the server afterwards so configured
providers and sources pick the value up.

  set     read the value from stdin (piped; one trailing newline is
          dropped) or, on a terminal, from a prompt that does not echo.
          The value is never taken from arguments or the environment and
          never printed. An existing secret is replaced only with -force.
  list    print the stored secret names, one per line (never values).
  delete  remove the secret (absent is not an error).

  name    1-128 characters of A-Z a-z 0-9 . _ -
  -db PATH        SQLite database (default $DOORWARDEN_DB or /data/doorwarden.db)
  -force          replace an existing secret
  -allow-owner-mismatch
                  run although the database file belongs to another user
`

// maxSecretSize bounds a secret value read from stdin.
const maxSecretSize = 64 << 10

// isTerminal reports whether r is an interactive terminal (replaced in
// tests).
var isTerminal = func(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// readPassword reads one line from the terminal r without echo (replaced
// in tests).
var readPassword = func(r io.Reader) ([]byte, error) {
	return term.ReadPassword(int(r.(*os.File).Fd()))
}

// runAdminSecret implements `doorwarden admin secret ...`. Values are read
// from stdin only and never written anywhere but the database (sealed).
func runAdminSecret(args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, adminSecretUsage)
		return 2
	}
	action := args[0]
	rest := args[1:]
	var name string
	switch action {
	case "set", "delete":
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			fmt.Fprint(stderr, adminSecretUsage)
			return 2
		}
		name, rest = rest[0], rest[1:]
	case "list":
	default:
		fmt.Fprint(stderr, adminSecretUsage)
		return 2
	}
	fs := flag.NewFlagSet("admin secret "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath, allowOwner := dbFlags(fs)
	force := fs.Bool("force", false, "replace an existing secret")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "doorwarden admin secret %s: %v\n", action, err)
		return 1
	}
	if fs.NArg() > 0 {
		// Never echo them: a value passed here by mistake must not reach
		// the terminal scrollback or a log.
		return fail(fmt.Errorf("%d unexpected argument(s) after the flags; the value is read from stdin, never from arguments", fs.NArg()))
	}
	if action != "list" && !app.ValidSecretName(name) {
		return fail(fmt.Errorf("secret name %q must be 1-128 characters of A-Z a-z 0-9 . _ -", name))
	}
	var box *secrets.Box
	if action == "set" {
		mk := os.Getenv("DOORWARDEN_MASTER_KEY")
		if mk == "" {
			return fail(errors.New("DOORWARDEN_MASTER_KEY is not set: it must be the server's master key"))
		}
		b, err := secrets.NewBox(mk)
		if err != nil {
			return fail(err)
		}
		box = b
	}
	st, err := openExistingStore(*dbPath, *allowOwner)
	if err != nil {
		return fail(err)
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	keys, err := st.ListSettingKeys(ctx, app.SecretKVPrefix)
	if err != nil {
		return fail(err)
	}
	switch action {
	case "list":
		for _, k := range keys {
			fmt.Fprintln(out, strings.TrimPrefix(k, app.SecretKVPrefix))
		}
		return 0
	case "delete":
		ss := &app.SecretStore{KV: st}
		if err := ss.Delete(ctx, name); err != nil {
			return fail(err)
		}
		if contains(keys, app.SecretKVPrefix+name) {
			fmt.Fprintf(out, "Secret %q deleted. Restart the server; config references to secret:%s now fail.\n", name, name)
		} else {
			fmt.Fprintf(out, "No secret %q was stored; nothing changed.\n", name)
		}
		return 0
	}
	// set
	exists := contains(keys, app.SecretKVPrefix+name)
	if exists && !*force {
		return fail(fmt.Errorf("secret %q already exists; pass -force to replace it", name))
	}
	if err := checkMasterKey(ctx, st, box, keys); err != nil {
		return fail(err)
	}
	v, err := readSecretValue(name)
	if err != nil {
		return fail(err)
	}
	ss := &app.SecretStore{KV: st, Box: box}
	if err := ss.Put(ctx, name, v); err != nil {
		return fail(err)
	}
	verb := "stored"
	if exists {
		verb = "replaced"
	}
	fmt.Fprintf(out, "Secret %q %s (%d bytes, encrypted). Reference it in the config as secret:%s and restart the server.\n", name, verb, len(v.Reveal()), name)
	return 0
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// checkMasterKey refuses a master key that cannot open the secrets already
// stored: values sealed under a different key would be unreadable by the
// server.
func checkMasterKey(ctx context.Context, st *store.Store, box *secrets.Box, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	v, _, err := st.GetSetting(ctx, keys[0])
	if err != nil {
		return err
	}
	sealed, err := base64.StdEncoding.DecodeString(v)
	if err == nil {
		_, err = box.Open(sealed)
	}
	if err != nil {
		return errors.New("DOORWARDEN_MASTER_KEY cannot decrypt the secrets already stored; use the server's master key")
	}
	return nil
}

// readSecretValue reads the value from stdin: with a terminal through a
// prompt without echo (asked twice), otherwise all of stdin with one
// trailing newline removed. Empty values are refused.
func readSecretValue(name string) (secrets.Secret, error) {
	var b []byte
	if isTerminal(stdin) {
		fmt.Fprintf(stderr, "Value for secret %s (not echoed): ", name)
		v1, err := readPassword(stdin)
		fmt.Fprintln(stderr)
		if err != nil {
			return "", fmt.Errorf("reading the value: %w", err)
		}
		fmt.Fprintf(stderr, "Repeat the value: ")
		v2, err := readPassword(stdin)
		fmt.Fprintln(stderr)
		if err != nil {
			return "", fmt.Errorf("reading the value: %w", err)
		}
		if !bytes.Equal(v1, v2) {
			return "", errors.New("the two values differ; nothing was stored")
		}
		b = v1
	} else {
		r, err := io.ReadAll(io.LimitReader(stdin, maxSecretSize+1))
		if err != nil {
			return "", fmt.Errorf("reading the value from stdin: %w", err)
		}
		if len(r) > maxSecretSize {
			return "", fmt.Errorf("the value is larger than %d bytes", maxSecretSize)
		}
		b = r
		if bytes.HasSuffix(b, []byte("\r\n")) {
			b = b[:len(b)-2]
		} else if bytes.HasSuffix(b, []byte("\n")) {
			b = b[:len(b)-1]
		}
	}
	if len(b) == 0 {
		return "", errors.New("the value is empty (pipe it on stdin, e.g. printf %s \"$TOKEN\" | doorwarden admin secret set NAME, or run on a terminal to be prompted)")
	}
	return secrets.Secret(b), nil
}
