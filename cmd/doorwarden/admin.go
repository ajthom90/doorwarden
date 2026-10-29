package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/web"
)

func init() { subcommands["admin"] = runAdmin }

const adminUsage = `usage: doorwarden admin <reset-password|unlock> [-db PATH] [-user NAME]
       doorwarden admin secret <set|list|delete> ... (see doorwarden admin secret)

Out-of-band recovery for the local administrator. Works directly on the
database (host access is the authority), also while the server runs.

  reset-password  set a new random password, printed once on stdout; ends
                  every session and clears login limits. Creates the
                  administrator (-user, default admin) when none exists.
  unlock          end every session and clear login limits; the password
                  is unchanged.

  -db PATH        SQLite database (default $DOORWARDEN_DB or /data/doorwarden.db)
  -allow-owner-mismatch
                  run although the database file belongs to another user
                  (refused by default: files SQLite creates would then be
                  owned by this user, e.g. root, and lock the server out)
`

// runAdmin implements `doorwarden admin ...`. Secrets go to out (stdout)
// only, never to a log.
func runAdmin(args []string, out io.Writer) int {
	if len(args) > 0 && args[0] == "secret" {
		return runAdminSecret(args[1:], out)
	}
	if len(args) == 0 || (args[0] != "reset-password" && args[0] != "unlock") {
		fmt.Fprint(stderr, adminUsage)
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("admin "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath, allowOwner := dbFlags(fs)
	user := fs.String("user", "admin", "user name when reset-password creates the administrator")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "doorwarden admin %s: %v\n", action, err)
		return 1
	}
	st, err := openExistingStore(*dbPath, *allowOwner)
	if err != nil {
		return fail(err)
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, exists, err := st.GetAdmin(ctx)
	if err != nil {
		return fail(err)
	}
	switch action {
	case "unlock":
		if !exists {
			return fail(errors.New("no administrator exists yet; use reset-password to create one, or the first-run setup token from the server log"))
		}
		if err := st.ResetCredentials(ctx, ""); err != nil {
			return fail(err)
		}
		fmt.Fprintln(out, "Unlocked: every session ended and login limits cleared. The password is unchanged.")
		return 0
	default: // reset-password
		b := make([]byte, 18)
		if _, err := rand.Read(b); err != nil {
			return fail(err)
		}
		pw := base64.RawURLEncoding.EncodeToString(b)
		h, err := web.NewHasher(web.DefaultArgon2Params, 1).Hash(pw)
		if err != nil {
			return fail(err)
		}
		if exists {
			if err := st.ResetCredentials(ctx, h); err != nil {
				return fail(err)
			}
		} else {
			if !web.ValidUsername(*user) {
				return fail(errors.New("-user must be 1-64 characters of letters, digits and . _ - @"))
			}
			if err := st.CreateAdmin(ctx, *user, h, time.Now()); err != nil {
				return fail(err)
			}
		}
		fmt.Fprintf(out, "new password: %s\n", pw)
		fmt.Fprintln(out, "Every session ended and login limits cleared. This password is shown once; change it after signing in.")
		return 0
	}
}

// stdin and stderr are the CLI's input and diagnostics streams (replaced in
// tests).
var (
	stdin  io.Reader = os.Stdin
	stderr io.Writer = os.Stderr
)

// dbFlags registers the -db and -allow-owner-mismatch flags shared by every
// subcommand that works directly on the database.
func dbFlags(fs *flag.FlagSet) (dbPath *string, allowOwner *bool) {
	def := "/data/doorwarden.db"
	if v := os.Getenv("DOORWARDEN_DB"); v != "" {
		def = v
	}
	dbPath = fs.String("db", def, "SQLite database (env DOORWARDEN_DB)")
	allowOwner = fs.Bool("allow-owner-mismatch", false, "run although the database belongs to another user")
	return dbPath, allowOwner
}

// openExistingStore opens the database at path for an out-of-band CLI: it
// never creates an empty database by mistyping the path, and it refuses a
// database owned by another user unless allowOwner is set (SQLite creates
// -wal/-shm files owned by whoever opens the database; root-owned ones
// would lock the server, running as the file's owner, out of it).
func openExistingStore(path string, allowOwner bool) (*store.Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("database %s: %w", path, err)
	}
	if err := checkOwner("database", path, allowOwner); err != nil {
		return nil, err
	}
	return store.Open(path)
}

// checkOwner refuses path when it belongs to another user than this
// process (see openExistingStore), unless allowOwner is set.
func checkOwner(what, path string, allowOwner bool) error {
	if uid, mismatch := dbOwner(path); mismatch && !allowOwner {
		return fmt.Errorf("%s %s belongs to uid %d, but this runs as uid %d; run it as that user (e.g. docker exec -u %d ...) or pass -allow-owner-mismatch", what, path, uid, os.Geteuid(), uid)
	}
	return nil
}
