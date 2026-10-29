package main

import (
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/web"
)

func adminDB(t *testing.T, withAdmin bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dw.db")
	st, err := store.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if withAdmin {
		h, _ := web.NewHasher(web.Argon2Params{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}, 1).Hash("old-password-123")
		if err := st.CreateAdmin(ctx, "admin", h, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateSession(ctx, store.Session{IDHash: "s1", Username: "admin", CSRF: "c", CreatedAt: time.Now(), LastSeen: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func openDB(t *testing.T, p string) *store.Store {
	t.Helper()
	st, err := store.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

var pwLine = regexp.MustCompile(`(?m)^new password: (\S+)$`)

// reset-password prints a fresh password on stdout, stores its hash, bumps
// the credential generation (clearing the server's login limits) and ends
// every session.
func TestAdminResetPassword(t *testing.T) {
	p := adminDB(t, true)
	var out bytes.Buffer
	if c := run([]string{"admin", "reset-password", "-db", p}, &out); c != 0 {
		t.Fatalf("exit %d: %s", c, out.String())
	}
	m := pwLine.FindStringSubmatch(out.String())
	if m == nil || len(m[1]) < 20 {
		t.Fatalf("no password printed:\n%s", out.String())
	}
	st := openDB(t, p)
	adm, _, _ := st.GetAdmin(context.Background())
	if !web.NewHasher(web.DefaultArgon2Params, 1).Verify(adm.PasswordHash, m[1]) {
		t.Fatal("printed password does not verify")
	}
	if adm.Generation != 1 {
		t.Fatalf("generation = %d", adm.Generation)
	}
	if _, ok, _ := st.GetSession(context.Background(), "s1"); ok {
		t.Fatal("session survived reset-password")
	}
}

// With no administrator, reset-password creates one (--user, default
// admin) with a printed random password.
func TestAdminResetPasswordCreates(t *testing.T) {
	p := adminDB(t, false)
	var out bytes.Buffer
	if c := run([]string{"admin", "reset-password", "-db", p, "-user", "ops"}, &out); c != 0 {
		t.Fatalf("exit %d: %s", c, out.String())
	}
	m := pwLine.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no password printed:\n%s", out.String())
	}
	adm, ok, _ := openDB(t, p).GetAdmin(context.Background())
	if !ok || adm.Username != "ops" || !web.NewHasher(web.DefaultArgon2Params, 1).Verify(adm.PasswordHash, m[1]) {
		t.Fatalf("admin = %+v ok=%v", adm, ok)
	}
}

// unlock keeps the password, ends every session and bumps the generation.
func TestAdminUnlock(t *testing.T) {
	p := adminDB(t, true)
	var out bytes.Buffer
	if c := run([]string{"admin", "unlock", "-db", p}, &out); c != 0 {
		t.Fatalf("exit %d: %s", c, out.String())
	}
	st := openDB(t, p)
	adm, _, _ := st.GetAdmin(context.Background())
	if adm.Generation != 1 || !web.NewHasher(web.DefaultArgon2Params, 1).Verify(adm.PasswordHash, "old-password-123") {
		t.Fatalf("unlock changed the password or not the generation: %+v", adm)
	}
	if _, ok, _ := st.GetSession(context.Background(), "s1"); ok {
		t.Fatal("session survived unlock")
	}
	if strings.Contains(out.String(), "old-password") {
		t.Fatal("password echoed")
	}
}

// A missing database is refused (never created empty), as are unknown
// actions.
func TestAdminErrors(t *testing.T) {
	var out bytes.Buffer
	if c := run([]string{"admin", "unlock", "-db", filepath.Join(t.TempDir(), "nope.db")}, &out); c == 0 {
		t.Fatal("missing database accepted")
	}
	if c := run([]string{"admin", "frobnicate"}, &out); c == 0 {
		t.Fatal("unknown action accepted")
	}
	if c := run([]string{"admin"}, &out); c == 0 {
		t.Fatal("no action accepted")
	}
	p := adminDB(t, false)
	if c := run([]string{"admin", "unlock", "-db", p}, &out); c == 0 {
		t.Fatal("unlock without an administrator succeeded")
	}
}
