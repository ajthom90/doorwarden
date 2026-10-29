package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Exactly one admin can exist; a second create fails with ErrAdminExists.
func TestCreateAdminOnce(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if _, ok, err := s.GetAdmin(ctx); err != nil || ok {
		t.Fatalf("fresh store: ok=%v err=%v", ok, err)
	}
	t0 := time.Unix(1_800_000_000, 0)
	if err := s.CreateAdmin(ctx, "admin", "$argon2id$x", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAdmin(ctx, "other", "$argon2id$y", t0); !errors.Is(err, ErrAdminExists) {
		t.Fatalf("second create: %v", err)
	}
	a, ok, err := s.GetAdmin(ctx)
	if err != nil || !ok || a.Username != "admin" || a.PasswordHash != "$argon2id$x" || !a.CreatedAt.Equal(t0) {
		t.Fatalf("admin = %+v ok=%v err=%v", a, ok, err)
	}
	if err := s.SetAdminPassword(ctx, "$argon2id$z"); err != nil {
		t.Fatal(err)
	}
	if a, _, _ := s.GetAdmin(ctx); a.PasswordHash != "$argon2id$z" {
		t.Fatalf("password not changed: %+v", a)
	}
}

// Two concurrent creates produce exactly one admin.
func TestCreateAdminRace(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.CreateAdmin(ctx, []string{"a", "b"}[i], "h", time.Now())
		}()
	}
	wg.Wait()
	ok, exists := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrAdminExists):
			exists++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || exists != 1 {
		t.Fatalf("ok=%d exists=%d", ok, exists)
	}
}

func TestSessions(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	t0 := time.Unix(1_800_000_000, 0)
	if err := s.CreateSession(ctx, Session{IDHash: "h1", Username: "admin", CSRF: "c1", CreatedAt: t0, LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetSession(ctx, "h1")
	if err != nil || !ok || got.Username != "admin" || got.CSRF != "c1" || !got.LastSeen.Equal(t0) {
		t.Fatalf("get = %+v ok=%v err=%v", got, ok, err)
	}
	if _, ok, _ := s.GetSession(ctx, "nope"); ok {
		t.Fatal("unknown session found")
	}
	t1 := t0.Add(time.Hour)
	if err := s.TouchSession(ctx, "h1", t1); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.GetSession(ctx, "h1"); !got.LastSeen.Equal(t1) {
		t.Fatalf("touch: %+v", got)
	}
	if err := s.CreateSession(ctx, Session{IDHash: "h2", Username: "admin", CSRF: "c2", CreatedAt: t0, LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetSession(ctx, "h1"); ok {
		t.Fatal("deleted session found")
	}
	// Expired: idle before t1 removes h2 (last seen t0).
	n, err := s.DeleteExpiredSessions(ctx, t1, t0.Add(-time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("expired n=%d err=%v", n, err)
	}
	_ = s.CreateSession(ctx, Session{IDHash: "h3", Username: "admin", CSRF: "c3", CreatedAt: t0, LastSeen: t1})
	if err := s.DeleteAllSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetSession(ctx, "h3"); ok {
		t.Fatal("DeleteAllSessions left a session")
	}
}

// SetServiceOverrides only touches overrides_json (inserting a row when the
// key is new); TouchService never touches it.
func TestSetServiceOverrides(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	t0 := time.Unix(1_800_000_000, 0)
	if err := s.SetServiceOverrides(ctx, "docker/app", "docker", `{"rename":"web"}`, t0); err != nil {
		t.Fatal(err)
	}
	v, ok, err := s.GetService(ctx, "docker/app")
	if err != nil || !ok || v.OverridesJSON != `{"rename":"web"}` || v.State != "discovered" {
		t.Fatalf("insert = %+v ok=%v err=%v", v, ok, err)
	}
	t1 := t0.Add(time.Minute)
	if err := s.TouchService(ctx, "docker/app", "docker", "published", t1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetServiceOverrides(ctx, "docker/app", "docker", `{"port":8443}`, t1.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	v, _, _ = s.GetService(ctx, "docker/app")
	if v.OverridesJSON != `{"port":8443}` || v.State != "published" || !v.LastSeen.Equal(t1) || !v.FirstSeen.Equal(t0) {
		t.Fatalf("update = %+v", v)
	}
	if _, ok, _ := s.GetService(ctx, "nope"); ok {
		t.Fatal("unknown service found")
	}
}
