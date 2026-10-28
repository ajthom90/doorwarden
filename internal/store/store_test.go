package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pp.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func TestMigrationsIdempotentOnReopen(t *testing.T) {
	s, p := openTemp(t)
	var n1 int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n1); err != nil {
		t.Fatal(err)
	}
	if n1 < 1 {
		t.Fatalf("expected applied migrations, got %d", n1)
	}
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var n2 int
	s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n2)
	if n1 != n2 {
		t.Fatalf("migrations reapplied: %d vs %d", n1, n2)
	}
}

func TestOwnershipRoundtrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	r := DNSRecord{Provider: "cf", Zone: "example.test", Name: "app.example.test", Type: "A", Value: "192.0.2.10", ProviderRecordID: "r1", OwnerKey: "svc1", CreatedAt: t0}
	if err := s.AddOwnedRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Value, r.ProviderRecordID = "192.0.2.11", "r2"
	if err := s.AddOwnedRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListOwnedRecords(ctx, "cf", "example.test")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v %v", got, err)
	}
	if got[0].Value != "192.0.2.11" || got[0].ProviderRecordID != "r2" || !got[0].CreatedAt.Equal(t0) || got[0].RemovedAfter != nil {
		t.Fatalf("bad %+v", got[0])
	}
	if err := s.DeleteOwnedRecord(ctx, "cf", "example.test", "app.example.test", "A"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ListOwnedRecords(ctx, "cf", "example.test")
	if len(got) != 0 {
		t.Fatalf("not deleted: %v", got)
	}
}

func TestListOwnedRecordsScopedToProviderAndZone(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	for _, r := range []DNSRecord{
		{Provider: "cf", Zone: "example.test", Name: "a.example.test", Type: "A", Value: "192.0.2.1", CreatedAt: t0},
		{Provider: "cf", Zone: "other.test", Name: "a.other.test", Type: "A", Value: "192.0.2.2", CreatedAt: t0},
		{Provider: "pihole", Zone: "example.test", Name: "a.example.test", Type: "A", Value: "192.0.2.3", CreatedAt: t0},
	} {
		if err := s.AddOwnedRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListOwnedRecords(ctx, "cf", "example.test")
	if err != nil || len(got) != 1 || got[0].Value != "192.0.2.1" {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestUpsertServiceUpdatesInPlace(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	s.UpsertService(ctx, Service{Key: "k", Source: "docker", State: "active", OverridesJSON: "{}", FirstSeen: t0, LastSeen: t0})
	later := t0.Add(time.Hour)
	if err := s.UpsertService(ctx, Service{Key: "k", Source: "docker", State: "stale", OverridesJSON: `{"a":1}`, FirstSeen: later, LastSeen: later}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListServices(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	g := got[0]
	if g.State != "stale" || g.OverridesJSON != `{"a":1}` || !g.FirstSeen.Equal(t0) || !g.LastSeen.Equal(later) {
		t.Fatalf("bad %+v", g)
	}
}

func TestServiceRemovedAfterNullable(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	s.UpsertService(ctx, Service{Key: "a", Source: "docker", State: "active", FirstSeen: t0, LastSeen: t0})
	ra := t0.Add(24 * time.Hour)
	s.UpsertService(ctx, Service{Key: "b", Source: "docker", State: "removed", FirstSeen: t0, LastSeen: t0, RemovedAfter: &ra})
	got, _ := s.ListServices(ctx)
	if len(got) != 2 || got[0].RemovedAfter != nil || got[1].RemovedAfter == nil || !got[1].RemovedAfter.Equal(ra) {
		t.Fatalf("bad %+v", got)
	}
	// clearing it again
	s.UpsertService(ctx, Service{Key: "b", Source: "docker", State: "active", FirstSeen: t0, LastSeen: t0})
	got, _ = s.ListServices(ctx)
	if got[1].RemovedAfter != nil {
		t.Fatal("removed_after not cleared")
	}
}

func TestCertRoundtrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	c := Cert{ID: "c1", Zone: "example.test", DomainsJSON: `["*.example.test"]`, Issuer: "le", Staging: true, NotAfter: t0.Add(90 * 24 * time.Hour), Status: "valid", LastResult: "ok", Path: "/certs/c1", Managed: true}
	if err := s.UpsertCert(ctx, c); err != nil {
		t.Fatal(err)
	}
	check := func(want Cert) {
		t.Helper()
		got, err := s.ListCerts(ctx)
		if err != nil || len(got) != 1 {
			t.Fatalf("%v %v", got, err)
		}
		if !got[0].NotAfter.Equal(want.NotAfter) {
			t.Fatalf("NotAfter %v != %v", got[0].NotAfter, want.NotAfter)
		}
		g := got[0]
		g.NotAfter, want.NotAfter = time.Time{}, time.Time{}
		if !reflect.DeepEqual(g, want) {
			t.Fatalf("got %+v want %+v", g, want)
		}
	}
	check(c)
	c.Status, c.LastError, c.Staging = "error", "boom", false
	if err := s.UpsertCert(ctx, c); err != nil {
		t.Fatal(err)
	}
	check(c)
}

func TestActivityNewestFirstAndLimited(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	for i, m := range []string{"one", "two", "three"} {
		s.AppendActivity(ctx, ActivityEntry{TS: t0.Add(time.Duration(i) * time.Minute), Level: "info", Kind: "k", Message: m})
	}
	got, err := s.ListActivity(ctx, 2)
	if err != nil || len(got) != 2 || got[0].Message != "three" || got[1].Message != "two" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestSettingsMissingKey(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	v, ok, err := s.GetSetting(ctx, "nope")
	if err != nil || ok || v != "" {
		t.Fatalf("%q %v %v", v, ok, err)
	}
	s.SetSetting(ctx, "a", "1")
	s.SetSetting(ctx, "a", "2")
	v, ok, _ = s.GetSetting(ctx, "a")
	if !ok || v != "2" {
		t.Fatalf("%q %v", v, ok)
	}
}

func TestDeleteSetting(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.DeleteSetting(ctx, "absent"); err != nil {
		t.Fatalf("deleting an absent key: %v", err)
	}
	if err := s.SetSetting(ctx, "a", "1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, "b", "2"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSetting(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetSetting(ctx, "a"); ok {
		t.Fatal("a still set")
	}
	if v, ok, _ := s.GetSetting(ctx, "b"); !ok || v != "2" {
		t.Fatalf("b %q %v", v, ok)
	}
}

func TestStoreSurvivesReopen(t *testing.T) {
	s, p := openTemp(t)
	ctx := context.Background()
	s.SetSetting(ctx, "k", "v")
	s.UpsertService(ctx, Service{Key: "svc", Source: "docker", State: "active", FirstSeen: t0, LastSeen: t0})
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v, ok, _ := s2.GetSetting(ctx, "k"); !ok || v != "v" {
		t.Fatal("setting lost")
	}
	if l, _ := s2.ListServices(ctx); len(l) != 1 {
		t.Fatal("service lost")
	}
}
