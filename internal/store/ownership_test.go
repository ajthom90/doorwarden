package store

import (
	"context"
	"errors"
	"testing"
)

func rec(provider, zone, name, typ, val, owner string) DNSRecord {
	return DNSRecord{Provider: provider, Zone: zone, Name: name, Type: typ, Value: val, OwnerKey: owner, CreatedAt: t0}
}

func TestOwnedRecordNormalization(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.AddOwnedRecord(ctx, rec("cf", "example.test", "App.Example.Test.", "a", "192.0.2.1", "o")); err != nil {
		t.Fatal(err)
	}
	// same row via different spelling: update in place, not a second row
	if err := s.AddOwnedRecord(ctx, rec("cf", "example.test", "app.example.test", "A", "192.0.2.2", "o")); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListOwnedRecords(ctx, "cf", "example.test")
	if err != nil || len(got) != 1 || got[0].Name != "app.example.test" || got[0].Type != "A" || got[0].Value != "192.0.2.2" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := s.DeleteOwnedRecord(ctx, "cf", "example.test", "APP.example.test.", "a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListOwnedRecords(ctx, "cf", "example.test"); len(got) != 0 {
		t.Fatalf("not deleted: %+v", got)
	}
}

func TestOwnerConflictLeavesRowUntouched(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	orig := rec("cf", "example.test", "app.example.test", "A", "192.0.2.1", "ownerA")
	orig.ProviderRecordID = "r1"
	if err := s.AddOwnedRecord(ctx, orig); err != nil {
		t.Fatal(err)
	}
	other := rec("cf", "example.test", "APP.example.test.", "a", "192.0.2.9", "ownerB")
	other.ProviderRecordID = "r9"
	err := s.AddOwnedRecord(ctx, other)
	if !errors.Is(err, ErrOwnerConflict) {
		t.Fatalf("err = %v", err)
	}
	got, _ := s.ListOwnedRecords(ctx, "cf", "example.test")
	if len(got) != 1 || got[0].OwnerKey != "ownerA" || got[0].Value != "192.0.2.1" || got[0].ProviderRecordID != "r1" {
		t.Fatalf("row changed: %+v", got)
	}
}

func TestSameOwnerUpdate(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	r := rec("cf", "example.test", "app.example.test", "A", "192.0.2.1", "o")
	r.ProviderRecordID = "r1"
	if err := s.AddOwnedRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Value, r.ProviderRecordID = "192.0.2.2", "r2"
	if err := s.AddOwnedRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListOwnedRecords(ctx, "cf", "example.test")
	if len(got) != 1 || got[0].Value != "192.0.2.2" || got[0].ProviderRecordID != "r2" || got[0].OwnerKey != "o" {
		t.Fatalf("%+v", got)
	}
}

func TestDeleteOwnedRecordOnlyMatching(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	rows := []DNSRecord{
		rec("cf", "example.test", "a.example.test", "A", "192.0.2.1", "o"),
		rec("cf", "example.test", "b.example.test", "A", "192.0.2.2", "o"),
		rec("cf", "example.test", "a.example.test", "TXT", "x", "o"),
		rec("pihole", "example.test", "a.example.test", "A", "192.0.2.3", "o"),
		rec("cf", "other.test", "a.example.test", "A", "192.0.2.4", "o"),
	}
	for _, r := range rows {
		if err := s.AddOwnedRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteOwnedRecord(ctx, "cf", "example.test", "a.example.test", "A"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListOwnedRecords(ctx, "cf", "example.test")
	if len(got) != 2 || got[0].Name != "a.example.test" || got[0].Type != "TXT" || got[1].Name != "b.example.test" {
		t.Fatalf("cf/example.test: %+v", got)
	}
	if got, _ := s.ListOwnedRecords(ctx, "pihole", "example.test"); len(got) != 1 {
		t.Fatalf("pihole row lost")
	}
	if got, _ := s.ListOwnedRecords(ctx, "cf", "other.test"); len(got) != 1 {
		t.Fatalf("other zone row lost")
	}
}

func TestWildcardRoundtrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.AddOwnedRecord(ctx, rec("cf", "example.test", "*.Example.Test", "A", "192.0.2.1", "o")); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListOwnedRecords(ctx, "cf", "example.test")
	if len(got) != 1 || got[0].Name != "*.example.test" {
		t.Fatalf("%+v", got)
	}
	if err := s.DeleteOwnedRecord(ctx, "cf", "example.test", "*.example.test", "A"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListOwnedRecords(ctx, "cf", "example.test"); len(got) != 0 {
		t.Fatal("not deleted")
	}
}

func TestListActivityDefaultLimit(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.AppendActivity(ctx, ActivityEntry{TS: t0, Level: "info", Kind: "k", Message: "m"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListActivity(ctx, 0)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
}
