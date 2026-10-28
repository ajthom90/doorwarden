package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
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

func TestSetOwnedRemovalOwnerGuarded(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	r := rec("cf", "example.test", "app.example.test", "A", "192.0.2.1", "docker:app")
	r.ProviderRecordID = "r1"
	if err := s.AddOwnedRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(24 * time.Hour)
	// another owner: nothing changes
	if err := s.SetOwnedRemoval(ctx, "cf", "example.test", "app.example.test", "A", "docker:other", &at); !errors.Is(err, ErrOwnedRecordNotFound) {
		t.Fatalf("other owner: err = %v", err)
	}
	if got, _ := s.ListOwnedRecords(ctx, "cf", "example.test"); got[0].RemovedAfter != nil {
		t.Fatalf("other owner changed the row: %+v", got)
	}
	// no row at all
	if err := s.SetOwnedRemoval(ctx, "cf", "example.test", "web.example.test", "A", "docker:app", &at); !errors.Is(err, ErrOwnedRecordNotFound) {
		t.Fatalf("missing row: err = %v", err)
	}
	// the owner, spelled unnormalized: set
	if err := s.SetOwnedRemoval(ctx, "cf", "example.test", "APP.example.test.", "a", "docker:app", &at); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListOwnedRecords(ctx, "cf", "example.test")
	if len(got) != 1 || got[0].RemovedAfter == nil || !got[0].RemovedAfter.Equal(at) ||
		got[0].Value != "192.0.2.1" || got[0].ProviderRecordID != "r1" || got[0].OwnerKey != "docker:app" {
		t.Fatalf("after set: %+v", got)
	}
	// clear
	if err := s.SetOwnedRemoval(ctx, "cf", "example.test", "app.example.test", "A", "docker:app", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListOwnedRecords(ctx, "cf", "example.test"); got[0].RemovedAfter != nil {
		t.Fatalf("not cleared: %+v", got)
	}
	// other provider/zone never matched
	if err := s.SetOwnedRemoval(ctx, "cf2", "example.test", "app.example.test", "A", "docker:app", &at); !errors.Is(err, ErrOwnedRecordNotFound) {
		t.Fatalf("other provider: err = %v", err)
	}
}

func TestDeleteOwnedRecordIfDue(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	r := rec("cf", "example.test", "app.example.test", "A", "192.0.2.1", "docker:app")
	if err := s.AddOwnedRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		got, _ := s.ListOwnedRecords(ctx, "cf", "example.test")
		return len(got)
	}
	del := func(owner string, now time.Time) bool {
		t.Helper()
		ok, err := s.DeleteOwnedRecordIfDue(ctx, "cf", "example.test", "APP.example.test.", "a", owner, now)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	// not scheduled: never deleted
	if del("docker:app", t0.Add(1000*time.Hour)) || count() != 1 {
		t.Fatal("unscheduled row deleted")
	}
	at := t0.Add(24 * time.Hour)
	if err := s.SetOwnedRemoval(ctx, "cf", "example.test", "app.example.test", "A", "docker:app", &at); err != nil {
		t.Fatal(err)
	}
	// at the deadline (not after) and before: kept
	if del("docker:app", at) || del("docker:app", t0) || count() != 1 {
		t.Fatal("deleted before the deadline")
	}
	// another owner: kept
	if del("docker:other", at.Add(time.Hour)) || count() != 1 {
		t.Fatal("other owner deleted")
	}
	// due and owned: deleted, once
	if !del("docker:app", at.Add(time.Second)) || count() != 0 {
		t.Fatal("due row not deleted")
	}
	if del("docker:app", at.Add(time.Hour)) {
		t.Fatal("deleted twice")
	}
}

func TestDeleteOwnedRecordOwned(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.AddOwnedRecord(ctx, rec("cf", "example.test", "app.example.test", "A", "192.0.2.1", "docker:app")); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.DeleteOwnedRecordOwned(ctx, "cf", "example.test", "app.example.test", "A", "docker:other"); ok || err != nil {
		t.Fatalf("other owner: %v %v", ok, err)
	}
	if ok, err := s.DeleteOwnedRecordOwned(ctx, "cf", "example.test", "App.Example.Test.", "a", "docker:app"); !ok || err != nil {
		t.Fatalf("owner: %v %v", ok, err)
	}
	if got, _ := s.ListOwnedRecords(ctx, "cf", "example.test"); len(got) != 0 {
		t.Fatalf("rows %+v", got)
	}
}

func TestReassignOwnedRecordOwnerGuarded(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	r := rec("cf", "example.test", "app.example.test", "A", "192.0.2.1", "docker:old")
	r.ProviderRecordID = "r1"
	at := t0.Add(time.Hour)
	r.RemovedAfter = &at
	if err := s.AddOwnedRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	// wrong old owner: nothing changes
	if err := s.ReassignOwnedRecord(ctx, "cf", "example.test", "app.example.test", "A", "docker:x", "static:new"); !errors.Is(err, ErrOwnedRecordNotFound) {
		t.Fatalf("wrong owner: %v", err)
	}
	if err := s.ReassignOwnedRecord(ctx, "cf", "example.test", "web.example.test", "A", "docker:old", "static:new"); !errors.Is(err, ErrOwnedRecordNotFound) {
		t.Fatalf("missing row: %v", err)
	}
	for _, bad := range []string{"", " ", "zone:example.test", "ZONE:x"} {
		if err := s.ReassignOwnedRecord(ctx, "cf", "example.test", "app.example.test", "A", "docker:old", bad); err == nil {
			t.Fatalf("new owner %q accepted", bad)
		}
	}
	got, _ := s.ListOwnedRecords(ctx, "cf", "example.test")
	if got[0].OwnerKey != "docker:old" || got[0].RemovedAfter == nil {
		t.Fatalf("changed: %+v", got)
	}
	if err := s.ReassignOwnedRecord(ctx, "cf", "example.test", "APP.example.test.", "a", "docker:old", "static:new"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ListOwnedRecords(ctx, "cf", "example.test")
	if len(got) != 1 || got[0].OwnerKey != "static:new" || got[0].RemovedAfter != nil || got[0].Value != "192.0.2.1" ||
		got[0].ProviderRecordID != "r1" || !got[0].CreatedAt.Equal(r.CreatedAt.UTC().Truncate(time.Second)) {
		t.Fatalf("after reassign: %+v", got)
	}
}

func TestListAllOwnedRecords(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	for _, r := range []DNSRecord{
		rec("cf", "b.test", "x.b.test", "A", "192.0.2.1", "docker:x"),
		rec("old", "a.test", "y.a.test", "AAAA", "2001:db8::1", "docker:y"),
		rec("cf", "a.test", "z.a.test", "A", "192.0.2.2", "docker:z"),
	} {
		if err := s.AddOwnedRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListAllOwnedRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range got {
		keys = append(keys, r.Provider+"/"+r.Zone+"/"+r.Name)
	}
	if want := []string{"cf/a.test/z.a.test", "cf/b.test/x.b.test", "old/a.test/y.a.test"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("got %v want %v", keys, want)
	}
}
