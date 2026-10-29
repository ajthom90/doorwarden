// Package dnstest is a conformance suite every dns.Provider implementation
// reuses from its own tests.
package dnstest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
)

// Options configures RunWith.
type Options struct {
	// Zone is the zone the suite writes to. Real providers set a test zone.
	Zone string
	// OtherZone is a second zone for the zone-scoping subtest; empty skips it.
	OtherZone string
	// AllowMultiValue skips the "differing value returns ErrRecordExists"
	// subtest for providers that permit several values per (name, type).
	AllowMultiValue bool
	// SeedMultiValue, when set, creates an A record set holding all values at
	// name out of band (directly in the fake backend). The MultiValue subtest
	// then requires that Create/Update/Delete leave values doorwarden did not
	// write intact (or refuse with an error). Providers that cannot hold
	// several values per (name, type) leave it nil.
	SeedMultiValue func(ctx context.Context, zone, name string, values ...string) error
	// Unconfirmed, when set, returns a provider (same backend, writes accepted
	// but never visible to reads) that can only answer Create with
	// dns.ErrUnconfirmed. The UnconfirmedCreateReturnsRecord subtest requires the
	// error to wrap dns.ErrUnconfirmed AND the returned Record to describe what
	// was written, so a caller can record ownership.
	Unconfirmed func(t *testing.T) dns.Provider
	// Apex runs the ZoneApex subtest: an A record whose Name is the zone
	// itself is created, listed, updated and deleted. It writes the zone's
	// apex A record, so it is opt-in: set it for fake backends only, never
	// against a real zone.
	Apex bool
	// ApexForeign, when set (with Apex), seeds records Doorwarden does not
	// own at the zone apex (NS, SOA, MX, TXT, whatever the backend holds)
	// out of band before ZoneApex runs, and returns a check that they are
	// still intact afterwards.
	ApexForeign func(ctx context.Context, zone string) (intact func() error, err error)
}

// Run executes the suite with default zones example.test and other.test.
func Run(t *testing.T, factory func(t *testing.T) dns.Provider) {
	RunWith(t, factory, Options{Zone: "example.test", OtherZone: "other.test"})
}

func find(recs []dns.Record, name, typ string) (dns.Record, bool) {
	for _, r := range recs {
		if r.Name == name && r.Type == typ {
			return r, true
		}
	}
	return dns.Record{}, false
}

// RunWith executes the conformance suite. factory must return a provider on
// every call; each created record is deleted again on cleanup (best effort).
func RunWith(t *testing.T, factory func(t *testing.T) dns.Provider, o Options) {
	if o.Zone == "" {
		t.Fatal("dnstest.RunWith: Options.Zone is required (use Run for the example.test defaults)")
	}
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("dnstest: random prefix: %v", err)
	}
	prefix := "dwt" + hex.EncodeToString(rnd[:])
	zone := o.Zone
	name := func(label, z string) string { return prefix + "-" + label + "." + z }

	ctx := func(t *testing.T) context.Context {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		return c
	}
	// create makes a record and registers cleanup deleting it by returned ID.
	create := func(t *testing.T, p dns.Provider, z string, r dns.Record) dns.Record {
		t.Helper()
		got, err := p.CreateRecord(ctx(t), z, r)
		if err != nil {
			t.Fatalf("CreateRecord(%s): %v", r.Name, err)
		}
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = p.DeleteRecord(c, z, got)
		})
		return got
	}
	mk := func(label string) dns.Record {
		return dns.Record{Name: name(label, zone), Type: "A", Value: "192.0.2.10", TTL: 300}
	}
	list := func(t *testing.T, p dns.Provider, z string) []dns.Record {
		t.Helper()
		recs, err := p.ListRecords(ctx(t), z)
		if err != nil {
			t.Fatal(err)
		}
		return recs
	}

	t.Run("Test", func(t *testing.T) {
		if err := factory(t).Test(ctx(t)); err != nil {
			t.Fatalf("Test: %v", err)
		}
	})

	t.Run("CreateList", func(t *testing.T) {
		p, rec := factory(t), mk("create")
		got := create(t, p, zone, rec)
		if got.Name != rec.Name || got.Type != rec.Type || got.Value != rec.Value {
			t.Fatalf("created = %+v", got)
		}
		if _, ok := find(list(t, p, zone), rec.Name, "A"); !ok {
			t.Fatal("created record not listed")
		}
	})

	t.Run("CreateIdempotent", func(t *testing.T) {
		p, rec := factory(t), mk("idem")
		create(t, p, zone, rec)
		create(t, p, zone, rec)
		n := 0
		for _, r := range list(t, p, zone) {
			if r.Name == rec.Name && r.Type == "A" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("want 1 record, got %d", n)
		}
	})

	t.Run("CreateDifferentValueExists", func(t *testing.T) {
		if o.AllowMultiValue {
			t.Skip("provider allows multiple values per (name, type)")
		}
		p, rec := factory(t), mk("conflict")
		create(t, p, zone, rec)
		rec.Value = "192.0.2.99"
		if _, err := p.CreateRecord(ctx(t), zone, rec); !errors.Is(err, dns.ErrRecordExists) {
			t.Fatalf("want ErrRecordExists, got %v", err)
		}
	})

	t.Run("Update", func(t *testing.T) {
		p, rec := factory(t), mk("update")
		if !p.Capabilities().Update {
			t.Skip("provider does not support Update")
		}
		create(t, p, zone, rec)
		rec.Value = "192.0.2.11" // no ID: targets (name, type)
		upd, err := p.UpdateRecord(ctx(t), zone, rec)
		if err != nil {
			t.Fatal(err)
		}
		// Clean up the updated record by its own name/type/value too, so
		// providers that return no ID (or whose create-time handle is stale)
		// do not leak it.
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = p.DeleteRecord(c, zone, dns.Record{ID: upd.ID, Name: rec.Name, Type: rec.Type, Value: rec.Value})
		})
		if r, ok := find(list(t, p, zone), rec.Name, "A"); !ok || r.Value != "192.0.2.11" {
			t.Fatalf("after update: %+v", r)
		}
	})

	t.Run("UpdateByID", func(t *testing.T) {
		p := factory(t)
		if !p.Capabilities().Update {
			t.Skip("provider does not support Update")
		}
		created := create(t, p, zone, mk("updid"))
		if created.ID == "" {
			t.Skip("provider returned no record ID")
		}
		upd := created
		upd.Value = "192.0.2.12"
		if _, err := p.UpdateRecord(ctx(t), zone, upd); err != nil {
			t.Fatal(err)
		}
		if r, ok := find(list(t, p, zone), created.Name, "A"); !ok || r.Value != "192.0.2.12" {
			t.Fatalf("after update by ID: %+v", r)
		}
	})

	t.Run("UpdateMissing", func(t *testing.T) {
		p := factory(t)
		if !p.Capabilities().Update {
			t.Skip("provider does not support Update")
		}
		if _, err := p.UpdateRecord(ctx(t), zone, mk("nope")); !errors.Is(err, dns.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("UpdateUnknownID", func(t *testing.T) {
		p := factory(t)
		if !p.Capabilities().Update {
			t.Skip("provider does not support Update")
		}
		r := mk("unkid")
		r.ID = "doorwarden-no-such-id"
		if _, err := p.UpdateRecord(ctx(t), zone, r); !errors.Is(err, dns.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		p := factory(t)
		created := create(t, p, zone, mk("del"))
		if err := p.DeleteRecord(ctx(t), zone, created); err != nil {
			t.Fatal(err)
		}
		if _, ok := find(list(t, p, zone), created.Name, "A"); ok {
			t.Fatal("record still listed")
		}
	})

	t.Run("DeleteByID", func(t *testing.T) {
		p := factory(t)
		created := create(t, p, zone, mk("delid"))
		if created.ID == "" {
			t.Skip("provider returned no record ID")
		}
		if err := p.DeleteRecord(ctx(t), zone, dns.Record{ID: created.ID}); err != nil {
			t.Fatal(err)
		}
		if _, ok := find(list(t, p, zone), created.Name, "A"); ok {
			t.Fatal("record still listed after delete by ID")
		}
	})

	t.Run("DeleteWrongValueKeepsRecord", func(t *testing.T) {
		p := factory(t)
		created := create(t, p, zone, mk("delwrong"))
		wrong := dns.Record{Name: created.Name, Type: created.Type, Value: "198.51.100.77"}
		if err := p.DeleteRecord(ctx(t), zone, wrong); err != nil {
			t.Fatalf("delete with non-matching value must be a no-op, got %v", err)
		}
		if r, ok := find(list(t, p, zone), created.Name, "A"); !ok || r.Value != created.Value {
			t.Fatal("record with a different value was deleted or changed")
		}
	})

	t.Run("DeleteMissingOK", func(t *testing.T) {
		if err := factory(t).DeleteRecord(ctx(t), zone, mk("never")); err != nil {
			t.Fatalf("delete missing: %v", err)
		}
	})

	t.Run("WildcardRoundtrip", func(t *testing.T) {
		p := factory(t)
		if !p.Capabilities().WildcardA {
			t.Skip("provider does not support wildcard A")
		}
		w := dns.Record{Name: "*." + prefix + "-wild." + zone, Type: "A", Value: "192.0.2.20", TTL: 300}
		created := create(t, p, zone, w)
		if _, ok := find(list(t, p, zone), w.Name, "A"); !ok {
			t.Fatal("wildcard not listed")
		}
		if err := p.DeleteRecord(ctx(t), zone, created); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("MultiValueUnmanagedIntact", func(t *testing.T) {
		if o.SeedMultiValue == nil {
			t.Skip("no SeedMultiValue configured")
		}
		p := factory(t)
		name := name("multi", zone)
		if err := o.SeedMultiValue(ctx(t), zone, name, "192.0.2.1", "192.0.2.2"); err != nil {
			t.Fatalf("seed: %v", err)
		}
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			for _, v := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.77", "192.0.2.99"} {
				_ = p.DeleteRecord(c, zone, dns.Record{Name: name, Type: "A", Value: v})
			}
		})
		values := func() map[string]bool {
			m := map[string]bool{}
			for _, r := range list(t, p, zone) {
				if r.Name == name && r.Type == "A" {
					m[r.Value] = true
				}
			}
			return m
		}
		intact := func(op string) {
			t.Helper()
			if v := values(); !v["192.0.2.1"] || !v["192.0.2.2"] {
				t.Fatalf("%s destroyed unmanaged values: now %v", op, v)
			}
		}
		if p.Capabilities().Update {
			// ok or refused, but never destructive
			_, _ = p.UpdateRecord(ctx(t), zone, dns.Record{Name: name, Type: "A", Value: "192.0.2.99", TTL: 300})
			intact("Update")
		}
		_, _ = p.CreateRecord(ctx(t), zone, dns.Record{Name: name, Type: "A", Value: "192.0.2.77", TTL: 300})
		intact("Create")
		if err := p.DeleteRecord(ctx(t), zone, dns.Record{Name: name, Type: "A", Value: "192.0.2.1"}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if v := values(); v["192.0.2.1"] || !v["192.0.2.2"] {
			t.Fatalf("Delete of one value: now %v", v)
		}
	})

	t.Run("UnconfirmedCreateReturnsRecord", func(t *testing.T) {
		if o.Unconfirmed == nil {
			t.Skip("provider does not declare an unconfirmed-write mode")
		}
		p := o.Unconfirmed(t)
		rec := mk("unconf")
		got, err := p.CreateRecord(ctx(t), zone, rec)
		if !errors.Is(err, dns.ErrUnconfirmed) {
			t.Fatalf("want ErrUnconfirmed, got %v", err)
		}
		if got.Name != rec.Name || got.Type != rec.Type || got.Value != rec.Value {
			t.Fatalf("ErrUnconfirmed must come with the written record, got %+v", got)
		}
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = factory(t).DeleteRecord(c, zone, rec)
		})
	})

	t.Run("ListScopedToZone", func(t *testing.T) {
		if o.OtherZone == "" {
			t.Skip("no OtherZone configured")
		}
		p := factory(t)
		if !p.Capabilities().MultiZone {
			t.Skip("provider is not multi-zone")
		}
		other := dns.Record{Name: name("other", o.OtherZone), Type: "A", Value: "192.0.2.30", TTL: 300}
		create(t, p, o.OtherZone, other)
		if _, ok := find(list(t, p, zone), other.Name, "A"); ok {
			t.Fatal("record of another zone returned")
		}
	})

	t.Run("ZoneApex", func(t *testing.T) {
		if !o.Apex {
			t.Skip("Options.Apex not set (it writes the zone apex A record)")
		}
		p := factory(t)
		intact := func() error { return nil }
		if o.ApexForeign != nil {
			var err error
			if intact, err = o.ApexForeign(ctx(t), zone); err != nil {
				t.Fatalf("seeding foreign apex records: %v", err)
			}
		}
		rec := dns.Record{Name: zone, Type: "A", Value: "192.0.2.40", TTL: 300}
		got := create(t, p, zone, rec)
		if got.Name != zone || got.Value != rec.Value {
			t.Fatalf("created = %+v", got)
		}
		if r, ok := find(list(t, p, zone), zone, "A"); !ok || r.Value != rec.Value {
			t.Fatalf("apex A not listed: %+v", list(t, p, zone))
		}
		create(t, p, zone, rec) // idempotent
		upd := got
		upd.Value = "192.0.2.41"
		if _, err := p.UpdateRecord(ctx(t), zone, upd); err != nil {
			t.Fatalf("UpdateRecord(apex): %v", err)
		}
		if r, ok := find(list(t, p, zone), zone, "A"); !ok || r.Value != "192.0.2.41" {
			t.Fatalf("apex A not updated: %+v", list(t, p, zone))
		}
		if err := intact(); err != nil {
			t.Fatalf("after create/update: %v", err)
		}
		upd.ID = got.ID
		if err := p.DeleteRecord(ctx(t), zone, upd); err != nil {
			t.Fatalf("DeleteRecord(apex): %v", err)
		}
		if _, ok := find(list(t, p, zone), zone, "A"); ok {
			t.Fatal("apex A still listed after delete")
		}
		if err := intact(); err != nil {
			t.Fatalf("after delete: %v", err)
		}
	})
}
