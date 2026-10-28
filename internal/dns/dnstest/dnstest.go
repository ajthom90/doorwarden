// Package dnstest is a conformance suite every dns.Provider implementation
// reuses from its own tests.
package dnstest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
)

const zone = "example.test"

func find(recs []dns.Record, name, typ string) (dns.Record, bool) {
	for _, r := range recs {
		if r.Name == name && r.Type == typ {
			return r, true
		}
	}
	return dns.Record{}, false
}

// Run executes the conformance suite. factory must return a fresh, empty
// provider on every call.
func Run(t *testing.T, factory func(t *testing.T) dns.Provider) {
	ctx := func(t *testing.T) context.Context {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		return c
	}
	rec := dns.Record{Name: "app." + zone, Type: "A", Value: "192.0.2.10", TTL: 300}

	t.Run("Test", func(t *testing.T) {
		if err := factory(t).Test(ctx(t)); err != nil {
			t.Fatalf("Test: %v", err)
		}
	})

	t.Run("CreateList", func(t *testing.T) {
		p, c := factory(t), ctx(t)
		got, err := p.CreateRecord(c, zone, rec)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != rec.Name || got.Type != rec.Type || got.Value != rec.Value {
			t.Fatalf("created = %+v", got)
		}
		recs, err := p.ListRecords(c, zone)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := find(recs, rec.Name, "A"); !ok {
			t.Fatalf("created record not listed: %+v", recs)
		}
	})

	t.Run("CreateIdempotent", func(t *testing.T) {
		p, c := factory(t), ctx(t)
		if _, err := p.CreateRecord(c, zone, rec); err != nil {
			t.Fatal(err)
		}
		if _, err := p.CreateRecord(c, zone, rec); err != nil {
			t.Fatalf("second identical create: %v", err)
		}
		recs, _ := p.ListRecords(c, zone)
		n := 0
		for _, r := range recs {
			if r.Name == rec.Name && r.Type == "A" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("want 1 record, got %d", n)
		}
	})

	t.Run("Update", func(t *testing.T) {
		p, c := factory(t), ctx(t)
		if !p.Capabilities().Update {
			t.Skip("provider does not support Update")
		}
		created, err := p.CreateRecord(c, zone, rec)
		if err != nil {
			t.Fatal(err)
		}
		upd := created
		upd.Value = "192.0.2.11"
		if _, err := p.UpdateRecord(c, zone, upd); err != nil {
			t.Fatal(err)
		}
		recs, _ := p.ListRecords(c, zone)
		if r, ok := find(recs, rec.Name, "A"); !ok || r.Value != "192.0.2.11" {
			t.Fatalf("after update: %+v", recs)
		}
	})

	t.Run("UpdateMissing", func(t *testing.T) {
		p := factory(t)
		if !p.Capabilities().Update {
			t.Skip("provider does not support Update")
		}
		if _, err := p.UpdateRecord(ctx(t), zone, rec); !errors.Is(err, dns.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		p, c := factory(t), ctx(t)
		created, err := p.CreateRecord(c, zone, rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.DeleteRecord(c, zone, created); err != nil {
			t.Fatal(err)
		}
		recs, _ := p.ListRecords(c, zone)
		if _, ok := find(recs, rec.Name, "A"); ok {
			t.Fatalf("record still listed: %+v", recs)
		}
	})

	t.Run("DeleteMissingOK", func(t *testing.T) {
		if err := factory(t).DeleteRecord(ctx(t), zone, rec); err != nil {
			t.Fatalf("delete missing: %v", err)
		}
	})

	t.Run("WildcardRoundtrip", func(t *testing.T) {
		p, c := factory(t), ctx(t)
		if !p.Capabilities().WildcardA {
			t.Skip("provider does not support wildcard A")
		}
		w := dns.Record{Name: "*." + zone, Type: "A", Value: "192.0.2.20", TTL: 300}
		created, err := p.CreateRecord(c, zone, w)
		if err != nil {
			t.Fatal(err)
		}
		recs, _ := p.ListRecords(c, zone)
		if _, ok := find(recs, w.Name, "A"); !ok {
			t.Fatalf("wildcard not listed: %+v", recs)
		}
		if err := p.DeleteRecord(c, zone, created); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ListScopedToZone", func(t *testing.T) {
		p, c := factory(t), ctx(t)
		if !p.Capabilities().MultiZone {
			t.Skip("provider is not multi-zone")
		}
		other := "other.test"
		if _, err := p.CreateRecord(c, other, dns.Record{Name: "x." + other, Type: "A", Value: "192.0.2.30", TTL: 300}); err != nil {
			t.Skipf("cannot write to second zone (tolerated): %v", err)
		}
		recs, err := p.ListRecords(c, zone)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := find(recs, "x."+other, "A"); ok {
			t.Fatalf("record of another zone returned: %+v", recs)
		}
	})
}
