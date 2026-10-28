package fake_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/dnstest"
	"github.com/ajthom90/doorwarden/internal/dns/providers/fake"
)

func TestConformance(t *testing.T) {
	dnstest.Run(t, func(t *testing.T) dns.Provider { return fake.New(true) })
}

func TestConformanceNoWildcard(t *testing.T) {
	dnstest.Run(t, func(t *testing.T) dns.Provider { return fake.New(false) })
}

func TestRegisteredViaRegistry(t *testing.T) {
	p, err := dns.New("fake", map[string]any{"wildcard": false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Capabilities().WildcardA {
		t.Fatal("wildcard should be false")
	}
	if c, ok := dns.CapsFor("fake"); !ok || !c.WildcardA {
		t.Fatalf("static caps = %+v", c)
	}
}

func TestErrorInjectionAndCalls(t *testing.T) {
	ctx := context.Background()
	f := fake.New(true)
	boom := errors.New("boom")
	f.FailNext("Test", boom)
	if err := f.Test(ctx); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if err := f.Test(ctx); err != nil {
		t.Fatalf("second Test should succeed: %v", err)
	}
	f.FailNext("CreateRecord", boom)
	r := dns.Record{Name: "a.example.test", Type: "A", Value: "10.0.0.1"}
	if _, err := f.CreateRecord(ctx, "example.test", r); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.CreateRecord(ctx, "example.test", r); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 4 || calls[2].Op != "CreateRecord" || calls[2].Zone != "example.test" {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestSentinels(t *testing.T) {
	ctx := context.Background()
	f := fake.New(true)
	r := dns.Record{Name: "a.example.test", Type: "A", Value: "10.0.0.1"}
	if _, err := f.UpdateRecord(ctx, "example.test", r); !errors.Is(err, dns.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.CreateRecord(ctx, "example.test", r); err != nil {
		t.Fatal(err)
	}
	r.Value = "10.0.0.2"
	if _, err := f.CreateRecord(ctx, "example.test", r); !errors.Is(err, dns.ErrRecordExists) {
		t.Fatalf("err = %v", err)
	}
}

func TestInstanceCapsNarrowerThanStatic(t *testing.T) {
	static, _ := dns.CapsFor("fake")
	p, err := dns.New("fake", map[string]any{"wildcard": false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !static.WildcardA || p.Capabilities().WildcardA {
		t.Fatalf("static=%+v instance=%+v", static, p.Capabilities())
	}
}

func TestIdentityContract(t *testing.T) {
	ctx := context.Background()
	f := fake.New(true)
	r, _ := f.CreateRecord(ctx, "z.test", dns.Record{Name: "a.z.test", Type: "A", Value: "1.1.1.1"})
	// unknown ID: delete no-op, update ErrNotFound
	if err := f.DeleteRecord(ctx, "z.test", dns.Record{ID: "bogus"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.UpdateRecord(ctx, "z.test", dns.Record{ID: "bogus", Name: "a.z.test", Type: "A", Value: "2.2.2.2"}); !errors.Is(err, dns.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	// wrong value: no-op
	_ = f.DeleteRecord(ctx, "z.test", dns.Record{Name: "a.z.test", Type: "A", Value: "9.9.9.9"})
	if recs, _ := f.ListRecords(ctx, "z.test"); len(recs) != 1 {
		t.Fatalf("recs = %+v", recs)
	}
	_ = f.DeleteRecord(ctx, "z.test", dns.Record{ID: r.ID})
	if recs, _ := f.ListRecords(ctx, "z.test"); len(recs) != 0 {
		t.Fatalf("recs = %+v", recs)
	}
}
