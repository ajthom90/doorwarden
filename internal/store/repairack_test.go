package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRepairMassOKRoundtrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.SetRepairMassOK(ctx, "pihole", " Example.Test. ", t0); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := s.GetSetting(ctx, "dns/repair-mass-ok/pihole/example.test"); !ok || v != t0.Format(time.RFC3339) {
		t.Fatalf("stored %q %v", v, ok)
	}
	before := time.Now().Add(-time.Second)
	if err := s.AcknowledgeMassRepair(ctx, "cf/x", "other.test"); err != nil {
		t.Fatal(err)
	}
	// not parsable: left out
	s.SetSetting(ctx, RepairMassOKPrefix+"pihole/bad.test", "yesterday")
	s.SetSetting(ctx, RepairMassOKPrefix+"noslash", t0.Format(time.RFC3339))
	got, err := s.ListRepairMassOK(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got["pihole/example.test"].Equal(t0) || got["cf/x/other.test"].Before(before.Truncate(time.Second)) {
		t.Fatalf("got %v", got)
	}
	if err := s.ClearRepairMassOK(ctx, "pihole", "EXAMPLE.test"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListRepairMassOK(ctx); len(got) != 1 {
		t.Fatalf("not cleared: %v", got)
	}
	for _, c := range [][2]string{{"", "example.test"}, {"pihole", ""}, {"pihole", " . "}, {" pihole", "example.test"}} {
		if err := s.AcknowledgeMassRepair(ctx, c[0], c[1]); !errors.Is(err, ErrBadRepairAck) {
			t.Fatalf("%q: err %v", c, err)
		}
	}
}

func TestParseRepairMassOKKey(t *testing.T) {
	for k, want := range map[string][2]string{
		RepairMassOKKey("pihole", "a.test"): {"pihole", "a.test"},
		RepairMassOKKey("a/b", "c.test"):    {"a/b", "c.test"},
	} {
		p, z, ok := ParseRepairMassOKKey(k)
		if !ok || p != want[0] || z != want[1] {
			t.Fatalf("%s: %q %q %v", k, p, z, ok)
		}
	}
	for _, k := range []string{"dns/repair/p/z", RepairMassOKPrefix + "p/", RepairMassOKPrefix + "/z", RepairMassOKPrefix + "pz"} {
		if _, _, ok := ParseRepairMassOKKey(k); ok {
			t.Fatalf("%s parsed", k)
		}
	}
}
