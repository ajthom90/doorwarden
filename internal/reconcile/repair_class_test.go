package reconcile

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// ---- rows whose desired value changed and that are missing: repair-class ----

const newTarget = "192.0.2.77"

// movedCfg is phCfg with target_ip changed: every owned row (value target)
// needs an update.
func movedCfg() *config.Config {
	c := phCfg()
	c.Zones[0].TargetIP = newTarget
	return c
}

// updates returns the DNSEnsure actions that change an owned row's value
// (not repairs), as "name id".
func updates(as []Action) []string {
	var out []string
	for _, a := range ofKind(as, DNSEnsure) {
		if !a.Repair && a.Record.ID != "" {
			out = append(out, a.Record.Name+" "+a.Record.ID)
		}
	}
	return out
}

func TestPlanRepairClassUpdates(t *testing.T) {
	cases := []struct {
		wanted, missing int
		trip            bool
		updates         int // present rows updated + missing rows re-created
	}{
		{10, 0, false, 10},  // a target_ip migration: every present row, uncapped
		{30, 0, false, 30},  // uncapped
		{3, 3, false, 3},    // the zone wiped, but only 3 rows: capped path
		{10, 10, true, 0},   // the zone wiped: breaker
		{10, 6, true, 4},    // mixed: the 4 present rows are updated, the 6 missing held
		{10, 5, false, 10},  // 50%: 5 present + 5 missing (the cap)
		{20, 8, false, 17},  // 12 present + 5 of 8 missing
		{20, 10, false, 15}, // 10 present + 5 of 10 missing
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d of %d", c.missing, c.wanted), func(t *testing.T) {
			desired, obs := massCase(c.wanted, c.missing)
			got := Plan(desired, obs, movedCfg(), t0)
			sk := breakerSkips(got)
			if (len(sk) == 1) != c.trip || len(sk) > 1 || len(repairs(got)) != 0 {
				t.Fatalf("plan %v", sums(got))
			}
			if c.trip && !strings.Contains(sk[0].Reason, fmt.Sprintf("(%d of %d)", c.missing, c.wanted)) {
				t.Fatalf("skip %s", sk[0].Reason)
			}
			u := updates(got)
			if len(u) != c.updates {
				t.Fatalf("updates %d, want %d: %v", len(u), c.updates, u)
			}
			missingSent := 0
			for _, a := range ofKind(got, DNSEnsure) {
				if a.Record.Value != newTarget {
					t.Fatalf("value %s", sum(a))
				}
				if obs.OwnedMissing[OwnedRowKey(a.Provider, a.Zone, a.Record.Name, a.Record.Type)] {
					missingSent++
					if !strings.Contains(a.Reason, "missing at the provider") {
						t.Fatalf("reason %q", a.Reason)
					}
				}
			}
			if missingSent > RepairCapPerZone || (c.trip && missingSent != 0) {
				t.Fatalf("%d missing rows re-created: %v", missingSent, u)
			}
		})
	}
}

// Same-value repairs and repair-class updates share one count and one cap.
func TestPlanRepairClassSharesBreakerAndCap(t *testing.T) {
	// 4 rows already at the new value (2 missing) and 4 rows at the old one
	// (2 missing): 4 missing of 8, exactly half: no trip, 4 sent in all
	desired, obs := massCase(8, 0)
	for i := range obs.Owned {
		if i < 4 {
			obs.Owned[i].Value = newTarget
		}
	}
	obs.OwnedMissing = missing(obs.Owned[0], obs.Owned[1], obs.Owned[4], obs.Owned[5])
	got := Plan(desired, obs, movedCfg(), t0)
	if len(breakerSkips(got)) != 0 || len(repairs(got)) != 2 || len(updates(got)) != 4 {
		t.Fatalf("plan %v", sums(got))
	}
	// one more missing old-value row: 5 of 8 trips, holding both kinds
	obs.OwnedMissing[OwnedRowKey("dnsp", "example.test", obs.Owned[6].Name, "A")] = true
	got = Plan(desired, obs, movedCfg(), t0)
	if len(breakerSkips(got)) != 1 || len(repairs(got)) != 0 || len(updates(got)) != 1 {
		t.Fatalf("plan %v", sums(got))
	}
	// the cap is shared: 7 missing of 20, mixed kinds: 5 sent in all
	desired, obs = massCase(20, 7)
	for i := range obs.Owned {
		if i%2 == 0 {
			obs.Owned[i].Value = newTarget
		}
	}
	got = Plan(desired, obs, movedCfg(), t0)
	sent := 0
	for _, a := range ofKind(got, DNSEnsure) {
		if obs.OwnedMissing[OwnedRowKey(a.Provider, a.Zone, a.Record.Name, a.Record.Type)] {
			sent++
		}
	}
	if sent != RepairCapPerZone || len(breakerSkips(got)) != 0 {
		t.Fatalf("sent %d: %v", sent, sums(got))
	}
}

// A missing row whose value changed is held while its owner's source is
// unavailable, and a foreign record at the name makes it a Conflict (still
// counted as missing).
func TestPlanRepairClassNotEligibleOrBlocked(t *testing.T) {
	desired, obs := massCase(4, 2)
	got := Plan(desired, obs, movedCfg(), t0)
	if u := updates(got); len(u) != 4 {
		t.Fatalf("updates %v", u)
	}
	obs.Foreign["dnsp/example.test"] = []dns.Record{{ID: "f", Name: "s00.example.test", Type: "CNAME", Value: "x.test"}}
	got = Plan(desired, obs, movedCfg(), t0)
	if u := updates(got); len(u) != 3 || len(ofKind(got, Conflict)) != 1 {
		t.Fatalf("plan %v", sums(got))
	}
	// 4 of 6 missing, s00 of them blocked by a foreign record: trips
	desired, obs = massCase(6, 4)
	obs.Foreign["dnsp/example.test"] = []dns.Record{{ID: "f", Name: "s00.example.test", Type: "CNAME", Value: "x.test"}}
	if got := Plan(desired, obs, movedCfg(), t0); len(breakerSkips(got)) != 1 || len(updates(got)) != 2 {
		t.Fatalf("4 of 6 missing (one blocked) must trip: %v", sums(got))
	}
	// unavailable source: never re-created blind, and not counted
	desired, obs = massCase(1, 0)
	tn := pub("truenas:nas", "nas", "example.test", 80)
	tn.Source = "truenas"
	desired = append(desired, tn)
	row := owned("example.test", "nas.example.test", "A", target, "truenas:nas")
	obs.Owned = append(obs.Owned, row)
	obs.OwnedMissing = missing(row)
	obs.Unavailable = map[string]bool{"truenas": true}
	for _, a := range ofKind(Plan(desired, obs, movedCfg(), t0), DNSEnsure) {
		if a.Record.Name == "nas.example.test" {
			t.Fatalf("re-created for an unavailable source: %s", sum(a))
		}
	}
}

// The mass-repair acknowledgement lets the capped repair-class updates
// through too.
func TestPlanRepairClassAck(t *testing.T) {
	desired, obs := massCase(10, 10)
	obs.RepairMassOK = map[string]time.Time{"dnsp/example.test": t0}
	got := Plan(desired, obs, movedCfg(), t0)
	if len(breakerSkips(got)) != 0 || len(updates(got)) != RepairCapPerZone {
		t.Fatalf("plan %v", sums(got))
	}
	for _, a := range ofKind(got, DNSEnsure) {
		if !strings.Contains(a.Reason, "acknowledged at") {
			t.Fatalf("reason %q", a.Reason)
		}
	}
}

func TestPlanRepairClassDeterministicUnderShuffle(t *testing.T) {
	desired, obs := massCase(30, 9)
	for i := range obs.Owned {
		if i%3 == 0 {
			obs.Owned[i].Value = newTarget
		}
	}
	want := sums(Plan(desired, obs, movedCfg(), t0))
	for seed := int64(0); seed < 50; seed++ {
		r := rand.New(rand.NewSource(seed))
		d := append([]model.Service(nil), desired...)
		o := obs
		o.Owned = append([]store.DNSRecord(nil), obs.Owned...)
		r.Shuffle(len(d), func(i, j int) { d[i], d[j] = d[j], d[i] })
		r.Shuffle(len(o.Owned), func(i, j int) { o.Owned[i], o.Owned[j] = o.Owned[j], o.Owned[i] })
		if got := sums(Plan(d, o, movedCfg(), t0)); !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d:\n%v\nwant\n%v", seed, got, want)
		}
	}
}

// End to end: target_ip changes while the zone is wiped. 10 records: the
// breaker holds (no write) until acknowledged; 3 records: re-created with the
// new value through the capped path.
func TestDNSE2ERepairClassTargetChangeOnWipedZone(t *testing.T) {
	t.Run("10: breaker", func(t *testing.T) {
		w, desired := ackWorld(t, 10)
		w.wipe()
		w.cfg.Zones[0].TargetIP = newTarget
		for i := 1; i <= 2; i++ {
			n := len(w.fk.Calls())
			acts := w.mustCycle(t0.Add(time.Duration(i)*time.Minute), desired...)
			if len(w.writes(n)) != 0 || len(breakerSkips(acts)) != 1 || len(ofKind(acts, DNSEnsure)) != 0 {
				t.Fatalf("cycle %d: writes %v plan %v", i, w.writes(n), sums(acts))
			}
		}
		if err := w.st.SetRepairMassOK(context.Background(), dzp, dz, t0.Add(2*time.Minute)); err != nil {
			t.Fatal(err)
		}
		for i, want := range []int{5, 5, 0} {
			n := len(w.fk.Calls())
			w.mustCycle(t0.Add(time.Duration(3+i)*time.Minute), desired...)
			creates := 0
			for _, op := range ops(w.fk, n) {
				if op == "CreateRecord" {
					creates++
				}
			}
			if creates != want {
				t.Fatalf("cycle %d: calls %v", i, ops(w.fk, n))
			}
		}
		if w.ackPresent() {
			t.Fatal("acknowledgement not cleared")
		}
		recs := w.records()
		if len(recs) != 10 {
			t.Fatalf("records %v", recs)
		}
		for _, r := range recs {
			if r.Value != newTarget {
				t.Fatalf("records %v", recs)
			}
		}
	})
	t.Run("3: capped path", func(t *testing.T) {
		w, desired := ackWorld(t, 3)
		w.wipe()
		w.cfg.Zones[0].TargetIP = newTarget
		acts := w.mustCycle(t0.Add(time.Minute), desired...)
		recs := w.records()
		if len(breakerSkips(acts)) != 0 || len(recs) != 3 || recs[0].Value != newTarget {
			t.Fatalf("records %v plan %v", recs, sums(acts))
		}
	})
	t.Run("20 present: a migration is not capped", func(t *testing.T) {
		w, desired := ackWorld(t, 20)
		w.cfg.Zones[0].TargetIP = newTarget
		n := len(w.fk.Calls())
		w.mustCycle(t0.Add(time.Minute), desired...)
		if len(w.writes(n)) != 20 {
			t.Fatalf("writes %v", w.writes(n))
		}
		for _, r := range w.records() {
			if r.Value != newTarget {
				t.Fatalf("records %v", w.records())
			}
		}
	})
}
