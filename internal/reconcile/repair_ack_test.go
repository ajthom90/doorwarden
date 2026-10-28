package reconcile

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// ---- mass-repair acknowledgement (operator override of the breaker) ----

// The breaker Skip is self-describing: a stable synthetic key, the counts,
// the acknowledgement key, the API action and the fallback without the API.
func TestPlanRepairBreakerSkipNamesTheWayOut(t *testing.T) {
	desired, obs := massCase(10, 6)
	got := Plan(desired, obs, phCfg(), t0)
	sk := breakerSkips(got)
	if len(sk) != 1 || len(repairs(got)) != 0 {
		t.Fatalf("plan %v", sums(got))
	}
	s := sk[0]
	if s.Key != "repair-breaker:dnsp/example.test" || s.Key != RepairBreakerKey("dnsp", "Example.Test.") || s.Host != "example.test" {
		t.Fatalf("skip %+v", s)
	}
	for _, want := range []string{"(6 of 10)", "dns/repair-mass-ok/dnsp/example.test", "POST /api/v1/dns/repair/ack",
		`{"provider":"dnsp","zone":"example.test"}`, "INSERT OR REPLACE INTO kv", "24h", "5 per cycle"} {
		if !strings.Contains(s.Reason, want) {
			t.Fatalf("reason lacks %q: %s", want, s.Reason)
		}
	}
}

func TestPlanRepairMassOK(t *testing.T) {
	cases := []struct {
		name  string
		acks  map[string]time.Time
		trips bool
	}{
		{"no ack", nil, true},
		{"ack", map[string]time.Time{"dnsp/example.test": t0.Add(-time.Minute)}, false},
		{"ack just now", map[string]time.Time{"dnsp/example.test": t0}, false},
		{"ack almost expired", map[string]time.Time{"dnsp/example.test": t0.Add(-RepairMassOKTTL + time.Second)}, false},
		{"ack expired", map[string]time.Time{"dnsp/example.test": t0.Add(-RepairMassOKTTL)}, true},
		{"ack in the future", map[string]time.Time{"dnsp/example.test": t0.Add(time.Hour)}, true},
		{"ack slightly ahead", map[string]time.Time{"dnsp/example.test": t0.Add(time.Minute)}, false},
		{"other provider", map[string]time.Time{"other/example.test": t0}, true},
		{"other zone", map[string]time.Time{"dnsp/other.test": t0}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			desired, obs := massCase(20, 12)
			obs.RepairMassOK = c.acks
			got := Plan(desired, obs, phCfg(), t0)
			r, sk := repairs(got), breakerSkips(got)
			if c.trips {
				if len(sk) != 1 || len(r) != 0 {
					t.Fatalf("plan %v", sums(got))
				}
				return
			}
			// capped as usual, never more
			if len(sk) != 0 || len(r) != RepairCapPerZone {
				t.Fatalf("plan %v", sums(got))
			}
			for _, a := range ofKind(got, DNSEnsure) {
				if a.Repair && !strings.Contains(a.Reason, "acknowledged at") {
					t.Fatalf("reason %q", a.Reason)
				}
			}
		})
	}
	// an ack of a pair that does not trip changes nothing
	desired, obs := massCase(20, 2)
	plain := sums(Plan(desired, obs, phCfg(), t0))
	obs.RepairMassOK = map[string]time.Time{"dnsp/example.test": t0}
	if got := sums(Plan(desired, obs, phCfg(), t0)); strings.Join(got, "\n") != strings.Join(plain, "\n") {
		t.Fatalf("ack changed an untripped plan:\n%v\nvs\n%v", got, plain)
	}
}

// GatherObserved reads the acknowledgements, normalized, whatever they say;
// Plan decides whether they count.
func TestGatherObservedReadsRepairMassOK(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	if err := st.SetRepairMassOK(ctx, dzp, "Example.Test.", t0); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, store.RepairMassOKPrefix+"dnsp/bad.test", "nope"); err != nil {
		t.Fatal(err)
	}
	obs, errs := GatherObserved(ctx, map[string]dns.Provider{}, st, nil, 0)
	if len(errs) != 0 || len(obs.RepairMassOK) != 1 || !obs.RepairMassOK["dnsp/example.test"].Equal(t0) {
		t.Fatalf("acks %v errs %v", obs.RepairMassOK, errs)
	}
	var o Observed
	obs.Fill(&o)
	if !o.RepairMassOK["dnsp/example.test"].Equal(t0) {
		t.Fatalf("not filled: %v", o.RepairMassOK)
	}
}

func ackWorld(t *testing.T, n int) (*world, []model.Service) {
	t.Helper()
	w := newWorld(t, "per-host")
	var desired []model.Service
	for i := 0; i < n; i++ {
		desired = append(desired, pub(fmt.Sprintf("docker:s%02d", i), fmt.Sprintf("s%02d", i), dz, 80))
	}
	w.mustCycle(t0, desired...)
	return w, desired
}

func (w *world) wipe() {
	w.t.Helper()
	for _, rec := range w.records() {
		if err := w.fk.DeleteRecord(context.Background(), dz, rec); err != nil {
			w.t.Fatal(err)
		}
	}
}

func (w *world) ackPresent() bool {
	w.t.Helper()
	_, ok, err := w.st.GetSetting(context.Background(), store.RepairMassOKKey(dzp, dz))
	if err != nil {
		w.t.Fatal(err)
	}
	return ok
}

// A real mass loss: the breaker holds until the operator acknowledges it;
// then 5 per cycle until done, the acknowledgement is cleared once the zone
// has recovered, and a later mass loss trips the breaker again.
func TestDNSE2ERepairMassOKOverride(t *testing.T) {
	w, desired := ackWorld(t, 12)
	ctx := context.Background()
	w.wipe()
	at := t0.Add(time.Minute)
	cycle := func(want int, wantSkip, wantAck bool) {
		t.Helper()
		at = at.Add(time.Minute)
		n := len(w.fk.Calls())
		acts := w.mustCycle(at, desired...)
		if len(repairs(acts)) != want || len(w.writes(n)) != want || (len(breakerSkips(acts)) == 1) != wantSkip || w.ackPresent() != wantAck {
			t.Fatalf("at %v: repairs %v writes %v skips %v ack %v", at, repairs(acts), w.writes(n), sums(breakerSkips(acts)), w.ackPresent())
		}
	}
	cycle(0, true, false)
	// an acknowledgement dated in the future (a clock stepped back) is not
	// honored
	if err := w.st.SetRepairMassOK(ctx, dzp, dz, at.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	cycle(0, true, true)
	if err := w.st.SetRepairMassOK(ctx, dzp, dz, at); err != nil {
		t.Fatal(err)
	}
	cycle(5, false, true)  // 12 of 12 missing: acknowledged, capped
	cycle(5, false, false) // 7 of 12: capped; 2 left after the batch: recovered, cleared
	cycle(2, false, false) // 2 of 12: no breaker, no acknowledgement needed
	cycle(0, false, false)
	if len(w.records()) != 12 {
		t.Fatalf("records %d", len(w.records()))
	}
	// a new mass loss within 24h: the old acknowledgement is gone
	w.wipe()
	cycle(0, true, false)
	cycle(0, true, false)
}

// The acknowledgement lapses after 24h: the breaker holds again. (The key is
// removed by the executor's sweep, see TestDNSExecSweepRepairMassOK; this
// plan has no DNS action, so the executor does not run.)
func TestDNSE2ERepairMassOKExpires(t *testing.T) {
	w, desired := ackWorld(t, 12)
	ctx := context.Background()
	w.wipe()
	if err := w.st.SetRepairMassOK(ctx, dzp, dz, t0); err != nil {
		t.Fatal(err)
	}
	acts := w.mustCycle(t0.Add(time.Minute), desired...)
	if len(repairs(acts)) != 5 || !w.ackPresent() {
		t.Fatalf("plan %v", sums(acts))
	}
	// the zone is wiped again; a day later the acknowledgement no longer counts
	w.wipe()
	n := len(w.fk.Calls())
	acts = w.mustCycle(t0.Add(RepairMassOKTTL), desired...)
	if len(repairs(acts)) != 0 || len(breakerSkips(acts)) != 1 || len(w.writes(n)) != 0 {
		t.Fatalf("writes %v plan %v", w.writes(n), sums(acts))
	}
}

// An acknowledgement of another provider or zone does not let the repairs
// through.
func TestDNSE2ERepairMassOKWrongPairIgnored(t *testing.T) {
	w, desired := ackWorld(t, 6)
	ctx := context.Background()
	w.wipe()
	for _, pz := range [][2]string{{"other", dz}, {dzp, "other.test"}} {
		if err := w.st.SetRepairMassOK(ctx, pz[0], pz[1], t0); err != nil {
			t.Fatal(err)
		}
	}
	n := len(w.fk.Calls())
	acts := w.mustCycle(t0.Add(time.Minute), desired...)
	if len(repairs(acts)) != 0 || len(breakerSkips(acts)) != 1 || len(w.writes(n)) != 0 {
		t.Fatalf("writes %v plan %v", w.writes(n), sums(acts))
	}
}

// The sweep (first non-dry Apply, then hourly) removes acknowledgements that
// no longer count or name a pair the executor does not manage; a dry run
// never sweeps.
func TestDNSExecSweepRepairMassOK(t *testing.T) {
	r := newClockRig(t)
	ctx := context.Background()
	keep := map[string]bool{}
	set := func(p, z string, at time.Time, kept bool) {
		t.Helper()
		if err := r.st.SetRepairMassOK(ctx, p, z, at); err != nil {
			t.Fatal(err)
		}
		keep[store.RepairMassOKKey(p, z)] = kept
	}
	set(dzp, dz, t0.Add(-time.Hour), true)
	set(dzp, "other.test", t0, false) // not managed
	set("other", dz, t0, false)       // not the zone's provider
	set(dzp, "old.test", t0.Add(-48*time.Hour), false)
	if err := r.st.SetSetting(ctx, store.RepairMassOKPrefix+"dnsp/bad.test", "nope"); err != nil {
		t.Fatal(err)
	}
	keep[store.RepairMassOKPrefix+"dnsp/bad.test"] = false
	check := func(dry bool) {
		t.Helper()
		for k, kept := range keep {
			if _, ok, _ := r.st.GetSetting(ctx, k); ok != (kept || dry) {
				t.Fatalf("dry %v: %s present=%v", dry, k, ok)
			}
		}
	}
	if err := r.apply(t, true); err != nil {
		t.Fatal(err)
	}
	check(true)
	if err := r.apply(t, false); err != nil {
		t.Fatal(err)
	}
	check(false)
	// a day later the remaining one has expired: the next sweep removes it
	r.set(t0.Add(RepairMassOKTTL))
	if err := r.apply(t, false); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := r.st.GetSetting(ctx, store.RepairMassOKKey(dzp, dz)); ok {
		t.Fatal("expired acknowledgement not swept")
	}
}

// A dry run never clears an acknowledgement, recovered or expired.
func TestDNSE2ERepairMassOKDryRunNeverClears(t *testing.T) {
	w, desired := ackWorld(t, 6)
	ctx := context.Background()
	w.wipe()
	if err := w.st.SetRepairMassOK(ctx, dzp, dz, t0); err != nil {
		t.Fatal(err)
	}
	if err := w.st.SetRepairMassOK(ctx, dzp, "stale.test", t0.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	w.runner.DryRun = func() bool { return true }
	for i := 1; i <= 3; i++ {
		n := len(w.fk.Calls())
		acts := w.mustCycle(t0.Add(time.Duration(i)*time.Minute), desired...)
		if len(repairs(acts)) != 5 || len(w.writes(n)) != 0 {
			t.Fatalf("dry run: writes %v plan %v", w.writes(n), sums(acts))
		}
	}
	if acks, _ := w.st.ListRepairMassOK(ctx); len(acks) != 2 {
		t.Fatalf("dry run cleared: %v", acks)
	}
	// the real run repairs 5 of 6; 1 missing left: cleared
	w.runner.DryRun = nil
	w.mustCycle(t0.Add(5*time.Minute), desired...)
	if w.ackPresent() {
		t.Fatal("not cleared")
	}
}

// The executor clears an acknowledgement only from a successful listing of
// its pair and only when few enough rows are missing there.
func TestDNSExecClearRecoveredAcks(t *testing.T) {
	ctx := context.Background()
	t.Run("still many missing: kept", func(t *testing.T) {
		r := newClockRig(t)
		var as []Action
		for i := 0; i < 10; i++ {
			name := fmt.Sprintf("s%02d.example.test", i)
			r.addRow(t, name, "A", ip1, "gone-"+name, "docker:"+name)
			if i < 5 {
				as = append(as, repairOf(name, ip1, "gone-"+name, "docker:"+name))
			}
		}
		if err := r.st.SetRepairMassOK(ctx, dzp, dz, t0); err != nil {
			t.Fatal(err)
		}
		if err := r.apply(t, false, as...); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := r.st.GetSetting(ctx, store.RepairMassOKKey(dzp, dz)); !ok {
			t.Fatal("cleared with 5 of 10 still missing")
		}
		// the next 5: none missing, cleared
		as = nil
		for i := 5; i < 10; i++ {
			name := fmt.Sprintf("s%02d.example.test", i)
			as = append(as, repairOf(name, ip1, "gone-"+name, "docker:"+name))
		}
		if err := r.apply(t, false, as...); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := r.st.GetSetting(ctx, store.RepairMassOKKey(dzp, dz)); ok {
			t.Fatal("not cleared after recovery")
		}
		if !strings.Contains(r.act.messages(), "mass-repair acknowledgement of dnsp/example.test cleared: 0 of 10") {
			t.Fatalf("activity %q", r.act.messages())
		}
	})
	t.Run("listing failed: kept", func(t *testing.T) {
		r := newClockRig(t)
		r.addRow(t, "a.example.test", "A", ip1, "gone-a", "docker:a")
		if err := r.st.SetRepairMassOK(ctx, dzp, dz, t0); err != nil {
			t.Fatal(err)
		}
		r.fk.FailNext("ListRecords", fmt.Errorf("down"))
		_ = r.apply(t, false, repairOf("a.example.test", ip1, "gone-a", "docker:a"))
		if _, ok, _ := r.st.GetSetting(ctx, store.RepairMassOKKey(dzp, dz)); !ok {
			t.Fatal("cleared without a listing")
		}
	})
	t.Run("no listing in the batch: kept", func(t *testing.T) {
		r := newClockRig(t)
		if err := r.st.SetRepairMassOK(ctx, dzp, dz, t0); err != nil {
			t.Fatal(err)
		}
		if err := r.apply(t, false); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := r.st.GetSetting(ctx, store.RepairMassOKKey(dzp, dz)); !ok {
			t.Fatal("cleared without a listing")
		}
	})
}
