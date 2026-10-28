package reconcile

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// ---- Plan: mass-repair breaker and per-zone cap ----

// massCase builds m Published services in example.test (per-host), each with
// its owned row, the first n of them (by name) missing at a listing that is
// otherwise empty.
func massCase(m, n int) ([]model.Service, Observed) {
	var desired []model.Service
	var rows []store.DNSRecord
	for i := 0; i < m; i++ {
		name := fmt.Sprintf("s%02d", i)
		desired = append(desired, pub("docker:"+name, name, "example.test", 80))
		rows = append(rows, owned("example.test", name+".example.test", "A", target, "docker:"+name))
	}
	return desired, Observed{Foreign: listed("example.test"), Owned: rows, OwnedMissing: missing(rows[:n]...)}
}

func breakerSkips(as []Action) []Action {
	var out []Action
	for _, a := range ofKind(as, Skip) {
		if a.Alert == AlertDNSMassMissing {
			out = append(out, a)
		}
	}
	return out
}

func TestPlanRepairBreakerAndCap(t *testing.T) {
	cases := []struct {
		wanted, missing int
		trip            bool
		repaired        int
	}{
		{1, 1, false, 1},
		{3, 3, false, 3},   // 100% but not more than 3
		{4, 3, false, 3},   // 75% but not more than 3
		{4, 4, true, 0},    // more than 3 and more than half
		{8, 4, false, 4},   // exactly 50%: not more than half
		{10, 5, false, 5},  // exactly 50%
		{10, 6, true, 0},   // 60%
		{20, 7, false, 5},  // 35%: capped at 5
		{10, 10, true, 0},  // an empty listing
		{50, 50, true, 0},  // an empty listing
		{50, 25, false, 5}, // 50%: capped
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d of %d", c.missing, c.wanted), func(t *testing.T) {
			desired, obs := massCase(c.wanted, c.missing)
			got := Plan(desired, obs, phCfg(), t0)
			r, sk := repairs(got), breakerSkips(got)
			if len(r) != c.repaired {
				t.Fatalf("repairs %d, want %d: %v", len(r), c.repaired, r)
			}
			if !c.trip {
				if len(sk) != 0 {
					t.Fatalf("breaker tripped: %v", sums(sk))
				}
				// a window of the missing rows by name, from RepairRotation
				off := RepairRotation("dnsp/example.test", t0, c.missing)
				var want []string
				for i := 0; i < len(r); i++ {
					want = append(want, fmt.Sprintf("s%02d.example.test", (off+i)%c.missing))
				}
				sort.Strings(want)
				for i, s := range r {
					if !strings.Contains(s, want[i]+" ") {
						t.Fatalf("repair %d is %s, want %s (all %v)", i, s, want[i], r)
					}
				}
				return
			}
			if len(sk) != 1 || len(ofKind(got, Skip)) != 1 {
				t.Fatalf("want exactly one breaker Skip: %v", sums(got))
			}
			s := sk[0]
			want := fmt.Sprintf("most owned records missing at dnsp/example.test (%d of %d); refusing mass repair: check the provider and zone configuration",
				c.missing, c.wanted)
			if !strings.HasPrefix(s.Reason, want) || s.Provider != "dnsp" || s.Zone != "example.test" {
				t.Fatalf("skip %+v", s)
			}
			for _, a := range got {
				if a.Repair {
					t.Fatalf("repair emitted while tripped: %s", sum(a))
				}
			}
			assertNone(t, got, DNSDelete, DNSScheduleRemoval)
		})
	}
}

// Only WANTED rows eligible for repair count: orphans, protected owners and
// owners whose source is unavailable neither trip the breaker nor dilute it.
func TestPlanRepairBreakerCountsOnlyEligibleRows(t *testing.T) {
	// 3 wanted rows missing of 3, plus missing rows of a stopped owner, an
	// absent owner (orphan) and an owner from an unavailable source: still
	// 3 of 3, no trip, 3 repairs
	desired, obs := massCase(3, 3)
	desired = append(desired, svc("docker:stop", "stop", "example.test", model.StateStopped, "198.51.100.5", 80))
	tn := pub("truenas:nas", "nas", "example.test", 80)
	tn.Source = "truenas"
	desired = append(desired, tn)
	extra := []store.DNSRecord{owned("example.test", "stop.example.test", "A", target, "docker:stop"),
		owned("example.test", "gone.example.test", "A", target, "docker:gone"),
		owned("example.test", "nas.example.test", "A", target, "truenas:nas")}
	obs.Owned = append(obs.Owned, extra...)
	for k := range missing(extra...) {
		obs.OwnedMissing[k] = true
	}
	obs.Unavailable = map[string]bool{"truenas": true}
	got := Plan(desired, obs, phCfg(), t0)
	if len(breakerSkips(got)) != 0 || len(repairs(got)) != 3 {
		t.Fatalf("plan %v", sums(got))
	}
	// 4 wanted missing of 4 trips even though the zone holds other present rows
	// of ineligible owners
	desired, obs = massCase(4, 4)
	desired = append(desired, svc("docker:stop", "stop", "example.test", model.StateStopped, "198.51.100.5", 80))
	obs.Owned = append(obs.Owned, owned("example.test", "stop.example.test", "A", target, "docker:stop"))
	if got := Plan(desired, obs, phCfg(), t0); len(breakerSkips(got)) != 1 || len(repairs(got)) != 0 {
		t.Fatalf("plan %v", sums(got))
	}
	// rows of owners from an unavailable source do not dilute it either: 4
	// of 4 eligible missing, next to 4 present rows of unavailable owners
	desired, obs = massCase(4, 4)
	obs.Unavailable = map[string]bool{"truenas": true}
	for i := 0; i < 4; i++ {
		n := fmt.Sprintf("nas%d", i)
		desired = append(desired, pub("truenas:"+n, n, "example.test", 80))
		obs.Owned = append(obs.Owned, owned("example.test", n+".example.test", "A", target, "truenas:"+n))
	}
	if got := Plan(desired, obs, phCfg(), t0); len(breakerSkips(got)) != 1 || len(repairs(got)) != 0 {
		t.Fatalf("plan %v", sums(got))
	}
	// a drifted wanted row counts as wanted but not missing: 4 missing of 9
	desired, obs = massCase(9, 4)
	k := OwnedRowKey("dnsp", "example.test", "s08.example.test", "A")
	obs.OwnedDrifted = map[string][]dns.Record{k: {{ID: "x", Name: "s08.example.test", Type: "A", Value: ipFX}}}
	if got := Plan(desired, obs, phCfg(), t0); len(breakerSkips(got)) != 0 || len(repairs(got)) != 4 {
		t.Fatalf("plan %v", sums(got))
	}
}

// A missing row a foreign record blocks counts as missing (Conflict stays
// reported) and is never repaired.
func TestPlanRepairBreakerBlockedRowsCountAsMissing(t *testing.T) {
	desired, obs := massCase(6, 3)
	obs.OwnedMissing[OwnedRowKey("dnsp", "example.test", "s05.example.test", "A")] = true
	obs.Foreign["dnsp/example.test"] = []dns.Record{{ID: "f", Name: "s05.example.test", Type: "CNAME", Value: "x.test"}}
	got := Plan(desired, obs, phCfg(), t0)
	if len(breakerSkips(got)) != 1 || len(repairs(got)) != 0 || len(ofKind(got, Conflict)) != 1 {
		t.Fatalf("4 of 6 missing (one blocked) must trip: %v", sums(got))
	}
}

// The selection is the same whatever order desired and Owned come in.
func TestPlanRepairCapDeterministicUnderShuffle(t *testing.T) {
	desired, obs := massCase(30, 9)
	want := repairs(Plan(desired, obs, phCfg(), t0))
	if len(want) != RepairCapPerZone {
		t.Fatalf("repairs %v", want)
	}
	for seed := int64(0); seed < 50; seed++ {
		r := rand.New(rand.NewSource(seed))
		d := append([]model.Service(nil), desired...)
		o := obs
		o.Owned = append([]store.DNSRecord(nil), obs.Owned...)
		r.Shuffle(len(d), func(i, j int) { d[i], d[j] = d[j], d[i] })
		r.Shuffle(len(o.Owned), func(i, j int) { o.Owned[i], o.Owned[j] = o.Owned[j], o.Owned[i] })
		if got := repairs(Plan(d, o, phCfg(), t0)); !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: %v, want %v", seed, got, want)
		}
	}
}

// The wildcard row counts as a row; a wildcard zone has at most one wanted
// row, so its breaker can never trip.
func TestPlanRepairWildcardRowNeverTrips(t *testing.T) {
	row := owned("example.test", "*.example.test", "A", target, WildcardOwnerKey("example.test"))
	cfg := cfgOf(zone("example.test", "wildcard", "wildcard"))
	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}, OwnedMissing: missing(row)}
	got := Plan([]model.Service{pub("docker:app", "app", "example.test", 80)}, obs, cfg, t0)
	if len(repairs(got)) != 1 || len(breakerSkips(got)) != 0 {
		t.Fatalf("plan %v", sums(got))
	}
}

// ---- executor: one listing per provider/zone per batch ----

func TestDNSExecRepairListsOncePerBatch(t *testing.T) {
	for _, n := range []int{1, 5, 10} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			r := newClockRig(t)
			var as []Action
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("s%02d.example.test", i)
				r.addRow(t, name, "A", ip1, "gone-"+name, "docker:"+name)
				as = append(as, repairOf(name, ip1, "gone-"+name, "docker:"+name))
			}
			skip := len(r.fk.Calls())
			if err := r.apply(t, false, as...); err != nil {
				t.Fatal(err)
			}
			lists := 0
			for _, op := range ops(r.fk, skip) {
				if op == "ListRecords" {
					lists++
				}
			}
			if lists != 1 || len(r.zoneRecords(t)) != n {
				t.Fatalf("listings %d, records %d: %v", lists, len(r.zoneRecords(t)), ops(r.fk, skip))
			}
		})
	}
}

// A failed listing is not retried within the batch: every repair of the pair
// fails with ErrListingUnavailable, counts its attempt and creates nothing.
func TestDNSExecRepairListingFailureListsOnce(t *testing.T) {
	r := newClockRig(t)
	var as []Action
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("s%02d.example.test", i)
		r.addRow(t, name, "A", ip1, "gone-"+name, "docker:"+name)
		as = append(as, repairOf(name, ip1, "gone-"+name, "docker:"+name))
	}
	r.fk.FailNext("ListRecords", errors.New("down"))
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, as...); !errors.Is(err, ErrListingUnavailable) {
		t.Fatalf("err %v", err)
	}
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords" {
		t.Fatalf("calls %s", got)
	}
	for i := 0; i < 4; i++ {
		if s, _ := r.repairState(t, fmt.Sprintf("s%02d.example.test", i)); s.Attempts != 1 {
			t.Fatalf("row %d state %+v", i, s)
		}
	}
}

// A foreign record blocks only its own row; the others of the batch are
// re-created from the same (single) listing.
func TestDNSExecRepairForeignBlocksOnlyItsRow(t *testing.T) {
	r := newClockRig(t)
	var as []Action
	for _, n := range []string{"a", "b", "c"} {
		name := n + ".example.test"
		r.addRow(t, name, "A", ip1, "gone-"+name, "docker:"+n)
		as = append(as, repairOf(name, ip1, "gone-"+name, "docker:"+n))
	}
	r.seed(t, "b.example.test", "CNAME", "elsewhere.test")
	skip := len(r.fk.Calls())
	err := r.apply(t, false, as...)
	if !errors.Is(err, ErrForeignRecord) || !strings.Contains(err.Error(), "b.example.test") {
		t.Fatalf("err %v", err)
	}
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords,CreateRecord,CreateRecord" {
		t.Fatalf("calls %s", got)
	}
	var names []string
	for _, rec := range r.zoneRecords(t) {
		names = append(names, rec.Name+" "+rec.Type)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "a.example.test A,b.example.test CNAME,c.example.test A" {
		t.Fatalf("records %v", names)
	}
}

// ---- end to end ----

// More than 5 missing rows, but not most of them: 5 per cycle until all are
// back, then no more writes.
func TestDNSE2ERepairCapAcrossCycles(t *testing.T) {
	w := newWorld(t, "per-host")
	var desired []model.Service
	for i := 0; i < 20; i++ {
		desired = append(desired, pub(fmt.Sprintf("docker:s%02d", i), fmt.Sprintf("s%02d", i), dz, 80))
	}
	w.mustCycle(t0, desired...)
	ctx := context.Background()
	for _, row := range w.rows()[:7] {
		if err := w.fk.DeleteRecord(ctx, dz, dns.Record{ID: row.ProviderRecordID}); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range []int{5, 2, 0} {
		n := len(w.fk.Calls())
		acts := w.mustCycle(t0.Add(time.Duration(i+1)*time.Minute), desired...)
		if r := repairs(acts); len(r) != want || len(w.writes(n)) != want {
			t.Fatalf("cycle %d: repairs %v writes %v", i, r, w.writes(n))
		}
	}
	if len(w.records()) != 20 {
		t.Fatalf("records %d", len(w.records()))
	}
}

// A provider listing that is (wrongly) empty: the breaker holds every cycle
// with no write, and lets the repairs through by itself once most records
// are listed again.
func TestDNSE2ERepairBreakerHoldsThenClears(t *testing.T) {
	w := newWorld(t, "per-host")
	var desired []model.Service
	for i := 0; i < 6; i++ {
		desired = append(desired, pub(fmt.Sprintf("docker:s%02d", i), fmt.Sprintf("s%02d", i), dz, 80))
	}
	w.mustCycle(t0, desired...)
	saved := w.records()
	ctx := context.Background()
	for _, rec := range saved {
		_ = w.fk.DeleteRecord(ctx, dz, rec) // wiped
	}
	for i := 1; i <= 2; i++ {
		n := len(w.fk.Calls())
		acts := w.mustCycle(t0.Add(time.Duration(i)*time.Minute), desired...)
		if len(w.writes(n)) != 0 || len(repairs(acts)) != 0 || len(breakerSkips(acts)) != 1 ||
			!strings.Contains(breakerSkips(acts)[0].Reason, "(6 of 6)") {
			t.Fatalf("cycle %d: writes %v plan %v", i, w.writes(n), sums(acts))
		}
	}
	// the operator restores 4 of them (by hand: new IDs): 2 of 6 missing
	for _, rec := range saved[:4] {
		if _, err := w.fk.CreateRecord(ctx, dz, dns.Record{Name: rec.Name, Type: rec.Type, Value: rec.Value}); err != nil {
			t.Fatal(err)
		}
	}
	acts := w.mustCycle(t0.Add(3*time.Minute), desired...)
	if len(breakerSkips(acts)) != 0 || len(repairs(acts)) != 2 || len(w.records()) != 6 {
		t.Fatalf("plan %v records %v", sums(acts), w.records())
	}
}

// ---- M1: an unconfirmed write naming another value is ambiguous ----

func TestDNSExecUnconfirmedOtherValueIsAmbiguous(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		r, u := unconfRig(t, false)
		u.push("CreateRecord", unconfStep{apply: true, record: true, value: ipFX})
		if err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app")); !errors.Is(err, dns.ErrUnconfirmed) {
			t.Fatalf("err %v", err)
		}
		if rows := r.rows(t); len(rows) != 0 {
			t.Fatalf("rows %+v", rows)
		}
		if !strings.Contains(r.act.messages(), "OUTCOME UNKNOWN") {
			t.Fatalf("activity %q", r.act.messages())
		}
	})
	t.Run("update returning the old value", func(t *testing.T) {
		r, u := unconfRig(t, false)
		rec := r.seed(t, "app.example.test", "A", ip1)
		r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
		u.push("UpdateRecord", unconfStep{apply: false, record: true, id: "fake-77", value: ip1})
		if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); !errors.Is(err, dns.ErrUnconfirmed) {
			t.Fatalf("err %v", err)
		}
		if rows := r.rows(t); len(rows) != 1 || rows[0].Value != ip1 || rows[0].ProviderRecordID != rec.ID {
			t.Fatalf("row changed: %+v", rows)
		}
	})
	t.Run("same value, other spelling: the target is stored", func(t *testing.T) {
		r, u := unconfRig(t, false)
		u.push("CreateRecord", unconfStep{apply: true, record: true, value: "::ffff:" + ip1})
		if err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app")); err != nil {
			t.Fatal(err)
		}
		if rows := r.rows(t); len(rows) != 1 || rows[0].Value != ip1 {
			t.Fatalf("rows %+v", rows)
		}
	})
}

// ---- M2: an unconfirmed update that rotated the ID but did not land ----

func TestDNSExecUnconfirmedUpdateRotatedIDNotLanded(t *testing.T) {
	r, u := unconfRig(t, false)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	u.push("UpdateRecord", unconfStep{apply: false, record: true, id: "fake-rotated"})
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
		t.Fatal(err)
	}
	if rows := r.rows(t); rows[0].ProviderRecordID != "fake-rotated" || rows[0].Value != ip1 {
		t.Fatalf("rows %+v", rows)
	}
	key := pendingKey(dzp, dz, "app.example.test", "A")
	if v, ok, _ := r.st.GetSetting(context.Background(), key); !ok || !strings.Contains(v, `"old_id":"`+rec.ID+`"`) ||
		!strings.Contains(v, `"value":"`+ip2+`"`) {
		t.Fatalf("pending %q %v", v, ok)
	}
	// next cycle: the rotated ID does not exist; the record under the old ID
	// is ours and is updated, not refused as foreign
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
		t.Fatalf("err %v (calls %v)", err, ops(r.fk, skip))
	}
	recs, rows := r.zoneRecords(t), r.rows(t)
	if len(recs) != 1 || recs[0].ID != rec.ID || recs[0].Value != ip2 || rows[0].Value != ip2 || rows[0].ProviderRecordID != rec.ID {
		t.Fatalf("records %+v rows %+v", recs, rows)
	}
	if _, ok, _ := r.st.GetSetting(context.Background(), key); ok {
		t.Fatal("pending update not cleared by the confirmed update")
	}
}

// A pending update older than its TTL is ignored: the record under the old
// ID is then a foreign record (reported, never written over).
func TestDNSExecPendingUpdateExpires(t *testing.T) {
	r, u := unconfRig(t, false)
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	u.push("UpdateRecord", unconfStep{apply: false, record: true, id: "fake-rotated"})
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); err != nil {
		t.Fatal(err)
	}
	r.exec.now = fixedNow(t0.Add(3 * time.Hour))
	if err := r.apply(t, false, ensure("app.example.test", ip2, "docker:app")); !errors.Is(err, ErrForeignRecord) {
		t.Fatalf("err %v", err)
	}
	if recs := r.zoneRecords(t); len(recs) != 1 || recs[0].Value != ip1 {
		t.Fatalf("records %+v", recs)
	}
}

// ---- M3: repair state housekeeping ----

func TestDNSExecRepairStateSweep(t *testing.T) {
	r := newClockRig(t)
	ctx := context.Background()
	r.addRow(t, "app.example.test", "A", ip1, "fake-1", "docker:app")
	keys := map[string]bool{
		repairKey(dzp, dz, "app.example.test", "A"):    true, // row exists: kept
		pendingKey(dzp, dz, "app.example.test", "A"):   true,
		repairKey(dzp, dz, "gone.example.test", "A"):   false, // no row: swept
		pendingKey(dzp, dz, "gone.example.test", "A"):  false,
		repairKey(dzp, dz, "app.example.test", "AAAA"): false,
		"dns/other": true, // not ours
	}
	for k := range keys {
		if err := r.st.SetSetting(ctx, k, `{"attempts":1}`); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.apply(t, true); err != nil { // a dry run never sweeps
		t.Fatal(err)
	}
	if _, ok, _ := r.st.GetSetting(ctx, repairKey(dzp, dz, "gone.example.test", "A")); !ok {
		t.Fatal("dry run swept")
	}
	if err := r.apply(t, false); err != nil {
		t.Fatal(err)
	}
	for k, keep := range keys {
		if _, ok, _ := r.st.GetSetting(ctx, k); ok != keep {
			t.Fatalf("%s present=%v, want %v", k, ok, keep)
		}
	}
}

// Deleting the row deletes its repair and pending-update keys.
func TestDNSExecDeleteClearsRepairState(t *testing.T) {
	r := newClockRig(t)
	ctx := context.Background()
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	r.due(t, "app.example.test", "docker:app")
	_ = r.apply(t, false) // the start-of-batch sweep keeps them (the row exists)
	for _, k := range []string{repairKey(dzp, dz, "app.example.test", "A"), pendingKey(dzp, dz, "app.example.test", "A")} {
		if err := r.st.SetSetting(ctx, k, `{}`); err != nil {
			t.Fatal(err)
		}
	}
	row := r.rows(t)[0]
	a := del("app.example.test", ip1, rec.ID, "docker:app")
	a.RemovedAfter = row.RemovedAfter
	if err := r.apply(t, false, a); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{repairKey(dzp, dz, "app.example.test", "A"), pendingKey(dzp, dz, "app.example.test", "A")} {
		if _, ok, _ := r.st.GetSetting(ctx, k); ok {
			t.Fatalf("%s not cleared", k)
		}
	}
}

// A clock stepped back never holds a repair longer than the backoff cap.
func TestDNSExecRepairClockStepBackClamped(t *testing.T) {
	r := newClockRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "fake-gone", "docker:app")
	key := repairKey(dzp, dz, "app.example.test", "A")
	// written before the clock went back 10h
	st := fmt.Sprintf(`{"attempts":7,"next_at":%d,"last_at":%d}`, t0.Add(10*time.Hour).Unix(), t0.Add(9*time.Hour).Unix())
	if err := r.st.SetSetting(context.Background(), key, st); err != nil {
		t.Fatal(err)
	}
	a := repairOf("app.example.test", ip1, "fake-gone", "docker:app")
	for _, at := range []time.Time{t0, t0.Add(30 * time.Minute), t0.Add(time.Hour - time.Second)} {
		r.set(at)
		skip := len(r.fk.Calls())
		if err := r.apply(t, false, a); err != nil || len(ops(r.fk, skip)) != 0 {
			t.Fatalf("at %v: err %v calls %v", at, err, ops(r.fk, skip))
		}
	}
	r.set(t0.Add(time.Hour))
	skip := len(r.fk.Calls())
	if err := r.apply(t, false, a); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ops(r.fk, skip), ","); got != "ListRecords,CreateRecord" {
		t.Fatalf("calls %s", got)
	}
}
