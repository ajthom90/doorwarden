package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/providers/fake"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// hookedFake runs afterDelete after every successful DeleteRecord.
type hookedFake struct {
	*fake.Fake
	afterDelete func()
}

func (h *hookedFake) DeleteRecord(ctx context.Context, zone string, r dns.Record) error {
	err := h.Fake.DeleteRecord(ctx, zone, r)
	if err == nil && h.afterDelete != nil {
		h.afterDelete()
	}
	return err
}

// Plans can be computed from a stale view: Runner serializes plan+apply, but
// the caller gathers Observed outside that lock. These tests apply such a
// plan after a newer cycle changed the stored state and check the executors
// re-verify against the store instead of trusting the plan.

// A stale plan (service absent, row and route past their deadline) applied
// after a newer cycle cancelled the removal (service back) deletes nothing.
func TestStalePlanDeleteAfterCancelKeepsRecordAndRoute(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("docker:app", "app", dz, 80)
	w.mustCycle(t0, app)
	w.mustCycle(t0.Add(time.Minute)) // absent: route and record scheduled
	stale := w.observe(context.Background())
	w.mustCycle(t0.Add(30*time.Hour), app) // back: both cancelled
	if rows := w.rows(); len(rows) != 1 || rows[0].RemovedAfter != nil {
		t.Fatalf("not cancelled: %+v", rows)
	}
	n := len(w.fk.Calls())
	acts, err := w.reconcileAt(t0.Add(30*time.Hour), nil, stale)
	if err != nil {
		t.Fatal(err)
	}
	if len(ofKind(acts, DNSDelete)) != 1 || len(ofKind(acts, RouteRemove)) != 1 {
		t.Fatalf("the stale plan should ask for both removals: %v", sums(acts))
	}
	if got := w.writes(n); len(got) != 0 {
		t.Fatalf("provider writes %v", got)
	}
	if rows := w.rows(); len(rows) != 1 || rows[0].OwnerKey != "docker:app" || rows[0].RemovedAfter != nil {
		t.Fatalf("rows %+v", rows)
	}
	if len(w.records()) != 1 {
		t.Fatal("record deleted")
	}
	if rs, _ := w.st.ListRoutes(context.Background()); len(rs) != 1 || rs[0].RemovedAfter != nil {
		t.Fatalf("routes %+v", rs)
	}
	// the next fresh cycle is steady
	n = len(w.fk.Calls())
	acts = w.mustCycle(t0.Add(31*time.Hour), app)
	assertOrphans(t, acts)
	assertNone(t, acts, RouteRemove, ScheduleRemoval)
	if got := w.writes(n); len(got) != 0 {
		t.Fatalf("writes %v", got)
	}
}

// A stale DNSDelete for a row whose removal was cancelled and then
// re-scheduled (a new absence) is refused too: it was planned for another
// schedule, and the new one is not due.
func TestStalePlanDeleteForOtherScheduleRefused(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("docker:app", "app", dz, 80)
	w.mustCycle(t0, app)
	w.mustCycle(t0.Add(time.Minute))
	stale := w.observe(context.Background())
	w.mustCycle(t0.Add(30*time.Hour), app)          // back
	w.mustCycle(t0.Add(30*time.Hour + time.Minute)) // gone again: new schedule
	acts, err := w.reconcileAt(t0.Add(30*time.Hour+2*time.Minute), nil, stale)
	if err != nil || len(ofKind(acts, DNSDelete)) != 1 {
		t.Fatalf("err %v plan %v", err, sums(acts))
	}
	rows := w.rows()
	if len(rows) != 1 || rows[0].RemovedAfter == nil || !rows[0].RemovedAfter.Equal(t0.Add(54*time.Hour+time.Minute)) {
		t.Fatalf("rows %+v", rows)
	}
	if len(w.records()) != 1 {
		t.Fatal("record deleted")
	}
	if rs, _ := w.st.ListRoutes(context.Background()); len(rs) != 1 {
		t.Fatalf("route deleted: %+v", rs)
	}
}

// A stale DNSScheduleRemoval never moves an existing schedule and never
// schedules a row whose value changed since the plan.
func TestStalePlanScheduleGuarded(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("docker:app", "app", dz, 80)
	w.mustCycle(t0, app)
	stale := w.observe(context.Background()) // row unscheduled
	w.mustCycle(t0.Add(time.Minute))         // gone: scheduled at t0+1m+24h
	acts, err := w.reconcileAt(t0.Add(2*time.Hour), nil, stale)
	if err != nil || len(ofKind(acts, DNSScheduleRemoval)) != 1 {
		t.Fatalf("err %v plan %v", err, sums(acts))
	}
	if rows := w.rows(); rows[0].RemovedAfter == nil || !rows[0].RemovedAfter.Equal(t0.Add(time.Minute+24*time.Hour)) {
		t.Fatalf("schedule moved: %+v", rows)
	}

	// value changed since the plan (target_ip moved): no schedule
	w2 := newWorld(t, "per-host")
	w2.mustCycle(t0, app)
	stale = w2.observe(context.Background())
	w2.cfg.Zones[0].TargetIP = ip2
	w2.mustCycle(t0.Add(time.Minute), app)
	if rows := w2.rows(); rows[0].Value != ip2 {
		t.Fatalf("rows %+v", rows)
	}
	acts, err = w2.reconcileAt(t0.Add(2*time.Minute), nil, stale)
	if err != nil || len(ofKind(acts, DNSScheduleRemoval)) != 1 {
		t.Fatalf("err %v plan %v", err, sums(acts))
	}
	if rows := w2.rows(); rows[0].RemovedAfter != nil {
		t.Fatalf("scheduled a row whose value changed: %+v", rows)
	}
}

// A stale DNSCancelRemoval / DNSScheduleRemoval pair (computed while the
// service was renamed back) applied after the service moved on deletes
// nothing, and the next fresh cycle restores the schedules.
func TestStalePlanCancelNeverDeletes(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("docker:app", "app", dz, 80)
	web := app
	web.Name = "web"
	w.mustCycle(t0, app)
	w.mustCycle(t0.Add(time.Minute), web) // app row scheduled
	stale := w.observe(context.Background())
	acts, err := w.reconcileAt(t0.Add(2*time.Minute), []model.Service{app}, stale) // stale view: renamed back
	if err != nil || len(ofKind(acts, DNSCancelRemoval)) != 1 || len(ofKind(acts, DNSScheduleRemoval)) != 1 {
		t.Fatalf("err %v plan %v", err, sums(acts))
	}
	// fresh reality: still web
	acts = w.mustCycle(t0.Add(3*time.Minute), web)
	assertNone(t, acts, DNSDelete)
	rows := w.rows()
	if len(rows) != 2 || len(w.records()) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	if rows[0].Name != "app.example.test" || rows[0].RemovedAfter == nil || rows[1].RemovedAfter != nil {
		t.Fatalf("schedules not restored: %+v", rows)
	}
}

// Executor: a DNSDelete is applied only for the same, due schedule.
func TestDNSExecDeleteRequiresSameDueSchedule(t *testing.T) {
	ctx := context.Background()
	past, other, future := t0.Add(-time.Hour), t0.Add(-2*time.Hour), t0.Add(time.Hour)
	cases := []struct {
		name      string
		rowRA     *time.Time
		actionRA  *time.Time
		wantErr   error
		wantGone  bool
		wantInLog string
	}{
		{"row not scheduled (cancelled)", nil, &past, nil, false, "not scheduled"},
		{"other schedule", &other, &past, nil, false, "planned for"},
		{"not due yet", &future, &future, nil, false, "not due"},
		{"action without schedule", &past, nil, ErrDNSRefused, false, ""},
		{"same due schedule", &past, &past, nil, true, "deleted"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := perHostRig(t)
			rec := r.seed(t, "app.example.test", "A", ip1)
			r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
			if c.rowRA != nil {
				if err := r.st.SetOwnedRemoval(ctx, dzp, dz, "app.example.test", "A", "docker:app", c.rowRA); err != nil {
					t.Fatal(err)
				}
			}
			skip := len(r.fk.Calls())
			a := del("app.example.test", ip1, rec.ID, "docker:app")
			a.RemovedAfter = c.actionRA
			err := r.apply(t, false, a)
			if c.wantErr != nil && !errors.Is(err, c.wantErr) || c.wantErr == nil && err != nil {
				t.Fatalf("err %v", err)
			}
			if !c.wantGone && len(r.fk.Calls()) != skip {
				t.Fatalf("provider called: %v", ops(r.fk, skip))
			}
			gone := len(r.rows(t)) == 0
			if gone != c.wantGone || (len(r.zoneRecords(t)) == 0) != c.wantGone {
				t.Fatalf("rows %+v records %+v", r.rows(t), r.zoneRecords(t))
			}
			if c.wantInLog != "" && !strings.Contains(r.act.messages(), c.wantInLog) {
				t.Fatalf("activity %q", r.act.messages())
			}
		})
	}
}

// Executor: if the row changes between the provider delete and the
// conditional row delete, the row is kept and the outcome is loud.
func TestDNSExecDeleteRowChangedDuringDeleteIsLoud(t *testing.T) {
	ctx := context.Background()
	h := &hookedFake{}
	r := perHostRig(t, func(c *DNSExecutorConfig) {
		h.Fake = c.Providers[dzp].(*fake.Fake)
		c.Providers = map[string]dns.Provider{dzp: h}
	})
	rec := r.seed(t, "app.example.test", "A", ip1)
	r.addRow(t, "app.example.test", "A", ip1, rec.ID, "docker:app")
	past := t0.Add(-time.Hour)
	if err := r.st.SetOwnedRemoval(ctx, dzp, dz, "app.example.test", "A", "docker:app", &past); err != nil {
		t.Fatal(err)
	}
	// a concurrent writer cancels the removal right after the provider delete
	h.afterDelete = func() { _ = r.st.SetOwnedRemoval(ctx, dzp, dz, "app.example.test", "A", "docker:app", nil) }
	a := del("app.example.test", ip1, rec.ID, "docker:app")
	a.RemovedAfter = &past
	err := r.apply(t, false, a)
	if err == nil || !strings.Contains(err.Error(), "row changed") {
		t.Fatalf("err %v", err)
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].RemovedAfter != nil || rows[0].Value != "" || rows[0].ProviderRecordID != "" {
		t.Fatalf("row not marked for re-creation: %+v", rows)
	}
	if !strings.Contains(r.act.messages(), "re-creates") {
		t.Fatalf("activity %q", r.act.messages())
	}
	// the next plan sees another value; its DNSEnsure re-creates the record
	h.afterDelete = nil
	if err := r.apply(t, false, ensure("app.example.test", ip1, "docker:app")); err != nil {
		t.Fatal(err)
	}
	if rows, recs := r.rows(t), r.zoneRecords(t); len(rows) != 1 || rows[0].Value != ip1 || len(recs) != 1 ||
		recs[0].ID != rows[0].ProviderRecordID {
		t.Fatalf("rows %+v records %+v", rows, recs)
	}
}

// Route executor: a grace-period RouteRemove deletes only a route whose
// removal is set and due; takeover/rename removals trust the plan.
func TestRouteExecutorGraceRemovalOnlyWhenDue(t *testing.T) {
	ctx := context.Background()
	now := t0
	st := openStore(t)
	ex := NewRouteExecutor(st, func() time.Time { return now })
	s := pub("docker:app", "app", "example.test", 8080)
	write := func() {
		t.Helper()
		if err := ex.Apply(ctx, []Action{routeWrite(s, "example.test", "app.example.test", &s.Backend)}, false); err != nil {
			t.Fatal(err)
		}
	}
	has := func() bool { _, ok, _ := st.GetRoute(ctx, "docker:app"); return ok }
	write()
	for _, cause := range []RemovalCause{CauseRemovalGrace, ""} {
		if err := ex.Apply(ctx, []Action{{Kind: RouteRemove, Key: "docker:app", Cause: cause}}, false); err != nil || !has() {
			t.Fatalf("cause %q: unscheduled route removed (err %v)", cause, err)
		}
	}
	at := t0.Add(time.Hour)
	if err := ex.Apply(ctx, []Action{{Kind: ScheduleRemoval, Key: "docker:app", RemovedAfter: &at}}, false); err != nil {
		t.Fatal(err)
	}
	now = at
	if err := ex.Apply(ctx, []Action{{Kind: RouteRemove, Key: "docker:app", Cause: CauseRemovalGrace}}, false); err != nil || !has() {
		t.Fatalf("removed at the deadline (err %v)", err)
	}
	now = at.Add(time.Second)
	if err := ex.Apply(ctx, []Action{{Kind: RouteRemove, Key: "docker:app", Cause: CauseRemovalGrace}}, false); err != nil || has() {
		t.Fatalf("due route kept (err %v)", err)
	}
	for _, cause := range []RemovalCause{CauseTakeover, CauseRename} {
		write()
		if err := ex.Apply(ctx, []Action{{Kind: RouteRemove, Key: "docker:app", Cause: cause}}, false); err != nil || has() {
			t.Fatalf("cause %q: route kept (err %v)", cause, err)
		}
	}
}

// Plan: removals carry what the executors re-verify.
func TestPlanRemovalsCarryCauseAndSchedule(t *testing.T) {
	cfg := phCfg()
	ra := t0.Add(-time.Hour)
	row := ownedRA("example.test", "app.example.test", "A", target, "docker:app", &ra)
	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row},
		Known: knownMap(known("docker:app", "example.test", "app.example.test", &ra))}
	acts := Plan(nil, obs, cfg, t0)
	d, rr := ofKind(acts, DNSDelete), ofKind(acts, RouteRemove)
	if len(d) != 1 || d[0].RemovedAfter == nil || !d[0].RemovedAfter.Equal(ra) || d[0].RemovedAfter == row.RemovedAfter {
		t.Fatalf("DNSDelete must carry a copy of the row's schedule: %v", sums(acts))
	}
	if len(rr) != 1 || rr[0].Cause != CauseRemovalGrace || rr[0].RemovedAfter == nil || !rr[0].RemovedAfter.Equal(ra) {
		t.Fatalf("RouteRemove %+v", rr)
	}

	// takeover by an absent loser's winner, a present loser's takeover, and a rename-away
	win := pub("static:new", "app", "example.test", 80)
	obs = Observed{Foreign: listed("example.test"), Known: knownMap(known("docker:old", "example.test", "app.example.test", nil))}
	if rr := ofKind(Plan([]model.Service{win}, obs, cfg, t0), RouteRemove); len(rr) != 1 || rr[0].Cause != CauseTakeover {
		t.Fatalf("absent takeover %+v", rr)
	}
	lose := pub("docker:old", "app", "example.test", 81)
	if rr := ofKind(Plan([]model.Service{win, lose}, obs, cfg, t0), RouteRemove); len(rr) != 1 || rr[0].Cause != CauseTakeover {
		t.Fatalf("present takeover %+v", rr)
	}
	// rename away onto a hostname an absent higher-rank holder keeps through grace
	obs = Observed{Known: knownMap(known("static:s", "example.test", "web.example.test", tp(t0.Add(time.Hour))),
		known("docker:a", "example.test", "app.example.test", nil))}
	got := Plan([]model.Service{pub("docker:a", "web", "example.test", 1)}, obs, cfgOf(zone("example.test", "", "")), t0)
	if rr := ofKind(got, RouteRemove); len(rr) != 1 || rr[0].Cause != CauseRename {
		t.Fatalf("rename %v", sums(got))
	}
}
