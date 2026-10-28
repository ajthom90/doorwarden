package reconcile

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/providers/fake"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// world composes Plan + MultiExecutor(DNSExecutor, RouteExecutor) over a real
// store and the fake provider, gathering Observed the way the orchestrator
// will.
type world struct {
	t      *testing.T
	cfg    *config.Config
	st     *store.Store
	fk     *fake.Fake
	runner *Runner
}

func newWorld(t *testing.T, mode string) *world {
	t.Helper()
	w := &world{t: t, cfg: dnsCfg(dnsZoneCfg(dz, mode)), st: openStore(t), fk: fake.New(true)}
	de, err := NewDNSExecutor(DNSExecutorConfig{Config: w.cfg, Providers: map[string]dns.Provider{dzp: w.fk},
		Store: w.st, Activity: w.st, Now: fixedNow(t0)})
	if err != nil {
		t.Fatal(err)
	}
	re := NewRouteExecutor(w.st, fixedNow(t0))
	m := NewMultiExecutor(nil).Handle(DNSEnsure, de).Handle(DNSDelete, de)
	for _, k := range []ActionKind{RouteWrite, RouteRemove, ScheduleRemoval, CancelRemoval} {
		m.Handle(k, re)
	}
	w.runner = &Runner{Exec: m, Config: w.cfg}
	return w
}

func (w *world) observe(ctx context.Context) Observed {
	w.t.Helper()
	routes, err := w.st.ListRoutes(ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	known, lk := ObservedFromRoutes(routes)
	owned, foreign, _ := GatherObserved(ctx, map[string]dns.Provider{dzp: w.fk}, w.st, DNSZoneRefs(w.cfg), 0)
	return Observed{Owned: owned, Foreign: foreign, Known: known, LastKnown: lk}
}

func (w *world) cycle(now time.Time, desired ...model.Service) ([]Action, error) {
	w.t.Helper()
	ctx := context.Background()
	return w.runner.Reconcile(ctx, desired, w.observe(ctx), now)
}

func (w *world) mustCycle(now time.Time, desired ...model.Service) []Action {
	w.t.Helper()
	acts, err := w.cycle(now, desired...)
	if err != nil {
		w.t.Fatalf("cycle: %v\nplan: %v", err, sums(acts))
	}
	return acts
}

func (w *world) rows() []store.DNSRecord {
	w.t.Helper()
	rs, err := w.st.ListOwnedRecords(context.Background(), dzp, dz)
	if err != nil {
		w.t.Fatal(err)
	}
	return rs
}

func (w *world) records() []dns.Record {
	w.t.Helper()
	rs, err := w.fk.ListRecords(context.Background(), dz)
	if err != nil {
		w.t.Fatal(err)
	}
	return rs
}

func (w *world) writes(skip int) []string {
	var out []string
	for _, c := range w.fk.Calls()[skip:] {
		if c.Op != "ListRecords" {
			out = append(out, c.Op+" "+c.Record.ID+" "+c.Record.Name+" "+c.Record.Value)
		}
	}
	return out
}

func TestDNSE2EPublishOwnUpdateRemove(t *testing.T) {
	w := newWorld(t, "per-host")
	foreign, _ := w.fk.CreateRecord(context.Background(), dz, dns.Record{Name: "nas.example.test", Type: "A", Value: ipFX})
	app, other := pub("docker:app", "app", dz, 80), pub("docker:other", "other", dz, 81)

	// publish: created and owned
	w.mustCycle(t0, app, other)
	rows := w.rows()
	if len(rows) != 2 || rows[0].Name != "app.example.test" || rows[0].OwnerKey != "docker:app" || rows[0].Value != ip1 {
		t.Fatalf("rows %+v", rows)
	}
	appID := rows[0].ProviderRecordID

	// steady state: no provider writes
	n := len(w.fk.Calls())
	w.mustCycle(t0.Add(time.Minute), app, other)
	if got := w.writes(n); len(got) != 0 {
		t.Fatalf("steady state wrote %v", got)
	}

	// value change: update by stored ID
	w.cfg.Zones[0].TargetIP = ip2
	n = len(w.fk.Calls())
	w.mustCycle(t0.Add(2*time.Minute), app, other)
	got := w.writes(n)
	if len(got) != 2 || got[0] != "UpdateRecord "+appID+" app.example.test "+ip2 {
		t.Fatalf("writes %v", got)
	}
	if rows := w.rows(); rows[0].Value != ip2 || rows[0].ProviderRecordID != appID {
		t.Fatalf("rows %+v", rows)
	}

	// app goes away: scheduled, then after grace its own record only is deleted
	w.mustCycle(t0.Add(3*time.Minute), other)
	if len(w.rows()) != 2 {
		t.Fatal("deleted before grace")
	}
	n = len(w.fk.Calls())
	acts := w.mustCycle(t0.Add(48*time.Hour), other)
	if d := ofKind(acts, DNSDelete); len(d) != 1 {
		t.Fatalf("plan %v", sums(acts))
	}
	if got := w.writes(n); len(got) != 1 || got[0] != "DeleteRecord "+appID+" app.example.test "+ip2 {
		t.Fatalf("writes %v", got)
	}
	rows = w.rows()
	if len(rows) != 1 || rows[0].OwnerKey != "docker:other" {
		t.Fatalf("rows %+v", rows)
	}
	recs := w.records()
	if len(recs) != 2 || recs[0] != foreign || recs[1].Name != "other.example.test" {
		t.Fatalf("zone %+v", recs)
	}
}

func TestDNSE2EForeignIdenticalRecordIsConflict(t *testing.T) {
	w := newWorld(t, "per-host")
	fr, _ := w.fk.CreateRecord(context.Background(), dz, dns.Record{Name: "app.example.test", Type: "A", Value: ip1})
	n := len(w.fk.Calls())
	acts := w.mustCycle(t0, pub("docker:app", "app", dz, 80))
	if c := ofKind(acts, Conflict); len(c) != 1 || !strings.Contains(c[0].Reason, "foreign record exists") {
		t.Fatalf("plan %v", sums(acts))
	}
	assertNone(t, acts, DNSEnsure)
	if got := w.writes(n); len(got) != 0 {
		t.Fatalf("writes %v", got)
	}
	if len(w.rows()) != 0 {
		t.Fatal("ownership written")
	}
	if recs := w.records(); len(recs) != 1 || recs[0] != fr {
		t.Fatalf("zone %+v", recs)
	}
	if len(ofKind(acts, RouteWrite)) != 1 {
		t.Fatal("route must still be written")
	}
}

// A foreign record appearing after Observed was gathered: Plan (on the stale
// listing) emits a create; the executor's own listing refuses it.
func TestDNSE2EExecutorGuardsStaleObserved(t *testing.T) {
	w := newWorld(t, "per-host")
	ctx := context.Background()
	obs := w.observe(ctx)
	fr, _ := w.fk.CreateRecord(ctx, dz, dns.Record{Name: "app.example.test", Type: "A", Value: ip1})
	n := len(w.fk.Calls())
	acts, err := w.runner.Reconcile(ctx, []model.Service{pub("docker:app", "app", dz, 80)}, obs, t0)
	if len(ofKind(acts, DNSEnsure)) != 1 {
		t.Fatalf("plan %v", sums(acts))
	}
	if !errors.Is(err, ErrForeignRecord) {
		t.Fatalf("err %v", err)
	}
	if got := w.writes(n); len(got) != 0 {
		t.Fatalf("writes %v", got)
	}
	if len(w.rows()) != 0 {
		t.Fatal("ownership written")
	}
	if recs := w.records(); len(recs) != 1 || recs[0] != fr {
		t.Fatalf("zone %+v", recs)
	}
}

func TestDNSE2EListingFailureSkips(t *testing.T) {
	w := newWorld(t, "per-host")
	w.fk.FailNext("ListRecords", errors.New("unreachable"))
	n := len(w.fk.Calls())
	acts := w.mustCycle(t0, pub("docker:app", "app", dz, 80))
	if s := ofKind(acts, Skip); len(s) != 1 || !strings.Contains(s[0].Reason, "unknown") {
		t.Fatalf("plan %v", sums(acts))
	}
	assertNone(t, acts, DNSEnsure)
	if got := w.writes(n); len(got) != 0 {
		t.Fatalf("writes %v", got)
	}
	// next cycle the listing works and the record is created
	w.mustCycle(t0.Add(time.Minute), pub("docker:app", "app", dz, 80))
	if len(w.rows()) != 1 {
		t.Fatal("not created after recovery")
	}
}

func TestDNSE2EWildcardNeverDeleted(t *testing.T) {
	w := newWorld(t, "wildcard")
	app := pub("docker:app", "app", dz, 80)
	w.mustCycle(t0, app)
	rows := w.rows()
	if len(rows) != 1 || rows[0].Name != "*.example.test" || rows[0].OwnerKey != WildcardOwnerKey(dz) {
		t.Fatalf("rows %+v", rows)
	}
	w.mustCycle(t0.Add(time.Minute))
	n := len(w.fk.Calls())
	acts := w.mustCycle(t0.Add(48 * time.Hour))
	assertNone(t, acts, DNSDelete)
	if got := w.writes(n); len(got) != 0 {
		t.Fatalf("writes %v", got)
	}
	if len(w.rows()) != 1 || len(w.records()) != 1 {
		t.Fatal("wildcard record removed")
	}
}

func TestDNSE2EDeleteFailureKeepsOwnership(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("docker:app", "app", dz, 80)
	w.mustCycle(t0, app)
	w.mustCycle(t0.Add(time.Minute))
	w.fk.FailNext("DeleteRecord", errors.New("api down"))
	if _, err := w.cycle(t0.Add(48 * time.Hour)); err == nil || !strings.Contains(err.Error(), "api down") {
		t.Fatalf("err %v", err)
	}
	if rows := w.rows(); len(rows) != 1 || rows[0].OwnerKey != "docker:app" {
		t.Fatalf("ownership dropped: %+v", rows)
	}
	if len(w.records()) != 1 {
		t.Fatal("record gone")
	}
}

// Rename/move: documents what the executor sees (see report). The old record
// stays owned by the key and is never deleted.
func TestDNSE2ERenameKeepsOldRecordOwned(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("docker:app", "app", dz, 80)
	w.mustCycle(t0, app)
	renamed := app
	renamed.Name = "app2"
	acts := w.mustCycle(t0.Add(time.Minute), renamed)
	if e := ofKind(acts, DNSEnsure); len(e) != 1 || e[0].Record.Name != "app2.example.test" || e[0].Owner != "docker:app" {
		t.Fatalf("plan %v", sums(acts))
	}
	assertNone(t, acts, DNSDelete)
	rows := w.rows()
	if len(rows) != 2 || rows[0].Name != "app.example.test" || rows[1].Name != "app2.example.test" ||
		rows[0].OwnerKey != "docker:app" || rows[1].OwnerKey != "docker:app" {
		t.Fatalf("rows %+v", rows)
	}
	// removed later: only the current hostname's record is deleted
	w.mustCycle(t0.Add(2 * time.Minute))
	acts = w.mustCycle(t0.Add(48 * time.Hour))
	if d := ofKind(acts, DNSDelete); len(d) != 1 || d[0].Record.Name != "app2.example.test" {
		t.Fatalf("plan %v", sums(acts))
	}
	if rows := w.rows(); len(rows) != 1 || rows[0].Name != "app.example.test" {
		t.Fatalf("rows %+v", rows)
	}
}

func TestDNSE2EConcurrentReconcileSerialized(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("docker:app", "app", dz, 80)
	ctx := context.Background()
	obs := w.observe(ctx) // all goroutines plan from the same stale view
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.runner.Reconcile(ctx, []model.Service{app}, obs, t0); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	creates := 0
	for _, c := range w.fk.Calls() {
		if c.Op == "CreateRecord" {
			creates++
		}
	}
	if creates != 1 || len(w.rows()) != 1 || len(w.records()) != 1 {
		t.Fatalf("creates %d rows %d", creates, len(w.rows()))
	}
}

func TestDNSE2EDryRunWritesNothing(t *testing.T) {
	w := newWorld(t, "per-host")
	w.cfg.Settings.DryRun = true
	acts := w.mustCycle(t0, pub("docker:app", "app", dz, 80))
	if len(ofKind(acts, DNSEnsure)) != 1 {
		t.Fatalf("plan %v", sums(acts))
	}
	for _, c := range w.fk.Calls() {
		if c.Op != "ListRecords" { // GatherObserved's listing, not the executor
			t.Fatalf("dry run called %s", c.Op)
		}
	}
	if len(w.rows()) != 0 {
		t.Fatal("ownership written")
	}
}
