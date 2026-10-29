package reconcile

import (
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// A protected owner (present, not cleanly Published) whose row was
// scheduled while it was absent cancels the schedule as soon as it is
// present again, in any state: the frozen deadline must not survive into a
// later publish cycle and delete the record at once.
func TestOrphanProtectedOwnerReturnCancelsSchedule(t *testing.T) {
	cfg := phCfg()
	ra := tp(t0.Add(-time.Hour))
	row := ownedRA("example.test", "app.example.test", "A", target, "truenas:app", ra)
	for _, st := range []string{model.StateStopped, model.StatePending, model.StateError} {
		for _, name := range []string{"app", "web"} {
			s := svc("truenas:app", name, "example.test", st, "198.51.100.5", 80)
			got := Plan([]model.Service{s}, Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}}, cfg, t0)
			assertOrphans(t, got, "DNSCancelRemoval example.test app.example.test truenas:app [app.example.test A 192.0.2.10]")
		}
	}
	// carried forward from an unavailable source, or with invalid labels:
	// present again too
	pubd := pub("truenas:app", "web", "example.test", 80)
	got := Plan([]model.Service{pubd}, Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row},
		Unavailable: map[string]bool{"truenas": true}}, cfg, t0)
	assertOrphans(t, got, "DNSCancelRemoval example.test app.example.test truenas:app [app.example.test A 192.0.2.10]")
	inv := pub("truenas:app", "web", "missing.test", 80)
	got = Plan([]model.Service{inv}, Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}}, cfg, t0)
	assertOrphans(t, got, "DNSCancelRemoval example.test app.example.test truenas:app [app.example.test A 192.0.2.10]")
	// unscheduled rows of a protected owner stay untouched
	row.RemovedAfter = nil
	got = Plan([]model.Service{svc("truenas:app", "web", "example.test", model.StateStopped, "198.51.100.5", 80)},
		Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}}, cfg, t0)
	assertOrphans(t, got)
}

// End to end: the owner vanishes (record scheduled), returns Stopped under a
// renamed label, stays stopped past the old deadline, then is published
// under the new name: the old record is cancelled on return, never deleted
// in the publish cycle, and only then scheduled afresh.
func TestProtectedOwnerReturnE2ENoImmediateDelete(t *testing.T) {
	w := newWorld(t, "per-host")
	app := pub("truenas:app", "app", dz, 80)
	w.mustCycle(t0, app)
	w.mustCycle(t0.Add(time.Minute)) // absent: route and record scheduled
	if rs := w.rows(); len(rs) != 1 || rs[0].RemovedAfter == nil {
		t.Fatalf("rows %+v", w.rows())
	}
	stopped := svc("truenas:app", "web", dz, model.StateStopped, "198.51.100.5", 80)
	acts := w.mustCycle(t0.Add(2*time.Hour), stopped)
	if len(ofKind(acts, DNSCancelRemoval)) != 1 {
		t.Fatalf("return: %v", sums(acts))
	}
	if rs := w.rows(); len(rs) != 1 || rs[0].RemovedAfter != nil {
		t.Fatalf("rows after return %+v", rs)
	}
	acts = w.mustCycle(t0.Add(48*time.Hour), stopped) // past the old deadline
	assertNone(t, acts, DNSDelete, DNSScheduleRemoval)
	published := pub("truenas:app", "web", dz, 80)
	acts = w.mustCycle(t0.Add(49*time.Hour), published)
	assertNone(t, acts, DNSDelete)
	if s := ofKind(acts, DNSScheduleRemoval); len(s) != 1 || s[0].Record.Name != "app."+dz ||
		!s[0].RemovedAfter.Equal(t0.Add(49*time.Hour).Add(24*time.Hour)) {
		t.Fatalf("publish: %v", sums(acts))
	}
	if len(w.records()) != 2 {
		t.Fatalf("records %+v", w.records())
	}
	acts = w.mustCycle(t0.Add(74*time.Hour), published) // after the fresh grace
	if d := ofKind(acts, DNSDelete); len(d) != 1 || d[0].Record.Name != "app."+dz {
		t.Fatalf("after grace: %v", sums(acts))
	}
	if rs := w.records(); len(rs) != 1 || rs[0].Name != "web."+dz {
		t.Fatalf("records %+v", rs)
	}
}
