package reconcile

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/store"
)

// ---- the acknowledgement is cleared at the end of every non-dry cycle ----

// holdAll gives every owned row of w a repair backoff that is not due for
// the next hour.
func (w *world) holdAll(at time.Time) {
	w.t.Helper()
	for _, r := range w.rows() {
		v := fmt.Sprintf(`{"attempts":3,"next_at":%d,"last_at":%d}`, at.Add(time.Hour).Unix(), at.Unix())
		if err := w.st.SetSetting(context.Background(), repairKey(r.Provider, r.Zone, r.Name, r.Type), v); err != nil {
			w.t.Fatal(err)
		}
	}
}

// restore re-creates every owned record by hand (new provider IDs, our
// values), as an operator restoring a backup would.
func (w *world) restore() {
	w.t.Helper()
	for _, r := range w.rows() {
		if _, err := w.fk.CreateRecord(context.Background(), dz, dns.Record{Name: r.Name, Type: r.Type, Value: r.Value}); err != nil {
			w.t.Fatal(err)
		}
	}
}

func creates(w *world, n int) int {
	c := 0
	for _, op := range ops(w.fk, n) {
		if op == "CreateRecord" {
			c++
		}
	}
	return c
}

// The zone recovers while every missing row waits for its backoff: no DNS
// action is planned at all, and the acknowledgement is still cleared, so a
// second outage within 24h trips the breaker again instead of re-creating.
func TestDNSE2EAckClearedWithoutDNSActions(t *testing.T) {
	w, desired := ackWorld(t, 12)
	ctx := context.Background()
	w.wipe()
	w.holdAll(t0)
	if err := w.st.SetRepairMassOK(ctx, dzp, dz, t0); err != nil {
		t.Fatal(err)
	}
	acts := w.mustCycle(t0.Add(time.Minute), desired...)
	if len(ofKind(acts, DNSEnsure)) != 0 || len(breakerSkips(acts)) != 0 || !w.ackPresent() {
		t.Fatalf("plan %v ack %v", sums(acts), w.ackPresent())
	}
	w.restore()
	acts = w.mustCycle(t0.Add(2*time.Minute), desired...)
	if len(ofKind(acts, DNSEnsure)) != 0 {
		t.Fatalf("plan %v", sums(acts))
	}
	if w.ackPresent() {
		t.Fatal("acknowledgement kept after the zone recovered")
	}
	w.wipe()
	n := len(w.fk.Calls())
	acts = w.mustCycle(t0.Add(3*time.Minute), desired...)
	if len(breakerSkips(acts)) != 1 || creates(w, n) != 0 {
		t.Fatalf("second outage: plan %v calls %v", sums(acts), ops(w.fk, n))
	}
}

// An acknowledgement of a pair that never tripped is cleared by the next
// cycle; a later outage trips the breaker.
func TestDNSE2EAckOnHealthyPairCleared(t *testing.T) {
	w, desired := ackWorld(t, 12)
	if err := w.st.SetRepairMassOK(context.Background(), dzp, dz, t0); err != nil {
		t.Fatal(err)
	}
	w.mustCycle(t0.Add(time.Minute), desired...)
	if w.ackPresent() {
		t.Fatal("acknowledgement of a healthy pair kept")
	}
	w.wipe()
	n := len(w.fk.Calls())
	acts := w.mustCycle(t0.Add(2*time.Minute), desired...)
	if len(breakerSkips(acts)) != 1 || creates(w, n) != 0 {
		t.Fatalf("outage: plan %v calls %v", sums(acts), ops(w.fk, n))
	}
}

// A dry cycle never lists for, nor clears, an acknowledgement.
func TestDNSE2EAckDryCycleKeeps(t *testing.T) {
	w, desired := ackWorld(t, 3)
	if err := w.st.SetRepairMassOK(context.Background(), dzp, dz, t0); err != nil {
		t.Fatal(err)
	}
	w.runner.DryRun = func() bool { return true }
	n := len(w.fk.Calls())
	w.mustCycle(t0.Add(time.Minute), desired...)
	// the gather lists once; nothing else
	if !w.ackPresent() || len(ops(w.fk, n)) != 1 {
		t.Fatalf("ack %v calls %v", w.ackPresent(), ops(w.fk, n))
	}
}

// Presence is counted like the plan's: a record of someone else at an owned
// name and type (another value and ID) does not make the row present.
func TestDNSExecFinishForeignAtOwnedNameCountsMissing(t *testing.T) {
	ctx := context.Background()
	r := newClockRig(t)
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("s%02d.example.test", i)
		r.addRow(t, name, "A", ip1, "gone-"+name, "docker:"+name)
		if i < 2 {
			r.seed(t, name, "A", ip1) // ours by value
		} else {
			r.seed(t, name, "A", "198.51.100.99") // foreign
		}
	}
	if err := r.st.SetRepairMassOK(ctx, dzp, dz, t0); err != nil {
		t.Fatal(err)
	}
	r.exec.Finish(ctx)
	if _, ok, _ := r.st.GetSetting(ctx, store.RepairMassOKKey(dzp, dz)); !ok {
		t.Fatal("cleared while 8 of 10 owned records are not ours at the provider")
	}
}

// Every spelling of a pair's key is cleared on recovery, and kept while it
// has not recovered.
func TestDNSExecFinishClearsEveryKeyVariant(t *testing.T) {
	ctx := context.Background()
	r := newClockRig(t)
	r.addRow(t, "a.example.test", "A", ip1, "x", "docker:a")
	r.seed(t, "a.example.test", "A", ip1)
	keys := []string{store.RepairMassOKPrefix + "dnsp/Example.Test", store.RepairMassOKPrefix + "dnsp/example.test.", store.RepairMassOKKey(dzp, dz)}
	for _, k := range keys {
		if err := r.st.SetSetting(ctx, k, t0.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	r.exec.Finish(ctx)
	for _, k := range keys {
		if _, ok, _ := r.st.GetSetting(ctx, k); ok {
			t.Fatalf("%s kept", k)
		}
	}
	// one listing for the pair, not one per key
	if got := ops(r.fk, 0); len(got) != 2 || got[1] != "ListRecords" {
		t.Fatalf("calls %v", got)
	}
}

// Of duplicate spellings, a valid acknowledgement wins over an expired or
// future-dated one, whatever the map order.
func TestGatherObservedDuplicateAckKeys(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := t0
	set := func(k string, at time.Time) {
		t.Helper()
		if err := st.SetSetting(ctx, store.RepairMassOKPrefix+k, at.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	set("dnsp/Example.Test", now.Add(-30*time.Hour)) // expired
	set("dnsp/example.test.", now.Add(-time.Hour))   // valid
	set("dnsp/EXAMPLE.test", now.Add(10*time.Hour))  // future
	for i := 0; i < 20; i++ {
		obs, _ := GatherObservedAt(ctx, map[string]dns.Provider{}, st, nil, 0, now)
		if got := obs.RepairMassOK["dnsp/example.test"]; !got.Equal(now.Add(-time.Hour)) {
			t.Fatalf("ack %v", got)
		}
	}
}

// MultiExecutor finishes each distinct handler once after a non-dry Apply,
// even with no action for it, and never in dry run.
type finishRec struct {
	applies, finishes int
}

func (f *finishRec) Apply(context.Context, []Action, bool) error { f.applies++; return nil }
func (f *finishRec) Finish(context.Context)                      { f.finishes++ }

func TestMultiExecutorFinish(t *testing.T) {
	f := &finishRec{}
	m := NewMultiExecutor(nil)
	for _, k := range DNSActionKinds {
		m.Handle(k, f)
	}
	ctx := context.Background()
	if err := m.Apply(ctx, nil, false); err != nil || f.finishes != 1 {
		t.Fatalf("err %v finishes %d", err, f.finishes)
	}
	a1, a2 := ensure("a.example.test", ip1, "docker:a"), Action{Kind: DNSDelete}
	if err := m.Apply(ctx, []Action{a1, a2}, false); err != nil || f.finishes != 2 || f.applies != 2 {
		t.Fatalf("err %v finishes %d applies %d", err, f.finishes, f.applies)
	}
	if err := m.Apply(ctx, []Action{a1}, true); err != nil || f.finishes != 2 {
		t.Fatalf("dry: finishes %d", f.finishes)
	}
}

// The breaker condition, not only "at most 3 missing", decides: 5 of 10
// missing (not more than half) is untripped and clears; 6 of 10 keeps.
func TestDNSExecFinishClearsWhenUntripped(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		present int
		kept    bool
	}{{5, false}, {4, true}, {10, false}, {6, false}} {
		r := newClockRig(t)
		for i := 0; i < 10; i++ {
			name := fmt.Sprintf("s%02d.example.test", i)
			r.addRow(t, name, "A", ip1, "", "docker:"+name)
			if i < c.present {
				r.seed(t, name, "A", ip1)
			}
		}
		// a row scheduled for removal is not counted
		r.addRow(t, "old.example.test", "A", ip1, "", "docker:old")
		at := t0.Add(time.Hour)
		if err := r.st.SetOwnedRemoval(ctx, dzp, dz, "old.example.test", "A", "docker:old", &at); err != nil {
			t.Fatal(err)
		}
		if err := r.st.SetRepairMassOK(ctx, dzp, dz, t0); err != nil {
			t.Fatal(err)
		}
		r.exec.Finish(ctx)
		if _, ok, _ := r.st.GetSetting(ctx, store.RepairMassOKKey(dzp, dz)); ok != c.kept {
			t.Fatalf("%d of 10 present: kept %v", c.present, ok)
		}
	}
}

// A small pair never trips (3 of 3 missing): its acknowledgement clears.
func TestDNSExecFinishClearsSmallPair(t *testing.T) {
	ctx := context.Background()
	r := newClockRig(t)
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("s%02d.example.test", i)
		r.addRow(t, name, "A", ip1, "", "docker:"+name)
	}
	if err := r.st.SetRepairMassOK(ctx, dzp, dz, t0); err != nil {
		t.Fatal(err)
	}
	r.exec.Finish(ctx)
	if _, ok, _ := r.st.GetSetting(ctx, store.RepairMassOKKey(dzp, dz)); ok {
		t.Fatal("kept for a pair that cannot trip")
	}
}
