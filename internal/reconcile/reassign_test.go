package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

func reassigns(as []Action) []string {
	var out []string
	for _, a := range ofKind(as, DNSReassign) {
		out = append(out, a.Record.Name+" "+a.Record.Type+" "+a.Owner+"->"+a.NewOwner)
	}
	return out
}

// checkRowOnce fails when one row gets two DNS lifecycle actions, or an
// ensure and a lifecycle action, in one plan.
func checkRowOnce(t *testing.T, acts []Action) {
	t.Helper()
	seen := map[string]ActionKind{}
	for _, a := range acts {
		switch a.Kind {
		case DNSEnsure, DNSDelete, DNSScheduleRemoval, DNSCancelRemoval, DNSReassign:
		default:
			continue
		}
		k := a.Provider + " " + a.Zone + " " + normName(a.Record.Name) + " " + normType(a.Record.Type)
		if prev, ok := seen[k]; ok && !(prev == DNSCancelRemoval && a.Kind == DNSEnsure) && !(prev == DNSEnsure && a.Kind == DNSCancelRemoval) {
			t.Fatalf("row %s got %s and %s: %v", k, prev, a.Kind, sums(acts))
		}
		seen[k] = a.Kind
	}
}

func TestReassignOnTakeover(t *testing.T) {
	cfg := phCfg()
	win := pub("static:new", "app", "example.test", 80)
	for _, ra := range []*time.Time{nil, tp(t0.Add(time.Hour)), tp(t0.Add(-time.Hour))} {
		row := ownedRA("example.test", "app.example.test", "A", target, "docker:old", ra)
		// absent loser, Known (route still there) and after the route is gone
		for _, k := range []map[string]KnownService{knownMap(known("docker:old", "example.test", "app.example.test", ra)), nil} {
			obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}, Known: k}
			acts := Plan([]model.Service{win}, obs, cfg, t0)
			if got := reassigns(acts); len(got) != 1 || got[0] != "app.example.test A docker:old->static:new" {
				t.Fatalf("ra %v known %v: %v", ra, k != nil, sums(acts))
			}
			a := ofKind(acts, DNSReassign)[0]
			if a.Key != "static:new" || a.Svc == nil || a.Svc.Key != "static:new" || a.Provider != dzp || a.Record.Value != target {
				t.Fatalf("action %+v", a)
			}
			assertNone(t, acts, DNSEnsure, DNSScheduleRemoval, DNSDelete, DNSCancelRemoval)
			checkRowOnce(t, acts)
		}
	}
}

func TestReassignOnlyWhenSafe(t *testing.T) {
	cfg := phCfg()
	win := pub("static:new", "app", "example.test", 80)
	row := owned("example.test", "app.example.test", "A", target, "docker:old")
	base := func() Observed {
		return Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}}
	}
	t.Run("values differ: the old path", func(t *testing.T) {
		obs := base()
		obs.Owned = []store.DNSRecord{owned("example.test", "app.example.test", "A", "192.0.2.99", "docker:old")}
		acts := Plan([]model.Service{win}, obs, cfg, t0)
		assertNone(t, acts, DNSReassign, DNSEnsure)
		if len(ofKind(acts, DNSScheduleRemoval)) != 1 {
			t.Fatalf("%v", sums(acts))
		}
	})
	t.Run("new owner not Published", func(t *testing.T) {
		for _, st := range []string{model.StateStopped, model.StatePending, model.StateError} {
			s := svc("static:new", "app", "example.test", st, "198.51.100.5", 80)
			acts := Plan([]model.Service{s}, base(), cfg, t0)
			assertNone(t, acts, DNSReassign)
		}
	})
	t.Run("new owner without backend or invalid", func(t *testing.T) {
		nb := pub("static:new", "app", "example.test", 0)
		inv := win
		inv.Options.Middlewares = []string{"undefined@file"}
		for _, s := range []model.Service{nb, inv} {
			assertNone(t, Plan([]model.Service{s}, base(), cfg, t0), DNSReassign)
		}
	})
	t.Run("old owner's source unavailable or unknown", func(t *testing.T) {
		obs := base()
		obs.Unavailable = map[string]bool{"docker": true}
		acts := Plan([]model.Service{win}, obs, cfg, t0)
		assertNone(t, acts, DNSReassign, DNSScheduleRemoval, DNSDelete)
		obs = base()
		obs.Owned = []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "other:old")}
		assertNone(t, Plan([]model.Service{win}, obs, cfg, t0), DNSReassign, DNSScheduleRemoval, DNSDelete)
	})
	t.Run("old owner present and still declaring (conflict loser)", func(t *testing.T) {
		lose := pub("docker:old", "app", "example.test", 81)
		acts := Plan([]model.Service{win, lose}, base(), cfg, t0)
		assertNone(t, acts, DNSReassign, DNSScheduleRemoval, DNSDelete)
	})
	t.Run("old owner present but protected", func(t *testing.T) {
		stopped := svc("docker:old", "other", "example.test", model.StateStopped, "198.51.100.5", 81)
		assertNone(t, Plan([]model.Service{win, stopped}, base(), cfg, t0), DNSReassign, DNSScheduleRemoval, DNSDelete)
	})
	t.Run("old owner renamed away: reassigned", func(t *testing.T) {
		moved := pub("docker:old", "elsewhere", "example.test", 81)
		acts := Plan([]model.Service{win, moved}, base(), cfg, t0)
		if got := reassigns(acts); len(got) != 1 || got[0] != "app.example.test A docker:old->static:new" {
			t.Fatalf("%v", sums(acts))
		}
		checkRowOnce(t, acts)
	})
	t.Run("type differs (the zone switched to AAAA)", func(t *testing.T) {
		c6 := cfgOf(zone("example.test", "per-host", "wildcard"))
		c6.Zones[0].TargetIP = "2001:db8::10"
		acts := Plan([]model.Service{win}, base(), c6, t0)
		assertNone(t, acts, DNSReassign)
	})
	t.Run("wildcard and zone rows never", func(t *testing.T) {
		obs := base()
		obs.Owned = []store.DNSRecord{owned("example.test", "*.example.test", "A", target, WildcardOwnerKey("example.test"))}
		assertNone(t, Plan([]model.Service{win}, obs, cfg, t0), DNSReassign)
	})
}

// Two present services want the same row: only the hostname winner gets it.
func TestReassignTwoCandidatesGoesToWinner(t *testing.T) {
	cfg := phCfg()
	row := owned("example.test", "app.example.test", "A", target, "truenas:old")
	obs := Observed{Foreign: listed("example.test"), Owned: []store.DNSRecord{row}}
	for _, order := range [][]model.Service{
		{pub("docker:b", "app", "example.test", 80), pub("static:a", "app", "example.test", 81)},
		{pub("static:a", "app", "example.test", 81), pub("docker:b", "app", "example.test", 80)},
	} {
		acts := Plan(order, obs, cfg, t0)
		if got := reassigns(acts); len(got) != 1 || got[0] != "app.example.test A truenas:old->static:a" {
			t.Fatalf("%v", sums(acts))
		}
		checkRowOnce(t, acts)
	}
}

// Rename without a stable id / container recreated under a new name: the
// record stays at the provider in every cycle; ownership moves to the new
// key; once the new key goes away the record IS deleted after grace.
func TestReassignE2EKeepsRecordContinuously(t *testing.T) {
	for _, c := range []struct{ name, oldKey, newKey string }{
		{"static rename without id", "static:app", "static:app-2"},
		{"container recreated", "docker:app_1", "docker:app_2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t, "per-host")
			oldSvc, newSvc := pub(c.oldKey, "app", dz, 80), pub(c.newKey, "app", dz, 80)
			has := func() {
				t.Helper()
				recs := w.records()
				if len(recs) != 1 || recs[0].Name != "app.example.test" || recs[0].Value != ip1 {
					t.Fatalf("no record: %+v", recs)
				}
			}
			w.mustCycle(t0, oldSvc)
			has()
			id := w.rows()[0].ProviderRecordID
			n := len(w.fk.Calls())
			// final-review H1: the same-rank newcomer waits out the absent
			// incumbent's grace period (Conflict); the record stays
			acts := w.mustCycle(t0.Add(time.Minute), newSvc)
			if len(ofKind(forKey(acts, c.newKey), Conflict)) != 1 || len(reassigns(acts)) != 0 {
				t.Fatalf("plan %v", sums(acts))
			}
			has()
			acts = w.mustCycle(t0.Add(12*time.Hour), newSvc)
			if len(ofKind(forKey(acts, c.newKey), Conflict)) != 1 || len(reassigns(acts)) != 0 {
				t.Fatalf("plan %v", sums(acts))
			}
			has()
			// grace over: the route is removed, the newcomer takes the
			// hostname and the record over in the same cycle (never deleted)
			acts = w.mustCycle(t0.Add(24*time.Hour+2*time.Minute), newSvc)
			if got := reassigns(acts); len(got) != 1 {
				t.Fatalf("plan %v", sums(acts))
			}
			assertNone(t, acts, DNSDelete)
			has()
			if got := w.writes(n); len(got) != 0 {
				t.Fatalf("provider writes %v", got)
			}
			rows := w.rows()
			if len(rows) != 1 || rows[0].OwnerKey != c.newKey || rows[0].RemovedAfter != nil || rows[0].ProviderRecordID != id {
				t.Fatalf("rows %+v", rows)
			}
			for _, off := range []time.Duration{25 * time.Hour, 26 * time.Hour, 49 * time.Hour} {
				acts := w.mustCycle(t0.Add(off), newSvc)
				assertOrphans(t, acts)
				assertNone(t, acts, DNSReassign)
				has()
			}
			// the new key goes away: removed after grace (no stale owner left)
			w.mustCycle(t0.Add(50 * time.Hour))
			has()
			acts = w.mustCycle(t0.Add(75 * time.Hour))
			if len(ofKind(acts, DNSDelete)) != 1 {
				t.Fatalf("plan %v", sums(acts))
			}
			if len(w.records()) != 0 || len(w.rows()) != 0 {
				t.Fatalf("records %+v rows %+v", w.records(), w.rows())
			}
		})
	}
}

func reassignAct(name, value, oldOwner, newOwner string) Action {
	s := pub(newOwner, strings.SplitN(name, ".", 2)[0], dz, 80)
	return Action{Kind: DNSReassign, Zone: dz, Host: name, Key: newOwner, Provider: dzp, Owner: oldOwner, NewOwner: newOwner,
		Svc: &s, Record: &dns.Record{Name: name, Type: "A", Value: value}}
}

func TestDNSExecReassign(t *testing.T) {
	ctx := context.Background()
	t.Run("transfers ownership, clears schedule, no provider call", func(t *testing.T) {
		r := perHostRig(t)
		r.addRow(t, "app.example.test", "A", ip1, "fake-1", "docker:old")
		r.due(t, "app.example.test", "docker:old")
		skip := len(r.fk.Calls())
		if err := r.apply(t, false, reassignAct("APP.example.test.", ip1, "docker:old", "static:new")); err != nil {
			t.Fatal(err)
		}
		rows := r.rows(t)
		if len(rows) != 1 || rows[0].OwnerKey != "static:new" || rows[0].RemovedAfter != nil || rows[0].ProviderRecordID != "fake-1" {
			t.Fatalf("rows %+v", rows)
		}
		if len(r.fk.Calls()) != skip {
			t.Fatalf("provider called %v", ops(r.fk, skip))
		}
		if !strings.Contains(r.act.messages(), "reassigned") {
			t.Fatalf("activity %q", r.act.messages())
		}
		// idempotent
		if err := r.apply(t, false, reassignAct("app.example.test", ip1, "docker:old", "static:new")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("stale: owner or value changed is a no-op", func(t *testing.T) {
		r := perHostRig(t)
		r.addRow(t, "app.example.test", "A", ip1, "fake-1", "docker:other")
		r.addRow(t, "web.example.test", "A", ip2, "fake-2", "docker:old")
		if err := r.apply(t, false, reassignAct("app.example.test", ip1, "docker:old", "static:new"),
			reassignAct("web.example.test", ip1, "docker:old", "static:new"),
			reassignAct("none.example.test", ip1, "docker:old", "static:new")); err != nil {
			t.Fatal(err)
		}
		rows := r.rows(t)
		if rows[0].OwnerKey != "docker:other" || rows[1].OwnerKey != "docker:old" {
			t.Fatalf("rows %+v", rows)
		}
	})
	t.Run("refusals", func(t *testing.T) {
		r := perHostRig(t)
		r.addRow(t, "app.example.test", "A", ip1, "fake-1", "docker:old")
		zoneOwner := reassignAct("app.example.test", ip1, "docker:old", "zone:example.test")
		noSvc := reassignAct("app.example.test", ip1, "docker:old", "static:new")
		noSvc.Svc = nil
		otherSvc := reassignAct("app.example.test", ip1, "docker:old", "static:new")
		otherSvc.Svc.Key = "static:x"
		stopped := reassignAct("app.example.test", ip1, "docker:old", "static:new")
		stopped.Svc.State = model.StateStopped
		empty := reassignAct("app.example.test", ip1, "docker:old", "static:new")
		empty.NewOwner = ""
		same := reassignAct("app.example.test", ip1, "docker:old", "docker:old")
		for name, a := range map[string]Action{"zone new owner": zoneOwner, "no svc": noSvc, "other svc": otherSvc,
			"not published": stopped, "empty": empty, "same": same} {
			if err := r.apply(t, false, a); !errors.Is(err, ErrDNSRefused) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		rw := newDNSRig(t, dnsCfg(dnsZoneCfg(dz, "wildcard")))
		rw.addRow(t, "*.example.test", "A", ip1, "fake-1", WildcardOwnerKey(dz))
		wc := reassignAct("*.example.test", ip1, WildcardOwnerKey(dz), "static:new")
		if err := rw.apply(t, false, wc); !errors.Is(err, ErrDNSRefused) {
			t.Fatalf("wildcard: %v", err)
		}
		if rows := r.rows(t); rows[0].OwnerKey != "docker:old" {
			t.Fatalf("rows %+v", rows)
		}
		if rows := rw.rows(t); rows[0].OwnerKey != WildcardOwnerKey(dz) {
			t.Fatalf("rows %+v", rows)
		}
	})
	t.Run("dry run writes nothing", func(t *testing.T) {
		r := perHostRig(t)
		r.addRow(t, "app.example.test", "A", ip1, "fake-1", "docker:old")
		if err := r.apply(t, true, reassignAct("app.example.test", ip1, "docker:old", "static:new")); err != nil {
			t.Fatal(err)
		}
		if rows := r.rows(t); rows[0].OwnerKey != "docker:old" {
			t.Fatalf("rows %+v", rows)
		}
		if !strings.Contains(r.act.messages(), "dry run: would reassign") {
			t.Fatalf("activity %q", r.act.messages())
		}
	})
	_ = ctx
}

// Every DNS kind is registered by RegisterDNSExecutor.
func TestRegisterDNSExecutorCoversAllDNSKinds(t *testing.T) {
	want := []ActionKind{DNSEnsure, DNSDelete, DNSScheduleRemoval, DNSCancelRemoval, DNSReassign}
	if len(DNSActionKinds) != len(want) {
		t.Fatalf("DNSActionKinds %v", DNSActionKinds)
	}
	for _, k := range want {
		if !isDNSKind(k) {
			t.Fatalf("%s not a DNS kind", k)
		}
	}
	for _, k := range KindOrder {
		in := false
		for _, d := range DNSActionKinds {
			in = in || d == k
		}
		if in != isDNSKind(k) {
			t.Fatalf("%s: DNSActionKinds and isDNSKind disagree", k)
		}
	}
	rec := &Recorder{}
	m := RegisterDNSExecutor(NewMultiExecutor(nil), rec)
	var acts []Action
	for _, k := range want {
		acts = append(acts, Action{Kind: k})
	}
	if err := m.Apply(context.Background(), acts, false); err != nil {
		t.Fatal(err)
	}
	if n := len(rec.Calls()); n != len(want) {
		t.Fatalf("dispatched %d batches", n)
	}
}
