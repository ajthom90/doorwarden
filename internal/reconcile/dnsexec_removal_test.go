package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
)

func schedule(name, value, id, owner string, at time.Time) Action {
	return Action{Kind: DNSScheduleRemoval, Zone: dz, Host: name, Key: owner, Provider: dzp, Owner: owner,
		Record: &dns.Record{ID: id, Name: name, Type: "A", Value: value}, RemovedAfter: &at}
}

func cancelRm(name, value, id, owner string) Action {
	return Action{Kind: DNSCancelRemoval, Zone: dz, Host: name, Key: owner, Provider: dzp, Owner: owner,
		Record: &dns.Record{ID: id, Name: name, Type: "A", Value: value}}
}

func TestDNSExecScheduleAndCancelRemovalNoProviderCall(t *testing.T) {
	r := perHostRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "fake-1", "docker:app")
	skip := len(r.fk.Calls())
	at := t0.Add(24 * time.Hour)
	if err := r.apply(t, false, schedule("APP.example.test.", ip1, "fake-1", "docker:app", at)); err != nil {
		t.Fatal(err)
	}
	rows := r.rows(t)
	if len(rows) != 1 || rows[0].RemovedAfter == nil || !rows[0].RemovedAfter.Equal(at) || rows[0].Value != ip1 ||
		rows[0].ProviderRecordID != "fake-1" {
		t.Fatalf("rows %+v", rows)
	}
	if err := r.apply(t, false, cancelRm("app.example.test", ip1, "fake-1", "docker:app")); err != nil {
		t.Fatal(err)
	}
	if rows := r.rows(t); rows[0].RemovedAfter != nil {
		t.Fatalf("not cancelled: %+v", rows)
	}
	if n := len(r.fk.Calls()) - skip; n != 0 {
		t.Fatalf("provider called %d times", n)
	}
	if m := r.act.messages(); !strings.Contains(m, "scheduled removal") || !strings.Contains(m, "cancelled") {
		t.Fatalf("activity %q", m)
	}
}

func TestDNSExecScheduleRemovalOwnerGuarded(t *testing.T) {
	r := perHostRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "fake-1", "docker:app")
	at := t0.Add(time.Hour)
	// another owner, and a row that does not exist: no-op, no error
	if err := r.apply(t, false, schedule("app.example.test", ip1, "fake-1", "docker:other", at),
		schedule("web.example.test", ip1, "fake-2", "docker:app", at)); err != nil {
		t.Fatal(err)
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].RemovedAfter != nil {
		t.Fatalf("rows %+v", rows)
	}
}

func TestDNSExecScheduleRemovalRefusals(t *testing.T) {
	r := newDNSRig(t, dnsCfg(dnsZoneCfg(dz, "wildcard")))
	r.addRow(t, "*.example.test", "A", ip1, "fake-1", WildcardOwnerKey(dz))
	at := t0.Add(time.Hour)
	wc := schedule("*.example.test", ip1, "fake-1", WildcardOwnerKey(dz), at)
	if err := r.apply(t, false, wc); !errors.Is(err, ErrDNSRefused) {
		t.Fatalf("wildcard: %v", err)
	}
	noAt := schedule("app.example.test", ip1, "fake-1", "docker:app", at)
	noAt.RemovedAfter = nil
	if err := r.apply(t, false, noAt); err == nil {
		t.Fatal("schedule without RemovedAfter accepted")
	}
	other := schedule("app.other.test", ip1, "fake-1", "docker:app", at)
	other.Zone = "other.test"
	if err := r.apply(t, false, other); !errors.Is(err, ErrDNSRefused) {
		t.Fatalf("unconfigured zone: %v", err)
	}
	if rows := r.rows(t); len(rows) != 1 || rows[0].RemovedAfter != nil {
		t.Fatalf("rows %+v", rows)
	}
}

func TestDNSExecScheduleRemovalDryRunWritesNothing(t *testing.T) {
	r := perHostRig(t)
	r.addRow(t, "app.example.test", "A", ip1, "fake-1", "docker:app")
	if err := r.apply(t, true, schedule("app.example.test", ip1, "fake-1", "docker:app", t0.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if rows := r.rows(t); rows[0].RemovedAfter != nil {
		t.Fatalf("dry run wrote: %+v", rows)
	}
	if m := r.act.messages(); !strings.Contains(m, "dry run: would schedule removal") {
		t.Fatalf("activity %q", m)
	}
	at := t0.Add(time.Hour)
	if err := r.st.SetOwnedRemoval(context.Background(), dzp, dz, "app.example.test", "A", "docker:app", &at); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(t, true, cancelRm("app.example.test", ip1, "fake-1", "docker:app")); err != nil {
		t.Fatal(err)
	}
	if rows := r.rows(t); rows[0].RemovedAfter == nil {
		t.Fatalf("dry run cleared: %+v", rows)
	}
	if m := r.act.messages(); !strings.Contains(m, "dry run: would cancel") {
		t.Fatalf("activity %q", m)
	}
}
