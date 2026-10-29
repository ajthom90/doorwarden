package reconcile

import (
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// An approved service whose backend port changed (the gate reports it
// Pending and quarantined) stops being served: its route is removed with
// CauseQuarantine, an alerted Invalid says to re-approve, and no DNS or
// certificate removal is planned. It keeps its hostname: a same-rank
// squatter on that name is a Conflict on this and every later cycle.
// Re-approval (Published again, no longer quarantined) resumes serving.
func TestQuarantineRemovesRouteKeepsHostname(t *testing.T) {
	e := newE2E(t)
	app := pub("docker:app", "app", "example.test", 8080)
	e.cycle([]model.Service{app})
	e.mustRoute("docker:app")

	moved := app
	moved.State = model.StatePending
	moved.Backend.Port = 8099
	squat := pub("docker:aaa", "app", "example.test", 8080) // doorwarden.name=app on the freed port
	e.quarantined = map[string]bool{"docker:app": true}
	for i := 0; i < 3; i++ {
		e.now = t0.Add(time.Duration(i+1) * time.Hour)
		acts := e.cycle([]model.Service{squat, moved})
		mine := forKey(acts, "docker:app")
		rr := ofKind(mine, RouteRemove)
		inv := ofKind(mine, Invalid)
		if len(inv) != 1 || !strings.Contains(inv[0].Reason, "backend changed; re-approve to resume") {
			t.Fatalf("cycle %d: want the quarantine Invalid, got %v", i, sums(acts))
		}
		if i == 0 {
			if len(rr) != 1 || rr[0].Cause != CauseQuarantine || inv[0].Alert != AlertQuarantined {
				t.Fatalf("cycle 0: want RouteRemove(quarantine) and an alert, got %v", sums(acts))
			}
		} else if len(rr) != 0 || inv[0].Alert != "" {
			t.Fatalf("cycle %d: route already removed; got %v (alert %q)", i, sums(acts), inv[0].Alert)
		}
		if r, ok := e.route("docker:app"); !ok || !r.Quarantined || r.Port != 8080 {
			t.Fatalf("cycle %d: want the route kept and quarantined: %+v %v", i, r, ok)
		}
		if c := ofKind(forKey(acts, "docker:aaa"), Conflict); len(c) != 1 || !strings.Contains(c[0].Reason, "docker:app") {
			t.Fatalf("cycle %d: want Conflict for the squatter naming docker:app, got %v", i, sums(acts))
		}
		if len(ofKind(forKey(acts, "docker:aaa"), RouteWrite)) != 0 {
			t.Fatalf("cycle %d: squatter routed: %v", i, sums(acts))
		}
		if _, ok := e.route("docker:aaa"); ok {
			t.Fatalf("cycle %d: squatter persisted", i)
		}
		assertNone(t, acts, ScheduleRemoval)
		assertNone(t, acts, DNSScheduleRemoval)
		assertNone(t, acts, DNSDelete)
		assertNone(t, acts, RouteWrite)
	}

	e.quarantined = nil
	moved.State = model.StatePublished // re-approved
	e.now = t0.Add(5 * time.Hour)
	acts := e.cycle([]model.Service{squat, moved})
	if rw := ofKind(forKey(acts, "docker:app"), RouteWrite); len(rw) != 1 || rw[0].Backend.Port != 8099 {
		t.Fatalf("re-approved service not routed: %v", sums(acts))
	}
	if r := e.mustRoute("docker:app"); r.Port != 8099 || r.Quarantined {
		t.Fatalf("route %+v", r)
	}
}

// The quarantined service keeps its per-host DNS record (and nothing
// issues or drops certificates for it) while it is quarantined.
func TestQuarantineKeepsDNSAndCert(t *testing.T) {
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	s := svc("docker:app", "app", "example.test", model.StatePending, "198.51.100.5", 8099)
	obs := Observed{
		Owned:       []store.DNSRecord{owned("example.test", "app.example.test", "A", target, "docker:app")},
		Foreign:     listed("example.test"),
		Known:       knownMap(known("docker:app", "example.test", "app.example.test", nil)),
		LastKnown:   map[string]model.Backend{"docker:app": {Scheme: "http", Host: "198.51.100.5", Port: 8080}},
		Quarantined: map[string]bool{"docker:app": true},
	}
	acts := Plan([]model.Service{s}, obs, cfg, t0)
	if rr := ofKind(acts, RouteRemove); len(rr) != 1 || rr[0].Cause != CauseQuarantine {
		t.Fatalf("want RouteRemove(quarantine): %v", sums(acts))
	}
	assertNone(t, acts, DNSScheduleRemoval, DNSDelete, ScheduleRemoval, CertEnsure, DNSEnsure, RouteWrite)
}

// Without the quarantine flag a Pending service with a Known route keeps
// its route as before (no approval at all, e.g. a mode change).
func TestPendingWithoutQuarantineKeepsRoute(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	s := svc("docker:app", "app", "example.test", model.StatePending, "198.51.100.5", 8099)
	obs := Observed{Known: knownMap(known("docker:app", "example.test", "app.example.test", nil))}
	acts := Plan([]model.Service{s}, obs, cfg, t0)
	assertNone(t, acts, RouteRemove)
	assertNone(t, acts, Invalid)
}

// A quarantined service reserves only the hostname it was approved and
// served under (its persisted route), never the one its unapproved labels
// now declare: approved A at a.example.test changes its label to
// b.example.test, which C holds; C keeps b, A keeps a reserved but is not
// served, and a fresh D later claims b without A blocking it.
func TestQuarantineReservesOnlyApprovedHostname(t *testing.T) {
	e := newE2E(t)
	a := pub("docker:a", "a", "example.test", 8080)
	c := pub("docker:c", "b", "example.test", 8081)
	e.cycle([]model.Service{a, c})
	e.mustRoute("docker:a")
	e.mustRoute("docker:c")

	renamed := a
	renamed.State = model.StatePending
	renamed.Name = "b" // doorwarden.name=b, not approved
	e.quarantined = map[string]bool{"docker:a": true}
	e.now = t0.Add(time.Hour)
	acts := e.cycle([]model.Service{renamed, c})
	if len(ofKind(forKey(acts, "docker:c"), Conflict)) != 0 || len(ofKind(forKey(acts, "docker:c"), RouteRemove)) != 0 {
		t.Fatalf("C lost b.example.test to an unapproved rename: %v", sums(acts))
	}
	if r := e.mustRoute("docker:c"); r.Hostname != "b.example.test" || r.Quarantined {
		t.Fatalf("C route %+v", r)
	}
	if r, ok := e.route("docker:a"); !ok || !r.Quarantined || r.Hostname != "a.example.test" {
		t.Fatalf("A route not kept quarantined at a.example.test: %+v %v", r, ok)
	}
	if len(ofKind(forKey(acts, "docker:a"), RouteWrite)) != 0 {
		t.Fatalf("A served: %v", sums(acts))
	}

	// a squatter at A's approved name is still blocked
	sq := pub("docker:0sq", "a", "example.test", 9000)
	e.now = t0.Add(2 * time.Hour)
	acts = e.cycle([]model.Service{renamed, c, sq})
	if cf := ofKind(forKey(acts, "docker:0sq"), Conflict); len(cf) != 1 || !strings.Contains(cf[0].Reason, "docker:a") {
		t.Fatalf("squatter at a.example.test not blocked by A: %v", sums(acts))
	}

	// C leaves; once its route is gone, fresh D claims b without A blocking it
	d := pub("docker:d", "b", "example.test", 8082)
	e.now = t0.Add(3 * time.Hour)
	e.cycle([]model.Service{renamed})
	e.now = t0.Add(30 * 24 * time.Hour)
	e.cycle([]model.Service{renamed})
	if _, ok := e.route("docker:c"); ok {
		t.Fatal("C route not removed after grace")
	}
	e.now = e.now.Add(time.Hour)
	acts = e.cycle([]model.Service{renamed, d})
	if rw := ofKind(forKey(acts, "docker:d"), RouteWrite); len(rw) != 1 {
		t.Fatalf("D not routed at b.example.test: %v", sums(acts))
	}
}

// A quarantined service that was never served (no persisted route) makes
// no hostname claim at all.
func TestQuarantineWithoutRouteClaimsNothing(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	q := svc("docker:a", "d", "example.test", model.StatePending, "198.51.100.5", 8099)
	d := svc("docker:d", "d", "example.test", model.StatePublished, "198.51.100.6", 8080)
	obs := Observed{Quarantined: map[string]bool{"docker:a": true}}
	acts := Plan([]model.Service{q, d}, obs, cfg, t0)
	if len(ofKind(forKey(acts, "docker:d"), RouteWrite)) != 1 {
		t.Fatalf("D blocked by an unserved quarantined service: %v", sums(acts))
	}
	assertNone(t, forKey(acts, "docker:a"), Conflict, RouteRemove, RouteWrite)
}
