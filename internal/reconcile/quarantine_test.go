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
