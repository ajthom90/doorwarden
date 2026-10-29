package reconcile

import (
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
)

// A same-rank challenger with a lexicographically smaller key never takes a
// hostname from the incumbent (the key that serves it per the persisted
// routes): it becomes a Conflict, across cycles (Known is re-read from the
// store every cycle, so a restart sees the same).
func TestIncumbentKeepsHostnameAgainstSameRankChallenger(t *testing.T) {
	e := newE2E(t)
	victim := pub("docker:victim", "victim", "example.test", 8080)
	e.cycle([]model.Service{victim})
	before := e.mustRoute("docker:victim")

	attacker := pub("docker:aaa", "victim", "example.test", 9999) // doorwarden.name=victim
	for i := 0; i < 3; i++ {
		e.now = t0.Add(time.Duration(i+1) * time.Hour)
		acts := e.cycle([]model.Service{attacker, victim})
		c := ofKind(forKey(acts, "docker:aaa"), Conflict)
		if len(c) != 1 || !strings.Contains(c[0].Reason, "docker:victim") || !strings.Contains(c[0].Reason, "incumbent") {
			t.Fatalf("cycle %d: want Conflict for docker:aaa naming the incumbent, got %v", i, sums(acts))
		}
		if len(ofKind(forKey(acts, "docker:aaa"), RouteWrite)) != 0 {
			t.Fatalf("cycle %d: challenger routed: %v", i, sums(acts))
		}
		assertNone(t, acts, RouteRemove)
		if _, ok := e.route("docker:aaa"); ok {
			t.Fatal("challenger persisted")
		}
		if got := e.mustRoute("docker:victim"); got.Port != before.Port || got.Hostname != before.Hostname {
			t.Fatalf("incumbent row changed: %+v", got)
		}
	}
	// the attacker listed first or last makes no difference
	acts := e.cycle([]model.Service{victim, attacker})
	if len(ofKind(forKey(acts, "docker:victim"), RouteWrite)) != 1 {
		t.Fatalf("incumbent not routed: %v", sums(acts))
	}
}

// A stopped incumbent keeps its hostname too (the challenger appearing while
// the victim is stopped for maintenance must not take it).
func TestStoppedIncumbentKeepsHostname(t *testing.T) {
	e := newE2E(t)
	victim := pub("docker:victim", "victim", "example.test", 8080)
	e.cycle([]model.Service{victim})
	e.now = t0.Add(time.Hour)
	stopped := svc("docker:victim", "victim", "example.test", model.StateStopped, "", 0)
	attacker := pub("docker:aaa", "victim", "example.test", 9999)
	acts := e.cycle([]model.Service{attacker, stopped})
	if len(ofKind(forKey(acts, "docker:aaa"), Conflict)) != 1 || len(ofKind(forKey(acts, "docker:aaa"), RouteWrite)) != 0 {
		t.Fatalf("stopped incumbent lost its hostname: %v", sums(acts))
	}
	assertNone(t, acts, RouteRemove)
	e.mustRoute("docker:victim")
}

// Once the incumbent is gone, the challenger waits out the removal grace and
// then takes over.
func TestChallengerTakesOverAfterIncumbentGrace(t *testing.T) {
	e := newE2E(t)
	victim := pub("docker:victim", "victim", "example.test", 8080)
	e.cycle([]model.Service{victim})
	attacker := pub("docker:aaa", "victim", "example.test", 9999)

	e.now = t0.Add(time.Hour)
	acts := e.cycle([]model.Service{attacker}) // victim gone: removal scheduled
	if len(ofKind(forKey(acts, "docker:victim"), ScheduleRemoval)) != 1 || len(ofKind(forKey(acts, "docker:aaa"), Conflict)) != 1 {
		t.Fatalf("want ScheduleRemoval for victim and Conflict for challenger, got %v", sums(acts))
	}
	e.now = t0.Add(10 * time.Hour) // within grace
	acts = e.cycle([]model.Service{attacker})
	if len(ofKind(forKey(acts, "docker:aaa"), RouteWrite)) != 0 {
		t.Fatalf("challenger routed within the incumbent's grace: %v", sums(acts))
	}
	e.now = t0.Add(26 * time.Hour) // grace over
	acts = e.cycle([]model.Service{attacker})
	if len(ofKind(forKey(acts, "docker:aaa"), RouteWrite)) != 1 {
		t.Fatalf("challenger not routed after grace: %v", sums(acts))
	}
	if _, ok := e.route("docker:victim"); ok {
		t.Fatal("incumbent row still present after grace")
	}
	e.mustRoute("docker:aaa")
}

// Cross-source rank still wins over incumbency: a static entry takes the
// hostname from a docker incumbent.
func TestHigherRankBeatsIncumbent(t *testing.T) {
	e := newE2E(t)
	e.cycle([]model.Service{pub("docker:app", "app", "example.test", 8080)})
	e.now = t0.Add(time.Hour)
	acts := e.cycle([]model.Service{pub("docker:app", "app", "example.test", 8080), pub("static:app", "app", "example.test", 7070)})
	if len(ofKind(forKey(acts, "static:app"), RouteWrite)) != 1 || len(ofKind(forKey(acts, "docker:app"), Conflict)) != 1 {
		t.Fatalf("rank did not win: %v", sums(acts))
	}
	if rr := ofKind(forKey(acts, "docker:app"), RouteRemove); len(rr) != 1 || rr[0].Cause != CauseTakeover {
		t.Fatalf("want takeover RouteRemove of docker:app, got %v", sums(acts))
	}
}

// First-time ties (no incumbent) keep the deterministic key order.
func TestFirstTimeTieKeepsKeyOrder(t *testing.T) {
	acts := Plan([]model.Service{pub("docker:bbb", "app", "example.test", 1), pub("docker:aaa", "app", "example.test", 2)},
		Observed{}, cfgOf(zone("example.test", "", "")), t0)
	if len(ofKind(forKey(acts, "docker:aaa"), RouteWrite)) != 1 || len(ofKind(forKey(acts, "docker:bbb"), Conflict)) != 1 {
		t.Fatalf("key order not kept: %v", sums(acts))
	}
}

// A phantom (Known route of an unavailable source) is the incumbent within
// its rank: a same-rank newcomer from another available source of the same
// type does not displace it, whatever the key order.
func TestPhantomIncumbentKeepsHostnameAgainstSameRankNewcomer(t *testing.T) {
	cfg := cfgOf(zone("example.test", "", ""))
	obs := Observed{Unavailable: map[string]bool{"docker": true},
		Known: knownMap(known("docker:zzz", "example.test", "app.example.test", nil))}
	n := pub("docker:aaa", "app", "example.test", 1)
	n.Source = "docker2"
	got := Plan([]model.Service{n}, obs, cfg, t0)
	assertSums(t, got, "Conflict example.test app.example.test docker:aaa")
}

// A Published service whose labels became invalid while it holds a Known
// route gets an Invalid flagged AlertPublishedInvalid (the caller notifies)
// naming the hostname it still holds; an Invalid service without a Known
// route is not flagged.
func TestHeldInvalidIsFlaggedForNotification(t *testing.T) {
	e := newE2E(t)
	e.cycle([]model.Service{pub("docker:app", "app", "example.test", 8080)})
	e.now = t0.Add(time.Hour)
	acts := e.cycle([]model.Service{pub("docker:app", "!!!", "example.test", 8080), pub("docker:fresh", "!!!", "example.test", 1)})
	inv := ofKind(forKey(acts, "docker:app"), Invalid)
	if len(inv) != 1 || inv[0].Alert != AlertPublishedInvalid || !strings.Contains(inv[0].Reason, "app.example.test") {
		t.Fatalf("held Invalid: %+v", inv)
	}
	if f := ofKind(forKey(acts, "docker:fresh"), Invalid); len(f) != 1 || f[0].Alert != "" {
		t.Fatalf("fresh Invalid: %+v", f)
	}
}
