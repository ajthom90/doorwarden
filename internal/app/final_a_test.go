package app

import (
	"context"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/notify"
	"github.com/ajthom90/doorwarden/internal/reconcile"
)

func conflictEvents(ev []notify.Event, key string) []notify.Event {
	var out []notify.Event
	for _, e := range ev {
		if e.Kind == "conflict" && e.Fields["key"] == key {
			out = append(out, e)
		}
	}
	return out
}

// Final-review H1 at app level: a same-source container with a smaller key
// and doorwarden.name=victim does not take the incumbent's hostname, the
// challenger's Conflict is notified with a stable dedupe key, and the
// incumbent keeps the hostname across a restart (Known comes from the
// persisted routes).
func TestIncumbentKeepsHostnameAcrossCyclesAndRestart(t *testing.T) {
	e := newEnv(t, testYAML)
	victim := svc("docker", "victim")
	victim.Key = "docker:victim"
	e.src.set(nil, victim)
	a := e.app()
	ctx := context.Background()
	if res := a.RunOnce(ctx); res.Err != nil {
		t.Fatal(res.Err)
	}
	attacker := svc("docker", "aaa")
	attacker.Key, attacker.Name = "docker:aaa", "victim"
	attacker.Backend.Port = 9999
	e.src.set(nil, attacker, victim)

	check := func(a *App, label string) {
		t.Helper()
		res := a.RunOnce(ctx)
		if res.Err != nil {
			t.Fatalf("%s: %v", label, res.Err)
		}
		for _, x := range res.Actions {
			if x.Key == "docker:aaa" && x.Kind != reconcile.Conflict {
				t.Fatalf("%s: challenger got %s", label, x.Kind)
			}
			if x.Kind == reconcile.RouteRemove {
				t.Fatalf("%s: incumbent route removed", label)
			}
		}
		routes, err := e.st.ListRoutes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 || routes[0].Key != "docker:victim" || routes[0].Port != 8080 {
			t.Fatalf("%s: routes = %+v", label, routes)
		}
	}
	check(a, "cycle 1")
	check(a, "cycle 2")
	ev := conflictEvents(e.notif.events(), "docker:aaa")
	if len(ev) == 0 || !strings.Contains(ev[0].Message, "incumbent") || !strings.Contains(ev[0].Message, "docker:victim") {
		t.Fatalf("conflict notifications = %+v", e.notif.events())
	}
	for _, x := range ev[1:] {
		if x.DedupeKey != ev[0].DedupeKey {
			t.Fatalf("dedupe key changed between cycles: %q vs %q", x.DedupeKey, ev[0].DedupeKey)
		}
	}

	// restart: a new App over the same database
	_ = a.Close(ctx)
	e.st = e.openStore()
	b := e.app()
	check(b, "after restart")
}
