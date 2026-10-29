package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/model"
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

// Final-review H2/H3 ruling: a portal-less TrueNAS app (Error, no host) gets
// a backend from a UI Port override: Discovered with the source's target_ip
// and the port, still Pending in approve mode until approved; then a port
// change reported by the source needs re-approval.
func TestTrueNASPortOverridePromotesPortalLessApp(t *testing.T) {
	e := newEnv(t, testYAML)
	tn := &fakeSource{name: "truenas"}
	errApp := model.Service{Key: "truenas:app", Source: "truenas", Name: "app", State: model.StateError,
		Backend: model.Backend{Scheme: "http"}}
	tn.set(nil, errApp)
	a := e.app(func(o *Options) { o.Sources = []SourceSpec{{Source: tn, Mode: approval.ModeApprove}} })
	ctx := context.Background()
	a.RunOnce(ctx)
	if s := info(t, a, "truenas:app"); s.State != model.StateError {
		t.Fatalf("state %+v", s)
	}
	// a skip-verify override alone is still refused (no host)
	if err := a.SetServiceOverride(ctx, "truenas:app", func(o *model.UIOverrides) error { b := false; o.SkipVerify = &b; return nil }); err == nil {
		t.Fatal("override without a port accepted for a host-less app")
	}
	if err := a.SetServiceOverride(ctx, "truenas:app", func(o *model.UIOverrides) error { p := 30080; o.Port = &p; return nil }); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	s := info(t, a, "truenas:app")
	if s.State != model.StatePending || s.Backend.Host != "192.0.2.10" || s.Backend.Port != 30080 || s.Backend.Scheme != "http" {
		t.Fatalf("promoted: %+v", s)
	}
	if err := a.Approve(ctx, "truenas:app", s.Fingerprint); err != nil {
		t.Fatal(err)
	}
	res := a.RunOnce(ctx)
	if s := info(t, a, "truenas:app"); s.State != model.StatePublished {
		t.Fatalf("approved: %+v", s)
	}
	routed := false
	for _, x := range res.Actions {
		routed = routed || (x.Kind == reconcile.RouteWrite && x.Key == "truenas:app" && x.Backend.Port == 30080)
	}
	if !routed {
		t.Fatalf("no route: %+v", res.Actions)
	}
}

// A TrueNAS app whose portal port changes needs re-approval.
func TestTrueNASPortalPortChangeNeedsApproval(t *testing.T) {
	e := newEnv(t, testYAML)
	tn := &fakeSource{name: "truenas"}
	app := model.Service{Key: "truenas:app", Source: "truenas", Name: "app", State: model.StateDiscovered,
		Backend: model.Backend{Scheme: "http", Host: "192.0.2.10", Port: 30001}}
	tn.set(nil, app)
	a := e.app(func(o *Options) { o.Sources = []SourceSpec{{Source: tn, Mode: approval.ModeApprove}} })
	ctx := context.Background()
	a.RunOnce(ctx)
	if err := a.Approve(ctx, "truenas:app", info(t, a, "truenas:app").Fingerprint); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	if s := info(t, a, "truenas:app"); s.State != model.StatePublished {
		t.Fatalf("approved: %+v", s)
	}
	app.Backend.Port = 30002
	tn.set(nil, app)
	res := a.RunOnce(ctx)
	if s := info(t, a, "truenas:app"); s.State != model.StatePending {
		t.Fatalf("changed portal port kept the approval: %+v", s)
	}
	for _, x := range res.Actions {
		if x.Kind == reconcile.RouteWrite && x.Key == "truenas:app" && x.Backend.Port == 30002 {
			t.Fatalf("unapproved port routed: %+v", x)
		}
	}
}

// Dry run refuses the certificate actions that would talk to the CA and
// write certificates (checked before anything else).
func TestDryRunRefusesCertActions(t *testing.T) {
	e := newEnv(t, testYAML)
	a := e.app()
	ctx := context.Background()
	if err := a.SetDryRun(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := a.RenewCert(ctx, "example.test"); !errors.Is(err, ErrDryRun) {
		t.Fatalf("RenewCert in dry run: %v", err)
	}
	if err := a.SwitchProduction(ctx, "le"); !errors.Is(err, ErrDryRun) {
		t.Fatalf("SwitchProduction in dry run: %v", err)
	}
	if err := a.SetDryRun(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := a.RenewCert(ctx, "example.test"); errors.Is(err, ErrDryRun) {
		t.Fatal("refused outside dry run")
	}
}
