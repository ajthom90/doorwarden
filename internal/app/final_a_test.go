package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/config"
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

// Close drains background ACME orders (bounded) before it closes the
// sources and the notifier, so the caller can close the store afterwards.
func TestCloseWaitsForACMEOrdersBeforeClosingSources(t *testing.T) {
	e := newEnv(t, testYAML)
	a := e.app()
	release := make(chan struct{})
	var sourcesClosedEarly atomic.Bool
	a.ordersWait = func(ctx context.Context) error {
		select {
		case <-release:
			sourcesClosedEarly.Store(e.src.closed.Load() != 0)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { done <- a.Close(context.Background()) }()
	select {
	case <-done:
		t.Fatal("Close returned while an order was running")
	case <-time.After(100 * time.Millisecond):
	}
	if e.src.closed.Load() != 0 {
		t.Fatal("sources closed before the orders drained")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	if sourcesClosedEarly.Load() || e.src.closed.Load() != 1 {
		t.Fatalf("closed early=%v count=%d", sourcesClosedEarly.Load(), e.src.closed.Load())
	}
}

// The drain is bounded: a stuck order does not block shutdown forever.
func TestCloseDrainIsBounded(t *testing.T) {
	e := newEnv(t, testYAML)
	a := e.app()
	a.drainTimeout = 50 * time.Millisecond
	a.ordersWait = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	start := time.Now()
	_ = a.Close(context.Background())
	if time.Since(start) > 2*time.Second || e.src.closed.Load() != 1 {
		t.Fatalf("took %v, sources closed %d", time.Since(start), e.src.closed.Load())
	}
}

// A Published service whose labels become invalid while it holds its route
// is notified (deduplicated per reason) and recorded in the activity log.
func TestHeldInvalidNotified(t *testing.T) {
	e := newEnv(t, testYAML)
	s := svc("docker", "app")
	e.src.set(nil, s)
	a := e.app()
	ctx := context.Background()
	a.RunOnce(ctx)
	if got := info(t, a, s.Key); got.State != model.StatePublished {
		t.Fatalf("not published: %+v", got)
	}
	s.Name = "!!!"
	e.src.set(nil, s)
	a.RunOnce(ctx)
	a.RunOnce(ctx)
	var ev []notify.Event
	for _, x := range e.notif.events() {
		if x.Kind == "service.invalid" {
			ev = append(ev, x)
		}
	}
	if len(ev) == 0 || ev[0].Fields["key"] != s.Key || !strings.Contains(ev[0].Message, "app.example.test") {
		t.Fatalf("invalid notifications: %+v", e.notif.events())
	}
	for _, x := range ev[1:] {
		if x.DedupeKey != ev[0].DedupeKey {
			t.Fatal("dedupe key changed")
		}
	}
	act, _ := e.st.ListActivity(ctx, 100)
	found := false
	for _, x := range act {
		found = found || (strings.Contains(x.Message, s.Key) && strings.Contains(strings.ToLower(x.Message), "invalid"))
	}
	if !found {
		t.Fatalf("activity: %+v", act)
	}
}

// Each zone's target_ip is handed to discovery sources, normalized, so a
// container labelled with a zone uses that zone's host.
func TestZoneTargetsForSources(t *testing.T) {
	cfg := &config.Config{Zones: []config.Zone{{Name: "Example.Test.", TargetIP: "192.0.2.10"}, {Name: "lan.test", TargetIP: "10.0.0.5"}}}
	got := zoneTargets(cfg)
	if len(got) != 2 || got["example.test"] != "192.0.2.10" || got["lan.test"] != "10.0.0.5" {
		t.Fatalf("zoneTargets = %v", got)
	}
}

// When the approval gate cannot resolve a source's services (approvals
// unreadable; here an invalid mode makes Resolve fail), the source is
// treated as unavailable: its published services are never scheduled for
// removal and their routes stay.
func TestGateResolveErrorMarksSourceUnavailable(t *testing.T) {
	e := newEnv(t, testYAML)
	s := svc("docker", "app")
	e.src.set(nil, s)
	a := e.app()
	ctx := context.Background()
	a.RunOnce(ctx)
	if got := info(t, a, s.Key); got.State != model.StatePublished {
		t.Fatalf("not published: %+v", got)
	}
	for i := range a.sources {
		if a.sources[i].Source == e.src {
			a.sources[i].Mode = "bogus"
		}
	}
	for i := 0; i < 2; i++ {
		res := a.RunOnce(ctx)
		for _, x := range res.Actions {
			if x.Kind == reconcile.ScheduleRemoval || x.Kind == reconcile.RouteRemove {
				t.Fatalf("cycle %d: %s for %s after a gate error", i, x.Kind, x.Key)
			}
		}
	}
	if routes, _ := e.st.ListRoutes(ctx); len(routes) != 1 || routes[0].Key != s.Key || routes[0].RemovedAfter != nil {
		t.Fatalf("routes = %+v", routes)
	}
	act, _ := e.st.ListActivity(ctx, 100)
	found := false
	for _, x := range act {
		found = found || strings.Contains(x.Message, "approvals could not be loaded")
	}
	if !found {
		t.Fatalf("no activity about the gate error: %+v", act)
	}
}

// The server's startup error (and whatever it logs) carries no fragment of
// an env value that failed decoding or validation.
func TestStartupConfigErrorHasNoEnvValueFragment(t *testing.T) {
	const secret = "S3cretEnvValue-0123456789"
	env := func(k string) (string, bool) {
		if k == "SECRET" {
			return secret, true
		}
		return "", false
	}
	for name, extra := range map[string]string{
		"decode":   "static:\n  - name: app\n    host: 192.0.2.5\n    port: ${SECRET}\n",
		"validate": "",
	} {
		t.Run(name, func(t *testing.T) {
			yml := testYAML + extra
			if extra == "" { // a validation error quoting the value
				yml = strings.Replace(testYAML, "settings: {grace_period: 1h, poll_interval: 1h}",
					"settings: {grace_period: 1h, poll_interval: 1h, default_zone: \"${SECRET}\"}", 1)
			}
			path, _, _ := writeConfig(t, yml)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var logBuf bytes.Buffer
			err := RunWith(ctx, Flags{Config: path, DB: filepath.Join(t.TempDir(), "dw.db")}, env,
				slog.New(slog.NewTextHandler(&logBuf, nil)))
			if err == nil {
				t.Fatal("no error")
			}
			for n := 3; n <= len(secret); n++ {
				if strings.Contains(err.Error(), secret[:n]) || strings.Contains(logBuf.String(), secret[:n]) {
					t.Fatalf("prefix %q leaked: err=%v log=%s", secret[:n], err, logBuf.String())
				}
			}
		})
	}
}

// The held-invalid dedupe key is the service key plus a hash of the
// reason's sorted problems: word order (map iteration) does not change it;
// a different problem does.
func TestHeldInvalidDedupeKeyStable(t *testing.T) {
	a := invalidDedupeKey("docker:app", "labels invalid (bad port; bad scheme)")
	b := invalidDedupeKey("docker:app", "labels invalid (bad scheme; bad port)")
	c := invalidDedupeKey("docker:app", "labels invalid (bad zone)")
	if a != b || a == c || !strings.HasPrefix(a, "invalid/docker:app/") || strings.Contains(a, "scheme") {
		t.Fatalf("%q %q %q", a, b, c)
	}
}
