package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

var _ RouteStore = (*store.Store)(nil)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "dw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func routeWrite(s model.Service, zone, host string, b *model.Backend) Action {
	return Action{Kind: RouteWrite, Zone: zone, Host: host, Key: s.Key, Svc: copySvc(s), Backend: b}
}

func listRoutes(t *testing.T, st RouteStore) []store.Route {
	t.Helper()
	rs, err := st.ListRoutes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// countingStore wraps a RouteStore and counts writes.
type countingStore struct {
	RouteStore
	writes int
}

func (c *countingStore) UpsertRoute(ctx context.Context, r store.Route) error {
	c.writes++
	return c.RouteStore.UpsertRoute(ctx, r)
}
func (c *countingStore) DeleteRoute(ctx context.Context, k string) error {
	c.writes++
	return c.RouteStore.DeleteRoute(ctx, k)
}
func (c *countingStore) SetRouteRemoval(ctx context.Context, k string, at *time.Time) error {
	c.writes++
	return c.RouteStore.SetRouteRemoval(ctx, k, at)
}

func TestRouteExecutorWriteMapsFields(t *testing.T) {
	st := openStore(t)
	ex := NewRouteExecutor(st, fixedNow(t0))
	s := pub("docker:app", "app", "example.test", 8080)
	s.Options = model.Options{Websockets: true, Middlewares: []string{"auth@file"}}
	b := model.Backend{Scheme: "https", Host: "198.51.100.7", Port: 8443, SkipVerify: true}
	if err := ex.Apply(context.Background(), []Action{routeWrite(s, "example.test", "app.example.test", &b)}, false); err != nil {
		t.Fatal(err)
	}
	want := []store.Route{{Key: "docker:app", Source: "docker", Zone: "example.test", Hostname: "app.example.test",
		Scheme: "https", Host: "198.51.100.7", Port: 8443, SkipVerify: true, Websockets: true,
		Middlewares: []string{"auth@file"}, UpdatedAt: t0}}
	if got := listRoutes(t, st); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestRouteExecutorRejectsMissingBackend(t *testing.T) {
	st := openStore(t)
	ex := NewRouteExecutor(st, fixedNow(t0))
	s := pub("docker:app", "app", "example.test", 8080)
	good := model.Backend{Scheme: "http", Host: "198.51.100.5", Port: 8080}
	cases := map[string]Action{
		"nil backend":   routeWrite(s, "example.test", "app.example.test", nil),
		"empty backend": routeWrite(s, "example.test", "app.example.test", &model.Backend{}),
		"no port":       routeWrite(s, "example.test", "app.example.test", &model.Backend{Scheme: "http", Host: "198.51.100.5"}),
		"no host":       routeWrite(s, "example.test", "app.example.test", &model.Backend{Scheme: "http", Port: 80}),
		"nil svc":       {Kind: RouteWrite, Zone: "example.test", Host: "app.example.test", Key: s.Key, Backend: &good},
		"no hostname":   routeWrite(s, "example.test", "", &good),
	}
	for name, a := range cases {
		if err := ex.Apply(context.Background(), []Action{a}, false); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if got := listRoutes(t, st); len(got) != 0 {
		t.Fatalf("persisted: %+v", got)
	}
	// an invalid RouteWrite never clobbers an existing route
	if err := ex.Apply(context.Background(), []Action{routeWrite(s, "example.test", "app.example.test", &good)}, false); err != nil {
		t.Fatal(err)
	}
	if err := ex.Apply(context.Background(), []Action{routeWrite(s, "example.test", "app.example.test", &model.Backend{})}, false); err == nil {
		t.Fatal("empty backend accepted")
	}
	if got := listRoutes(t, st); len(got) != 1 || got[0].Port != 8080 {
		t.Fatalf("clobbered: %+v", got)
	}
}

func TestRouteExecutorRejectsEmptyScheme(t *testing.T) {
	st := openStore(t)
	s := pub("docker:app", "app", "example.test", 8080)
	b := model.Backend{Host: "198.51.100.5", Port: 8080}
	if err := NewRouteExecutor(st, fixedNow(t0)).Apply(context.Background(),
		[]Action{routeWrite(s, "example.test", "app.example.test", &b)}, false); !errors.Is(err, store.ErrInvalidRoute) {
		t.Fatalf("want ErrInvalidRoute, got %v", err)
	}
	if got := listRoutes(t, st); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestRouteExecutorNonPublishedWriteIsNoop(t *testing.T) {
	cs := &countingStore{RouteStore: openStore(t)}
	ex := NewRouteExecutor(cs, fixedNow(t0))
	for _, st := range []string{model.StateStopped, model.StateError, model.StatePending, model.StateDiscovered, ""} {
		s := pub("docker:app", "app", "example.test", 8080)
		s.State = st
		if err := ex.Apply(context.Background(), []Action{routeWrite(s, "example.test", "app.example.test", &s.Backend)}, false); err != nil {
			t.Fatalf("%q: %v", st, err)
		}
	}
	if cs.writes != 0 || len(listRoutes(t, cs)) != 0 {
		t.Fatalf("non-published RouteWrite wrote: writes=%d", cs.writes)
	}
}

func TestRouteExecutorDryRunWritesNothing(t *testing.T) {
	cs := &countingStore{RouteStore: openStore(t)}
	ex := NewRouteExecutor(cs, fixedNow(t0))
	s := pub("docker:app", "app", "example.test", 8080)
	at := t0.Add(time.Hour)
	acts := []Action{
		routeWrite(s, "example.test", "app.example.test", &s.Backend),
		{Kind: ScheduleRemoval, Key: "docker:app", RemovedAfter: &at},
		{Kind: CancelRemoval, Key: "docker:app"},
		{Kind: RouteRemove, Key: "docker:app"},
	}
	if err := ex.Apply(context.Background(), acts, true); err != nil {
		t.Fatal(err)
	}
	if cs.writes != 0 || len(listRoutes(t, cs)) != 0 {
		t.Fatalf("dry run wrote: writes=%d", cs.writes)
	}
	if err := ex.Apply(context.Background(), acts[:2], false); err != nil || cs.writes != 2 {
		t.Fatalf("live: writes=%d err=%v", cs.writes, err)
	}
}

func TestRouteExecutorRemovalScheduleAndIgnoredKinds(t *testing.T) {
	cs := &countingStore{RouteStore: openStore(t)}
	ex := NewRouteExecutor(cs, fixedNow(t0))
	s := pub("docker:app", "app", "example.test", 8080)
	at := t0.Add(24 * time.Hour)
	ctx := context.Background()
	if err := ex.Apply(ctx, []Action{routeWrite(s, "example.test", "app.example.test", &s.Backend),
		{Kind: ScheduleRemoval, Key: "docker:app", RemovedAfter: &at}}, false); err != nil {
		t.Fatal(err)
	}
	if got := listRoutes(t, cs); got[0].RemovedAfter == nil || !got[0].RemovedAfter.Equal(at) {
		t.Fatalf("not scheduled: %+v", got)
	}
	if err := ex.Apply(ctx, []Action{{Kind: CancelRemoval, Key: "docker:app"}}, false); err != nil {
		t.Fatal(err)
	}
	if got := listRoutes(t, cs); got[0].RemovedAfter != nil {
		t.Fatalf("not cleared: %+v", got)
	}
	// ScheduleRemoval without a time is an error and writes nothing.
	n := cs.writes
	if err := ex.Apply(ctx, []Action{{Kind: ScheduleRemoval, Key: "docker:app"}}, false); err == nil || cs.writes != n {
		t.Fatalf("err=%v writes=%d", err, cs.writes-n)
	}
	// Schedule/cancel for a key without a route: nothing to do, no error.
	if err := ex.Apply(ctx, []Action{{Kind: ScheduleRemoval, Key: "docker:none", RemovedAfter: &at},
		{Kind: CancelRemoval, Key: "docker:none"}}, false); err != nil {
		t.Fatalf("absent key: %v", err)
	}
	if got := listRoutes(t, cs); len(got) != 1 {
		t.Fatalf("absent key created rows: %+v", got)
	}
	// Kinds this executor does not handle are ignored.
	n = cs.writes
	if err := ex.Apply(ctx, []Action{{Kind: DNSEnsure, Key: "docker:app"}, {Kind: CertEnsure},
		{Kind: DNSDelete, Key: "docker:app"}, {Kind: Conflict, Key: "docker:app"}, {Kind: Skip}, {Kind: Invalid}}, false); err != nil {
		t.Fatal(err)
	}
	if cs.writes != n || len(listRoutes(t, cs)) != 1 {
		t.Fatal("ignored kinds wrote")
	}
	// RouteRemove deletes; repeated is fine.
	for i := 0; i < 2; i++ {
		if err := ex.Apply(ctx, []Action{{Kind: RouteRemove, Key: "docker:app", Cause: CauseTakeover}}, false); err != nil {
			t.Fatal(err)
		}
	}
	if got := listRoutes(t, cs); len(got) != 0 {
		t.Fatalf("not removed: %+v", got)
	}
}

func TestRouteExecutorContinuesAfterError(t *testing.T) {
	st := openStore(t)
	ex := NewRouteExecutor(st, fixedNow(t0))
	a := pub("docker:a", "a", "example.test", 8080)
	b := pub("docker:b", "b", "example.test", 8081)
	err := ex.Apply(context.Background(), []Action{
		routeWrite(a, "example.test", "a.example.test", nil),
		routeWrite(b, "example.test", "b.example.test", &b.Backend),
	}, false)
	if err == nil || !strings.Contains(err.Error(), "docker:a") {
		t.Fatalf("want error naming docker:a, got %v", err)
	}
	if got := listRoutes(t, st); len(got) != 1 || got[0].Key != "docker:b" {
		t.Fatalf("later action not applied: %+v", got)
	}
}

func TestObservedFromRoutes(t *testing.T) {
	at := t0.Add(time.Hour)
	routes := []store.Route{
		{Key: "docker:a", Source: "docker", Zone: "example.test", Hostname: "a.example.test", Scheme: "https",
			Host: "198.51.100.5", Port: 8443, SkipVerify: true, Websockets: true, Middlewares: []string{"m"}, RemovedAfter: &at},
		{Key: "static:b", Source: "static", Zone: "example.test", Hostname: "b.example.test", Scheme: "http",
			Host: "198.51.100.6", Port: 80},
	}
	known, lk := ObservedFromRoutes(routes)
	wantK := map[string]KnownService{
		"docker:a": {Key: "docker:a", Source: "docker", Zone: "example.test", Hostname: "a.example.test", RemovedAfter: &at},
		"static:b": {Key: "static:b", Source: "static", Zone: "example.test", Hostname: "b.example.test"},
	}
	wantLK := map[string]model.Backend{
		"docker:a": {Scheme: "https", Host: "198.51.100.5", Port: 8443, SkipVerify: true},
		"static:b": {Scheme: "http", Host: "198.51.100.6", Port: 80},
	}
	if !reflect.DeepEqual(known, wantK) || !reflect.DeepEqual(lk, wantLK) {
		t.Fatalf("known %+v\nlk %+v", known, lk)
	}
	// the returned RemovedAfter is a copy
	*known["docker:a"].RemovedAfter = t0
	if !routes[0].RemovedAfter.Equal(at) {
		t.Fatal("RemovedAfter aliased")
	}
	if k, l := ObservedFromRoutes(nil); k == nil || l == nil || len(k)+len(l) != 0 {
		t.Fatal("want empty non-nil maps")
	}
}

// --- end to end: Plan + MultiExecutor + RouteExecutor over a real store ---

type e2e struct {
	t   *testing.T
	st  *store.Store
	cfg *config.Config
	now time.Time
	ex  *MultiExecutor
	// winners is Plan's hostname winners of the last cycle.
	winners map[string]claimant
	// quarantined is Observed.Quarantined for every cycle.
	quarantined map[string]bool
	// crashWindow disables the one-row-per-hostname check at the end of a
	// cycle (for tests that deliberately leave a crash-window or source
	// outage state); the renderer-agrees-with-Plan check still runs.
	crashWindow bool
}

func newE2E(t *testing.T) *e2e {
	e := &e2e{t: t, st: openStore(t), now: t0,
		// no records mode and no issuer: only route actions are planned
		cfg: &config.Config{Zones: []config.Zone{{Name: "example.test", TargetIP: target}},
			Settings:    config.Settings{GracePeriod: 24 * time.Hour},
			Middlewares: e2eMiddlewares()}}
	re := NewRouteExecutor(e.st, func() time.Time { return e.now })
	e.ex = NewMultiExecutor(nil).Handle(RouteWrite, re).Handle(RouteRemove, re).
		Handle(ScheduleRemoval, re).Handle(CancelRemoval, re)
	return e
}

// e2eMiddlewares defines the middlewares the E2E services reference (Plan
// fails services with undefined middlewares closed).
func e2eMiddlewares() map[string]map[string]any {
	return map[string]map[string]any{
		"auth": {"forwardAuth": map[string]any{"address": "http://192.0.2.50:9091/verify"}},
		"gzip": {"compress": map[string]any{}},
	}
}

// cycle runs one reconcile at e.now with Observed built from the store.
func (e *e2e) cycle(desired []model.Service, unavailable ...string) []Action {
	e.t.Helper()
	known, lk := ObservedFromRoutes(listRoutes(e.t, e.st))
	un := map[string]bool{}
	for _, u := range unavailable {
		un[u] = true
	}
	obs := Observed{Known: known, LastKnown: lk, Unavailable: un, Quarantined: e.quarantined}
	acts, winners := planWithWinners(desired, obs, e.cfg, e.now)
	if !reflect.DeepEqual(acts, Plan(desired, obs, e.cfg, e.now)) {
		e.t.Fatal("planWithWinners differs from Plan")
	}
	e.winners = winners
	if err := e.ex.Apply(context.Background(), acts, false); err != nil {
		e.t.Fatalf("apply: %v (actions %v)", err, sums(acts))
	}
	assertRendererAgrees(e.t, e)
	return acts
}

func (e *e2e) route(key string) (store.Route, bool) {
	e.t.Helper()
	r, ok, err := e.st.GetRoute(context.Background(), key)
	if err != nil {
		e.t.Fatal(err)
	}
	return r, ok
}

func (e *e2e) mustRoute(key string) store.Route {
	e.t.Helper()
	r, ok := e.route(key)
	if !ok {
		e.t.Fatalf("route %s missing", key)
	}
	return r
}

func TestE2ERouteLifecycle(t *testing.T) {
	e := newE2E(t)
	app := pub("docker:app", "app", "example.test", 8080)

	// publish -> persisted
	e.cycle([]model.Service{app})
	r := e.mustRoute("docker:app")
	if r.Hostname != "app.example.test" || r.Host != "198.51.100.5" || r.Port != 8080 || r.Source != "docker" {
		t.Fatalf("published route %+v", r)
	}
	before := listRoutes(t, e.st)

	// docker unavailable (nothing listed): routes untouched
	e.now = t0.Add(time.Hour)
	acts := e.cycle(nil, "docker")
	assertNone(t, acts, RouteRemove, ScheduleRemoval, RouteWrite)
	if after := listRoutes(t, e.st); !reflect.DeepEqual(after, before) {
		t.Fatalf("outage changed routes\n%+v\n%+v", before, after)
	}

	// stopped (no backend): route kept with its last-known backend
	e.now = t0.Add(2 * time.Hour)
	stopped := svc("docker:app", "app", "example.test", model.StateStopped, "", 0)
	e.cycle([]model.Service{stopped})
	if r := e.mustRoute("docker:app"); r.Host != "198.51.100.5" || r.Port != 8080 || r.RemovedAfter != nil {
		t.Fatalf("stopped changed route: %+v", r)
	}

	// restarted on a new port: backend updated
	e.now = t0.Add(3 * time.Hour)
	e.cycle([]model.Service{pub("docker:app", "app", "example.test", 9090)})
	if r := e.mustRoute("docker:app"); r.Port != 9090 || !r.UpdatedAt.Equal(e.now) {
		t.Fatalf("restart not applied: %+v", r)
	}

	// removed from docker: removal scheduled, route kept
	removedAt := t0.Add(4 * time.Hour)
	e.now = removedAt
	acts = e.cycle(nil)
	if len(ofKind(acts, ScheduleRemoval)) != 1 {
		t.Fatalf("want ScheduleRemoval, got %v", sums(acts))
	}
	deadline := removedAt.Add(24 * time.Hour)
	if r := e.mustRoute("docker:app"); r.RemovedAfter == nil || !r.RemovedAfter.Equal(deadline) || r.Port != 9090 {
		t.Fatalf("schedule not persisted: %+v", r)
	}

	// within grace (and exactly at the deadline): nothing removed
	for _, at := range []time.Time{removedAt.Add(12 * time.Hour), deadline} {
		e.now = at
		acts = e.cycle(nil)
		assertNone(t, acts, RouteRemove, ScheduleRemoval)
		e.mustRoute("docker:app")
	}

	// past grace but docker unavailable: still not removed
	e.now = deadline.Add(time.Second)
	acts = e.cycle(nil, "docker")
	assertNone(t, acts, RouteRemove)
	e.mustRoute("docker:app")

	// past grace with docker available: RouteRemove deletes the row
	acts = e.cycle(nil)
	if len(ofKind(acts, RouteRemove)) != 1 {
		t.Fatalf("want RouteRemove, got %v", sums(acts))
	}
	if _, ok := e.route("docker:app"); ok {
		t.Fatal("route not deleted after grace")
	}
	// forgotten: nothing further planned
	e.now = deadline.Add(time.Hour)
	if acts = e.cycle(nil); len(acts) != 0 {
		t.Fatalf("after removal: %v", sums(acts))
	}
}

func TestE2EReappearanceCancelsRemoval(t *testing.T) {
	e := newE2E(t)
	app := pub("docker:app", "app", "example.test", 8080)
	e.cycle([]model.Service{app})
	e.now = t0.Add(time.Hour)
	e.cycle(nil)
	if r := e.mustRoute("docker:app"); r.RemovedAfter == nil {
		t.Fatal("not scheduled")
	}
	e.now = t0.Add(2 * time.Hour)
	acts := e.cycle([]model.Service{app})
	if len(ofKind(acts, CancelRemoval)) != 1 {
		t.Fatalf("want CancelRemoval, got %v", sums(acts))
	}
	if r := e.mustRoute("docker:app"); r.RemovedAfter != nil || r.Port != 8080 {
		t.Fatalf("not cancelled: %+v", r)
	}
	// long after the old deadline the route is still there
	e.now = t0.Add(72 * time.Hour)
	acts = e.cycle([]model.Service{app})
	assertNone(t, acts, RouteRemove, ScheduleRemoval, CancelRemoval)
	e.mustRoute("docker:app")
}

func TestE2EStoppedWithoutPriorRouteSkips(t *testing.T) {
	// A Stopped service that never had a route gets nothing persisted.
	e := newE2E(t)
	e.cycle([]model.Service{svc("docker:app", "app", "example.test", model.StateStopped, "", 0)})
	if got := listRoutes(t, e.st); len(got) != 0 {
		t.Fatalf("stopped service routed: %+v", got)
	}
}

func TestE2EHostnameConflictRemovesLoserRoute(t *testing.T) {
	e := newE2E(t)
	dock := pub("docker:app", "app", "example.test", 8080)
	e.cycle([]model.Service{dock})
	e.mustRoute("docker:app")

	// a static entry claims the same hostname and is routable: it wins
	e.now = t0.Add(time.Hour)
	stat := pub("static:app", "app", "example.test", 9000)
	stat.Backend.Host = "198.51.100.9"
	acts := e.cycle([]model.Service{dock, stat})
	if rr := ofKind(acts, RouteRemove); len(rr) != 1 || rr[0].Key != "docker:app" {
		t.Fatalf("want RouteRemove docker:app, got %v", sums(acts))
	}
	if _, ok := e.route("docker:app"); ok {
		t.Fatal("loser route not deleted")
	}
	if r := e.mustRoute("static:app"); r.Hostname != "app.example.test" || r.Host != "198.51.100.9" {
		t.Fatalf("winner route %+v", r)
	}

	// the loser is forgotten: next cycle it only gets a Conflict
	e.now = t0.Add(2 * time.Hour)
	acts = e.cycle([]model.Service{dock, stat})
	if got := sums(forKey(acts, "docker:app")); len(got) != 1 || !strings.HasPrefix(got[0], "Conflict ") {
		t.Fatalf("loser actions %v", got)
	}
	if got := listRoutes(t, e.st); len(got) != 1 || got[0].Key != "static:app" {
		t.Fatalf("routes %+v", got)
	}
}

func TestRouteExecutorSurfacesStoreErrors(t *testing.T) {
	boom := errors.New("boom")
	fs := failingStore{err: boom}
	ex := NewRouteExecutor(fs, fixedNow(t0))
	at := t0
	s := pub("docker:a", "a", "example.test", 80)
	for _, a := range []Action{routeWrite(s, "example.test", "a.example.test", &s.Backend),
		{Kind: RouteRemove, Key: "docker:a"}, {Kind: ScheduleRemoval, Key: "docker:a", RemovedAfter: &at},
		{Kind: CancelRemoval, Key: "docker:a"}} {
		if err := ex.Apply(context.Background(), []Action{a}, false); !errors.Is(err, boom) {
			t.Errorf("%s: got %v", a.Kind, err)
		}
	}
}

type failingStore struct{ err error }

func (f failingStore) UpsertRoute(context.Context, store.Route) error            { return f.err }
func (f failingStore) DeleteRoute(context.Context, string) error                 { return f.err }
func (f failingStore) SetRouteRemoval(context.Context, string, *time.Time) error { return f.err }
func (f failingStore) ListRoutes(context.Context) ([]store.Route, error)         { return nil, f.err }
func (f failingStore) QuarantineRoute(context.Context, string) error             { return f.err }
func (f failingStore) DeleteRouteIfDue(context.Context, string, time.Time) (bool, error) {
	return false, f.err
}

func TestE2ENonPublishedNeverRewritesRoute(t *testing.T) {
	e := newE2E(t)
	app := pub("docker:app", "app", "example.test", 8080)
	app.Options = model.Options{Middlewares: []string{"auth@file"}, Websockets: true}
	e.cycle([]model.Service{app})
	want := e.mustRoute("docker:app")
	if !reflect.DeepEqual(want.Middlewares, []string{"auth@file"}) {
		t.Fatalf("published route %+v", want)
	}

	// stopped, labels dropped the middleware and websockets
	e.now = t0.Add(time.Hour)
	stopped := svc("docker:app", "app", "example.test", model.StateStopped, "", 0)
	acts := e.cycle([]model.Service{stopped})
	if len(ofKind(acts, RouteWrite)) != 1 {
		t.Fatalf("plan should still emit RouteWrite for stopped: %v", sums(acts))
	}
	if got := e.mustRoute("docker:app"); !reflect.DeepEqual(got, want) {
		t.Fatalf("stopped rewrote route\n got %+v\nwant %+v", got, want)
	}

	// stopped with a renamed name label: hostname unchanged
	e.now = t0.Add(2 * time.Hour)
	renamed := svc("docker:app", "renamed", "example.test", model.StateStopped, "", 0)
	e.cycle([]model.Service{renamed})
	if got := e.mustRoute("docker:app"); !reflect.DeepEqual(got, want) {
		t.Fatalf("renamed stopped rewrote route: %+v", got)
	}

	// error state (bad scheme label; options not parsed): unchanged
	e.now = t0.Add(3 * time.Hour)
	errd := svc("docker:app", "app", "example.test", model.StateError, "", 0)
	errd.Backend.Scheme = "http"
	e.cycle([]model.Service{errd})
	if got := e.mustRoute("docker:app"); !reflect.DeepEqual(got, want) {
		t.Fatalf("error state rewrote route: %+v", got)
	}

	// back to Published with a changed middleware set: only now it changes
	e.now = t0.Add(4 * time.Hour)
	app2 := pub("docker:app", "app", "example.test", 8080)
	app2.Options = model.Options{Middlewares: []string{"auth@file", "gzip@file"}}
	e.cycle([]model.Service{app2})
	got := e.mustRoute("docker:app")
	if !reflect.DeepEqual(got.Middlewares, []string{"auth@file", "gzip@file"}) || got.Websockets || !got.UpdatedAt.Equal(e.now) {
		t.Fatalf("published change not applied: %+v", got)
	}
}

func TestE2EInvalidBackendWinnerDoesNotEvictLoser(t *testing.T) {
	for name, mut := range map[string]func(*model.Backend){
		"h2c scheme": func(b *model.Backend) { b.Scheme = "h2c" },
		"port 70000": func(b *model.Backend) { b.Port = 70000 },
		"host:port":  func(b *model.Backend) { b.Host = "198.51.100.9:80" },
	} {
		t.Run(name, func(t *testing.T) {
			e := newE2E(t)
			dock := pub("docker:app", "app", "example.test", 8080)
			e.cycle([]model.Service{dock})
			before := e.mustRoute("docker:app")

			e.now = t0.Add(time.Hour)
			stat := pub("static:app", "app", "example.test", 9000)
			mut(&stat.Backend)
			acts := e.cycle([]model.Service{dock, stat})
			assertNone(t, acts, RouteRemove)
			if inv := ofKind(forKey(acts, "static:app"), Invalid); len(inv) != 1 {
				t.Fatalf("want static:app Invalid, got %v", sums(acts))
			}
			if rw := ofKind(acts, RouteWrite); len(rw) != 0 {
				t.Fatalf("unexpected RouteWrite %v", sums(rw))
			}
			if got := e.mustRoute("docker:app"); !reflect.DeepEqual(got, before) {
				t.Fatalf("loser route changed: %+v", got)
			}
			if _, ok := e.route("static:app"); ok {
				t.Fatal("invalid winner persisted")
			}
		})
	}
}
