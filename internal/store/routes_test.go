package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func sampleRoute(key, host string, port int) Route {
	return Route{Key: key, Source: "docker", Zone: "example.test", Hostname: host,
		Scheme: "http", Host: "198.51.100.5", Port: port, UpdatedAt: t0}
}

func TestRoutesUpsertListGetDelete(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	b := sampleRoute("docker:b", "b.example.test", 8081)
	a := Route{Key: "docker:a", Source: "docker", Zone: "Example.Test.", Hostname: "A.Example.Test.",
		Scheme: "https", Host: "198.51.100.6", Port: 8443, SkipVerify: true, Websockets: true,
		Middlewares: []string{"auth@file", "gzip"}, UpdatedAt: t0}
	for _, r := range []Route{b, a} {
		if err := s.UpsertRoute(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListRoutes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantA := a
	wantA.Zone, wantA.Hostname = "example.test", "a.example.test"
	if want := []Route{wantA, b}; !reflect.DeepEqual(got, want) {
		t.Fatalf("list\n got %+v\nwant %+v", got, want)
	}
	r, ok, err := s.GetRoute(ctx, "docker:a")
	if err != nil || !ok || !reflect.DeepEqual(r, wantA) {
		t.Fatalf("get %+v %v %v", r, ok, err)
	}
	if _, ok, err := s.GetRoute(ctx, "nope"); err != nil || ok {
		t.Fatalf("absent get ok=%v err=%v", ok, err)
	}
	// update in place changes backend and drops middlewares
	a2 := a
	a2.Port, a2.Middlewares, a2.UpdatedAt = 9443, nil, t0.Add(time.Hour)
	if err := s.UpsertRoute(ctx, a2); err != nil {
		t.Fatal(err)
	}
	r, _, _ = s.GetRoute(ctx, "docker:a")
	if r.Port != 9443 || r.Middlewares != nil || !r.UpdatedAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("not updated: %+v", r)
	}
	for i := 0; i < 2; i++ { // idempotent
		if err := s.DeleteRoute(ctx, "docker:a"); err != nil {
			t.Fatal(err)
		}
	}
	got, _ = s.ListRoutes(ctx)
	if len(got) != 1 || got[0].Key != "docker:b" {
		t.Fatalf("after delete: %+v", got)
	}
}

func TestRoutesUpsertPreservesRemovedAfter(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	r := sampleRoute("docker:a", "a.example.test", 80)
	if err := s.UpsertRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(24 * time.Hour)
	if err := s.SetRouteRemoval(ctx, "docker:a", &at); err != nil {
		t.Fatal(err)
	}
	r.Port = 81
	r.RemovedAfter = nil // ignored by UpsertRoute
	if err := s.UpsertRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.GetRoute(ctx, "docker:a")
	if got.Port != 81 || got.RemovedAfter == nil || !got.RemovedAfter.Equal(at) {
		t.Fatalf("removed_after not preserved: %+v", got)
	}
	// RemovedAfter on a fresh insert is ignored too: only SetRouteRemoval sets it.
	n := sampleRoute("docker:n", "n.example.test", 80)
	n.RemovedAfter = &at
	if err := s.UpsertRoute(ctx, n); err != nil {
		t.Fatal(err)
	}
	if g, _, _ := s.GetRoute(ctx, "docker:n"); g.RemovedAfter != nil {
		t.Fatalf("insert set removed_after: %+v", g)
	}
	if err := s.SetRouteRemoval(ctx, "docker:a", nil); err != nil {
		t.Fatal(err)
	}
	if g, _, _ := s.GetRoute(ctx, "docker:a"); g.RemovedAfter != nil {
		t.Fatalf("not cleared: %+v", g)
	}
}

func TestSetRouteRemovalMissingKey(t *testing.T) {
	s, _ := openTemp(t)
	at := t0
	if err := s.SetRouteRemoval(context.Background(), "nope", &at); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("want ErrRouteNotFound, got %v", err)
	}
	if err := s.SetRouteRemoval(context.Background(), "nope", nil); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("want ErrRouteNotFound, got %v", err)
	}
	if got, _ := s.ListRoutes(context.Background()); len(got) != 0 {
		t.Fatalf("created a row: %+v", got)
	}
}

func TestUpsertRouteRejectsInvalid(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	mut := map[string]func(*Route){
		"empty key":      func(r *Route) { r.Key = "" },
		"blank key":      func(r *Route) { r.Key = " " },
		"padded key":     func(r *Route) { r.Key = " docker:a" },
		"padded source":  func(r *Route) { r.Source = "docker " },
		"upper scheme":   func(r *Route) { r.Scheme = "HTTP" },
		"h2c scheme":     func(r *Route) { r.Scheme = "h2c" },
		"host space":     func(r *Route) { r.Host = "a b" },
		"host padded":    func(r *Route) { r.Host = " app" },
		"host newline":   func(r *Route) { r.Host = "app\n" },
		"host slash":     func(r *Route) { r.Host = "app/x" },
		"host at":        func(r *Route) { r.Host = "u@app" },
		"host port":      func(r *Route) { r.Host = "app:8080" },
		"ipv4 port":      func(r *Route) { r.Host = "198.51.100.5:80" },
		"empty source":   func(r *Route) { r.Source = "" },
		"empty zone":     func(r *Route) { r.Zone = "." },
		"empty hostname": func(r *Route) { r.Hostname = "" },
		"bad scheme":     func(r *Route) { r.Scheme = "ftp" },
		"empty scheme":   func(r *Route) { r.Scheme = "" },
		"empty host":     func(r *Route) { r.Host = "  " },
		"port 0":         func(r *Route) { r.Port = 0 },
		"port too big":   func(r *Route) { r.Port = 65536 },
		"negative port":  func(r *Route) { r.Port = -1 },
	}
	for name, m := range mut {
		r := sampleRoute("docker:a", "a.example.test", 80)
		m(&r)
		if err := s.UpsertRoute(ctx, r); !errors.Is(err, ErrInvalidRoute) {
			t.Errorf("%s: want ErrInvalidRoute, got %v for %+v", name, err, r)
		}
	}
	if got, _ := s.ListRoutes(ctx); len(got) != 0 {
		t.Fatalf("invalid routes persisted: %+v", got)
	}
	// an invalid update must not clobber a valid row
	good := sampleRoute("docker:a", "a.example.test", 80)
	if err := s.UpsertRoute(ctx, good); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.Host = ""
	if err := s.UpsertRoute(ctx, bad); err == nil {
		t.Fatal("accepted empty host")
	}
	if g, _, _ := s.GetRoute(ctx, "docker:a"); g.Host != good.Host {
		t.Fatalf("clobbered: %+v", g)
	}
}

func TestRoutesPersistAcrossReopen(t *testing.T) {
	s, p := openTemp(t)
	ctx := context.Background()
	r := sampleRoute("docker:a", "a.example.test", 80)
	r.Middlewares = []string{"m1"}
	if err := s.UpsertRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(time.Hour)
	if err := s.SetRouteRemoval(ctx, "docker:a", &at); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.ListRoutes(ctx)
	r.RemovedAfter = &at
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], r) {
		t.Fatalf("after reopen %+v %v", got, err)
	}
}

func TestRoutesMigrationAppliesOnDBAt0002(t *testing.T) {
	s, p := openTemp(t)
	ctx := context.Background()
	if err := s.SetApproval(ctx, "k", "fp"); err != nil {
		t.Fatal(err)
	}
	// roll the database back to the 0002 state
	if _, err := s.db.Exec(`DROP TABLE routes; DELETE FROM schema_migrations WHERE version IN ('0003_routes.sql', '0005_route_quarantine.sql')`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var n int
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = '0003_routes.sql'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("0003 not recorded: %d %v", n, err)
	}
	if fp, ok, _ := s2.GetApproval(ctx, "k"); !ok || fp != "fp" {
		t.Fatal("0002 data lost")
	}
	if err := s2.UpsertRoute(ctx, sampleRoute("docker:a", "a.example.test", 80)); err != nil {
		t.Fatal(err)
	}
	// hostname index exists and is not unique: two keys may share a hostname
	if err := s2.UpsertRoute(ctx, sampleRoute("static:a", "a.example.test", 81)); err != nil {
		t.Fatalf("shared hostname rejected: %v", err)
	}
	var idx int
	s2.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='routes' AND name='routes_hostname'`).Scan(&idx)
	if idx != 1 {
		t.Fatal("routes_hostname index missing")
	}
}

func TestUpsertRouteHostForms(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	cases := map[string]string{ // input -> stored
		"2001:db8::1":   "2001:db8::1",
		"[2001:db8::1]": "2001:db8::1", // stored unbracketed
		"app":           "app",
		"198.51.100.5":  "198.51.100.5",
	}
	i := 0
	for in, want := range cases {
		i++
		r := sampleRoute("docker:h"+string(rune('a'+i)), "h.example.test", 80)
		r.Host = in
		if err := s.UpsertRoute(ctx, r); err != nil {
			t.Fatalf("%q rejected: %v", in, err)
		}
		g, _, _ := s.GetRoute(ctx, r.Key)
		if g.Host != want {
			t.Errorf("%q stored as %q, want %q", in, g.Host, want)
		}
	}
}

func TestUpsertRouteUnchangedIsNoop(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	r := sampleRoute("docker:a", "a.example.test", 80)
	r.Middlewares = []string{"m"}
	if err := s.UpsertRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	same := r
	same.UpdatedAt = t0.Add(time.Hour)
	same.Hostname = "A.example.test." // normalizes to the same value
	if err := s.UpsertRoute(ctx, same); err != nil {
		t.Fatal(err)
	}
	if g, _, _ := s.GetRoute(ctx, "docker:a"); !g.UpdatedAt.Equal(t0) {
		t.Fatalf("unchanged upsert bumped updated_at: %v", g.UpdatedAt)
	}
	// each field change does write
	changes := map[string]func(*Route){
		"source": func(r *Route) { r.Source = "other" }, "zone": func(r *Route) { r.Zone = "other.test" },
		"hostname": func(r *Route) { r.Hostname = "b.example.test" }, "scheme": func(r *Route) { r.Scheme = "https" },
		"host": func(r *Route) { r.Host = "198.51.100.9" }, "port": func(r *Route) { r.Port = 81 },
		"skip": func(r *Route) { r.SkipVerify = true }, "ws": func(r *Route) { r.Websockets = true },
		"mw": func(r *Route) { r.Middlewares = nil },
	}
	n := 0
	for name, m := range changes {
		n++
		c := r
		m(&c)
		c.UpdatedAt = t0.Add(time.Duration(n) * time.Hour)
		if err := s.UpsertRoute(ctx, c); err != nil {
			t.Fatal(err)
		}
		if g, _, _ := s.GetRoute(ctx, "docker:a"); !g.UpdatedAt.Equal(c.UpdatedAt) {
			t.Errorf("%s change not written: %+v", name, g)
		}
		if err := s.UpsertRoute(ctx, r); err != nil { // restore
			t.Fatal(err)
		}
	}
}

func TestDeleteRouteIfDue(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.UpsertRoute(ctx, sampleRoute("docker:app", "app.example.test", 80)); err != nil {
		t.Fatal(err)
	}
	del := func(now time.Time) bool {
		t.Helper()
		ok, err := s.DeleteRouteIfDue(ctx, "docker:app", now)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if del(t0.Add(1000 * time.Hour)) {
		t.Fatal("unscheduled route deleted")
	}
	at := t0.Add(24 * time.Hour)
	if err := s.SetRouteRemoval(ctx, "docker:app", &at); err != nil {
		t.Fatal(err)
	}
	if del(at) || del(t0) {
		t.Fatal("deleted at or before the deadline")
	}
	if !del(at.Add(time.Second)) {
		t.Fatal("due route not deleted")
	}
	if _, ok, _ := s.GetRoute(ctx, "docker:app"); ok {
		t.Fatal("route still there")
	}
	if del(at.Add(time.Hour)) {
		t.Fatal("deleted twice")
	}
}

// QuarantineRoute marks a route quarantined (kept, not rendered); the next
// UpsertRoute (a Published RouteWrite) clears it, even with the same content.
func TestQuarantineRoute(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.QuarantineRoute(ctx, "docker:a"); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("absent: %v", err)
	}
	r := sampleRoute("docker:a", "a.example.test", 80)
	if err := s.UpsertRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.QuarantineRoute(ctx, "docker:a"); err != nil {
		t.Fatal(err)
	}
	if got, ok, _ := s.GetRoute(ctx, "docker:a"); !ok || !got.Quarantined || got.Port != 80 {
		t.Fatalf("%+v %v", got, ok)
	}
	if err := s.UpsertRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.GetRoute(ctx, "docker:a"); got.Quarantined {
		t.Fatal("upsert kept the quarantine")
	}
}
