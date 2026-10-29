package reconcile

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
)

// renderWinners applies the Traefik renderer's own pick (traefik.ByHostname)
// to persisted rows: one router per hostname, by model.SourceRank then key. It also returns
// how many rows share each hostname.
func renderWinners(routes []store.Route) (winner map[string]string, count map[string]int) {
	winner, count = map[string]string{}, map[string]int{}
	// the renderer's own grouping and pick (rank, then smaller key)
	for h, rs := range traefik.ByHostname(routes) {
		winner[h], count[h] = rs[0].Key, len(rs)
	}
	return winner, count
}

// assertRendererAgrees checks, after a cycle was applied, that every
// hostname has exactly one row and that, for EVERY hostname Plan resolved,
// the renderer's pick equals Plan's winner whenever the winner has a
// persisted row at that hostname. e.cycle calls it after every cycle unless
// e.crashWindow is set.
func assertRendererAgrees(t *testing.T, e *e2e) {
	t.Helper()
	rows := listRoutes(t, e.st)
	w, n := renderWinners(rows)
	for h, c := range n {
		if c != 1 && !e.crashWindow {
			t.Fatalf("hostname %s has %d rows: %+v", h, c, rows)
		}
	}
	byKey := map[string]store.Route{}
	for _, r := range rows {
		byKey[r.Key] = r
	}
	for h, pw := range e.winners {
		if r, ok := byKey[pw.key]; ok && r.Hostname == h && w[h] != pw.key {
			t.Fatalf("plan winner for %s is %s, renderer picks %q", h, pw.key, w[h])
		}
	}
}

func TestE2EErroredKnownServiceKeepsHostnameClaim(t *testing.T) {
	for _, state := range []string{model.StateError, model.StatePending, model.StateStopped} {
		t.Run(state, func(t *testing.T) {
			e := newE2E(t)
			st := pub("static:app", "app", "example.test", 8080)
			st.Options.Middlewares = []string{"auth@file"}
			e.cycle([]model.Service{st})
			before := e.mustRoute("static:app")

			e.now = t0.Add(time.Hour)
			bad := svc("static:app", "foo", "example.test", state, "", 0) // name label changed
			if state == model.StatePending {
				bad.Backend = st.Backend
			}
			newcomer := pub("docker:new", "app", "example.test", 9090)
			acts := e.cycle([]model.Service{bad, newcomer})
			if c := ofKind(forKey(acts, "docker:new"), Conflict); len(c) != 1 || !strings.Contains(c[0].Reason, "static:app") {
				t.Fatalf("want Conflict for docker:new naming static:app, got %v", sums(acts))
			}
			if rw := ofKind(forKey(acts, "docker:new"), RouteWrite); len(rw) != 0 {
				t.Fatalf("docker:new routed: %v", sums(rw))
			}
			assertNone(t, acts, RouteRemove)
			if got := e.mustRoute("static:app"); !reflect.DeepEqual(got, before) {
				t.Fatalf("row changed: %+v", got)
			}
			if _, ok := e.route("docker:new"); ok {
				t.Fatal("docker:new persisted")
			}
		})
	}
}

func TestE2EInvalidLabelKnownServiceKeepsClaim(t *testing.T) {
	// A stopped Known service whose current name label is unusable still
	// claims the hostname it serves.
	e := newE2E(t)
	e.cycle([]model.Service{pub("static:app", "app", "example.test", 8080)})
	e.now = t0.Add(time.Hour)
	bad := svc("static:app", "!!!", "example.test", model.StateStopped, "", 0)
	acts := e.cycle([]model.Service{bad, pub("docker:new", "app", "example.test", 9090)})
	if c := ofKind(forKey(acts, "docker:new"), Conflict); len(c) != 1 {
		t.Fatalf("want Conflict for docker:new, got %v", sums(acts))
	}
	if sk := ofKind(forKey(acts, "static:app"), Skip); len(sk) != 1 || !strings.Contains(sk[0].Reason, "app.example.test") {
		t.Fatalf("want a Skip reporting the label problem, got %v", sums(acts))
	}
}

func TestE2ESameSourceStoppedKnownVsPublishedNewcomer(t *testing.T) {
	// Final-review H1: whichever key is smaller, the stopped incumbent keeps
	// its hostname (its persisted route serves it); the Published newcomer is
	// a Conflict, nothing is removed, one row remains.
	for _, keys := range [][2]string{{"docker:a_old", "docker:b_new"}, {"docker:z_old", "docker:b_new"}} {
		t.Run(keys[0], func(t *testing.T) {
			e := newE2E(t)
			oldK, newK := keys[0], keys[1]
			e.cycle([]model.Service{pub(oldK, "app", "example.test", 8080)})
			e.now = t0.Add(time.Hour)
			stopped := svc(oldK, "other", "example.test", model.StateStopped, "", 0) // label renamed
			acts := e.cycle([]model.Service{stopped, pub(newK, "app", "example.test", 9090)})
			assertSums(t, forKey(acts, newK), "Conflict example.test app.example.test "+newK)
			assertNone(t, acts, RouteRemove)
			rs := listRoutes(t, e.st)
			if len(rs) != 1 || rs[0].Key != oldK || rs[0].Hostname != "app.example.test" {
				t.Fatalf("rows %+v", rs)
			}
		})
	}
}

func TestE2EStoppedThenPublishedAtNewHostnameMovesRoute(t *testing.T) {
	e := newE2E(t)
	e.cycle([]model.Service{pub("docker:app", "app", "example.test", 8080)})
	e.now = t0.Add(time.Hour)
	acts := e.cycle([]model.Service{svc("docker:app", "renamed", "example.test", model.StateStopped, "", 0)})
	if rw := ofKind(acts, RouteWrite); len(rw) != 1 || rw[0].Host != "app.example.test" ||
		!strings.Contains(rw[0].Reason, "persisted route unchanged") {
		t.Fatalf("stopped RouteWrite should name the stored hostname: %v %q", sums(acts), rw[0].Reason)
	}
	if r := e.mustRoute("docker:app"); r.Hostname != "app.example.test" {
		t.Fatalf("stopped moved route: %+v", r)
	}
	e.now = t0.Add(2 * time.Hour)
	acts = e.cycle([]model.Service{pub("docker:app", "renamed", "example.test", 8080)})
	rs := listRoutes(t, e.st)
	if len(rs) != 1 || rs[0].Hostname != "renamed.example.test" {
		t.Fatalf("route did not move: %+v", rs)
	}
}

func TestPlanNonPublishedKnownUsesKnownZoneForZonePlanning(t *testing.T) {
	cfg := &config.Config{Zones: []config.Zone{
		{Name: "a.test", TargetIP: target, Records: config.Records{Provider: "dnsp", Mode: "wildcard"}},
		{Name: "b.test", TargetIP: target, Records: config.Records{Provider: "dnsp", Mode: "wildcard"}},
	}}
	s := svc("docker:app", "app", "b.test", model.StateStopped, "", 0) // labels moved it to b.test
	obs := Observed{Foreign: listed("a.test", "b.test"),
		Known:     knownMap(known("docker:app", "a.test", "app.a.test", nil)),
		LastKnown: map[string]model.Backend{"docker:app": {Scheme: "http", Host: "198.51.100.5", Port: 80}}}
	got := Plan([]model.Service{s}, obs, cfg, t0)
	if d := ofKind(got, DNSEnsure); len(d) != 1 || d[0].Zone != "a.test" {
		t.Fatalf("want wildcard DNSEnsure for a.test only, got %v", sums(got))
	}
	if rw := ofKind(got, RouteWrite); len(rw) != 1 || rw[0].Host != "app.a.test" || rw[0].Zone != "a.test" {
		t.Fatalf("got %v", sums(got))
	}
}

func TestPlanPublishedInvalidBackendFallbackIsVisible(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", "wildcard"))
	lk := map[string]model.Backend{"docker:a": {Scheme: "http", Host: "198.51.100.5", Port: 4242}}
	s := pub("docker:a", "a", "example.test", 8080)
	s.Backend.Scheme = "h2c"
	got := Plan([]model.Service{s}, Observed{LastKnown: lk}, cfg, t0)
	rw := ofKind(got, RouteWrite)
	if len(rw) != 1 || rw[0].Backend.Port != 4242 ||
		!strings.Contains(rw[0].Reason, "current backend invalid (") || !strings.Contains(rw[0].Reason, "h2c") ||
		!strings.HasSuffix(rw[0].Reason, "; using last-known backend") {
		t.Fatalf("RouteWrite %v reason %q", sums(rw), func() string {
			if len(rw) > 0 {
				return rw[0].Reason
			}
			return ""
		}())
	}
	sk := ofKind(got, Skip)
	if len(sk) != 1 || sk[0].Key != "docker:a" || sk[0].Reason != rw[0].Reason {
		t.Fatalf("want visibility Skip, got %v", sums(got))
	}
	// a valid current backend: no Skip, no reason
	s.Backend.Scheme = "http"
	got = Plan([]model.Service{s}, Observed{LastKnown: lk}, cfg, t0)
	if len(ofKind(got, Skip)) != 0 || ofKind(got, RouteWrite)[0].Reason != "" {
		t.Fatalf("valid backend: %v", sums(got))
	}
}

// --- fix round 3: Published holders with invalid labels -----------------

// Final-review H1: a Published holder with invalid labels is the incumbent
// of its persisted hostname, so a same-rank routable newcomer does not take
// it: the holder stays Invalid (its route as last written), the newcomer is
// a Conflict, nothing is removed.
func TestE2EPublishedInvalidLabelHolderKeepsHostnameAgainstSameRankNewcomer(t *testing.T) {
	for name, mut := range map[string]func(*model.Service){
		"name !!!":       func(s *model.Service) { s.Name = "!!!" },
		"zone gone.test": func(s *model.Service) { s.Zone = "gone.test" },
	} {
		t.Run(name, func(t *testing.T) {
			e := newE2E(t)
			e.cycle([]model.Service{pub("docker:app", "app", "example.test", 8080)})
			before := e.mustRoute("docker:app")
			e.now = t0.Add(time.Hour)
			holder := pub("docker:app", "app", "example.test", 8080)
			mut(&holder)
			newcomer := pub("docker:new", "app", "example.test", 9090)
			for i := 0; i < 2; i++ {
				acts := e.cycle([]model.Service{holder, newcomer})
				got := sums(forKey(acts, "docker:app"))
				if len(got) != 1 || !strings.HasPrefix(got[0], "Invalid ") {
					t.Fatalf("holder actions %v", got)
				}
				// the newcomer collides on the holder's stored hostname
				assertSums(t, forKey(acts, "docker:new"), "Conflict example.test app.example.test docker:new")
				assertNone(t, acts, RouteRemove, RouteWrite)
				if r := e.mustRoute("docker:app"); !reflect.DeepEqual(r, before) {
					t.Fatalf("holder row changed %+v", r)
				}
				if e.winners["app.example.test"].key != "docker:app" {
					t.Fatalf("plan winner %+v", e.winners["app.example.test"])
				}
				e.now = e.now.Add(time.Hour)
			}
		})
	}
}

func TestE2EHigherRankedInvalidHolderKeepsHostname(t *testing.T) {
	e := newE2E(t)
	e.cycle([]model.Service{pub("static:app", "app", "example.test", 8080)})
	before := e.mustRoute("static:app")
	e.now = t0.Add(time.Hour)
	holder := pub("static:app", "!!!", "example.test", 8080)
	acts := e.cycle([]model.Service{holder, pub("docker:new", "app", "example.test", 9090)})
	if inv := ofKind(forKey(acts, "static:app"), Invalid); len(inv) != 1 {
		t.Fatalf("want Invalid for holder, got %v", sums(acts))
	}
	assertSums(t, forKey(acts, "docker:new"), "Conflict example.test app.example.test docker:new")
	assertNone(t, acts, RouteRemove, RouteWrite)
	if got := e.mustRoute("static:app"); !reflect.DeepEqual(got, before) {
		t.Fatalf("holder row changed %+v", got)
	}
}

func TestPlanPublishedInvalidHolderZoneRemovedFromConfig(t *testing.T) {
	// The holder's Known zone (and label zone) is no longer configured.
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	s := pub("docker:app", "app", "old.test", 8080)
	obs := Observed{Foreign: listed("example.test", "old.test"),
		Owned: []store.DNSRecord{owned("old.test", "app.old.test", "A", target, "docker:app")},
		Known: knownMap(known("docker:app", "old.test", "app.old.test", nil))}
	got := Plan([]model.Service{s}, obs, cfg, t0)
	// Invalid; its row in the unconfigured zone is only reported (Skip)
	if len(got) != 2 || got[0].Kind != Invalid || got[0].Key != "docker:app" || got[1].Kind != Skip {
		t.Fatalf("want only Invalid and Skip, got %v", sums(got))
	}
}

func TestE2EStoppedHolderVsBackendlessPublishedNewcomer(t *testing.T) {
	// Same source: neither is in the serving tier, so the key decides; the
	// newcomer is not routable, so the holder's route is never removed.
	for _, newK := range []string{"docker:a_new", "docker:z_new"} {
		t.Run(newK, func(t *testing.T) {
			e := newE2E(t)
			e.cycle([]model.Service{pub("docker:m_old", "app", "example.test", 8080)})
			before := e.mustRoute("docker:m_old")
			e.now = t0.Add(time.Hour)
			stopped := svc("docker:m_old", "app", "example.test", model.StateStopped, "", 0)
			newcomer := svc(newK, "app", "example.test", model.StatePublished, "", 0)
			acts := e.cycle([]model.Service{stopped, newcomer})
			assertNone(t, acts, RouteRemove)
			if got := e.mustRoute("docker:m_old"); !reflect.DeepEqual(got, before) {
				t.Fatalf("holder row changed %+v", got)
			}
			if rs := listRoutes(t, e.st); len(rs) != 1 {
				t.Fatalf("rows %+v", rs)
			}
		})
	}
}

func TestPlanStoppedRouteWriteInUnconfiguredZoneSaysSo(t *testing.T) {
	cfg := cfgOf(zone("example.test", "off", ""))
	s := svc("docker:app", "app", "example.test", model.StateStopped, "", 0)
	obs := Observed{Known: knownMap(known("docker:app", "old.test", "app.old.test", nil)),
		LastKnown: map[string]model.Backend{"docker:app": {Scheme: "http", Host: "198.51.100.5", Port: 80}}}
	got := Plan([]model.Service{s}, obs, cfg, t0)
	rw := ofKind(got, RouteWrite)
	if len(rw) != 1 || rw[0].Zone != "old.test" || rw[0].Host != "app.old.test" ||
		!strings.Contains(rw[0].Reason, "zone old.test is no longer configured") {
		t.Fatalf("got %v", sums(got))
	}
	assertNone(t, got, DNSEnsure, CertEnsure, RouteRemove)
}

// --- fix round 3: services removed but still within grace ----------------

func TestE2EAbsentHigherRankKeepsRouteAgainstLowerRankNewcomer(t *testing.T) {
	// static:app is absent (e.g. a brief config edit) while docker:new is
	// Published at its hostname: rank is compared first, so docker gets only a
	// Conflict and the static route keeps serving through the grace period.
	// Past the grace period the static route is removed and docker takes the
	// hostname in the same cycle (no dark cycle).
	for _, scheduled := range []bool{false, true} {
		t.Run(map[bool]string{false: "same cycle", true: "after schedule"}[scheduled], func(t *testing.T) {
			e := newE2E(t)
			e.cycle([]model.Service{pub("static:app", "app", "example.test", 8080)})
			before := e.mustRoute("static:app")
			if scheduled {
				e.now = t0.Add(time.Hour)
				e.cycle(nil)
				before = e.mustRoute("static:app")
			}
			dock := pub("docker:new", "app", "example.test", 9090)
			for _, at := range []time.Duration{2 * time.Hour, 20 * time.Hour} {
				e.now = t0.Add(at)
				acts := e.cycle([]model.Service{dock})
				if c := ofKind(forKey(acts, "docker:new"), Conflict); len(c) != 1 ||
					!strings.Contains(c[0].Reason, "static:app") || !strings.Contains(c[0].Reason, "grace period") {
					t.Fatalf("want docker Conflict naming the absent static winner, got %v", sums(acts))
				}
				assertNone(t, acts, RouteWrite, RouteRemove)
				r := e.mustRoute("static:app")
				if r.RemovedAfter == nil {
					t.Fatal("removal not scheduled")
				}
				r.RemovedAfter, before.RemovedAfter = nil, nil
				if !reflect.DeepEqual(r, before) {
					t.Fatalf("static row changed %+v", r)
				}
				if _, ok := e.route("docker:new"); ok {
					t.Fatal("docker routed during grace")
				}
			}
			// past grace: removed, and docker takes the name in the same cycle
			e.now = t0.Add(48 * time.Hour)
			acts := e.cycle([]model.Service{dock})
			assertSums(t, forKey(acts, "static:app"), "RouteRemove example.test app.example.test static:app")
			if rw := ofKind(acts, RouteWrite); len(rw) != 1 || rw[0].Key != "docker:new" {
				t.Fatalf("docker not routed at expiry: %v", sums(acts))
			}
			assertNone(t, acts, Conflict)
			if rs := listRoutes(t, e.st); len(rs) != 1 || rs[0].Key != "docker:new" {
				t.Fatalf("rows %+v", rs)
			}
		})
	}
}

// A higher-rank newcomer takes the hostname of an absent claimant at once;
// a same-rank one (final-review H1) waits for the absent incumbent's grace
// period to end.
func TestE2EAbsentYieldsToHigherRankNewcomerOnly(t *testing.T) {
	for name, keys := range map[string][2]string{
		"same rank":   {"docker:old", "docker:new"},
		"higher rank": {"truenas:app", "static:app"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newE2E(t)
			oldK, newK := keys[0], keys[1]
			e.cycle([]model.Service{pub(oldK, "app", "example.test", 8080)})
			e.now = t0.Add(time.Hour)
			acts := e.cycle([]model.Service{pub(newK, "app", "example.test", 9090)})
			if name == "higher rank" {
				assertSums(t, forKey(acts, oldK), "RouteRemove example.test app.example.test "+oldK)
				assertNone(t, acts, Conflict, ScheduleRemoval, DNSDelete)
				if rs := listRoutes(t, e.st); len(rs) != 1 || rs[0].Key != newK {
					t.Fatalf("rows %+v", rs)
				}
				return
			}
			assertSums(t, acts, "Conflict example.test app.example.test "+newK,
				"ScheduleRemoval example.test app.example.test "+oldK)
			if rs := listRoutes(t, e.st); len(rs) != 1 || rs[0].Key != oldK {
				t.Fatalf("rows %+v", rs)
			}
			e.now = t0.Add(26 * time.Hour)
			acts = e.cycle([]model.Service{pub(newK, "app", "example.test", 9090)})
			assertSums(t, acts, "RouteWrite example.test app.example.test "+newK+" ->198.51.100.5:9090",
				"RouteRemove example.test app.example.test "+oldK)
			if rs := listRoutes(t, e.st); len(rs) != 1 || rs[0].Key != newK {
				t.Fatalf("rows %+v", rs)
			}
		})
	}
}

func TestE2EAbsentInGraceKeepsRouteAgainstNonRoutableNewcomer(t *testing.T) {
	e := newE2E(t)
	e.cycle([]model.Service{pub("docker:old", "app", "example.test", 8080)})
	e.now = t0.Add(time.Hour)
	pending := svc("docker:new", "app", "example.test", model.StatePending, "198.51.100.5", 9090)
	acts := e.cycle([]model.Service{pending})
	assertSums(t, acts, "Conflict example.test app.example.test docker:new",
		"ScheduleRemoval example.test app.example.test docker:old")
	if rs := listRoutes(t, e.st); len(rs) != 1 || rs[0].Key != "docker:old" {
		t.Fatalf("rows %+v", rs)
	}
}

func TestPlanAbsentPastGraceKeepsDNSDeleteForItsOwnHostname(t *testing.T) {
	// the absent service is the only claimant of its hostname; its record was
	// scheduled together with its route, so both go in the same plan
	cfg := cfgOf(zone("example.test", "per-host", "per-host"))
	obs := Observed{Foreign: listed("example.test"),
		Owned: []store.DNSRecord{ownedRA("example.test", "app.example.test", "A", target, "docker:app", tp(t0.Add(-time.Second)))},
		Known: knownMap(known("docker:app", "example.test", "app.example.test", tp(t0.Add(-time.Second))))}
	assertSums(t, Plan(nil, obs, cfg, t0),
		"RouteRemove example.test app.example.test docker:app",
		"DNSDelete example.test app.example.test docker:app [app.example.test A 192.0.2.10]")
}

func TestE2EPhantomAndOutrankingNewcomerShareButAgree(t *testing.T) {
	// docker is down: its route stays (phantom) and a higher-ranked static
	// service takes the hostname. Both rows exist during the outage; the
	// renderer serves Plan's winner. When docker is back the phantom is a
	// present loser and its row is removed: one row again.
	e := newE2E(t)
	dock := pub("docker:app", "app", "example.test", 8080)
	e.cycle([]model.Service{dock})
	e.now = t0.Add(time.Hour)
	e.crashWindow = true
	st := pub("static:app", "app", "example.test", 9000)
	e.cycle([]model.Service{st}, "docker")
	w, n := renderWinners(listRoutes(t, e.st))
	if n["app.example.test"] != 2 || w["app.example.test"] != "static:app" || e.winners["app.example.test"].key != "static:app" {
		t.Fatalf("renderer %v %v plan %v", w, n, e.winners["app.example.test"].key)
	}
	e.crashWindow = false
	e.now = t0.Add(2 * time.Hour)
	acts := e.cycle([]model.Service{st, dock})
	assertSums(t, forKey(acts, "docker:app"), "Conflict example.test app.example.test docker:app",
		"RouteRemove example.test app.example.test docker:app")
}
