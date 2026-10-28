package reconcile

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

// renderWinners applies the T10b renderer rule to persisted rows: one router
// per hostname, chosen by source rank (key prefix) then key. It also returns
// how many rows share each hostname.
func renderWinners(routes []store.Route) (winner map[string]string, count map[string]int) {
	winner, count = map[string]string{}, map[string]int{}
	byHost := map[string][]store.Route{}
	for _, r := range routes {
		byHost[r.Hostname] = append(byHost[r.Hostname], r)
	}
	for h, rs := range byHost {
		sort.Slice(rs, func(i, j int) bool {
			ri, rj := sourceRank(rs[i].Key, rs[i].Source), sourceRank(rs[j].Key, rs[j].Source)
			if ri != rj {
				return ri < rj
			}
			return rs[i].Key < rs[j].Key
		})
		winner[h], count[h] = rs[0].Key, len(rs)
	}
	return winner, count
}

// assertRendererAgrees checks, after a cycle was applied, that every hostname
// has exactly one row and that the renderer's pick is the service Plan routed
// there (a Published RouteWrite) or, when Plan routed nobody, the row that
// Plan left serving.
func assertRendererAgrees(t *testing.T, e *e2e, acts []Action) {
	t.Helper()
	w, n := renderWinners(listRoutes(t, e.st))
	for h, c := range n {
		if c != 1 {
			t.Fatalf("hostname %s has %d rows: %+v", h, c, listRoutes(t, e.st))
		}
	}
	for _, a := range ofKind(acts, RouteWrite) {
		if a.Svc != nil && a.Svc.State == model.StatePublished && w[a.Host] != a.Key {
			t.Fatalf("plan routed %s to %s, renderer picks %q", a.Host, a.Key, w[a.Host])
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
			assertRendererAgrees(t, e, acts)
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
	assertRendererAgrees(t, e, acts)
}

func TestE2ESameSourceStoppedKnownVsPublishedNewcomer(t *testing.T) {
	// Deterministic whichever key is smaller: the Published newcomer wins
	// (serving tier), the stopped service's row is removed, one row remains.
	for _, keys := range [][2]string{{"docker:a_old", "docker:b_new"}, {"docker:z_old", "docker:b_new"}} {
		t.Run(keys[0], func(t *testing.T) {
			e := newE2E(t)
			oldK, newK := keys[0], keys[1]
			e.cycle([]model.Service{pub(oldK, "app", "example.test", 8080)})
			e.now = t0.Add(time.Hour)
			stopped := svc(oldK, "other", "example.test", model.StateStopped, "", 0) // label renamed
			acts := e.cycle([]model.Service{stopped, pub(newK, "app", "example.test", 9090)})
			assertSums(t, forKey(acts, oldK),
				"Conflict example.test app.example.test "+oldK,
				"RouteRemove example.test app.example.test "+oldK)
			rs := listRoutes(t, e.st)
			if len(rs) != 1 || rs[0].Key != newK || rs[0].Hostname != "app.example.test" {
				t.Fatalf("rows %+v", rs)
			}
			assertRendererAgrees(t, e, acts)
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
	assertRendererAgrees(t, e, acts)
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
