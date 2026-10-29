package reconcile

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
	"gopkg.in/yaml.v3"
)

// servedByRenderer renders the persisted rows with the config's middlewares
// and returns hostname -> key of the router serving it.
func servedByRenderer(t *testing.T, e *e2e) map[string]string {
	t.Helper()
	rows := listRoutes(t, e.st)
	f, _, err := traefik.Render(rows, traefik.MiddlewareDefs(e.cfg.MiddlewareDefs()), nil,
		traefik.Options{ExternalMiddlewares: e.cfg.Traefik.ExternalMiddlewares})
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		HTTP struct {
			Routers map[string]struct {
				Rule string `yaml:"rule"`
			} `yaml:"routers"`
		} `yaml:"http"`
	}
	if err := yaml.Unmarshal(f[traefik.RoutesFile], &d); err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, r := range rows {
		byName[traefik.Name(r.Key)] = r.Key
	}
	out := map[string]string{}
	for n, r := range d.HTTP.Routers {
		out[strings.TrimSuffix(strings.TrimPrefix(r.Rule, "Host(`"), "`)")] = byName[n]
	}
	return out
}

func withMW(s model.Service, mws ...string) model.Service {
	s.Options.Middlewares = mws
	return s
}

// A higher-ranked (or same-rank smaller-key) newcomer whose middleware is
// undefined is Invalid and never evicts the working incumbent.
func TestE2EUndefinedMiddlewareNewcomerNeverEvicts(t *testing.T) {
	for _, nk := range []string{"static:app", "truenas:app", "docker:a"} {
		for _, ref := range []string{"nope@file", "nope", "authh@file", "auth@docker", "a b"} {
			t.Run(nk+"/"+ref, func(t *testing.T) {
				e := newE2E(t)
				inc := withMW(pub("docker:b", "app", "example.test", 8080), "auth@file")
				e.cycle([]model.Service{inc})
				before := e.mustRoute("docker:b")

				e.now = t0.Add(time.Hour)
				nc := withMW(pub(nk, "app", "example.test", 9090), ref)
				acts := e.cycle([]model.Service{inc, nc})
				inv := ofKind(forKey(acts, nk), Invalid)
				if len(inv) != 1 || !strings.Contains(inv[0].Reason, "fail closed") || !strings.Contains(inv[0].Reason, ref) {
					t.Fatalf("newcomer actions %v", sums(forKey(acts, nk)))
				}
				if got := forKey(acts, nk); len(got) != 1 {
					t.Fatalf("newcomer got more than Invalid: %v", sums(got))
				}
				assertNone(t, acts, RouteRemove, Conflict)
				if after := e.mustRoute("docker:b"); !reflect.DeepEqual(after, before) {
					t.Fatalf("incumbent row changed: %+v", after)
				}
				if _, ok := e.route(nk); ok {
					t.Fatal("newcomer row written")
				}
				if got := servedByRenderer(t, e); !reflect.DeepEqual(got, map[string]string{"app.example.test": "docker:b"}) {
					t.Fatalf("served %v", got)
				}
			})
		}
	}
}

// Defined (bare or @file), chain and allowlisted external middlewares are
// routable.
func TestPlanDefinedAndExternalMiddlewaresRoutable(t *testing.T) {
	e := newE2E(t)
	e.cfg.Traefik.ExternalMiddlewares = []string{"crowdsec@docker"}
	e.cfg.Middlewares["both"] = map[string]any{"chain": map[string]any{"middlewares": []any{"auth", "gzip@file"}}}
	s := withMW(pub("static:app", "app", "example.test", 80), "auth", "gzip@file", "crowdsec@docker", "both@file")
	acts := e.cycle([]model.Service{s})
	if len(ofKind(acts, RouteWrite)) != 1 || len(ofKind(acts, Invalid)) != 0 {
		t.Fatalf("actions %v", sums(acts))
	}
	if got := servedByRenderer(t, e); got["app.example.test"] != "static:app" {
		t.Fatalf("served %v", got)
	}
}

// A middleware whose definition is itself invalid (chain to an undefined
// member) counts as undefined.
func TestPlanInvalidDefinitionCountsAsUndefined(t *testing.T) {
	e := newE2E(t)
	e.cfg.Middlewares["bad"] = map[string]any{"chain": map[string]any{"middlewares": []any{"nope"}}}
	acts := e.cycle([]model.Service{withMW(pub("static:app", "app", "example.test", 80), "bad@file")})
	if len(ofKind(acts, Invalid)) != 1 || len(ofKind(acts, RouteWrite)) != 0 {
		t.Fatalf("actions %v", sums(acts))
	}
}

// A served service whose labels switch to a typo'd middleware keeps its
// persisted route as last written (with its old, defined middleware): it is
// still served WITH its auth, holds its hostname as an Invalid holder, and
// a lower-ranked newcomer only gets a Conflict.
func TestE2ETypoMiddlewareKeepsLastWrittenRoute(t *testing.T) {
	e := newE2E(t)
	app := withMW(pub("static:app", "app", "example.test", 80), "auth@file")
	e.cycle([]model.Service{app})
	before := e.mustRoute("static:app")

	e.now = t0.Add(time.Hour)
	typo := withMW(pub("static:app", "app", "example.test", 81), "atuh@file")
	newcomer := pub("docker:new", "app", "example.test", 9090)
	acts := e.cycle([]model.Service{typo, newcomer})
	if len(ofKind(forKey(acts, "static:app"), Invalid)) != 1 || len(ofKind(forKey(acts, "docker:new"), Conflict)) != 1 {
		t.Fatalf("actions %v", sums(acts))
	}
	assertNone(t, acts, RouteRemove, RouteWrite)
	if after := e.mustRoute("static:app"); !reflect.DeepEqual(after, before) {
		t.Fatalf("row changed: %+v", after)
	}
	if got := servedByRenderer(t, e); !reflect.DeepEqual(got, map[string]string{"app.example.test": "static:app"}) {
		t.Fatalf("served %v", got)
	}
}

// When the DEFINITION a persisted route uses is removed from the config,
// Plan makes the service Invalid (held) and the renderer stops serving it:
// the hostname goes dark rather than serve without auth, and a lower-ranked
// newcomer does not take it.
func TestE2ERemovedDefinitionGoesDark(t *testing.T) {
	e := newE2E(t)
	app := withMW(pub("static:app", "app", "example.test", 80), "auth@file")
	e.cycle([]model.Service{app})

	e.now = t0.Add(time.Hour)
	delete(e.cfg.Middlewares, "auth")
	newcomer := pub("docker:new", "app", "example.test", 9090)
	acts := e.cycle([]model.Service{app, newcomer})
	if len(ofKind(forKey(acts, "static:app"), Invalid)) != 1 || len(ofKind(forKey(acts, "docker:new"), Conflict)) != 1 {
		t.Fatalf("actions %v", sums(acts))
	}
	assertNone(t, acts, RouteRemove, RouteWrite)
	if rows := listRoutes(t, e.st); len(rows) != 1 || rows[0].Key != "static:app" {
		t.Fatalf("rows %+v", rows)
	}
	if got := servedByRenderer(t, e); len(got) != 0 {
		t.Fatalf("served %v", got)
	}
}

// Rows written outside Plan are still guarded by the renderer (defence in
// depth): a persisted undefined middleware is not served.
func TestRendererStillFailsClosedOnPersistedRow(t *testing.T) {
	e := newE2E(t)
	if err := e.st.UpsertRoute(t.Context(), store.Route{Key: "static:x", Source: "static", Zone: "example.test",
		Hostname: "x.example.test", Scheme: "http", Host: "198.51.100.5", Port: 80, Middlewares: []string{"nope"}}); err != nil {
		t.Fatal(err)
	}
	if got := servedByRenderer(t, e); len(got) != 0 {
		t.Fatalf("served %v", got)
	}
}

// A chain spelled "Chain"/"CHAIN" with an undefined member, or in a cycle,
// is not a usable definition in Plan either (one shared rule); the same
// chain with resolvable members is.
func TestPlanChainTypeCaseInsensitive(t *testing.T) {
	for name, tc := range map[string]struct {
		defs     map[string]map[string]any
		routable bool
	}{
		"Chain undefined member": {map[string]map[string]any{"c": {"Chain": map[string]any{"Middlewares": []any{"nope"}}}}, false},
		"CHAIN cycle": {map[string]map[string]any{
			"c": {"CHAIN": map[string]any{"middlewares": []any{"d"}}},
			"d": {"chain": map[string]any{"MIDDLEWARES": []any{"c"}}}}, false},
		"Chain resolvable": {map[string]map[string]any{"c": {"Chain": map[string]any{"Middlewares": []any{"auth", "gzip@file"}}}}, true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newE2E(t)
			for n, d := range tc.defs {
				e.cfg.Middlewares[n] = d
			}
			acts := e.cycle([]model.Service{withMW(pub("static:app", "app", "example.test", 80), "c@file")})
			if got := len(ofKind(acts, RouteWrite)) == 1 && len(ofKind(acts, Invalid)) == 0; got != tc.routable {
				t.Fatalf("routable %v, actions %v", got, sums(acts))
			}
			if served := servedByRenderer(t, e)["app.example.test"] == "static:app"; served != tc.routable {
				t.Fatalf("served %v", served)
			}
		})
	}
}

// The unfavourable half of the label-typo trade-off, pinned so it stays a
// conscious choice: labels that ADD a typo'd auth middleware to a route that
// had none leave the old route WITHOUT auth served as last written. In auto
// mode the service is Published and Plan reports only an Invalid action; in
// approve mode the changed fingerprint makes it Pending (Plan: Skip) and it
// waits for review. In both modes the old route is still served.
func TestE2ETypoAddingAuthKeepsOldUnauthenticatedRoute(t *testing.T) {
	for _, state := range []string{model.StatePublished, model.StatePending} {
		t.Run(state, func(t *testing.T) {
			e := newE2E(t)
			e.cycle([]model.Service{pub("static:app", "app", "example.test", 80)})
			before := e.mustRoute("static:app")
			if len(before.Middlewares) != 0 {
				t.Fatalf("setup: %+v", before)
			}

			e.now = t0.Add(time.Hour)
			typo := withMW(pub("static:app", "app", "example.test", 80), "atuh@file")
			typo.State = state
			acts := e.cycle([]model.Service{typo})
			want := Invalid // auto: Published, reported Invalid
			if state == model.StatePending {
				want = Skip // approve: held Pending until a human approves
			}
			if len(acts) != 1 || acts[0].Kind != want {
				t.Fatalf("actions %v", sums(acts))
			}
			if after := e.mustRoute("static:app"); !reflect.DeepEqual(after, before) {
				t.Fatalf("row changed: %+v", after)
			}
			if got := servedByRenderer(t, e); got["app.example.test"] != "static:app" {
				t.Fatalf("served %v", got)
			}
		})
	}
}
