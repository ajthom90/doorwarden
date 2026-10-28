package traefik_test

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
	"gopkg.in/yaml.v3"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden.yml")

var (
	t0   = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	past = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
)

// unrelated files living in Traefik's directory; never touched.
var unrelated = map[string]string{
	"other.yml":              "http:\n  routers: {}\n",
	"doorwarden-foreign.yml": "# written by hand, no doorwarden header\nhttp: {}\n",
	"notes.txt":              "keep me\n",
}

const staleOwned = "doorwarden-legacy.yml"

type composer struct {
	t     *testing.T
	st    *store.Store
	cfg   *config.Config
	ex    *reconcile.MultiExecutor
	now   time.Time
	dir   string
	certs []traefik.TLSCert
	files traefik.Files
	probs []traefik.Problem
}

func newComposer(t *testing.T) *composer {
	st, err := store.Open(filepath.Join(t.TempDir(), "dw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := &composer{t: t, st: st, now: t0, dir: t.TempDir(),
		// one config feeds both Plan (fail-closed middleware check) and Render
		cfg: &config.Config{Zones: []config.Zone{{Name: "example.test", TargetIP: "192.0.2.10"}},
			Settings: config.Settings{GracePeriod: 24 * time.Hour},
			Middlewares: map[string]map[string]any{"auth": {"forwardAuth": map[string]any{
				"address": "http://192.0.2.50:9091/api/verify", "trustForwardHeader": true}}}},
		certs: []traefik.TLSCert{{Domains: []string{"*.example.test", "example.test"},
			CertFile: "example.test/fullchain.pem", KeyFile: "example.test/privkey.pem"}},
	}
	re := reconcile.NewRouteExecutor(st, func() time.Time { return c.now })
	c.ex = reconcile.NewMultiExecutor(nil).Handle(reconcile.RouteWrite, re).Handle(reconcile.RouteRemove, re).
		Handle(reconcile.ScheduleRemoval, re).Handle(reconcile.CancelRemoval, re)
	for n, s := range unrelated {
		p := filepath.Join(c.dir, n)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(c.dir, staleOwned), []byte(traefik.Header+"http: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *composer) rows() []store.Route {
	c.t.Helper()
	rs, err := c.st.ListRoutes(context.Background())
	if err != nil {
		c.t.Fatal(err)
	}
	return rs
}

// cycle runs Plan -> executor -> store -> Render -> Write and the per-cycle
// invariants. It returns the plan.
func (c *composer) cycle(desired []model.Service, unavailable ...string) []reconcile.Action {
	c.t.Helper()
	known, lk := reconcile.ObservedFromRoutes(c.rows())
	un := map[string]bool{}
	for _, u := range unavailable {
		un[u] = true
	}
	acts := reconcile.Plan(desired, reconcile.Observed{Known: known, LastKnown: lk, Unavailable: un}, c.cfg, c.now)
	if err := c.ex.Apply(context.Background(), acts, false); err != nil {
		c.t.Fatalf("apply: %v", err)
	}
	c.renderWrite()
	c.assertAgreesWithPlan(acts)
	return acts
}

// renderWrite renders the persisted rows and writes them, checking
// idempotency and the directory-ownership rules.
func (c *composer) renderWrite() {
	c.t.Helper()
	f, probs, err := traefik.Render(c.rows(), traefik.MiddlewareDefs(c.cfg.MiddlewareDefs()), c.certs,
		traefik.Options{ExternalMiddlewares: c.cfg.Traefik.ExternalMiddlewares})
	if err != nil {
		c.t.Fatal(err)
	}
	if err := traefik.Write(c.dir, f); err != nil {
		c.t.Fatal(err)
	}
	c.files, c.probs = f, probs
	for n, b := range f {
		if got, err := os.ReadFile(filepath.Join(c.dir, n)); err != nil || !bytes.Equal(got, b) {
			c.t.Fatalf("%s on disk differs from render (%v)", n, err)
		}
	}
	// Idempotent: age our files, write again, nothing may change.
	for n := range f {
		if err := os.Chtimes(filepath.Join(c.dir, n), past, past); err != nil {
			c.t.Fatal(err)
		}
	}
	before := c.snapshot()
	if err := traefik.Write(c.dir, f); err != nil {
		c.t.Fatal(err)
	}
	if after := c.snapshot(); !reflect.DeepEqual(before, after) {
		c.t.Fatalf("second Write changed the directory:\n%v\n%v", before, after)
	}
	for n, s := range unrelated {
		p := filepath.Join(c.dir, n)
		fi, err := os.Stat(p)
		if err != nil || !fi.ModTime().Equal(past) {
			c.t.Fatalf("unrelated %s touched (%v)", n, err)
		}
		if got, _ := os.ReadFile(p); string(got) != s {
			c.t.Fatalf("unrelated %s changed", n)
		}
	}
	if _, err := os.Lstat(filepath.Join(c.dir, staleOwned)); !os.IsNotExist(err) {
		c.t.Fatalf("stale owned file not removed: %v", err)
	}
	ents, _ := os.ReadDir(c.dir)
	if len(ents) != len(unrelated)+len(f) {
		c.t.Fatalf("unexpected directory entries: %v", ents)
	}
}

type entry struct {
	mtime time.Time
	data  string
}

func (c *composer) snapshot() map[string]entry {
	c.t.Helper()
	ents, err := os.ReadDir(c.dir)
	if err != nil {
		c.t.Fatal(err)
	}
	m := map[string]entry{}
	for _, e := range ents {
		p := filepath.Join(c.dir, e.Name())
		fi, err := os.Stat(p)
		if err != nil {
			c.t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		m[e.Name()] = entry{fi.ModTime(), string(b)}
	}
	return m
}

// served parses the routes file: hostname -> key of the router serving it.
func (c *composer) served() map[string]string {
	c.t.Helper()
	var d struct {
		HTTP struct {
			Routers map[string]struct {
				Rule    string `yaml:"rule"`
				Service string `yaml:"service"`
			} `yaml:"routers"`
			Services map[string]any `yaml:"services"`
		} `yaml:"http"`
	}
	if err := yaml.Unmarshal(c.files[traefik.RoutesFile], &d); err != nil {
		c.t.Fatal(err)
	}
	byName := map[string]string{}
	for _, r := range c.rows() {
		byName[traefik.Name(r.Key)] = r.Key
	}
	out := map[string]string{}
	for name, r := range d.HTTP.Routers {
		h := strings.TrimSuffix(strings.TrimPrefix(r.Rule, "Host(`"), "`)")
		if _, dup := out[h]; dup {
			c.t.Fatalf("two routers for %s", h)
		}
		if r.Service != name {
			c.t.Fatalf("router %s uses service %s", name, r.Service)
		}
		if _, ok := d.HTTP.Services[name]; !ok {
			c.t.Fatalf("router %s has no service", name)
		}
		out[h] = byName[name]
	}
	if len(d.HTTP.Services) != len(d.HTTP.Routers) {
		c.t.Fatalf("orphan services: %v", d.HTTP.Services)
	}
	return out
}

// assertAgreesWithPlan: the served hostnames are exactly Plan's winners that
// have a persisted row there, minus winners skipped fail-closed (each with a
// Problem); every served router is that winner's.
func (c *composer) assertAgreesWithPlan(acts []reconcile.Action) {
	c.t.Helper()
	rowsAt := map[string][]string{}
	keyHost := map[string]string{}
	for _, r := range c.rows() {
		rowsAt[r.Hostname] = append(rowsAt[r.Hostname], r.Key)
		keyHost[r.Key] = r.Hostname
	}
	winner := map[string]string{}
	for _, a := range acts {
		if a.Kind == reconcile.RouteWrite && keyHost[a.Key] == a.Host {
			winner[a.Host] = a.Key
		}
	}
	for h, ks := range rowsAt {
		if _, ok := winner[h]; ok {
			continue
		}
		if len(ks) != 1 {
			c.t.Fatalf("hostname %s has rows %v and no plan winner", h, ks)
		}
		winner[h] = ks[0] // e.g. a phantom during a source outage
	}
	skipped := map[string]bool{}
	for _, p := range c.probs {
		if p.Kind != traefik.KindShadowed && p.Key != "" {
			skipped[p.Key] = true
		}
	}
	want := map[string]string{}
	for h, k := range winner {
		if !skipped[k] {
			want[h] = k
		}
	}
	if got := c.served(); !reflect.DeepEqual(got, want) {
		c.t.Fatalf("served %v, plan winners with rows %v (problems %v)", got, want, c.probs)
	}
}

func (c *composer) golden(name string) {
	c.t.Helper()
	for file, suffix := range map[string]string{traefik.RoutesFile: "", traefik.TLSFile: "-tls"} {
		p := filepath.Join("testdata", name+suffix+".golden.yml")
		if suffix != "" && name != "01-publish" {
			continue // the TLS file never changes in this scenario
		}
		if *update {
			if err := os.WriteFile(p, c.files[file], 0o644); err != nil {
				c.t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(p)
		if err != nil {
			c.t.Fatal(err)
		}
		if !bytes.Equal(c.files[file], want) {
			c.t.Fatalf("%s mismatch:\n--- got\n%s\n--- want\n%s", p, c.files[file], want)
		}
	}
}

func (c *composer) assertProblems(want ...string) {
	c.t.Helper()
	var got []string
	for _, p := range c.probs {
		got = append(got, p.Kind+" "+p.Key)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		c.t.Fatalf("problems %v, want %v", c.probs, want)
	}
}

func (c *composer) assertUnchanged(prev traefik.Files) {
	c.t.Helper()
	if !reflect.DeepEqual(c.files, prev) {
		c.t.Fatalf("rendered files changed:\n%s\n---\n%s", prev[traefik.RoutesFile], c.files[traefik.RoutesFile])
	}
}

func copyFiles(f traefik.Files) traefik.Files {
	out := traefik.Files{}
	for k, v := range f {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func web(port int) model.Service {
	return model.Service{Key: "docker:web", Source: "docker", Name: "web", Zone: "example.test",
		State: model.StatePublished, Backend: model.Backend{Scheme: "http", Host: "198.51.100.10", Port: port}}
}

func wiki(name string, mws ...string) model.Service {
	return model.Service{Key: "static:wiki", Source: "static", Name: name, Zone: "example.test",
		State:   model.StatePublished,
		Backend: model.Backend{Scheme: "https", Host: "2001:db8::20", Port: 8443, SkipVerify: true},
		Options: model.Options{Middlewares: mws}}
}

func TestComposePlanExecutorStoreRender(t *testing.T) {
	c := newComposer(t)

	// 1. publish docker (plain http) and static (IPv6, https skip_verify, auth@file)
	c.cycle([]model.Service{web(8080), wiki("wiki", "auth@file")})
	c.assertProblems()
	c.golden("01-publish")
	if got := c.served(); !reflect.DeepEqual(got, map[string]string{
		"web.example.test": "docker:web", "wiki.example.test": "static:wiki"}) {
		t.Fatalf("served %v", got)
	}
	published := copyFiles(c.files)

	// 2. docker container stopped: route as last written, YAML byte-identical
	c.now = t0.Add(time.Hour)
	stopped := web(0)
	stopped.State, stopped.Backend = model.StateStopped, model.Backend{}
	c.cycle([]model.Service{stopped, wiki("wiki", "auth@file")})
	c.assertUnchanged(published)

	// 3. restarted on a NEW port
	c.now = t0.Add(2 * time.Hour)
	c.cycle([]model.Service{web(9090), wiki("wiki", "auth@file")})
	c.golden("03-new-port")
	newPort := copyFiles(c.files)

	// 4. docker source unavailable: routes persist, YAML byte-identical
	c.now = t0.Add(3 * time.Hour)
	c.cycle([]model.Service{wiki("wiki", "auth@file")}, "docker")
	c.assertUnchanged(newPort)

	// 5. docker back, container gone: removal scheduled, still rendered
	c.now = t0.Add(4 * time.Hour)
	c.cycle([]model.Service{wiki("wiki", "auth@file")})
	if r, ok, _ := c.st.GetRoute(context.Background(), "docker:web"); !ok || r.RemovedAfter == nil {
		t.Fatalf("removal not scheduled: %+v", r)
	}
	c.assertUnchanged(newPort)

	// 6. past grace: removed
	c.now = t0.Add(29 * time.Hour)
	c.cycle([]model.Service{wiki("wiki", "auth@file")})
	c.golden("06-removed")
	removed := copyFiles(c.files)

	// 7a. crash window: a docker row shares wiki's hostname; static is
	// rendered, the docker row is shadowed, the YAML is unchanged.
	if err := c.st.UpsertRoute(context.Background(), store.Route{Key: "docker:wiki2", Source: "docker",
		Zone: "example.test", Hostname: "wiki.example.test", Scheme: "http", Host: "198.51.100.11", Port: 80,
		UpdatedAt: c.now}); err != nil {
		t.Fatal(err)
	}
	c.renderWrite()
	c.assertProblems(traefik.KindShadowed + " docker:wiki2")
	c.assertUnchanged(removed)
	if got := c.served(); !reflect.DeepEqual(got, map[string]string{"wiki.example.test": "static:wiki"}) {
		t.Fatalf("served %v", got)
	}

	// 7b. hostname conflict: the docker newcomer loses to static, Plan
	// removes its row; only static is rendered.
	c.now = t0.Add(30 * time.Hour)
	wiki2 := web(80)
	wiki2.Key, wiki2.Name, wiki2.Backend.Host = "docker:wiki2", "wiki", "198.51.100.11"
	acts := c.cycle([]model.Service{wiki("wiki", "auth@file"), wiki2})
	if !hasAction(acts, reconcile.Conflict, "docker:wiki2") || !hasAction(acts, reconcile.RouteRemove, "docker:wiki2") {
		t.Fatalf("no conflict/removal for docker:wiki2: %v", acts)
	}
	c.assertProblems()
	c.assertUnchanged(removed)

	// 8a. static's labels now reference an undefined middleware: Plan fails
	// it closed (Invalid, no RouteWrite), so its route stays as last written
	// and is still served WITH its defined auth.
	c.now = t0.Add(31 * time.Hour)
	acts = c.cycle([]model.Service{wiki("wiki", "auth@file", "missing@file")})
	if !hasAction(acts, reconcile.Invalid, "static:wiki") || hasAction(acts, reconcile.RouteWrite, "static:wiki") {
		t.Fatalf("actions %v", acts)
	}
	if r, _, _ := c.st.GetRoute(context.Background(), "static:wiki"); !reflect.DeepEqual(r.Middlewares, []string{"auth@file"}) {
		t.Fatalf("row %+v", r)
	}
	c.assertProblems()
	c.assertUnchanged(removed)

	// 8b. the auth DEFINITION is removed from the config: Plan keeps the
	// service Invalid, the renderer no longer serves its persisted route
	// (fail closed: the hostname goes dark rather than serve without auth).
	c.now = t0.Add(31*time.Hour + 30*time.Minute)
	auth := c.cfg.Middlewares["auth"]
	delete(c.cfg.Middlewares, "auth")
	c.cycle([]model.Service{wiki("wiki", "auth@file")})
	c.assertProblems(traefik.KindUndefinedMiddleware + " static:wiki")
	if got := c.served(); len(got) != 0 {
		t.Fatalf("served %v", got)
	}
	c.golden("08-undefined-middleware")
	c.cfg.Middlewares["auth"] = auth

	// 9. fixed and renamed: the route moves to the new hostname
	c.now = t0.Add(32 * time.Hour)
	c.cycle([]model.Service{wiki("docs", "auth@file")})
	c.assertProblems()
	if got := c.served(); !reflect.DeepEqual(got, map[string]string{"docs.example.test": "static:wiki"}) {
		t.Fatalf("served %v", got)
	}
	c.golden("09-rename")
}

func hasAction(acts []reconcile.Action, k reconcile.ActionKind, key string) bool {
	for _, a := range acts {
		if a.Kind == k && a.Key == key {
			return true
		}
	}
	return false
}
