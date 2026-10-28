package traefik

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
	"gopkg.in/yaml.v3"
)

func rt(key, host string, port int) store.Route {
	src := key[:strings.IndexByte(key, ':')]
	return store.Route{Key: key, Source: src, Zone: "example.test", Hostname: host + ".example.test",
		Scheme: "http", Host: "198.51.100.5", Port: port}
}

func authDefs() MiddlewareDefs {
	return MiddlewareDefs{"auth": map[string]any{"forwardAuth": map[string]any{"address": "http://192.0.2.50:9091/verify"}}}
}

// doc is a typed view of the routes file for assertions.
type doc struct {
	HTTP struct {
		Routers map[string]struct {
			Rule        string         `yaml:"rule"`
			EntryPoints []string       `yaml:"entryPoints"`
			Service     string         `yaml:"service"`
			Middlewares []string       `yaml:"middlewares"`
			TLS         map[string]any `yaml:"tls"`
		} `yaml:"routers"`
		Services map[string]struct {
			LoadBalancer struct {
				Servers []struct {
					URL string `yaml:"url"`
				} `yaml:"servers"`
				PassHostHeader   *bool  `yaml:"passHostHeader"`
				ServersTransport string `yaml:"serversTransport"`
			} `yaml:"loadBalancer"`
		} `yaml:"services"`
		ServersTransports map[string]map[string]any `yaml:"serversTransports"`
		Middlewares       map[string]any            `yaml:"middlewares"`
	} `yaml:"http"`
}

// mustRender renders and drops KindNoCertificate Problems: the route tests
// render without certificates; certificate coverage has its own tests
// (TestRenderNoCertificateForHost).
func mustRender(t *testing.T, routes []store.Route, mw MiddlewareDefs, certs []TLSCert, opts Options) (Files, []Problem, doc) {
	t.Helper()
	f, all, err := Render(routes, mw, certs, opts)
	if err != nil {
		t.Fatal(err)
	}
	var probs []Problem
	for _, p := range all {
		if p.Kind != KindNoCertificate {
			probs = append(probs, p)
		}
	}
	var d doc
	b := f[RoutesFile]
	if !strings.HasPrefix(string(b), Header) {
		t.Fatalf("routes file lacks header:\n%s", b)
	}
	if err := yaml.Unmarshal(b, &d); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return f, probs, d
}

func kinds(ps []Problem) map[string][]string {
	m := map[string][]string{}
	for _, p := range ps {
		m[p.Kind] = append(m[p.Kind], p.Key)
	}
	for _, v := range m {
		sort.Strings(v)
	}
	return m
}

// served maps each router's hostname to the key whose router it is.
func served(t *testing.T, d doc, keys ...string) map[string]string {
	t.Helper()
	byName := map[string]string{}
	for _, k := range keys {
		byName[Name(k)] = k
	}
	out := map[string]string{}
	for name, r := range d.HTTP.Routers {
		h := strings.TrimSuffix(strings.TrimPrefix(r.Rule, "Host(`"), "`)")
		if _, dup := out[h]; dup {
			t.Fatalf("two routers for %s", h)
		}
		out[h] = byName[name]
	}
	return out
}

func TestRenderBasicRouterAndService(t *testing.T) {
	r := rt("docker:app", "app", 8080)
	r.Middlewares = []string{"auth@file", "auth"}
	r.Websockets = true
	_, probs, d := mustRender(t, []store.Route{r}, authDefs(), nil, Options{})
	if len(probs) != 0 {
		t.Fatalf("problems %v", probs)
	}
	n := Name("docker:app")
	ro, ok := d.HTTP.Routers[n]
	if !ok {
		t.Fatalf("router %s missing: %+v", n, d.HTTP.Routers)
	}
	if ro.Rule != "Host(`app.example.test`)" || !reflect.DeepEqual(ro.EntryPoints, []string{"websecure"}) ||
		ro.Service != n || !reflect.DeepEqual(ro.Middlewares, []string{"auth@file", "auth"}) || ro.TLS == nil {
		t.Fatalf("router %+v", ro)
	}
	s := d.HTTP.Services[n].LoadBalancer
	if len(s.Servers) != 1 || s.Servers[0].URL != "http://198.51.100.5:8080" || s.ServersTransport != "" ||
		s.PassHostHeader == nil || !*s.PassHostHeader {
		t.Fatalf("service %+v", s)
	}
	if len(d.HTTP.ServersTransports) != 0 {
		t.Fatalf("unexpected transports %v", d.HTTP.ServersTransports)
	}
	if !reflect.DeepEqual(d.HTTP.Middlewares, map[string]any{"auth": map[string]any{"forwardAuth": map[string]any{"address": "http://192.0.2.50:9091/verify"}}}) {
		t.Fatalf("middlewares %v", d.HTTP.Middlewares)
	}
}

func TestRenderTLSIsEmptyMapNotNull(t *testing.T) {
	f, _, _ := mustRender(t, []store.Route{rt("docker:app", "app", 80)}, nil, nil, Options{})
	if !strings.Contains(string(f[RoutesFile]), "tls: {}") {
		t.Fatalf("want literal tls: {}:\n%s", f[RoutesFile])
	}
	if strings.Contains(string(f[RoutesFile]), "null") {
		t.Fatalf("null in output:\n%s", f[RoutesFile])
	}
}

func TestRenderEntryPointOption(t *testing.T) {
	_, _, d := mustRender(t, []store.Route{rt("docker:app", "app", 80)}, nil, nil, Options{EntryPoint: "https"})
	if ep := d.HTTP.Routers[Name("docker:app")].EntryPoints; !reflect.DeepEqual(ep, []string{"https"}) {
		t.Fatalf("entrypoints %v", ep)
	}
	if _, _, err := Render(nil, nil, nil, Options{EntryPoint: "web secure"}); err == nil {
		t.Fatal("invalid entry point accepted")
	}
}

func TestRenderIPv6Bracketed(t *testing.T) {
	r := rt("static:v6", "v6", 8443)
	r.Host = "2001:db8::7"
	r.Scheme = "https"
	b := rt("static:v6b", "v6b", 80)
	b.Host = "[2001:db8::8]" // independent input may be bracketed
	_, probs, d := mustRender(t, []store.Route{r, b}, nil, nil, Options{})
	if len(probs) != 0 {
		t.Fatal(probs)
	}
	if u := d.HTTP.Services[Name("static:v6")].LoadBalancer.Servers[0].URL; u != "https://[2001:db8::7]:8443" {
		t.Fatalf("url %s", u)
	}
	if u := d.HTTP.Services[Name("static:v6b")].LoadBalancer.Servers[0].URL; u != "http://[2001:db8::8]:80" {
		t.Fatalf("url %s", u)
	}
}

func TestRenderSkipVerifyTransport(t *testing.T) {
	a := rt("static:a", "a", 443)
	a.Scheme, a.SkipVerify = "https", true
	b := rt("static:b", "b", 443)
	b.Scheme = "https"
	_, _, d := mustRender(t, []store.Route{a, b}, nil, nil, Options{})
	if st := d.HTTP.Services[Name("static:a")].LoadBalancer.ServersTransport; st != InsecureTransport {
		t.Fatalf("a transport %q", st)
	}
	if st := d.HTTP.Services[Name("static:b")].LoadBalancer.ServersTransport; st != "" {
		t.Fatalf("b transport %q", st)
	}
	if !reflect.DeepEqual(d.HTTP.ServersTransports, map[string]map[string]any{InsecureTransport: {"insecureSkipVerify": true}}) {
		t.Fatalf("transports %v", d.HTTP.ServersTransports)
	}
	// skip_verify on plain http is meaningless: no transport
	c := rt("static:c", "c", 80)
	c.SkipVerify = true
	_, _, d = mustRender(t, []store.Route{c}, nil, nil, Options{})
	if len(d.HTTP.ServersTransports) != 0 || d.HTTP.Services[Name("static:c")].LoadBalancer.ServersTransport != "" {
		t.Fatalf("http skip_verify got a transport: %+v", d.HTTP)
	}
}

func TestRenderOneRouterPerHostnameWinnerRule(t *testing.T) {
	cases := []struct {
		name string
		keys []string
		want string
	}{
		{"static beats truenas and docker", []string{"docker:a", "truenas:b", "static:z"}, "static:z"},
		{"truenas beats docker", []string{"docker:a", "truenas:z"}, "truenas:z"},
		{"docker beats unknown prefix", []string{"other:a", "docker:z"}, "docker:z"},
		{"same rank smaller key", []string{"docker:b", "docker:a"}, "docker:a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var rs []store.Route
			for i, k := range c.keys {
				rs = append(rs, rt(k, "app", 8000+i))
			}
			// both input orders
			for _, order := range [][]store.Route{rs, reverse(rs)} {
				_, probs, d := mustRender(t, order, nil, nil, Options{})
				if got := served(t, d, c.keys...); !reflect.DeepEqual(got, map[string]string{"app.example.test": c.want}) {
					t.Fatalf("served %v", got)
				}
				if len(d.HTTP.Services) != 1 {
					t.Fatalf("services %v", d.HTTP.Services)
				}
				var losers []string
				for _, k := range c.keys {
					if k != c.want {
						losers = append(losers, k)
					}
				}
				sort.Strings(losers)
				if got := kinds(probs)[KindShadowed]; !reflect.DeepEqual(got, losers) {
					t.Fatalf("shadowed %v want %v", got, losers)
				}
				for _, p := range probs {
					if !strings.Contains(p.Detail, c.want) {
						t.Fatalf("shadow detail %q does not name winner", p.Detail)
					}
				}
			}
		})
	}
}

// The renderer must use model.SourceRank itself, including its
// source-name fallback for keys without a known prefix.
func TestRenderWinnerUsesModelSourceRank(t *testing.T) {
	a := rt("other:a", "app", 1)
	a.Source = "docker"
	b := rt("other:b", "app", 2)
	b.Source = "static"
	if model.SourceRank(b.Key, b.Source) >= model.SourceRank(a.Key, a.Source) {
		t.Fatal("test premise")
	}
	_, _, d := mustRender(t, []store.Route{a, b}, nil, nil, Options{})
	if got := served(t, d, a.Key, b.Key); got["app.example.test"] != "other:b" {
		t.Fatalf("served %v", got)
	}
}

func TestRenderHostnameCaseInsensitive(t *testing.T) {
	a := rt("docker:a", "app", 1)
	b := rt("static:b", "app", 2)
	b.Hostname = "APP.example.test"
	_, probs, d := mustRender(t, []store.Route{a, b}, nil, nil, Options{})
	if len(d.HTTP.Routers) != 1 || len(probs) != 1 {
		t.Fatalf("routers %v problems %v", d.HTTP.Routers, probs)
	}
	if r := d.HTTP.Routers[Name("static:b")]; r.Rule != "Host(`app.example.test`)" {
		t.Fatalf("rule %q", r.Rule)
	}
}

func TestRenderUndefinedMiddlewareFailsClosed(t *testing.T) {
	refs := []string{"missing", "missing@file", "crowdsec@docker", "noop@internal", "auth@docker"}
	for _, ref := range refs {
		t.Run(ref, func(t *testing.T) {
			r := rt("static:app", "app", 80)
			r.Middlewares = []string{"auth@file", ref}
			other := rt("docker:other", "other", 81)
			_, probs, d := mustRender(t, []store.Route{r, other}, authDefs(), nil, Options{})
			if _, ok := d.HTTP.Routers[Name("static:app")]; ok {
				t.Fatal("router rendered despite undefined middleware")
			}
			if _, ok := d.HTTP.Services[Name("static:app")]; ok {
				t.Fatal("service rendered despite undefined middleware")
			}
			if _, ok := d.HTTP.Routers[Name("docker:other")]; !ok {
				t.Fatal("unrelated route dropped")
			}
			if got := kinds(probs); !reflect.DeepEqual(got, map[string][]string{KindUndefinedMiddleware: {"static:app"}}) {
				t.Fatalf("problems %v", probs)
			}
		})
	}
	// allowlisted external references are rendered
	r := rt("static:app", "app", 80)
	r.Middlewares = []string{"crowdsec@docker", "noop@internal"}
	_, probs, d := mustRender(t, []store.Route{r}, nil, nil, Options{ExternalMiddlewares: []string{"crowdsec@docker", "noop@internal"}})
	if len(probs) != 0 || !reflect.DeepEqual(d.HTTP.Routers[Name("static:app")].Middlewares, r.Middlewares) {
		t.Fatalf("external: %v %+v", probs, d.HTTP.Routers)
	}
}

// The winner failing a guard leaves the hostname dark: the shadowed
// lower-ranked row is never served in its place.
func TestRenderUnrenderableWinnerDoesNotFallThrough(t *testing.T) {
	win := rt("static:app", "app", 80)
	win.Middlewares = []string{"missing@file"}
	lose := rt("docker:app", "app", 81)
	_, probs, d := mustRender(t, []store.Route{win, lose}, nil, nil, Options{})
	if len(d.HTTP.Routers) != 0 || len(d.HTTP.Services) != 0 {
		t.Fatalf("hostname served: %+v", d.HTTP)
	}
	if got := kinds(probs); !reflect.DeepEqual(got, map[string][]string{
		KindUndefinedMiddleware: {"static:app"}, KindShadowed: {"docker:app"}}) {
		t.Fatalf("problems %v", probs)
	}
}

func TestRenderInvalidMiddlewareRefSkipsRoute(t *testing.T) {
	for _, ref := range []string{"a b", "a`b", "a/b", "a@b@c", ""} {
		r := rt("static:app", "app", 80)
		r.Middlewares = []string{ref}
		_, probs, d := mustRender(t, []store.Route{r}, MiddlewareDefs{}, nil, Options{})
		if len(d.HTTP.Routers) != 0 || len(d.HTTP.Services) != 0 {
			t.Fatalf("%q: rendered", ref)
		}
		if got := kinds(probs); !reflect.DeepEqual(got, map[string][]string{KindInvalidMiddleware: {"static:app"}}) {
			t.Fatalf("%q: problems %v", ref, probs)
		}
	}
}

func TestRenderInvalidDefinitionNotRenderedAndReferencesSkipped(t *testing.T) {
	defs := MiddlewareDefs{
		"two":      map[string]any{"headers": map[string]any{}, "basicAuth": map[string]any{}},
		"none":     map[string]any{},
		"scalar":   "basicAuth",
		"bad name": map[string]any{"headers": map[string]any{}},
		"x@file":   map[string]any{"headers": map[string]any{}},
		"ok":       map[string]any{"headers": map[string]any{"customRequestHeaders": map[string]any{"X-A": "1"}}},
		"tmpl":     map[string]any{"headers": map[string]any{"customRequestHeaders": map[string]any{"X-A": "{{ .X }}"}}},
		"chainbad": map[string]any{"chain": map[string]any{"middlewares": []any{"ok", "nope"}}},
	}
	r := rt("static:app", "app", 80)
	r.Middlewares = []string{"two"}
	tm := rt("static:tmpl", "tmpl", 80)
	tm.Middlewares = []string{"tmpl"}
	ch := rt("static:chain", "chain", 80)
	ch.Middlewares = []string{"chainbad@file"}
	ok := rt("static:ok", "ok", 80)
	ok.Middlewares = []string{"ok@file"}
	f, probs, d := mustRender(t, []store.Route{r, tm, ch, ok}, defs, nil, Options{})
	if !reflect.DeepEqual(keysOf(d.HTTP.Middlewares), []string{"ok"}) {
		t.Fatalf("middlewares %v", d.HTTP.Middlewares)
	}
	if _, ok := d.HTTP.Routers[Name("static:app")]; ok {
		t.Fatal("route referencing invalid definition rendered")
	}
	if _, ok := d.HTTP.Routers[Name("static:ok")]; !ok {
		t.Fatal("valid route missing")
	}
	var defProbs []string
	for _, p := range probs {
		if p.Kind == KindInvalidDefinition {
			defProbs = append(defProbs, p.Middleware)
		}
	}
	sort.Strings(defProbs)
	if !reflect.DeepEqual(defProbs, []string{"bad name", "chainbad", "none", "scalar", "tmpl", "two", "x@file"}) {
		t.Fatalf("definition problems %v", probs)
	}
	if got := kinds(probs)[KindUndefinedMiddleware]; !reflect.DeepEqual(got, []string{"static:app", "static:chain", "static:tmpl"}) {
		t.Fatalf("problems %v", probs)
	}
	if strings.Contains(string(f[RoutesFile]), "{{") {
		t.Fatal("template text rendered")
	}
}

func TestRenderValidChainRendered(t *testing.T) {
	defs := MiddlewareDefs{
		"hdr":  map[string]any{"headers": map[string]any{"customRequestHeaders": map[string]any{"X-A": "1"}}},
		"both": map[string]any{"chain": map[string]any{"middlewares": []any{"hdr", "crowdsec@docker"}}},
	}
	r := rt("static:app", "app", 80)
	r.Middlewares = []string{"both@file"}
	_, probs, d := mustRender(t, []store.Route{r}, defs, nil, Options{ExternalMiddlewares: []string{"crowdsec@docker"}})
	if len(probs) != 0 || len(d.HTTP.Routers) != 1 || !reflect.DeepEqual(keysOf(d.HTTP.Middlewares), []string{"both", "hdr"}) {
		t.Fatalf("%v %+v", probs, d.HTTP)
	}
}

func TestRenderRevalidatesRoutes(t *testing.T) {
	bad := map[string]func(*store.Route){
		"hostname backtick": func(r *store.Route) { r.Hostname = "a`) || Host(`b.example.test" },
		"hostname space":    func(r *store.Route) { r.Hostname = "a b.example.test" },
		"hostname empty":    func(r *store.Route) { r.Hostname = "" },
		"hostname ip":       func(r *store.Route) { r.Hostname = "2001:db8::1" },
		"host with port":    func(r *store.Route) { r.Host = "198.51.100.5:80" },
		"host slash":        func(r *store.Route) { r.Host = "a/b" },
		"scheme h2c":        func(r *store.Route) { r.Scheme = "h2c" },
		"port 0":            func(r *store.Route) { r.Port = 0 },
		"port 70000":        func(r *store.Route) { r.Port = 70000 },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) {
			r := rt("docker:app", "app", 80)
			mut(&r)
			f, probs, d := mustRender(t, []store.Route{r}, nil, nil, Options{})
			if len(d.HTTP.Routers) != 0 || len(d.HTTP.Services) != 0 {
				t.Fatalf("rendered:\n%s", f[RoutesFile])
			}
			if got := kinds(probs); !reflect.DeepEqual(got, map[string][]string{KindInvalidRoute: {"docker:app"}}) {
				t.Fatalf("problems %v", probs)
			}
		})
	}
}

func TestRenderRemovalScheduledStillRendered(t *testing.T) {
	r := rt("docker:app", "app", 80)
	at := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	r.RemovedAfter = &at
	_, _, d := mustRender(t, []store.Route{r}, nil, nil, Options{})
	if _, ok := d.HTTP.Routers[Name("docker:app")]; !ok {
		t.Fatal("scheduled-removal route not rendered")
	}
}

func TestRenderDeterministic(t *testing.T) {
	var rs []store.Route
	for i, k := range []string{"docker:a", "docker:b", "static:c", "truenas:d", "docker:e"} {
		r := rt(k, k[strings.IndexByte(k, ':')+1:], 8000+i)
		r.Middlewares = []string{"auth"}
		rs = append(rs, r)
	}
	f1, p1, err := Render(rs, authDefs(), nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	f2, p2, err := Render(reverse(rs), authDefs(), nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f1, f2) || !reflect.DeepEqual(p1, p2) {
		t.Fatalf("not deterministic:\n%s\n---\n%s", f1[RoutesFile], f2[RoutesFile])
	}
}

func TestRenderDuplicateKeyIsError(t *testing.T) {
	if _, _, err := Render([]store.Route{rt("docker:a", "a", 1), rt("docker:a", "b", 2)}, nil, nil, Options{}); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestNameIsSafeAndDistinct(t *testing.T) {
	keys := []string{"docker:app", "docker_app", "docker-app", "DOCKER:APP", "static:a.b", "truenas:" + strings.Repeat("x", 300), "docker:ä"}
	seen := map[string]string{}
	for _, k := range keys {
		n := Name(k)
		if n != Name(k) {
			t.Fatal("not deterministic")
		}
		for i := 0; i < len(n); i++ {
			c := n[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				t.Fatalf("%q -> %q has unsafe char", k, n)
			}
		}
		if len(n) > 64 {
			t.Fatalf("%q -> %q too long", k, n)
		}
		if o, dup := seen[n]; dup {
			t.Fatalf("%q and %q collide on %q", k, o, n)
		}
		seen[n] = k
	}
	if !strings.HasPrefix(Name("docker:app"), "docker-app-") {
		t.Fatalf("readable prefix lost: %s", Name("docker:app"))
	}
}

func TestRenderTLSFile(t *testing.T) {
	certs := []TLSCert{
		{Domains: []string{"*.example.test", "example.test"}, CertFile: "b/fullchain.pem", KeyFile: "b/privkey.pem"},
		{Domains: []string{"a.example.test"}, CertFile: "a/fullchain.pem", KeyFile: "a/privkey.pem"},
		{Domains: nil, CertFile: "c/fullchain.pem", KeyFile: "c/privkey.pem"},
	}
	f, probs, err := Render(nil, nil, certs, Options{PathPrefix: "/data/certs/"})
	if err != nil || len(probs) != 0 {
		t.Fatal(err, probs)
	}
	want := Header + `tls:
  certificates:
    - certFile: /data/certs/a/fullchain.pem
      keyFile: /data/certs/a/privkey.pem
    - certFile: /data/certs/b/fullchain.pem
      keyFile: /data/certs/b/privkey.pem
  options:
    default:
      minVersion: VersionTLS12
`
	if got := string(f[TLSFile]); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	f, _, _ = Render(nil, nil, nil, Options{})
	if got := string(f[TLSFile]); got != Header+"tls:\n  options:\n    default:\n      minVersion: VersionTLS12\n" {
		t.Fatalf("empty tls file %q", got)
	}
	f, _, _ = Render(nil, nil, certs[1:2], Options{})
	if !strings.Contains(string(f[TLSFile]), "certFile: /certs/a/fullchain.pem") {
		t.Fatalf("default prefix: %s", f[TLSFile])
	}
}

func TestRenderTLSRejectsBadPaths(t *testing.T) {
	for _, p := range []string{"../x.pem", "a/../../x.pem", "/etc/x.pem", "", "a/./b.pem", "a\nb.pem", "a//b.pem", "a b.pem"} {
		c := TLSCert{Domains: []string{"a.example.test"}, CertFile: p, KeyFile: "ok/privkey.pem"}
		f, probs, err := Render(nil, nil, []TLSCert{c}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(f[TLSFile]), "certFile") || len(probs) != 1 || probs[0].Kind != KindInvalidCert {
			t.Fatalf("%q: %s %v", p, f[TLSFile], probs)
		}
	}
}

func TestRenderNoRoutesFile(t *testing.T) {
	f, _, err := Render(nil, nil, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(f[RoutesFile]); got != Header+"http: {}\n" {
		t.Fatalf("got %q", got)
	}
	if len(f) != 2 {
		t.Fatalf("files %v", f)
	}
}

func reverse(rs []store.Route) []store.Route {
	out := append([]store.Route(nil), rs...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func keysOf[V any](m map[string]V) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// A chain spelled with other letter case is still a chain (Traefik folds
// file-provider key case): an undefined member or a cycle must make it
// invalid and fail closed exactly like a lowercase chain.
func TestRenderChainTypeCaseInsensitive(t *testing.T) {
	defs := MiddlewareDefs{
		"hdr":   map[string]any{"headers": map[string]any{}},
		"Upper": map[string]any{"Chain": map[string]any{"Middlewares": []any{"nope"}}},
		"cycA":  map[string]any{"CHAIN": map[string]any{"middlewares": []any{"cycB"}}},
		"cycB":  map[string]any{"chain": map[string]any{"MIDDLEWARES": []any{"cycA"}}},
		"good":  map[string]any{"Chain": map[string]any{"Middlewares": []any{"hdr"}}},
	}
	var routes []store.Route
	for _, m := range []string{"Upper", "cycA", "good"} {
		r := rt("static:"+strings.ToLower(m), strings.ToLower(m), 80)
		r.Middlewares = []string{m + "@file"}
		routes = append(routes, r)
	}
	_, probs, d := mustRender(t, routes, defs, nil, Options{})
	if !reflect.DeepEqual(keysOf(d.HTTP.Middlewares), []string{"good", "hdr"}) {
		t.Fatalf("middlewares %v", keysOf(d.HTTP.Middlewares))
	}
	if !reflect.DeepEqual(keysOf(d.HTTP.Routers), []string{Name("static:good")}) {
		t.Fatalf("routers %v", keysOf(d.HTTP.Routers))
	}
	if got := kinds(probs)[KindUndefinedMiddleware]; !reflect.DeepEqual(got, []string{"static:cyca", "static:upper"}) {
		t.Fatalf("problems %v", probs)
	}
}
