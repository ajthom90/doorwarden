package traefik

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/store"
)

var (
	tnow  = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	later = tnow.Add(60 * 24 * time.Hour)
	soon  = tnow.Add(10 * 24 * time.Hour)
	gone  = tnow.Add(-time.Hour)
)

// crow builds a cert row the way the ACME manager does: Path "<id>/v<N>".
func crow(id string, domains []string, notAfter time.Time, mods ...func(*store.Cert)) store.Cert {
	dj, _ := json.Marshal(domains)
	r := store.Cert{ID: id, Zone: "example.test", DomainsJSON: string(dj), Issuer: "le",
		NotAfter: notAfter, Status: "valid", LastResult: "ok", Path: id + "/v1", Managed: true}
	for _, m := range mods {
		m(&r)
	}
	return r
}

func staging(r *store.Cert) { r.Staging = true }
func imported(r *store.Cert) {
	r.Managed, r.Status, r.Issuer = false, "imported", ""
}
func status(s string) func(*store.Cert)    { return func(r *store.Cert) { r.Status = s } }
func atPath(p string) func(*store.Cert)    { return func(r *store.Cert) { r.Path = p } }
func inZone(z string) func(*store.Cert)    { return func(r *store.Cert) { r.Zone = z } }
func lastError(e string) func(*store.Cert) { return func(r *store.Cert) { r.LastError = e } }

func ids(cs []TLSCert) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}

func probKinds(ps []Problem) map[string][]string {
	m := map[string][]string{}
	for _, p := range ps {
		m[p.Kind] = append(m[p.Kind], p.Cert)
	}
	for _, v := range m {
		sort.Strings(v)
	}
	return m
}

var (
	wild    = []string{"*.example.test", "example.test"}
	appOnly = []string{"app.example.test"}
)

func TestCertsFromRowsSelection(t *testing.T) {
	cases := []struct {
		name  string
		rows  []store.Cert
		opts  TLSOptions
		want  []string
		probs map[string][]string
	}{
		{name: "production over staging even with an earlier expiry",
			rows: []store.Cert{crow("prod", wild, soon), crow("stag", wild, later, staging)},
			want: []string{"prod"}, probs: map[string][]string{KindCertSuperseded: {"stag"}}},
		{name: "later NotAfter wins among production",
			rows: []store.Cert{crow("old", wild, soon), crow("new", wild, later)},
			want: []string{"new"}, probs: map[string][]string{KindCertSuperseded: {"old"}}},
		{name: "later imported beats earlier managed",
			rows: []store.Cert{crow("mgd", wild, soon), crow("imp", wild, later, imported)},
			want: []string{"imp"}, probs: map[string][]string{KindCertSuperseded: {"mgd"}}},
		{name: "managed over imported only as a tie-break",
			rows: []store.Cert{crow("a-imp", wild, later, imported), crow("z-mgd", wild, later)},
			want: []string{"z-mgd"}, probs: map[string][]string{KindCertSuperseded: {"a-imp"}}},
		{name: "lexicographic id as the final tie-break",
			rows: []store.Cert{crow("b", wild, later), crow("a", wild, later)},
			want: []string{"a"}, probs: map[string][]string{KindCertSuperseded: {"b"}}},
		{name: "same set in another order and case is a duplicate",
			rows: []store.Cert{crow("a", []string{"Example.Test.", "*.EXAMPLE.test"}, later), crow("b", wild, soon)},
			want: []string{"a"}, probs: map[string][]string{KindCertSuperseded: {"b"}}},
		{name: "wildcard and specific host coexist",
			rows: []store.Cert{crow("w", wild, later), crow("app", appOnly, soon)},
			want: []string{"app", "w"}},
		{name: "expired excluded by default",
			rows: []store.Cert{crow("x", appOnly, gone)},
			want: []string{}, probs: map[string][]string{KindCertExpired: {"x"}}},
		{name: "expiry instant counts as expired",
			rows: []store.Cert{crow("x", appOnly, tnow)},
			want: []string{}, probs: map[string][]string{KindCertExpired: {"x"}}},
		{name: "expired not served even with ServeExpired when a valid cert exists for the set",
			rows: []store.Cert{crow("x", appOnly, gone), crow("v", appOnly, soon)}, opts: TLSOptions{ServeExpired: true},
			want: []string{"v"}, probs: map[string][]string{KindCertSuperseded: {"x"}}},
		{name: "ServeExpired serves the latest expired when nothing valid covers the names",
			rows: []store.Cert{crow("x1", appOnly, gone.Add(-time.Hour)), crow("x2", appOnly, gone)}, opts: TLSOptions{ServeExpired: true},
			want: []string{"x2"}, probs: map[string][]string{KindCertExpired: {"x2"}, KindCertSuperseded: {"x1"}}},
		{name: "ServeExpired never lets an expired exact name beat a valid wildcard",
			rows: []store.Cert{crow("x", appOnly, gone), crow("w", wild, later)}, opts: TLSOptions{ServeExpired: true},
			want: []string{"w"}, probs: map[string][]string{KindCertSuperseded: {"x"}}},
		{name: "ServeExpired: an expired cert sharing one name with a valid cert is dropped",
			rows: []store.Cert{crow("x", []string{"app.example.test", "old.other.test"}, gone), crow("v", appOnly, later)}, opts: TLSOptions{ServeExpired: true},
			want: []string{"v"}, probs: map[string][]string{KindCertSuperseded: {"x"}}},
		{name: "ServeExpired: an expired wildcard below a valid specific host is kept",
			rows: []store.Cert{crow("x", wild, gone), crow("v", appOnly, later)}, opts: TLSOptions{ServeExpired: true},
			want: []string{"v", "x"}, probs: map[string][]string{KindCertExpired: {"x"}}},
		{name: "staging specific host never beats a production wildcard",
			rows: []store.Cert{crow("s", appOnly, later, staging), crow("w", wild, soon)},
			want: []string{"w"}, probs: map[string][]string{KindCertSuperseded: {"s"}}},
		{name: "staging partly covered by production is dropped",
			rows: []store.Cert{crow("s", []string{"app.example.test", "x.other.test"}, later, staging), crow("w", wild, soon)},
			want: []string{"w"}, probs: map[string][]string{KindCertSuperseded: {"s"}}},
		{name: "staging wildcard below a production specific host is rendered",
			rows: []store.Cert{crow("s", wild, later, staging), crow("p", appOnly, soon)},
			want: []string{"p", "s"}},
		{name: "staging alone is rendered",
			rows: []store.Cert{crow("s", wild, later, staging)},
			want: []string{"s"}},
		{name: "valid staging beats expired production under ServeExpired",
			rows: []store.Cert{crow("s", wild, later, staging), crow("x", wild, gone)}, opts: TLSOptions{ServeExpired: true},
			want: []string{"s"}, probs: map[string][]string{KindCertSuperseded: {"x"}}},
		{name: "failed and unknown statuses are not servable",
			rows: []store.Cert{crow("f", appOnly, later, status("failed")), crow("u", wild, later, status("bogus"))},
			want: []string{}, probs: map[string][]string{KindCertUnusable: {"f", "u"}}},
		{name: "a failed row without files is not servable",
			rows: []store.Cert{crow("f", appOnly, time.Time{}, status("failed"), atPath(""))},
			want: []string{}, probs: map[string][]string{KindCertUnusable: {"f"}}},
		{name: "unwanted but valid keeps serving",
			rows: []store.Cert{crow("u", appOnly, later, status("unwanted"))},
			want: []string{"u"}},
		{name: "imported keeps serving",
			rows: []store.Cert{crow("i", appOnly, later, imported)},
			want: []string{"i"}},
		{name: "a failed renewal keeps the old certificate",
			rows: []store.Cert{crow("v", wild, soon, lastError("acme: rate limited"))},
			want: []string{"v"}},
		{name: "no expiry recorded is not servable",
			rows: []store.Cert{crow("z", appOnly, time.Time{})},
			want: []string{}, probs: map[string][]string{KindCertUnusable: {"z"}}},
		{name: "no domains",
			rows: []store.Cert{crow("e", nil, later), crow("e2", []string{}, later)},
			want: []string{}, probs: map[string][]string{KindInvalidCert: {"e", "e2"}}},
		{name: "bad domains json",
			rows: []store.Cert{crow("j", appOnly, later, func(r *store.Cert) { r.DomainsJSON = "{" })},
			want: []string{}, probs: map[string][]string{KindInvalidCert: {"j"}}},
		{name: "invalid domain names",
			rows: []store.Cert{crow("a", []string{"a..example.test"}, later), crow("b", []string{"*.*.example.test"}, later),
				crow("c", []string{"a.*.example.test"}, later), crow("d", []string{"192.0.2.1"}, later), crow("e", []string{"*"}, later),
				crow("f", []string{"a`b.example.test"}, later)},
			want: []string{}, probs: map[string][]string{KindInvalidCert: {"a", "b", "c", "d", "e", "f"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, probs := CertsFromRows(tc.rows, tc.opts, tnow)
			if g := ids(got); !reflect.DeepEqual(g, tc.want) {
				t.Fatalf("rendered %v, want %v (problems %v)", g, tc.want, probs)
			}
			want := tc.probs
			if want == nil {
				want = map[string][]string{}
			}
			if g := probKinds(probs); !reflect.DeepEqual(g, want) {
				t.Fatalf("problems %v, want %v", probs, want)
			}
			assertNoProblemRowRendered(t, got, probs)
		})
	}
}

// assertNoProblemRowRendered: a row with a Problem is never rendered, except
// the informational KindCertExpired for an expired row that ServeExpired
// deliberately serves.
func assertNoProblemRowRendered(t *testing.T, got []TLSCert, probs []Problem) {
	t.Helper()
	for _, p := range probs {
		for _, c := range got {
			if p.Cert == c.ID && p.Kind != KindCertExpired {
				t.Fatalf("row %s rendered despite problem %v", c.ID, p)
			}
		}
	}
}

func TestCertsFromRowsPaths(t *testing.T) {
	got, _, probs := CertsFromRows([]store.Cert{
		crow("rel", appOnly, later, atPath("rel/v3")),
		crow("abs", []string{"b.example.test"}, later, atPath("/srv/dw/certs/abs/v12")),
	}, TLSOptions{LocalCertsRoot: "/srv/dw/certs/"}, tnow)
	if len(probs) != 0 {
		t.Fatal(probs)
	}
	want := []TLSCert{
		{ID: "abs", Zone: "example.test", Domains: []string{"b.example.test"}, CertFile: "abs/v12/fullchain.pem", KeyFile: "abs/v12/privkey.pem"},
		{ID: "rel", Zone: "example.test", Domains: []string{"app.example.test"}, CertFile: "rel/v3/fullchain.pem", KeyFile: "rel/v3/privkey.pem"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	// The default root is /data/certs.
	got, _, probs = CertsFromRows([]store.Cert{crow("c", appOnly, later, atPath("/data/certs/c/v1"))}, TLSOptions{}, tnow)
	if len(probs) != 0 || len(got) != 1 || got[0].CertFile != "c/v1/fullchain.pem" {
		t.Fatalf("%+v %v", got, probs)
	}

	bad := []string{
		"", "c", "c/", "c/v1/", "c//v1", "./c/v1", "c/./v1", "c/v1/extra", "c/v1/..", "../c/v1", "c/../c/v1",
		"c/v0", "c/v01", "c/v", "c/vx", "c/V1", "c/v-1", "c/v1234567890", "c/current", "c/latest", "c/v1 ",
		"other/v1", "C/v1", "c\\v1", "c/v1\\..\\..", `C:\certs\c\v1`, "c/v1\x00", "c/v1\n",
		"/c/v1", "/etc/c/v1", "/data/certs/../c/v1", "/data/certsX/c/v1", "/data/certs", "/data/certs/c",
		"/data/certs//c/v1", "/data/certs/c/v1/", "/data/../data/certs/c/v1", "//data/certs/c/v1",
	}
	for _, p := range bad {
		got, _, probs := CertsFromRows([]store.Cert{crow("c", appOnly, later, atPath(p))}, TLSOptions{}, tnow)
		if len(got) != 0 || len(probs) != 1 || probs[0].Kind != KindInvalidCert || probs[0].Cert != "c" {
			t.Fatalf("path %q: rendered %+v problems %v", p, got, probs)
		}
	}
	for _, id := range []string{"", ".", "..", "C", "a/b", "a.b", "a b", "../x", strings.Repeat("a", 201)} {
		got, _, probs := CertsFromRows([]store.Cert{crow(id, appOnly, later, atPath(id+"/v1"))}, TLSOptions{}, tnow)
		if len(got) != 0 || len(probs) != 1 || probs[0].Kind != KindInvalidCert {
			t.Fatalf("id %q: rendered %+v problems %v", id, got, probs)
		}
	}
	// A bad certs root is a Problem for every row needing it, never a guess.
	for _, root := range []string{"data/certs", "/data/../certs", "/data/certs/./x"} {
		got, _, probs := CertsFromRows([]store.Cert{crow("c", appOnly, later, atPath("/data/certs/c/v1"))},
			TLSOptions{LocalCertsRoot: root}, tnow)
		if len(got) != 0 || len(probs) != 1 || probs[0].Kind != KindInvalidCert {
			t.Fatalf("root %q: rendered %+v problems %v", root, got, probs)
		}
	}
}

func TestCertsFromRowsDefault(t *testing.T) {
	other := inZone("other.test")
	cases := []struct {
		name, zone string
		rows       []store.Cert
		opts       TLSOptions
		want       string
	}{
		{"no default zone", "", []store.Cert{crow("w", wild, later)}, TLSOptions{}, ""},
		{"wildcard preferred over a later specific cert", "example.test",
			[]store.Cert{crow("app", appOnly, later.Add(time.Hour)), crow("w", wild, soon)}, TLSOptions{}, "w"},
		{"apex preferred when there is no wildcard", "example.test",
			[]store.Cert{crow("app", appOnly, later), crow("apex", []string{"example.test", "www.example.test"}, soon)}, TLSOptions{}, "apex"},
		{"any production cert of the zone otherwise", "example.test",
			[]store.Cert{crow("b", []string{"b.example.test"}, soon), crow("a", appOnly, later)}, TLSOptions{}, "a"},
		{"zone compared case-insensitively", "Example.Test.", []store.Cert{crow("w", wild, later)}, TLSOptions{}, "w"},
		{"only certs of the default zone", "example.test",
			[]store.Cert{crow("o", []string{"*.other.test"}, later, other)}, TLSOptions{}, ""},
		{"never a staging cert", "example.test", []store.Cert{crow("s", wild, later, staging)}, TLSOptions{}, ""},
		{"never an expired cert", "example.test", []store.Cert{crow("x", wild, gone)}, TLSOptions{ServeExpired: true}, ""},
		{"never a superseded cert", "example.test",
			[]store.Cert{crow("old", wild, soon), crow("new", wild, later)}, TLSOptions{}, "new"},
		{"never a problem row", "example.test", []store.Cert{crow("w", wild, later, atPath("../w/v1"))}, TLSOptions{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.DefaultZone = tc.zone
			certs, def, _ := CertsFromRows(tc.rows, tc.opts, tnow)
			if def.Cert.ID != tc.want {
				t.Fatalf("default %+v, want %q", def, tc.want)
			}
			if tc.want == "" {
				if def.IsSet() || def.Cert.CertFile != "" {
					t.Fatalf("default set: %+v", def)
				}
				return
			}
			if !def.IsSet() || def.Zone != "example.test" {
				t.Fatalf("default %+v", def)
			}
			found := false
			for _, c := range certs {
				found = found || reflect.DeepEqual(c, def.Cert)
			}
			if !found {
				t.Fatalf("default %+v is not one of the rendered certs %+v", def, certs)
			}
		})
	}
}

func TestCertsFromRowsDeterministic(t *testing.T) {
	rows := []store.Cert{
		crow("w", wild, later), crow("w2", wild, later), crow("w-old", wild, soon), crow("w-imp", wild, later, imported),
		crow("app", appOnly, soon), crow("app-s", appOnly, later, staging), crow("x", []string{"x.example.test"}, gone),
		crow("x2", []string{"x.example.test"}, gone.Add(-time.Hour)), crow("bad", appOnly, later, atPath("../bad/v1")),
		crow("o", []string{"*.other.test", "other.test"}, later, inZone("other.test")),
		crow("o-s", []string{"*.other.test", "other.test"}, later.Add(time.Hour), inZone("other.test"), staging),
		crow("f", []string{"f.example.test"}, later, status("failed")),
		crow("u", []string{"u.example.test"}, later, status("unwanted")),
		crow("n", []string{"n.example.test", "app.example.test"}, later),
	}
	for _, serve := range []bool{false, true} {
		opts := TLSOptions{DefaultZone: "example.test", ServeExpired: serve}
		c0, d0, p0 := CertsFromRows(rows, opts, tnow)
		if len(c0) == 0 || !d0.IsSet() || len(p0) == 0 {
			t.Fatalf("degenerate fixture: %v %v %v", c0, d0, p0)
		}
		rng := rand.New(rand.NewSource(17))
		for i := 0; i < 300; i++ {
			sh := append([]store.Cert(nil), rows...)
			rng.Shuffle(len(sh), func(a, b int) { sh[a], sh[b] = sh[b], sh[a] })
			c, d, p := CertsFromRows(sh, opts, tnow)
			if !reflect.DeepEqual(c, c0) || !reflect.DeepEqual(d, d0) || !reflect.DeepEqual(p, p0) {
				t.Fatalf("shuffle %d differs:\n%v\n%v\n%v\n%v", i, c, c0, p, p0)
			}
			assertNoProblemRowRendered(t, c, p)
		}
	}
}

func TestCovers(t *testing.T) {
	for _, tc := range []struct {
		cert, host string
		want       bool
	}{
		{"*.example.test", "a.example.test", true},
		{"*.example.test", "A.Example.Test", true},
		{"*.example.test", "a.b.example.test", false},
		{"*.example.test", "example.test", false},
		{"*.example.test", "aexample.test", false},
		{"example.test", "example.test", true},
		{"example.test", "a.example.test", false},
		{"a.example.test", "a.example.test", true},
		{"*.b.example.test", "a.b.example.test", true},
	} {
		if got := covers([]string{tc.cert}, tc.host); got != tc.want {
			t.Errorf("covers(%s, %s) = %v", tc.cert, tc.host, got)
		}
	}
}
