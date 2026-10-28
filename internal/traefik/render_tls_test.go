package traefik

import (
	"bytes"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/store"
	"gopkg.in/yaml.v3"
)

// traefikTLS mirrors the Traefik v3 file-provider TLS schema doorwarden
// writes; decoding is strict so a misspelled key fails.
type traefikTLS struct {
	TLS struct {
		Certificates []struct {
			CertFile string   `yaml:"certFile"`
			KeyFile  string   `yaml:"keyFile"`
			Stores   []string `yaml:"stores"`
		} `yaml:"certificates"`
		Options map[string]struct {
			MinVersion string `yaml:"minVersion"`
			SNIStrict  bool   `yaml:"sniStrict"`
		} `yaml:"options"`
		Stores map[string]struct {
			DefaultCertificate struct {
				CertFile string `yaml:"certFile"`
				KeyFile  string `yaml:"keyFile"`
			} `yaml:"defaultCertificate"`
		} `yaml:"stores"`
	} `yaml:"tls"`
}

func parseTLS(t *testing.T, b []byte) traefikTLS {
	t.Helper()
	var d traefikTLS
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return d
}

var tlsFixture = []TLSCert{
	{ID: "wild", Domains: []string{"*.example.test", "example.test"}, CertFile: "wild/v2/fullchain.pem", KeyFile: "wild/v2/privkey.pem"},
	{ID: "app", Domains: []string{"app.example.test"}, CertFile: "app/v1/fullchain.pem", KeyFile: "app/v1/privkey.pem"},
}

func TestRenderTLSDefaultStoreAndOptions(t *testing.T) {
	def := tlsFixture[0]
	f, probs, err := Render(nil, nil, tlsFixture, Options{DefaultCert: &def, MinTLSVersion: "VersionTLS13", SNIStrict: true})
	if err != nil || len(probs) != 0 {
		t.Fatal(err, probs)
	}
	want := Header + `tls:
  certificates:
    - certFile: /certs/app/v1/fullchain.pem
      keyFile: /certs/app/v1/privkey.pem
    - certFile: /certs/wild/v2/fullchain.pem
      keyFile: /certs/wild/v2/privkey.pem
  options:
    default:
      minVersion: VersionTLS13
      sniStrict: true
  stores:
    default:
      defaultCertificate:
        certFile: /certs/wild/v2/fullchain.pem
        keyFile: /certs/wild/v2/privkey.pem
`
	if got := string(f[TLSFile]); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	d := parseTLS(t, f[TLSFile])
	if d.TLS.Stores["default"].DefaultCertificate.KeyFile != "/certs/wild/v2/privkey.pem" ||
		d.TLS.Options["default"].MinVersion != "VersionTLS13" || !d.TLS.Options["default"].SNIStrict || len(d.TLS.Certificates) != 2 {
		t.Fatalf("%+v", d)
	}

	// Defaults: TLS 1.2, no sniStrict, no default store.
	f, _, err = Render(nil, nil, tlsFixture, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d = parseTLS(t, f[TLSFile])
	if len(d.TLS.Stores) != 0 || d.TLS.Options["default"].MinVersion != "VersionTLS12" || d.TLS.Options["default"].SNIStrict ||
		strings.Contains(string(f[TLSFile]), "sniStrict") || strings.Contains(string(f[TLSFile]), "stores") {
		t.Fatalf("%s", f[TLSFile])
	}
}

func TestRenderMinTLSVersionValidated(t *testing.T) {
	for _, v := range []string{"VersionTLS10", "VersionTLS11", "tls12", "VersionTLS12 ", "1.2"} {
		if _, _, err := Render(nil, nil, nil, Options{MinTLSVersion: v}); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
}

func TestRenderDefaultCertBadPath(t *testing.T) {
	bad := TLSCert{ID: "x", Domains: []string{"*.example.test"}, CertFile: "../x/fullchain.pem", KeyFile: "x/privkey.pem"}
	f, probs, err := Render(nil, nil, tlsFixture, Options{DefaultCert: &bad})
	if err != nil {
		t.Fatal(err)
	}
	if len(probs) != 1 || probs[0].Kind != KindInvalidCert || probs[0].Cert != "x" {
		t.Fatalf("%v", probs)
	}
	if d := parseTLS(t, f[TLSFile]); len(d.TLS.Stores) != 0 || len(d.TLS.Certificates) != 2 {
		t.Fatalf("%s", f[TLSFile])
	}
}

func hostRoute(key, host string) store.Route {
	return store.Route{Key: key, Source: "docker", Zone: "example.test", Hostname: host, Scheme: "http", Host: "198.51.100.5", Port: 80}
}

func TestRenderNoCertificateForHost(t *testing.T) {
	routes := []store.Route{
		hostRoute("docker:a", "a.example.test"),
		hostRoute("docker:ab", "a.b.example.test"),
		hostRoute("docker:apex", "example.test"),
		hostRoute("docker:other", "other.test"),
		hostRoute("docker:case", "Case.Example.Test"),
		hostRoute("docker:bad", "bad.other.test"),
	}
	certs := []TLSCert{
		{ID: "w", Domains: []string{"*.example.test"}, CertFile: "w/v1/fullchain.pem", KeyFile: "w/v1/privkey.pem"},
		// rejected (bad path): covers nothing
		{ID: "o", Domains: []string{"*.other.test"}, CertFile: "../o/fullchain.pem", KeyFile: "o/v1/privkey.pem"},
	}
	_, probs, d := mustRenderAll(t, routes, certs, Options{})
	if len(d.HTTP.Routers) != len(routes) {
		t.Fatalf("routers %v", d.HTTP.Routers)
	}
	var got []string
	for _, p := range probs {
		if p.Kind == KindNoCertificate {
			got = append(got, p.Hostname+"="+p.Key)
		}
	}
	want := []string{"a.b.example.test=docker:ab", "bad.other.test=docker:bad", "example.test=docker:apex", "other.test=docker:other"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v (all %v)", got, want, probs)
	}

	// The apex cert and a second-level wildcard close the gaps.
	certs = append(certs[:1],
		TLSCert{ID: "apex", Domains: []string{"example.test"}, CertFile: "apex/v1/fullchain.pem", KeyFile: "apex/v1/privkey.pem"},
		TLSCert{ID: "b", Domains: []string{"*.b.example.test"}, CertFile: "b/v1/fullchain.pem", KeyFile: "b/v1/privkey.pem"},
		TLSCert{ID: "o", Domains: []string{"*.other.test", "other.test"}, CertFile: "o/v1/fullchain.pem", KeyFile: "o/v1/privkey.pem"})
	_, probs, _ = mustRenderAll(t, routes, certs, Options{})
	if len(probs) != 0 {
		t.Fatal(probs)
	}
}

func mustRenderAll(t *testing.T, routes []store.Route, certs []TLSCert, opts Options) (Files, []Problem, doc) {
	t.Helper()
	f, probs, err := Render(routes, nil, certs, opts)
	if err != nil {
		t.Fatal(err)
	}
	var d doc
	if err := yaml.Unmarshal(f[RoutesFile], &d); err != nil {
		t.Fatal(err)
	}
	return f, probs, d
}

func TestRenderTLSDeterministic(t *testing.T) {
	var certs []TLSCert
	var routes []store.Route
	for i := 0; i < 12; i++ {
		n := "c" + strconv.Itoa(i)
		certs = append(certs, TLSCert{ID: n, Domains: []string{n + ".example.test"}, CertFile: n + "/v1/fullchain.pem", KeyFile: n + "/v1/privkey.pem"})
		routes = append(routes, hostRoute("docker:"+n, n+".example.test"), hostRoute("docker:x"+n, "x"+n+".example.test"))
	}
	certs = append(certs, TLSCert{ID: "bad", Domains: []string{"z.example.test"}, CertFile: "/abs", KeyFile: "k"})
	def := certs[3]
	opts := Options{DefaultCert: &def}
	f0, p0, err := Render(routes, nil, certs, opts)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 300; i++ {
		c := append([]TLSCert(nil), certs...)
		r := append([]store.Route(nil), routes...)
		rng.Shuffle(len(c), func(a, b int) { c[a], c[b] = c[b], c[a] })
		rng.Shuffle(len(r), func(a, b int) { r[a], r[b] = r[b], r[a] })
		f, p, err := Render(r, nil, c, opts)
		if err != nil || !reflect.DeepEqual(f, f0) || !reflect.DeepEqual(p, p0) {
			t.Fatalf("shuffle %d differs (%v)", i, err)
		}
	}
}

// TestRenderPathReadsNoFiles: the rendering and selection code cannot open
// files (no file-system imports); only write.go touches the disk.
func TestRenderPathReadsNoFiles(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{"os": true, "io/fs": true, "io/ioutil": true, "path/filepath": true, "syscall": true,
		"os/exec": true, "embed": true, "plugin": true, "unsafe": true, "golang.org/x/sys/unix": true}
	checked := 0
	for _, e := range ents {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || n == "write.go" {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), n, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if forbidden[p] {
				t.Errorf("%s imports %s: the render path must not read files", n, p)
			}
		}
		checked++
	}
	if checked < 2 {
		t.Fatalf("checked only %d files", checked)
	}
}
