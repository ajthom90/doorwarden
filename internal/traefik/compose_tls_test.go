package traefik_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
	"github.com/ajthom90/doorwarden/internal/traefikwire"
	"gopkg.in/yaml.v3"
)

// tlsWorld is a real store plus a certificate directory written the way
// internal/acme writes it (certs/<id>/v<N>/{fullchain,privkey}.pem, row Path
// "<id>/v<N>"), with a throwaway CA. Only the test touches PEM files.
type tlsWorld struct {
	t         *testing.T
	st        *store.Store
	cfg       *config.Config
	root, dyn string
	now       time.Time
	caKey     *ecdsa.PrivateKey
	ca        *x509.Certificate
	files     traefik.Files
	probs     []traefik.Problem
}

func newTLSWorld(t *testing.T) *tlsWorld {
	st, err := store.Open(filepath.Join(t.TempDir(), "dw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	w := &tlsWorld{t: t, st: st, root: filepath.Join(t.TempDir(), "certs"), dyn: t.TempDir(), now: t0}
	w.cfg = &config.Config{Zones: []config.Zone{{Name: "example.test", TargetIP: "192.0.2.10"}},
		Traefik: config.Traefik{CertPathPrefix: "/certs"}, ACME: config.ACME{CertsDir: w.root}}
	if err := os.MkdirAll(w.root, 0o700); err != nil {
		t.Fatal(err)
	}
	w.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "throwaway test CA"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &w.caKey.PublicKey, w.caKey)
	if err != nil {
		t.Fatal(err)
	}
	w.ca, _ = x509.ParseCertificate(der)
	for _, h := range []string{"web", "app", "deep.lab"} {
		key := "docker:" + strings.Split(h, ".")[0]
		if err := st.UpsertRoute(context.Background(), store.Route{Key: key, Source: "docker", Zone: "example.test",
			Hostname: h + ".example.test", Scheme: "http", Host: "198.51.100.10", Port: 8080, UpdatedAt: t0}); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

// issue writes a new version of id like acme.writeCertVersion and upserts
// its row like the manager (valid, managed).
func (w *tlsWorld) issue(id string, names []string, notAfter time.Time, mods ...func(*store.Cert)) string {
	w.t.Helper()
	n := 1
	if ents, err := os.ReadDir(filepath.Join(w.root, id)); err == nil {
		n += len(ents)
	}
	dir := filepath.Join(w.root, id, "v"+strconv.Itoa(n))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		w.t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(int64(n + 100)), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: t0.Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, w.ca, &key.PublicKey, w.caKey)
	if err != nil {
		w.t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.ca.Raw})...)
	for f, b := range map[string][]byte{"fullchain.pem": chain, "privkey.pem": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})} {
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			w.t.Fatal(err)
		}
	}
	dj, _ := json.Marshal(names)
	row := store.Cert{ID: id, Zone: "example.test", DomainsJSON: string(dj), Issuer: "le", NotAfter: notAfter,
		Status: "valid", LastResult: "ok", Path: id + "/v" + strconv.Itoa(n), Managed: true}
	for _, m := range mods {
		m(&row)
	}
	if err := w.st.UpsertCert(context.Background(), row); err != nil {
		w.t.Fatal(err)
	}
	return row.Path
}

func (w *tlsWorld) render() {
	w.t.Helper()
	routes, err := w.st.ListRoutes(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	rows, err := w.st.ListCerts(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	f, probs, err := traefikwire.Render(w.cfg, routes, rows, w.now)
	if err != nil {
		w.t.Fatal(err)
	}
	if err := traefik.Write(w.dyn, f); err != nil {
		w.t.Fatal(err)
	}
	w.files, w.probs = f, probs
}

type fileState struct {
	mtime time.Time
	mode  fs.FileMode
	data  string
}

// tree snapshots every entry below dir (paths, modes, mtimes, contents).
func tree(t *testing.T, dir string) map[string]fileState {
	t.Helper()
	m := map[string]fileState{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		s := fileState{mtime: fi.ModTime(), mode: fi.Mode()}
		if fi.Mode().IsRegular() && fi.Mode().Perm()&0o400 != 0 {
			b, _ := os.ReadFile(p)
			s.data = string(b)
		}
		m[p] = s
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (w *tlsWorld) age() {
	w.t.Helper()
	for n := range w.files {
		if err := os.Chtimes(filepath.Join(w.dyn, n), past, past); err != nil {
			w.t.Fatal(err)
		}
	}
}

func (w *tlsWorld) golden(name string) {
	w.t.Helper()
	p := filepath.Join("testdata", name+".golden.yml")
	if *update {
		if err := os.WriteFile(p, w.files[traefik.TLSFile], 0o644); err != nil {
			w.t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		w.t.Fatal(err)
	}
	if !bytes.Equal(w.files[traefik.TLSFile], want) {
		w.t.Fatalf("%s mismatch:\n--- got\n%s\n--- want\n%s", p, w.files[traefik.TLSFile], want)
	}
}

func (w *tlsWorld) problems() []string {
	var out []string
	for _, p := range w.probs {
		out = append(out, p.Kind+" "+p.Key+p.Cert)
	}
	sort.Strings(out)
	return out
}

// assertFilesResolve: every path in the TLS file, mapped from Traefik's
// prefix to the local certs root, exists, and each fullchain's leaf covers
// the names of its row (the test reads PEM files; the renderer never does).
func (w *tlsWorld) assertFilesResolve() {
	w.t.Helper()
	var d struct {
		TLS struct {
			Certificates []pemPair `yaml:"certificates"`
			Stores       map[string]struct {
				DefaultCertificate pemPair `yaml:"defaultCertificate"`
			} `yaml:"stores"`
		} `yaml:"tls"`
	}
	if err := yaml.Unmarshal(w.files[traefik.TLSFile], &d); err != nil {
		w.t.Fatal(err)
	}
	pairs := d.TLS.Certificates
	if s, ok := d.TLS.Stores["default"]; ok {
		pairs = append(pairs, s.DefaultCertificate)
	}
	local := func(p string) string {
		rel, ok := strings.CutPrefix(p, "/certs/")
		if !ok {
			w.t.Fatalf("%s is not below Traefik's /certs", p)
		}
		return filepath.Join(w.root, filepath.FromSlash(rel))
	}
	for _, c := range pairs {
		if fi, err := os.Stat(local(c.KeyFile)); err != nil || !fi.Mode().IsRegular() {
			w.t.Fatalf("key %s: %v", c.KeyFile, err)
		}
		b, err := os.ReadFile(local(c.CertFile))
		if err != nil {
			w.t.Fatal(err)
		}
		blk, _ := pem.Decode(b)
		leaf, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			w.t.Fatal(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: certPool(w.ca), DNSName: leaf.DNSNames[0], CurrentTime: t0}); err != nil {
			w.t.Fatalf("%s: %v", c.CertFile, err)
		}
	}
}

type pemPair struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

func certPool(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

func TestComposeTLSFromStoreRows(t *testing.T) {
	w := newTLSWorld(t)
	day := 24 * time.Hour
	w.issue("example-test-wildcard", []string{"*.example.test", "example.test"}, t0.Add(90*day))
	w.issue("deep-lab", []string{"deep.lab.example.test"}, t0.Add(5*day))

	// 1. issued: both certificates, wildcard is the default certificate.
	w.render()
	if got := w.problems(); len(got) != 0 {
		t.Fatalf("problems %v", got)
	}
	w.golden("tls-01-issued")
	w.assertFilesResolve()
	routes1 := w.files[traefik.RoutesFile]

	// 2. nothing changed: byte-identical, not rewritten (Traefik does not
	// reload), and Render+Write leave the certificate tree untouched.
	w.age()
	certTree := tree(t, w.root)
	dynBefore := tree(t, w.dyn)
	w.render()
	if !reflect.DeepEqual(tree(t, w.dyn), dynBefore) {
		t.Fatal("unchanged state rewrote the dynamic directory")
	}
	if !reflect.DeepEqual(tree(t, w.root), certTree) {
		t.Fatal("render/write touched the certificate directory")
	}

	// 3. re-issue (v1 -> v2): the TLS file changes (new version path), so
	// Traefik reloads; the routes file is not rewritten.
	w.issue("example-test-wildcard", []string{"*.example.test", "example.test"}, t0.Add(120*day))
	w.render()
	tls3, _ := os.ReadFile(filepath.Join(w.dyn, traefik.TLSFile))
	if string(tls3) == dynBefore[filepath.Join(w.dyn, traefik.TLSFile)].data {
		t.Fatal("re-issue did not change the TLS file")
	}
	if fi, _ := os.Stat(filepath.Join(w.dyn, traefik.TLSFile)); fi.ModTime().Equal(past) {
		t.Fatal("TLS file not rewritten")
	}
	if fi, _ := os.Stat(filepath.Join(w.dyn, traefik.RoutesFile)); !fi.ModTime().Equal(past) || !bytes.Equal(w.files[traefik.RoutesFile], routes1) {
		t.Fatal("routes file rewritten by a certificate change")
	}
	if s := string(tls3); !strings.Contains(s, "example-test-wildcard/v2/") || strings.Contains(s, "example-test-wildcard/v1/") {
		t.Fatalf("TLS file:\n%s", s)
	}
	w.golden("tls-03-reissued")
	w.assertFilesResolve()

	// 4. the only certificate for deep.lab expires: it leaves the TLS file,
	// routers are untouched, the route is reported uncovered (the wildcard
	// covers one label only).
	w.age()
	w.now = t0.Add(6 * day)
	w.render()
	if got, want := w.problems(), []string{traefik.KindCertExpired + " deep-lab", traefik.KindNoCertificate + " docker:deep"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("problems %v want %v", got, want)
	}
	if strings.Contains(string(w.files[traefik.TLSFile]), "deep-lab") {
		t.Fatalf("expired certificate rendered:\n%s", w.files[traefik.TLSFile])
	}
	if fi, _ := os.Stat(filepath.Join(w.dyn, traefik.RoutesFile)); !fi.ModTime().Equal(past) || !bytes.Equal(w.files[traefik.RoutesFile], routes1) {
		t.Fatal("routes file changed when a certificate expired")
	}
	w.golden("tls-04-expired")

	// 4b. serve_expired opts back in to rendering it (nothing valid covers it).
	w.cfg.Traefik.ServeExpired = true
	w.render()
	if !strings.Contains(string(w.files[traefik.TLSFile]), "deep-lab/v1/") || len(w.problems()) != 1 {
		t.Fatalf("serve_expired: %v\n%s", w.problems(), w.files[traefik.TLSFile])
	}
	w.cfg.Traefik.ServeExpired = false

	// 5. a staging certificate for a covered name is not rendered; the
	// production wildcard keeps serving app.example.test.
	w.issue("app-staging", []string{"app.example.test"}, t0.Add(80*day), func(r *store.Cert) { r.Staging = true })
	w.render()
	if strings.Contains(string(w.files[traefik.TLSFile]), "app-staging") {
		t.Fatalf("staging rendered:\n%s", w.files[traefik.TLSFile])
	}

	// 6. rendering never reads key material: with every key unreadable (and
	// then deleted) the output is byte-identical.
	before := copyFiles(w.files)
	keys, _ := filepath.Glob(filepath.Join(w.root, "*", "v*", "privkey.pem"))
	if len(keys) < 3 {
		t.Fatalf("keys %v", keys)
	}
	for _, k := range keys {
		if err := os.Chmod(k, 0); err != nil {
			t.Fatal(err)
		}
	}
	w.render()
	if !reflect.DeepEqual(w.files, before) {
		t.Fatal("output depends on key files")
	}
	for _, k := range keys {
		if err := os.Remove(k); err != nil {
			t.Fatal(err)
		}
	}
	w.render()
	if !reflect.DeepEqual(w.files, before) {
		t.Fatal("output depends on key files")
	}
}

func TestComposeTLSDefaultZones(t *testing.T) {
	w := newTLSWorld(t)
	w.issue("example-test-wildcard", []string{"*.example.test", "example.test"}, t0.Add(90*24*time.Hour))
	other := func(r *store.Cert) { r.Zone = "other.test" }
	w.issue("other-wildcard", []string{"*.other.test", "other.test"}, t0.Add(90*24*time.Hour), other)
	defaultOf := func() string {
		var d struct {
			TLS struct {
				Stores map[string]struct {
					DefaultCertificate pemPair `yaml:"defaultCertificate"`
				} `yaml:"stores"`
			} `yaml:"tls"`
		}
		if err := yaml.Unmarshal(w.files[traefik.TLSFile], &d); err != nil {
			t.Fatal(err)
		}
		return d.TLS.Stores["default"].DefaultCertificate.CertFile
	}
	z := func(n string) config.Zone { return config.Zone{Name: n, TargetIP: "192.0.2.10"} }
	for _, tc := range []struct {
		name  string
		zones []config.Zone
		dz    string
		want  string
	}{
		{"no zones", nil, "", ""},
		{"one zone", []config.Zone{z("example.test")}, "", "/certs/example-test-wildcard/v1/fullchain.pem"},
		{"two zones without default_zone", []config.Zone{z("example.test"), z("other.test")}, "", ""},
		{"two zones with default_zone", []config.Zone{z("example.test"), z("other.test")}, "other.test", "/certs/other-wildcard/v1/fullchain.pem"},
	} {
		w.cfg.Zones, w.cfg.Settings.DefaultZone = tc.zones, tc.dz
		w.render()
		if got := defaultOf(); got != tc.want {
			t.Fatalf("%s: default %q want %q", tc.name, got, tc.want)
		}
	}
}
