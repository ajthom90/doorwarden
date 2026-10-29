package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/acme"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

// testCA is a throwaway CA generated per test (never a real certificate).
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k}
}

// leaf returns fullchain (leaf + CA) and key PEM for names.
func (ca *testCA) leaf(t *testing.T, notAfter time.Time, names ...string) (chain, key []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
	kd, _ := x509.MarshalECPrivateKey(k)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

// npmTree lays out NPM's letsencrypt directory the way certbot does:
// live/npm-N/*.pem are symlinks into archive/npm-N/*1.pem.
func npmTree(t *testing.T, certs map[int][2][]byte) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "letsencrypt")
	for id, c := range certs {
		n := "npm-" + string(rune('0'+id))
		arch := filepath.Join(root, "archive", n)
		live := filepath.Join(root, "live", n)
		for _, d := range []string{arch, live} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for i, f := range []string{"fullchain", "privkey"} {
			if err := os.WriteFile(filepath.Join(arch, f+"1.pem"), c[i], 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join("..", "..", "archive", n, f+"1.pem"), filepath.Join(live, f+".pem")); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

const certsCfg = `zones:
  - name: example.test
    target_ip: 192.0.2.10
    certificate: {issuer: le, strategy: wildcard, challenge: dns-01, dns_provider: chal}
providers:
  chal: {type: cloudflare, cf_dns_api_token: "${CF_TOKEN}"}
issuers:
  le: {directory: staging, email: admin@example.test}
traefik: {dynamic_dir: /tmp}
acme: {certs_dir: "@CERTS@"}
`

type certsEnv struct {
	db, cfg, certs, npm string
	wildNotAfter        time.Time
}

func newCertsEnv(t *testing.T) *certsEnv {
	t.Helper()
	t.Setenv("DOORWARDEN_MASTER_KEY", testMasterKey)
	ca := newTestCA(t, "Test NPM CA R1")
	e := &certsEnv{db: adminDB(t, false), certs: filepath.Join(t.TempDir(), "certs"),
		wildNotAfter: time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)}
	wc, wk := ca.leaf(t, e.wildNotAfter, "*.example.test", "example.test")
	hc, hk := ca.leaf(t, time.Now().Add(80*24*time.Hour), "app.example.test")
	oc, ok := ca.leaf(t, time.Now().Add(80*24*time.Hour), "www.elsewhere.test")
	e.npm = npmTree(t, map[int][2][]byte{1: {wc, wk}, 2: {hc, hk}, 3: {oc, ok}})
	e.cfg = writeFile(t, "dw.yaml", strings.Replace(certsCfg, "@CERTS@", e.certs, 1))
	return e
}

func certsRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	errb := cliIO(t, "")
	var out bytes.Buffer
	c := run(append([]string{"certs", "import-npm"}, args...), &out)
	return c, out.String(), errb.String()
}

// -dry-run checks everything and writes nothing.
func TestCertsImportNPMDryRun(t *testing.T) {
	e := newCertsEnv(t)
	t.Setenv("DOORWARDEN_MASTER_KEY", "")
	c, out, errs := certsRun(t, "-npm-dir", e.npm, "-config", e.cfg, "-db", e.db, "-dry-run")
	if c != 1 { // npm-3 lies outside every zone
		t.Fatalf("exit %d\n%s\n%s", c, out, errs)
	}
	for _, w := range []string{"would import", "*.example.test, example.test", "app.example.test", "Test NPM CA R1",
		"2 certificate(s) would import, 1 failed", "Dry run: nothing was written", "no configured zone"} {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q:\n%s", w, out)
		}
	}
	if rows, _ := openDB(t, e.db).ListCerts(context.Background()); len(rows) != 0 {
		t.Fatalf("dry run wrote rows: %+v", rows)
	}
	if _, err := os.Stat(e.certs); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run created the certificate directory: %v", err)
	}
	if !strings.Contains(errs, "CF_TOKEN") {
		t.Fatalf("unset variable not noted: %q", errs)
	}
}

// A real import stores imported (unmanaged) rows and files the server
// serves, prints the summary, never the key, and a staging issuer never
// replaces the imported certificates.
func TestCertsImportNPM(t *testing.T) {
	e := newCertsEnv(t)
	// The letsencrypt directory, its live/ and one npm-N are accepted.
	c, out, errs := certsRun(t, "-npm-dir", filepath.Join(e.npm, "live", "npm-1"), "-config", e.cfg, "-db", e.db)
	if c != 0 {
		t.Fatalf("exit %d\n%s\n%s", c, out, errs)
	}
	c, out, errs = certsRun(t, "-npm-dir", e.npm, "-config", e.cfg, "-db", e.db)
	if c != 1 {
		t.Fatalf("exit %d (npm-3 must fail)\n%s\n%s", c, out, errs)
	}
	if strings.Contains(out+errs, "PRIVATE KEY") {
		t.Fatal("key material printed")
	}
	for _, w := range []string{"imported  ", "id:        imported-example_test-", "not after: " + e.wildNotAfter.UTC().Format(time.RFC3339),
		"issuer:    Test NPM CA R1", "2 certificate(s) imported, 1 failed", "staging issuer never replaces", "zone example.test: issuer le (directory staging)"} {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q:\n%s", w, out)
		}
	}
	st := openDB(t, e.db)
	rows, err := st.ListCerts(context.Background())
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v %v", rows, err)
	}
	var wild string
	for _, r := range rows {
		if r.Managed || r.Status != acme.StatusImported || r.Path == "" {
			t.Fatalf("row %+v", r)
		}
		for _, f := range []string{acme.FullchainFile, acme.PrivkeyFile} {
			if _, err := os.Stat(filepath.Join(e.certs, filepath.FromSlash(r.Path), f)); err != nil {
				t.Fatal(err)
			}
		}
		if strings.Contains(r.DomainsJSON, "*.example.test") {
			wild = r.ID
		}
	}
	if wild == "" {
		t.Fatal("wildcard not imported")
	}

	// The server's manager later finds the wildcard due with a staging
	// issuer: renewal is refused and the imported certificate stays.
	cfg, _, err := cliConfig(e.cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.NewBox(testMasterKey)
	mgr, err := acme.NewManager(acme.ManagerConfig{Config: cfg, Store: st, Box: box, CertsDir: e.certs,
		Now:    func() time.Time { return e.wildNotAfter.Add(-24 * time.Hour) },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), DeferStartupCleanup: true})
	if err != nil {
		t.Fatal(err)
	}
	var sawWild bool
	for _, r := range mgr.Renew(context.Background()) {
		if r.CertID == wild {
			sawWild = true
			if !errors.Is(r.Err, acme.ErrImportedStaging) {
				t.Fatalf("staging renewal of the imported wildcard: %v", r.Err)
			}
		}
	}
	if !sawWild {
		t.Fatal("wildcard not considered by Renew")
	}
	after, _ := st.ListCerts(context.Background())
	for _, r := range after {
		if r.ID == wild && (r.Managed || r.Status != acme.StatusImported) {
			t.Fatalf("imported wildcard replaced: %+v", r)
		}
	}
}

func TestCertsImportNPMRefusals(t *testing.T) {
	e := newCertsEnv(t)
	if c, _, _ := certsRun(t, "-config", e.cfg, "-db", e.db); c == 0 {
		t.Fatal("missing -npm-dir accepted")
	}
	if c, _, _ := certsRun(t, "-npm-dir", filepath.Join(t.TempDir(), "nope"), "-config", e.cfg, "-db", e.db); c == 0 {
		t.Fatal("missing npm dir accepted")
	}
	if c, _, _ := certsRun(t, "-npm-dir", e.npm, "-config", e.cfg, "-db", filepath.Join(t.TempDir(), "nope.db")); c == 0 {
		t.Fatal("missing database accepted")
	}
	t.Setenv("DOORWARDEN_MASTER_KEY", "")
	if c, _, errs := certsRun(t, "-npm-dir", e.npm, "-config", e.cfg, "-db", e.db); c == 0 || !strings.Contains(errs, "DOORWARDEN_MASTER_KEY") {
		t.Fatalf("no master key: %d %s", c, errs)
	}
	t.Setenv("DOORWARDEN_MASTER_KEY", testMasterKey)
	old := dbOwner
	dbOwner = func(string) (int, bool) { return 4242, true }
	t.Cleanup(func() { dbOwner = old })
	if c, _, errs := certsRun(t, "-npm-dir", e.npm, "-config", e.cfg, "-db", e.db); c == 0 || !strings.Contains(errs, "uid 4242") {
		t.Fatalf("foreign owner: %d %s", c, errs)
	}
	dbOwner = old
	if rows, _ := openDB(t, e.db).ListCerts(context.Background()); len(rows) != 0 {
		t.Fatalf("refused runs wrote rows: %+v", rows)
	}
	var out bytes.Buffer
	cliIO(t, "")
	if c := run([]string{"certs"}, &out); c != 2 {
		t.Fatal("certs without action")
	}
}
