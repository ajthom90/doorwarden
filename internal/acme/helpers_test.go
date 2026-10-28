package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/ajthom90/doorwarden/internal/store"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// testCA issues leaf certificates for fake orders.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t testing.TB) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "doorwarden test CA"},
		NotBefore: t0.Add(-24 * time.Hour), NotAfter: t0.Add(10 * 365 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{key: k, cert: c}
}

var serial int64 = 100

// leaf returns a fullchain PEM and key PEM for names expiring at notAfter.
func (ca *testCA) leaf(t testing.TB, names []string, notAfter time.Time) (chain, key []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

// fakeCA is a scripted obtain function.
type fakeCA struct {
	t  testing.TB
	ca *testCA
	mu sync.Mutex
	// fail, when set, returns this error for the next orders.
	fail error
	// lifetime of issued certs (from the clock's now).
	lifetime time.Duration
	clock    *clock
	orders   []order
	// block, when non-nil, makes obtain wait for it.
	block chan struct{}
	// lastKey is the key PEM of the last issued cert.
	lastKey []byte
}

func (f *fakeCA) obtain(ctx context.Context, o order) (obtained, error) {
	f.mu.Lock()
	f.orders = append(f.orders, o)
	fail, block := f.fail, f.block
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	if fail != nil {
		return obtained{}, fail
	}
	chain, key := f.ca.leaf(f.t, o.Names, f.clock.Now().Add(f.lifetime))
	f.mu.Lock()
	f.lastKey = key
	f.mu.Unlock()
	return obtained{ChainPEM: chain, KeyPEM: key}, nil
}

func (f *fakeCA) setFail(err error) { f.mu.Lock(); f.fail = err; f.mu.Unlock() }
func (f *fakeCA) count() int        { f.mu.Lock(); defer f.mu.Unlock(); return len(f.orders) }
func (f *fakeCA) last() order       { f.mu.Lock(); defer f.mu.Unlock(); return f.orders[len(f.orders)-1] }

type fakeDNSProvider struct{ name string }

func (fakeDNSProvider) Present(string, string, string) error { return nil }
func (fakeDNSProvider) CleanUp(string, string, string) error { return nil }

// testConfig: zone example.test (wildcard, dns-01 via cf), zone
// other.test (per-host), zone noissuer.test (no issuer).
func testConfig() *config.Config {
	return &config.Config{
		Zones: []config.Zone{
			{Name: "example.test", TargetIP: "192.0.2.10", Certificate: config.Certificate{Issuer: "le", Strategy: "wildcard", Challenge: "dns-01", DNSProvider: "cf"}},
			{Name: "other.test", TargetIP: "192.0.2.10", Certificate: config.Certificate{Issuer: "le", Strategy: "per-host", Challenge: "dns-01", DNSProvider: "r53"}},
			{Name: "noissuer.test", TargetIP: "192.0.2.10"},
		},
		Providers: map[string]config.ProviderCfg{
			"cf":  {Type: "cloudflare", Extra: map[string]any{"cf_dns_api_token": "cf-secret-token", "api_token": "ignored"}},
			"r53": {Type: "route53", Extra: map[string]any{"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "r53-secret", "AWS_REGION": "us-east-1"}},
		},
		Issuers:  map[string]config.Issuer{"le": {Directory: "staging", Email: "admin@example.test"}},
		Settings: config.Settings{RenewBefore: 30 * 24 * time.Hour},
	}
}

type harness struct {
	m     *Manager
	st    *store.Store
	ca    *fakeCA
	clock *clock
	dir   string
	logs  *syncBuffer
	box   *secrets.Box
	evs   *events
}

type events struct {
	mu  sync.Mutex
	evs []Event
}

func (e *events) Notify(_ context.Context, ev Event) {
	e.mu.Lock()
	e.evs = append(e.evs, ev)
	e.mu.Unlock()
}
func (e *events) list() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Event(nil), e.evs...)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newHarness(t *testing.T, cfg *config.Config, mod func(*ManagerConfig)) *harness {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secrets.NewBox("test-master-key-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		cfg = testConfig()
	}
	c := &clock{t: t0}
	logs := &syncBuffer{}
	evs := &events{}
	dir := filepath.Join(t.TempDir(), "certs")
	mc := ManagerConfig{Config: cfg, Store: st, Box: box, CertsDir: dir, Now: c.Now, Jitter: func() float64 { return 0 },
		ProviderByName: func(name string) (challenge.Provider, error) { return fakeDNSProvider{name}, nil },
		HTTP01Provider: func() (challenge.Provider, error) { return fakeDNSProvider{"http"}, nil },
		Logger:         slog.New(slog.NewTextHandler(io.MultiWriter(logs), &slog.HandlerOptions{Level: slog.LevelDebug})),
		Notifier:       evs,
	}
	if mod != nil {
		mod(&mc)
	}
	m, err := NewManager(mc)
	if err != nil {
		t.Fatal(err)
	}
	ca := &fakeCA{t: t, ca: newTestCA(t), lifetime: 90 * 24 * time.Hour, clock: c}
	m.obtain = ca.obtain
	return &harness{m: m, st: st, ca: ca, clock: c, dir: dir, logs: logs, box: box, evs: evs}
}

func (h *harness) row(t *testing.T, id string) store.Cert {
	t.Helper()
	r, ok, err := h.m.certRow(context.Background(), id)
	if err != nil || !ok {
		t.Fatalf("row %s: %v %v", id, ok, err)
	}
	return r
}

func openStore(t *testing.T) (*store.Store, error) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, nil
}

func newBox() (*secrets.Box, error) { return secrets.NewBox("test-master-key-0123456789") }

type errTest string

func (e errTest) Error() string { return string(e) }

func fmtS(f string, a ...any) string { return fmt.Sprintf(f, a...) }
