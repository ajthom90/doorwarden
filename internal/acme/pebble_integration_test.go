//go:build integration

// Integration tests against Pebble, Let's Encrypt's test ACME server, with
// pebble-challtestsrv as its DNS resolver and HTTP-01 responder.
//
// Run:
//
//	docker compose -f deploy/test/docker-compose.pebble.yml up -d
//	go test -tags integration ./internal/acme/...
//	docker compose -f deploy/test/docker-compose.pebble.yml down
//
// Endpoints (override with env): PEBBLE_DIRECTORY (default
// https://localhost:14000/dir), PEBBLE_EAB_DIRECTORY (default
// https://localhost:14001/dir), CHALLTESTSRV (default
// http://localhost:8055). Rate limiting cannot be simulated with Pebble;
// it is covered by unit tests with a canned problem document
// (TestRateLimitParking, TestLegoEABAccountAndRateLimitPark).
package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/ajthom90/doorwarden/internal/config"
)

// Pebble's published test MAC key for kid-1 (pebble-config-external-account-bindings.json).
const pebbleEABKid, pebbleEABHMAC = "kid-1", "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

var (
	pebbleDir    = envOr("PEBBLE_DIRECTORY", "https://localhost:14000/dir")
	pebbleEABDir = envOr("PEBBLE_EAB_DIRECTORY", "https://localhost:14001/dir")
	challtestsrv = envOr("CHALLTESTSRV", "http://localhost:8055")
)

func challPost(t testing.TB, path string, body any) error {
	b, _ := json.Marshal(body)
	resp, err := http.Post(challtestsrv+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv %s: %s", path, resp.Status)
	}
	return nil
}

// challDNS is a lego DNS provider that publishes TXT records through
// challtestsrv's management API. When broken is set it publishes a wrong
// value, so validation fails at the CA.
type challDNS struct {
	t       testing.TB
	broken  *atomic.Bool
	present *atomic.Int32
}

func (p challDNS) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	v := info.Value
	if p.broken.Load() {
		v = "wrong-value"
	}
	p.present.Add(1)
	return challPost(p.t, "/set-txt", map[string]string{"host": info.EffectiveFQDN, "value": v})
}

func (p challDNS) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return challPost(p.t, "/clear-txt", map[string]string{"host": info.EffectiveFQDN})
}

// challHTTP is a lego HTTP-01 provider backed by challtestsrv.
type challHTTP struct{ t testing.TB }

func (p challHTTP) Present(_, token, keyAuth string) error {
	return challPost(p.t, "/add-http01", map[string]string{"token": token, "content": keyAuth})
}

func (p challHTTP) CleanUp(_, token, _ string) error {
	return challPost(p.t, "/del-http01", map[string]string{"token": token})
}

type pebbleEnv struct {
	*harness
	broken  *atomic.Bool
	present *atomic.Int32
}

// pebbleHarness builds a Manager talking to Pebble with real lego.
// Every test gets its own zones (so challtestsrv records never collide)
// and its own store (so its own ACME account).
func pebbleHarness(t *testing.T, zones []config.Zone, eab bool) *pebbleEnv {
	t.Helper()
	if _, err := http.Get(challtestsrv); err != nil && strings.Contains(err.Error(), "refused") {
		t.Skip("pebble stack not running: docker compose -f deploy/test/docker-compose.pebble.yml up -d")
	}
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true") // no CNAME lookups against real DNS
	cfg := testConfig()
	cfg.Zones = zones
	iss := config.Issuer{Directory: pebbleDir, Email: "admin@example.test"}
	if eab {
		iss = config.Issuer{Directory: pebbleEABDir, Email: "admin@example.test", EABKid: pebbleEABKid, EABHMAC: pebbleEABHMAC}
	}
	cfg.Issuers = map[string]config.Issuer{"pebble": iss}
	env := &pebbleEnv{broken: &atomic.Bool{}, present: &atomic.Int32{}}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		// Pebble serves a throwaway certificate for localhost.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test CA
	}}
	h := newHarness(t, cfg, func(mc *ManagerConfig) {
		mc.HTTPClient = client
		mc.ProviderByName = func(string) (challenge.Provider, error) {
			return challDNS{t: t, broken: env.broken, present: env.present}, nil
		}
		mc.HTTP01Provider = func() (challenge.Provider, error) { return challHTTP{t}, nil }
		// challtestsrv's DNS is not reachable from the host: skip lego's
		// client-side propagation check (Pebble still validates via DNS).
		mc.DNS01Options = []dns01.ChallengeOption{dns01.PropagationWait(0, true)}
		mc.IssueTimeout = 2 * time.Minute
	})
	h.m.obtain = h.m.legoObtain
	h.clock.mu.Lock()
	h.clock.t = time.Now()
	h.clock.mu.Unlock()
	env.harness = h
	return env
}

func pzone(name, strategy, ch string) config.Zone {
	return config.Zone{Name: name, TargetIP: "192.0.2.10",
		Certificate: config.Certificate{Issuer: "pebble", Strategy: strategy, Challenge: ch, DNSProvider: "cf"}}
}

func ictx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	return c
}

// leafOf reads the row's current fullchain.pem and checks that privkey.pem
// matches.
func leafOf(t *testing.T, h *harness, id string) *x509.Certificate {
	t.Helper()
	chain, err := os.ReadFile(h.certFile(t, id, FullchainFile))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(h.certFile(t, id, PrivkeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(chain, key); err != nil {
		t.Fatalf("stored key does not match chain: %v", err)
	}
	b, _ := pem.Decode(chain)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sameNames(c *x509.Certificate, want ...string) bool {
	got := slices.Clone(c.DNSNames)
	slices.Sort(got)
	w := slices.Clone(want)
	slices.Sort(w)
	return slices.Equal(got, w)
}

func checkModes(t *testing.T, h *harness, id string) {
	t.Helper()
	for p, want := range map[string]os.FileMode{
		h.dir: 0o700, filepath.Join(h.dir, id): 0o700, filepath.Dir(h.certFile(t, id, FullchainFile)): 0o700,
		h.certFile(t, id, FullchainFile): 0o600, h.certFile(t, id, PrivkeyFile): 0o600,
	} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s: mode %o, want %o", p, st.Mode().Perm(), want)
		}
	}
}

func TestPebbleWildcardDNS01(t *testing.T) {
	e := pebbleHarness(t, []config.Zone{pzone("wild.example.test", "wildcard", "dns-01")}, false)
	b, err := e.m.Issue(ictx(t), IssueRequest{Zone: "wild.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	c := leafOf(t, e.harness, b.ID)
	if !sameNames(c, "*.wild.example.test", "wild.example.test") {
		t.Fatalf("names %v", c.DNSNames)
	}
	if r := e.row(t, b.ID); r.Status != StatusValid || !r.Managed || !r.NotAfter.Equal(c.NotAfter.UTC().Truncate(time.Second)) && !r.NotAfter.Equal(c.NotAfter) {
		t.Fatalf("row %+v (leaf %v)", r, c.NotAfter)
	}
	checkModes(t, e.harness, b.ID)
	if e.present.Load() < 2 {
		t.Fatalf("expected TXT records for wildcard and apex, got %d", e.present.Load())
	}
}

func TestPebbleRenewWithForcedClock(t *testing.T) {
	e := pebbleHarness(t, []config.Zone{pzone("renew.example.test", "wildcard", "dns-01")}, false)
	// Pebble picks certificate lifetimes from its profiles (6 or 90 days),
	// so renew 1h before expiry instead of the 30-day default.
	e.m.renewBefore = time.Hour
	b, err := e.m.Issue(ictx(t), IssueRequest{Zone: "renew.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	first := leafOf(t, e.harness, b.ID)
	t.Logf("issued %s, not after %s (clock %s)", first.SerialNumber, first.NotAfter, e.clock.Now())
	if res := e.m.Renew(ictx(t)); len(res) != 0 {
		t.Fatalf("fresh cert renewed: %+v", res)
	}
	// Move the clock to 30 minutes before expiry: inside renew_before.
	e.clock.Add(first.NotAfter.Sub(e.clock.Now()) - 30*time.Minute)
	res := e.m.Renew(ictx(t))
	if len(res) != 1 || res[0].Err != nil {
		t.Fatalf("%+v", res)
	}
	second := leafOf(t, e.harness, b.ID)
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("certificate not replaced")
	}
	checkModes(t, e.harness, b.ID)
}

func TestPebbleHTTP01(t *testing.T) {
	e := pebbleHarness(t, []config.Zone{pzone("web.example.test", "per-host", "http-01")}, false)
	res := e.m.IssueAll(ictx(t), IssueRequest{Zone: "web.example.test", Names: []string{"app.web.example.test"}})
	if len(res) != 1 || res[0].Err != nil {
		t.Fatalf("%+v", res)
	}
	if c := leafOf(t, e.harness, res[0].CertID); !sameNames(c, "app.web.example.test") {
		t.Fatalf("names %v", c.DNSNames)
	}
	// Wildcards are refused for http-01 before any CA contact.
	_, err := e.m.Issue(ictx(t), IssueRequest{Zone: "web.example.test", Names: []string{"*.web.example.test"}})
	if !errors.Is(err, ErrWildcardNeedsDNS01) {
		t.Fatalf("%v", err)
	}
}

func TestPebblePerHostAndSAN(t *testing.T) {
	e := pebbleHarness(t, []config.Zone{
		pzone("ph.example.test", "per-host", "dns-01"),
		pzone("san.example.test", "san", "dns-01"),
	}, false)
	res := e.m.IssueAll(ictx(t), IssueRequest{Zone: "ph.example.test", Names: []string{"a.ph.example.test", "b.ph.example.test"}})
	if len(res) != 2 {
		t.Fatalf("%d results", len(res))
	}
	for _, r := range res {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		if c := leafOf(t, e.harness, r.CertID); len(c.DNSNames) != 1 || c.DNSNames[0] != r.Names[0] {
			t.Fatalf("per-host cert names %v", c.DNSNames)
		}
	}
	res = e.m.IssueAll(ictx(t), IssueRequest{Zone: "san.example.test", Names: []string{"a.san.example.test", "b.san.example.test", "c.san.example.test"}})
	if len(res) != 1 || res[0].Err != nil {
		t.Fatalf("%+v", res)
	}
	if c := leafOf(t, e.harness, res[0].CertID); !sameNames(c, "a.san.example.test", "b.san.example.test", "c.san.example.test") {
		t.Fatalf("san names %v", c.DNSNames)
	}
}

func TestPebbleFailureKeepsOldCertAndBacksOff(t *testing.T) {
	e := pebbleHarness(t, []config.Zone{pzone("fail.example.test", "wildcard", "dns-01")}, false)
	b, err := e.m.Issue(ictx(t), IssueRequest{Zone: "fail.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(e.certFile(t, b.ID, FullchainFile))
	keyBefore, _ := os.ReadFile(e.certFile(t, b.ID, PrivkeyFile))
	rowBefore := e.row(t, b.ID)

	e.broken.Store(true)
	r := e.m.RenewNow(ictx(t), b.ID)
	if r.Err == nil {
		t.Fatal("renewal with wrong TXT value succeeded")
	}
	t.Logf("CA rejected as expected: %v", r.Err)
	after, _ := os.ReadFile(e.certFile(t, b.ID, FullchainFile))
	keyAfter, _ := os.ReadFile(e.certFile(t, b.ID, PrivkeyFile))
	if !bytes.Equal(before, after) || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("failure replaced the previous certificate files")
	}
	row := e.row(t, b.ID)
	if !row.NotAfter.Equal(rowBefore.NotAfter) || row.Status != StatusValid || row.LastResult != "error" || row.LastError == "" {
		t.Fatalf("row %+v", row)
	}
	// Backoff: the next (non-forced) attempt is deferred without an order.
	n := e.present.Load()
	_, err = e.m.Issue(ictx(t), IssueRequest{Zone: "fail.example.test"})
	if !errors.Is(err, ErrDeferred) || e.present.Load() != n {
		t.Fatalf("not deferred: %v", err)
	}
	// After the backoff, with DNS fixed, it succeeds.
	e.broken.Store(false)
	e.clock.Add(2 * time.Minute)
	if _, err := e.m.Issue(ictx(t), IssueRequest{Zone: "fail.example.test"}); err != nil {
		t.Fatal(err)
	}
	if final, _ := os.ReadFile(e.certFile(t, b.ID, FullchainFile)); bytes.Equal(final, before) {
		t.Fatal("certificate not replaced after recovery")
	}
}

func TestPebbleEAB(t *testing.T) {
	e := pebbleHarness(t, []config.Zone{pzone("eab.example.test", "wildcard", "dns-01")}, true)
	b, err := e.m.Issue(ictx(t), IssueRequest{Zone: "eab.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	leafOf(t, e.harness, b.ID)
	checkModes(t, e.harness, b.ID)
	if strings.Contains(e.logs.String(), pebbleEABHMAC) {
		t.Fatal("EAB HMAC logged")
	}

	// Without EAB the EAB-only CA refuses the account.
	e2 := pebbleHarness(t, []config.Zone{pzone("noeab.example.test", "wildcard", "dns-01")}, false)
	e2.m.cfg.Issuers["pebble"] = config.Issuer{Directory: pebbleEABDir, Email: "admin@example.test"}
	if _, err := e2.m.Issue(ictx(t), IssueRequest{Zone: "noeab.example.test"}); err == nil || !strings.Contains(err.Error(), "externalAccount") && !strings.Contains(err.Error(), "external account") {
		t.Fatalf("want EAB required error, got %v", err)
	}
}

// An imported per-host certificate for a zone apex and its www (as Nginx
// Proxy Manager stores one), due, in an http-01 zone of a non-staging
// issuer: Renew adopts it by an http-01 order for exactly its names.
func TestPebbleImportedApexAdoptedByHTTP01(t *testing.T) {
	e := pebbleHarness(t, []config.Zone{pzone("imp.example.test", "per-host", "http-01")}, false)
	e.m.wanted = func(zone string) []string {
		if zone == "imp.example.test" {
			return []string{"imp.example.test", "www.imp.example.test"}
		}
		return nil
	}
	chain, key := e.ca.ca.leaf(t, []string{"imp.example.test", "www.imp.example.test"}, time.Now().Add(10*24*time.Hour))
	ir, err := e.m.ImportPEM(ictx(t), "imp.example.test", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	res := e.m.Renew(ictx(t))
	if len(res) != 1 || res[0].Err != nil || res[0].CertID != ir.Bundle.ID {
		t.Fatalf("%+v", res)
	}
	c := leafOf(t, e.harness, ir.Bundle.ID)
	if !sameNames(c, "imp.example.test", "www.imp.example.test") {
		t.Fatalf("names %v", c.DNSNames)
	}
	if r := e.row(t, ir.Bundle.ID); !r.Managed || r.Status != StatusValid {
		t.Fatalf("row %+v", r)
	}
}
