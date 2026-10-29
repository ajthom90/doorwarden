package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/ajthom90/doorwarden/internal/acme"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/providers/fake"
	"github.com/ajthom90/doorwarden/internal/metrics"
	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/ajthom90/doorwarden/internal/store"
)

func scrape(t *testing.T, a *App) string {
	t.Helper()
	rec := httptest.NewRecorder()
	a.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

// metricValue returns the value of the series line starting with series
// ("" when absent).
func metricValue(body, series string) string {
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, series+" ") {
			return strings.TrimSpace(strings.TrimPrefix(l, series))
		}
	}
	return ""
}

// A live cycle counts the provider listing and the record it creates;
// update and delete are counted too, errors as errors.
func TestDNSOperationMetrics(t *testing.T) {
	e := newEnv(t, testYAML)
	met := metrics.New("test")
	e.src.set(nil, svc("docker", "app"))
	a := e.app(func(o *Options) { o.Metrics = met })
	if res := a.RunOnce(context.Background()); res.Err != nil {
		t.Fatal(res.Err)
	}
	body := scrape(t, a)
	if v := metricValue(body, `doorwarden_dns_operations_total{op="ensure",provider_type="fake",result="ok"}`); v != "1" {
		t.Fatalf("ensure = %q\n%s", v, body)
	}
	if v := metricValue(body, `doorwarden_dns_operations_total{op="list",provider_type="fake",result="ok"}`); v == "" || v == "0" {
		t.Fatalf("list = %q", v)
	}
	before := metricValue(body, `doorwarden_dns_operations_total{op="list",provider_type="fake",result="ok"}`)
	// A cycle with nothing to write lists the zone once and counts it
	// once (the observation is not counted twice).
	listsBefore := len(e.fk.Calls())
	a.RunOnce(context.Background())
	if n := len(e.fk.Calls()) - listsBefore; n != 1 {
		t.Fatalf("provider calls in a quiet cycle = %d", n)
	}
	after := metricValue(scrape(t, a), `doorwarden_dns_operations_total{op="list",provider_type="fake",result="ok"}`)
	if b, a2 := atoi(before), atoi(after); a2 != b+1 {
		t.Fatalf("list counts %s then %s, want +1", before, after)
	}

	p := &meteredProvider{Provider: fake.New(true), met: met}
	ctx := context.Background()
	r, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "x.example.test", Type: "A", Value: "192.0.2.1", TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
	r.Value = "192.0.2.2"
	if _, err := p.UpdateRecord(ctx, "example.test", r); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteRecord(ctx, "example.test", r); err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpdateRecord(ctx, "example.test", dns.Record{ID: "missing", Name: "y.example.test", Type: "A", Value: "192.0.2.3"}); err == nil {
		t.Fatal("update of a missing record succeeded")
	}
	body = scrape(t, a)
	for series, want := range map[string]string{
		`doorwarden_dns_operations_total{op="update",provider_type="fake",result="ok"}`:    "1",
		`doorwarden_dns_operations_total{op="update",provider_type="fake",result="error"}`: "1",
		`doorwarden_dns_operations_total{op="delete",provider_type="fake",result="ok"}`:    "1",
	} {
		if v := metricValue(body, series); v != want {
			t.Errorf("%s = %q, want %s", series, v, want)
		}
	}
}

// cert_expiry_seconds comes from the cert rows every cycle, dry run
// included.
func TestCertExpiryMetricDryRun(t *testing.T) {
	e := newEnv(t, testYAML)
	e.cfg.Settings.DryRun = true
	if err := e.st.UpsertCert(context.Background(), store.Cert{ID: "c1", Zone: "example.test", DomainsJSON: `["*.example.test"]`,
		NotAfter: time.Now().Add(48 * time.Hour), Status: "imported", Path: "c1/v1"}); err != nil {
		t.Fatal(err)
	}
	a := e.app(func(o *Options) { o.Metrics = metrics.New("test") })
	res := a.RunOnce(context.Background())
	if !res.DryRun || res.Rendered {
		t.Fatalf("not a dry cycle: %+v", res)
	}
	v := metricValue(scrape(t, a), `doorwarden_cert_expiry_seconds{zone="example.test"}`)
	if v == "" {
		t.Fatal("no expiry series after a dry cycle")
	}
}

var renewErrRe = regexp.MustCompile(`doorwarden_cert_renewal_total\{result="error"\} (\d+)`)

// A cycle's CertEnsure attempt counts in cert_renewal_total; the deferral
// on the next cycle (backoff) does not. The API's renew of an unknown
// certificate is no attempt either.
func TestCertRenewalCountsCertEnsure(t *testing.T) {
	dir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer dir.Close()
	yml := strings.Replace(testYAML, "    records: {provider: fk, mode: per-host}\n",
		"    records: {provider: fk, mode: per-host}\n    certificate: {issuer: le, strategy: per-host, challenge: dns-01, dns_provider: chal}\n", 1)
	yml = strings.Replace(yml, "  fk: {type: fake}\n", "  fk: {type: fake}\n  chal: {type: cloudflare, cf_dns_api_token: tok}\n", 1)
	yml += "issuers:\n  le: {directory: \"" + dir.URL + "/directory\", email: admin@example.test}\n"
	e := newEnv(t, yml)
	box, err := secrets.NewBox("test-master-key-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := acme.NewManager(acme.ManagerConfig{Config: e.cfg, Store: e.st, Box: box, CertsDir: e.certs,
		ProviderByName:      func(string) (challenge.Provider, error) { return nopChallenge{}, nil },
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		DeferStartupCleanup: true, IssueTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	e.src.set(nil, svc("docker", "app"))
	a := e.app(func(o *Options) { o.ACME = mgr; o.Metrics = metrics.New("test") })
	if res := a.RunOnce(context.Background()); res.Err == nil {
		t.Fatal("order unexpectedly succeeded")
	}
	m := renewErrRe.FindStringSubmatch(scrape(t, a))
	if m == nil || m[1] != "1" {
		t.Fatalf("renewal errors after the first attempt: %v", m)
	}
	a.RunOnce(context.Background()) // deferred by backoff: no attempt
	if err := a.RenewCert(context.Background(), "no-such-cert"); !errors.Is(err, acme.ErrNotFound) {
		t.Fatalf("RenewCert: %v", err)
	}
	if m := renewErrRe.FindStringSubmatch(scrape(t, a)); m == nil || m[1] != "1" {
		t.Fatalf("non-attempts counted: %v", m)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}
