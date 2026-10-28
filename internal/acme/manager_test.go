package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/ajthom90/doorwarden/internal/config"
)

var ctx = context.Background()

func wildcardReq() IssueRequest {
	return IssueRequest{Zone: "example.test", Names: []string{"*.example.test", "example.test"}}
}

func TestIssueWildcardWritesFilesAndRow(t *testing.T) {
	h := newHarness(t, nil, nil)
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	if b.ID != certID("example.test", []string{"*.example.test", "example.test"}) || !b.Staging || !b.Managed {
		t.Fatalf("bundle %v", b)
	}
	o := h.ca.last()
	if o.Dir.URL != LEStagingURL || o.Challenge != ChallengeDNS01 || strings.Join(o.Names, ",") != "*.example.test,example.test" {
		t.Fatalf("order %+v", o)
	}
	r := h.row(t, b.ID)
	if r.Status != StatusValid || !r.Managed || !r.Staging || r.Issuer != "le" || r.Path != b.ID+"/v1" || b.Dir != r.Path || r.Zone != "example.test" ||
		!r.NotAfter.Equal(t0.Add(90*24*time.Hour)) || r.DomainsJSON != `["*.example.test","example.test"]` {
		t.Fatalf("row %+v", r)
	}
	key, _ := os.ReadFile(filepath.Join(h.dir, b.ID, "v1", PrivkeyFile))
	if !bytes.Equal(key, []byte(b.Key.Reveal())) {
		t.Fatal("key file differs from bundle key")
	}
}

func TestCertFileModes(t *testing.T) {
	h := newHarness(t, nil, nil)
	// A pre-existing, too-open certs dir and cert dir are tightened.
	if err := os.MkdirAll(filepath.Join(h.dir, certID("example.test", []string{"*.example.test", "example.test"})), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	check := func(p string, want os.FileMode) {
		t.Helper()
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s: mode %o, want %o", p, st.Mode().Perm(), want)
		}
	}
	check(h.dir, 0o700)
	check(filepath.Join(h.dir, b.ID), 0o700)
	// Every version directory and file is private; renewals leave no temp
	// files and keep exactly the current and the previous version.
	for v := 1; v <= 4; v++ {
		vd := filepath.Join(h.dir, b.ID, fmtS("v%d", v))
		check(vd, 0o700)
		check(filepath.Join(vd, FullchainFile), 0o600)
		check(filepath.Join(vd, PrivkeyFile), 0o600)
		if ents, _ := os.ReadDir(vd); len(ents) != 2 {
			t.Fatalf("v%d files %v", v, ents)
		}
		h.clock.Add(70 * 24 * time.Hour)
		if res := h.m.RenewNow(ctx, b.ID); res.Err != nil {
			t.Fatal(res.Err)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(h.dir, b.ID))
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "v4,v5" || h.row(t, b.ID).Path != b.ID+"/v5" {
		t.Fatalf("versions %v, row %s", names, h.row(t, b.ID).Path)
	}
}

func TestFailureKeepsPreviousCert(t *testing.T) {
	h := newHarness(t, nil, nil)
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	before := h.row(t, b.ID)
	chain0, _ := os.ReadFile(h.certFile(t, b.ID, FullchainFile))
	key0, _ := os.ReadFile(h.certFile(t, b.ID, PrivkeyFile))

	h.clock.Add(65 * 24 * time.Hour)
	h.ca.setFail(errors.New("challenge provider exploded"))
	res := h.m.RenewNow(ctx, b.ID)
	if res.Err == nil || res.NextAttempt.IsZero() {
		t.Fatalf("want failure, got %+v", res)
	}
	chain1, _ := os.ReadFile(h.certFile(t, b.ID, FullchainFile))
	key1, _ := os.ReadFile(h.certFile(t, b.ID, PrivkeyFile))
	if vs := certVersions(h.dir, b.ID); len(vs) != 1 {
		t.Fatalf("failed renewal left versions %v", vs)
	}
	if !bytes.Equal(chain0, chain1) || !bytes.Equal(key0, key1) {
		t.Fatal("failed renewal touched the certificate files")
	}
	after := h.row(t, b.ID)
	if !after.NotAfter.Equal(before.NotAfter) || after.Path != before.Path || after.Status != StatusValid || !after.Managed {
		t.Fatalf("row changed: %+v -> %+v", before, after)
	}
	if after.LastResult != "error" || !strings.Contains(after.LastError, "exploded") {
		t.Fatalf("row error not recorded: %+v", after)
	}
	evs := h.evs.list()
	if len(evs) != 1 || evs[0].Kind != EventFailure || evs[0].CertID != b.ID {
		t.Fatalf("events %+v", evs)
	}
}

func TestFirstFailureCreatesFailedRow(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.ca.setFail(errors.New("nope"))
	_, err := h.m.Issue(ctx, wildcardReq())
	if err == nil {
		t.Fatal("want error")
	}
	r := h.row(t, certID("example.test", []string{"*.example.test", "example.test"}))
	if r.Status != StatusFailed || !r.NotAfter.IsZero() || r.Path != "" {
		t.Fatalf("row %+v", r)
	}
	if _, err := os.Stat(filepath.Join(h.dir, r.ID)); !os.IsNotExist(err) {
		t.Fatal("files written for a failed first order")
	}
}

func TestBackoffSchedule(t *testing.T) {
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute,
		32 * time.Minute, 64 * time.Minute, 128 * time.Minute, 256 * time.Minute, 6 * time.Hour, 6 * time.Hour}
	for i, w := range want {
		if got := backoffDelay(i+1, 0); got != w {
			t.Errorf("failure %d: %v, want %v", i+1, got, w)
		}
	}
	if got := backoffDelay(1, 0.999); got <= time.Minute || got > time.Minute+6*time.Second {
		t.Errorf("jitter out of range: %v", got)
	}
	if got := backoffDelay(40, 0.999); got != 6*time.Hour {
		t.Errorf("cap with jitter: %v", got)
	}
}

func TestBackoffAppliedBetweenAttempts(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.ca.setFail(errors.New("down"))
	for i, wait := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		n := h.ca.count()
		_, err := h.m.Issue(ctx, wildcardReq())
		if err == nil || errors.Is(err, ErrDeferred) || h.ca.count() != n+1 {
			t.Fatalf("attempt %d: %v (orders %d)", i, err, h.ca.count())
		}
		// Just before the backoff ends: deferred, no order placed.
		h.clock.Add(wait - time.Second)
		_, err = h.m.Issue(ctx, wildcardReq())
		var de *DeferredError
		if !errors.As(err, &de) || h.ca.count() != n+1 {
			t.Fatalf("attempt %d inside backoff: %v", i, err)
		}
		if !de.Until.Equal(h.clock.Now().Add(time.Second)) {
			t.Fatalf("until %v", de.Until)
		}
		h.clock.Add(time.Second)
	}
	// Success resets the backoff.
	h.ca.setFail(nil)
	if _, err := h.m.Issue(ctx, wildcardReq()); err != nil {
		t.Fatal(err)
	}
	h.ca.setFail(errors.New("down again"))
	h.m.Issue(ctx, wildcardReq())
	var a attemptState
	h.m.kv.getJSON(ctx, attemptKey(certID("example.test", []string{"*.example.test", "example.test"})), &a)
	if a.Failures != 1 || !a.NextAttempt.Equal(h.clock.Now().Add(time.Minute)) {
		t.Fatalf("after reset: %+v", a)
	}
}

func rateLimited(retryAfter string) error {
	var pd legoacme.ProblemDetails
	// A canned Let's Encrypt problem document.
	doc := `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s","status":429}`
	if err := json.Unmarshal([]byte(doc), &pd); err != nil {
		panic(err)
	}
	return &legoacme.RateLimitedError{ProblemDetails: &pd, RetryAfter: retryAfter}
}

func TestRateLimitParksUntilRetryAfter(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.ca.setFail(rateLimited("7200"))
	_, err := h.m.Issue(ctx, wildcardReq())
	if err == nil {
		t.Fatal("want error")
	}
	id := certID("example.test", []string{"*.example.test", "example.test"})
	if r := h.row(t, id); r.LastResult != "rate-limited" {
		t.Fatalf("row %+v", r)
	}
	h.ca.setFail(nil)
	// Even an explicit RenewNow (which skips ordinary backoff) waits.
	h.clock.Add(2*time.Hour - time.Second)
	res := h.m.RenewNow(ctx, id)
	var de *DeferredError
	if !errors.As(res.Err, &de) || !strings.Contains(de.Reason, "rate limited") || h.ca.count() != 1 {
		t.Fatalf("inside park: %+v", res)
	}
	if !de.Until.Equal(t0.Add(2 * time.Hour)) {
		t.Fatalf("parked until %v", de.Until)
	}
	h.clock.Add(time.Second)
	if res := h.m.RenewNow(ctx, id); res.Err != nil {
		t.Fatal(res.Err)
	}
}

func TestRateLimitRetryAfterVariants(t *testing.T) {
	now := t0
	if d := rateLimitPark(rateLimited(""), now); d != time.Hour {
		t.Errorf("missing Retry-After: %v", d)
	}
	if d := rateLimitPark(rateLimited(now.Add(30*time.Minute).Format(http1123)), now); d != 30*time.Minute {
		t.Errorf("http-date: %v", d)
	}
	if d := rateLimitPark(rateLimited("99999999"), now); d != maxRateLimitPark {
		t.Errorf("huge: %v", d)
	}
	pd := &legoacme.ProblemDetails{Type: legoacme.RateLimitedErr}
	if d := rateLimitPark(errors.Join(errors.New("x"), pd), now); d != time.Hour {
		t.Errorf("bare problem: %v", d)
	}
	if d := rateLimitPark(errors.New("other"), now); d != 0 {
		t.Errorf("other: %v", d)
	}
}

const http1123 = "Mon, 02 Jan 2006 15:04:05 GMT"

func TestFailedValidationsRefuseToHammer(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.ca.setFail(errors.Join(errors.New("error: one or more domains had a problem"),
		&legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:unauthorized", Detail: "Incorrect TXT record"}))
	id := certID("example.test", []string{"*.example.test", "example.test"})
	h.m.Issue(ctx, wildcardReq())
	for range maxFailedValidations - 1 {
		h.clock.Add(time.Minute)
		if res := h.m.RenewNow(ctx, id); res.Err == nil || errors.Is(res.Err, ErrDeferred) {
			t.Fatalf("%+v", res)
		}
	}
	n := h.ca.count()
	h.clock.Add(time.Minute)
	res := h.m.RenewNow(ctx, id)
	if !errors.Is(res.Err, ErrDeferred) || !strings.Contains(res.Err.Error(), "failed validations") || h.ca.count() != n {
		t.Fatalf("not refused: %v", res.Err)
	}
	// An hour after the first failure the guard lifts.
	h.clock.Add(time.Hour)
	if res := h.m.RenewNow(ctx, id); errors.Is(res.Err, ErrDeferred) {
		t.Fatalf("still refused: %v", res.Err)
	}
}

func TestDuplicateOrderGuard(t *testing.T) {
	h := newHarness(t, nil, nil)
	id := certID("example.test", []string{"*.example.test", "example.test"})
	if _, err := h.m.Issue(ctx, wildcardReq()); err != nil {
		t.Fatal(err)
	}
	for range maxDuplicateOrders - 1 {
		h.clock.Add(time.Hour)
		if res := h.m.RenewNow(ctx, id); res.Err != nil {
			t.Fatal(res.Err)
		}
	}
	h.clock.Add(time.Hour)
	if res := h.m.RenewNow(ctx, id); !errors.Is(res.Err, ErrDeferred) {
		t.Fatalf("5th duplicate in a week allowed: %v", res.Err)
	}
	if n, _ := h.m.OrdersLastWeek(ctx, "le"); n != maxDuplicateOrders {
		t.Fatalf("orders last week %d", n)
	}
}

func TestInFlightDedupe(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.ca.block = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, err := h.m.Issue(ctx, wildcardReq()); done <- err }()
	for h.ca.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	if _, err := h.m.Issue(ctx, wildcardReq()); !errors.Is(err, ErrInFlight) {
		t.Fatalf("want ErrInFlight, got %v", err)
	}
	close(h.ca.block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestIssueTimeoutPersistsLateResult(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.ca.block = make(chan struct{})
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := h.m.Issue(cctx, wildcardReq()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	close(h.ca.block)
	id := certID("example.test", []string{"*.example.test", "example.test"})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if r, ok, _ := h.m.certRow(ctx, id); ok && r.Status == StatusValid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late result not persisted")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRenewSelectsDueCerts(t *testing.T) {
	h := newHarness(t, nil, nil)
	wild, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	h.clock.Add(30 * 24 * time.Hour) // wildcard: 60 days left
	host, err := h.m.Issue(ctx, IssueRequest{Zone: "other.test", Names: []string{"app.other.test"}})
	if err != nil {
		t.Fatal(err)
	}
	h.clock.Add(31 * 24 * time.Hour) // wildcard: 29 days left (due), host: 59 days
	n := h.ca.count()
	res := h.m.Renew(ctx)
	if len(res) != 1 || res[0].CertID != wild.ID || res[0].Err != nil || h.ca.count() != n+1 {
		t.Fatalf("renew %+v", res)
	}
	if r := h.row(t, wild.ID); !r.NotAfter.Equal(h.clock.Now().Add(90 * 24 * time.Hour)) {
		t.Fatalf("not renewed: %+v", r)
	}
	if r := h.row(t, host.ID); !r.NotAfter.Equal(t0.Add(120 * 24 * time.Hour)) {
		t.Fatalf("host touched: %+v", r)
	}
	// Nothing due now.
	if res := h.m.Renew(ctx); len(res) != 0 {
		t.Fatalf("second renew %+v", res)
	}
}

func TestRenewBeforeFromSettings(t *testing.T) {
	cfg := testConfig()
	cfg.Settings.RenewBefore = 70 * 24 * time.Hour
	h := newHarness(t, cfg, nil)
	if _, err := h.m.Issue(ctx, wildcardReq()); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(21 * 24 * time.Hour) // 69 days left
	if res := h.m.Renew(ctx); len(res) != 1 || res[0].Err != nil {
		t.Fatalf("%+v", res)
	}
}

func TestImportedCertNotAutoRenewed(t *testing.T) {
	h := newHarness(t, nil, nil)
	// Not yet within renew_before: Renew leaves it alone (adoption of a
	// due imported cert: TestImportedAdoptedOnlyWhenDueAndZoneHasIssuer).
	chain, key := h.ca.ca.leaf(t, []string{"*.example.test", "example.test"}, t0.Add(60*24*time.Hour))
	ir, err := h.m.ImportPEM(ctx, "example.test", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	r := h.row(t, ir.Bundle.ID)
	if r.Managed || r.Status != StatusImported || r.Issuer != "" {
		t.Fatalf("row %+v", r)
	}
	res := h.m.Renew(ctx)
	if len(res) != 0 || h.ca.count() != 0 {
		t.Fatalf("renew %+v (orders %d)", res, h.ca.count())
	}
	if r := h.row(t, ir.Bundle.ID); r.Managed {
		t.Fatal("imported cert silently became managed")
	}
	// Explicit RenewNow switches it to managed under the same id.
	rn := h.m.RenewNow(ctx, ir.Bundle.ID)
	if rn.Err != nil {
		t.Fatal(rn.Err)
	}
	r = h.row(t, ir.Bundle.ID)
	if !r.Managed || r.Status != StatusValid || r.Issuer != "le" || h.ca.count() != 1 {
		t.Fatalf("after RenewNow %+v", r)
	}
}

func TestImportedCertWithoutIssuerCannotRenew(t *testing.T) {
	h := newHarness(t, nil, nil)
	chain, key := h.ca.ca.leaf(t, []string{"app.noissuer.test"}, t0.Add(10*24*time.Hour))
	ir, err := h.m.ImportPEM(ctx, "noissuer.test", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	if res := h.m.RenewNow(ctx, ir.Bundle.ID); !errors.Is(res.Err, ErrNoIssuer) || h.ca.count() != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestSwitchIssuerStagingToProduction(t *testing.T) {
	h := newHarness(t, nil, nil)
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil || !b.Staging {
		t.Fatal(b, err)
	}
	// Renew never switches on its own.
	h.clock.Add(70 * 24 * time.Hour)
	h.m.Renew(ctx)
	if o := h.ca.last(); o.Dir.URL != LEStagingURL {
		t.Fatalf("renew used %s", o.Dir.URL)
	}
	if _, err := h.m.SwitchIssuer(ctx, "le", "staging"); err == nil {
		t.Fatal("switch to staging accepted")
	}
	res, err := h.m.SwitchIssuer(ctx, "le", "production")
	if err != nil || len(res) != 1 || res[0].Err != nil {
		t.Fatalf("%+v %v", res, err)
	}
	if o := h.ca.last(); o.Dir.URL != LEProductionURL {
		t.Fatalf("switch used %s", o.Dir.URL)
	}
	if r := h.row(t, b.ID); r.Staging || !strings.HasPrefix(r.Path, b.ID+"/v") {
		t.Fatalf("row %+v", r)
	}
	// New issuance now goes to production.
	if b2, err := h.m.Issue(ctx, IssueRequest{Zone: "other.test", Names: []string{"x.other.test"}}); err != nil || b2.Staging {
		t.Fatal(b2, err)
	}
}

func TestExpiryNotificationsDeduped(t *testing.T) {
	cfg := testConfig()
	cfg.Settings.RenewBefore = time.Hour // keep Renew from renewing
	h := newHarness(t, cfg, nil)
	b, _ := h.m.Issue(ctx, wildcardReq())
	h.clock.Add(80 * 24 * time.Hour) // 10 days left
	h.m.Renew(ctx)
	h.m.Renew(ctx)
	evs := h.evs.list()
	if len(evs) != 1 || evs[0].Kind != EventExpiring || evs[0].Threshold != 14*24*time.Hour || evs[0].CertID != b.ID {
		t.Fatalf("events %+v", evs)
	}
	h.clock.Add(5 * 24 * time.Hour) // 5 days left
	h.m.Renew(ctx)
	h.m.Renew(ctx)
	evs = h.evs.list()
	if len(evs) != 2 || evs[1].Threshold != 7*24*time.Hour {
		t.Fatalf("events %+v", evs)
	}
}

func TestNewManagerValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*config.Config)
		want string
	}{
		{"unifi challenge provider", func(c *config.Config) { c.Providers["cf"] = config.ProviderCfg{Type: "unifi"} }, "unifi"},
		{"unknown lego type", func(c *config.Config) { c.Providers["cf"] = config.ProviderCfg{Type: "nosuchdns"} }, "not a lego DNS provider"},
		{"exec excluded", func(c *config.Config) { c.Providers["cf"] = config.ProviderCfg{Type: "exec"} }, "not a lego DNS provider"},
		{"wildcard http-01", func(c *config.Config) { c.Zones[0].Certificate.Challenge = "http-01" }, "dns-01"},
		{"default strategy http-01", func(c *config.Config) {
			c.Zones[0].Certificate.Challenge = "http-01"
			c.Zones[0].Certificate.Strategy = ""
		}, "dns-01"},
		{"missing dns provider", func(c *config.Config) { c.Zones[0].Certificate.DNSProvider = "" }, "dns_provider is required"},
		{"LE without email", func(c *config.Config) { c.Issuers["le"] = config.Issuer{Directory: "staging"} }, "email is required"},
		{"plain http directory", func(c *config.Config) {
			c.Issuers["le"] = config.Issuer{Directory: "http://acme.example.test/dir", Email: "admin@example.test"}
		}, "https"},
		{"undefined issuer", func(c *config.Config) { c.Zones[0].Certificate.Issuer = "nope" }, "not defined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			tc.mod(cfg)
			st, _ := openStore(t)
			box, _ := newBox()
			_, err := NewManager(ManagerConfig{Config: cfg, Store: st, Box: box, CertsDir: t.TempDir()})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestIssueRejectsBadRequests(t *testing.T) {
	h := newHarness(t, nil, nil)
	for _, req := range []IssueRequest{
		{Zone: "example.test", Names: []string{"a.example.org"}, Strategy: StrategyPerHost},
		{Zone: "unknown.test", Names: []string{"a.unknown.test"}},
		{Zone: "noissuer.test", Names: []string{"a.noissuer.test"}},
		{Zone: "other.test", Names: []string{"a.other.test", "b.other.test"}}, // per-host: 2 orders
	} {
		if _, err := h.m.Issue(ctx, req); err == nil {
			t.Errorf("%+v accepted", req)
		}
	}
	if h.ca.count() != 0 {
		t.Fatal("orders placed for bad requests")
	}
	res := h.m.IssueAll(ctx, IssueRequest{Zone: "other.test", Names: []string{"a.other.test", "b.other.test"}})
	if len(res) != 2 || res[0].Err != nil || res[1].Err != nil {
		t.Fatalf("%+v", res)
	}
}

// A bad name in a request is dropped (warning logged, reported in Result),
// the valid names are still ordered.
func TestIssueAllDropsInvalidNames(t *testing.T) {
	h := newHarness(t, nil, nil)
	res := h.m.IssueAll(ctx, IssueRequest{Zone: "other.test", Names: []string{"a.other.test", "bad_name.other.test", "b.other.test\n"}})
	if len(res) != 1 || res[0].Err != nil || strings.Join(res[0].Names, ",") != "a.other.test" {
		t.Fatalf("%+v", res)
	}
	if strings.Join(res[0].Dropped, "|") != "bad_name.other.test|b.other.test\n" {
		t.Fatalf("dropped %q", res[0].Dropped)
	}
	if h.ca.count() != 1 || strings.Join(h.ca.last().Names, ",") != "a.other.test" {
		t.Fatal("wrong orders")
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "invalid certificate name dropped") || !strings.Contains(logs, `b.other.test\\n`) {
		t.Fatalf("no warning: %s", logs)
	}
}

// Issue reports dropped names too: on the bundle, and in the error text.
func TestIssueReportsDroppedNames(t *testing.T) {
	h := newHarness(t, nil, nil)
	b, err := h.m.Issue(ctx, IssueRequest{Zone: "other.test", Names: []string{"a.other.test", "bad_name.other.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(b.Dropped, ",") != "bad_name.other.test" {
		t.Fatalf("bundle dropped %q", b.Dropped)
	}
	h.ca.setFail(errors.New("boom"))
	_, err = h.m.Issue(ctx, IssueRequest{Zone: "other.test", Names: []string{"c.other.test", "bad_name.other.test"}})
	if err == nil || !strings.Contains(err.Error(), "bad_name.other.test") {
		t.Fatalf("error does not report the dropped name: %v", err)
	}
}
