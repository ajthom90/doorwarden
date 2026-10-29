package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/acme"
	"github.com/ajthom90/doorwarden/internal/notify"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/go-acme/lego/v4/challenge"
)

// Dry-run cycles send no notifications; start-up housekeeping (LiveInit)
// waits for the first live cycle and runs once.
func TestDryRunNoNotificationsAndDeferredLiveInit(t *testing.T) {
	e := newEnv(t, testYAML)
	var inits atomic.Int32
	a := e.app(func(o *Options) {
		o.LiveInit = func(context.Context) error { inits.Add(1); return nil }
	})
	ctx := context.Background()
	if err := a.SetDryRun(ctx, true); err != nil {
		t.Fatal(err)
	}
	e.src.set(errors.New("daemon down"))
	a.RunOnce(ctx)
	a.countAndAlert(ctx, []reconcile.Action{{Kind: reconcile.Skip, Key: "docker/x", Alert: reconcile.AlertDNSMassMissing}})
	if ev := e.notif.events(); len(ev) != 0 {
		t.Fatalf("dry run notified: %+v", ev)
	}
	if inits.Load() != 0 {
		t.Fatal("LiveInit ran in dry run")
	}
	if err := a.SetDryRun(ctx, false); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	a.RunOnce(ctx)
	if inits.Load() != 1 {
		t.Fatalf("LiveInit ran %d times", inits.Load())
	}
	if len(e.notif.events()) == 0 {
		t.Fatal("live outage not notified")
	}
}

// A failing LiveInit is retried on the next live cycle.
func TestLiveInitRetried(t *testing.T) {
	e := newEnv(t, testYAML)
	var n atomic.Int32
	a := e.app(func(o *Options) {
		o.LiveInit = func(context.Context) error {
			if n.Add(1) == 1 {
				return errors.New("disk full")
			}
			return nil
		}
	})
	for i := 0; i < 3; i++ {
		a.RunOnce(context.Background())
	}
	if n.Load() != 2 {
		t.Fatalf("LiveInit calls = %d", n.Load())
	}
}

// RouteHosts: Wanted reports the snapshot's hosts per zone; Load fails on a
// store error (the renewal round is then skipped) and the old snapshot is
// kept; without any snapshot a read error fails open.
func TestRouteHostsWanted(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.set(nil, svc("docker", "app"), svc("docker", "web"))
	e.app().RunOnce(context.Background())
	h := NewRouteHosts(e.st, nil)
	if err := h.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(h.Wanted("Example.Test."), ",")
	if got != "app.example.test,web.example.test" {
		t.Fatalf("wanted = %q", got)
	}
	if w := h.Wanted("other.test"); len(w) != 0 {
		t.Fatalf("other zone = %v", w)
	}
	e.st.Close()
	if err := h.Load(context.Background()); err == nil {
		t.Fatal("Load succeeded on a closed store")
	}
	if got := strings.Join(h.Wanted("example.test"), ","); got != "app.example.test,web.example.test" {
		t.Fatalf("snapshot lost: %q", got)
	}
	fresh := NewRouteHosts(e.st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if w := fresh.Wanted("example.test"); len(w) == 0 {
		t.Fatal("store error made the zone unwanted")
	}
}

// A BeforeRenew error skips the round (Renew is not called: mgr is nil
// here and would panic).
func TestRenewSkippedWhenBeforeRenewFails(t *testing.T) {
	e := newEnv(t, testYAML)
	called := false
	a := e.app(func(o *Options) {
		o.BeforeRenew = func(context.Context) error { called = true; return errors.New("store busy") }
	})
	a.renewOnce(context.Background())
	if !called {
		t.Fatal("BeforeRenew not called")
	}
}

type nopChallenge struct{}

func (nopChallenge) Present(string, string, string) error { return nil }
func (nopChallenge) CleanUp(string, string, string) error { return nil }

// New with a real acme.NewManager registers the cert executor: a live
// CertEnsure reaches the ACME directory (a local test server) instead of
// failing with ErrNoExecutor. No public network is used.
func TestNewWithManagerRegistersCertExecutor(t *testing.T) {
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
		Wanted:              NewRouteHosts(e.st, nil).Wanted,
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		DeferStartupCleanup: true, IssueTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	e.src.set(nil, svc("docker", "app"))
	a := e.app(func(o *Options) { o.ACME = mgr })
	res := a.RunOnce(context.Background())
	var ensure bool
	for _, x := range res.Actions {
		ensure = ensure || x.Kind == reconcile.CertEnsure
	}
	if !ensure {
		t.Fatalf("no CertEnsure planned: %+v", res.Actions)
	}
	if errors.Is(res.Err, reconcile.ErrNoExecutor) {
		t.Fatalf("CertEnsure has no executor: %v", res.Err)
	}
	// The order itself fails locally (lego refuses plain http before any
	// request): proof the cert executor ran.
	if res.Err == nil || !strings.Contains(res.Err.Error(), "acme: order for app.example.test") {
		t.Fatalf("cert executor did not run: %v", res.Err)
	}
}

func TestACMENotifierSeverity(t *testing.T) {
	r := &recNotifier{}
	n := acmeNotifier(r)
	ctx := context.Background()
	n.Notify(ctx, acme.Event{Kind: acme.EventExpiring, CertID: "c", Threshold: 24 * time.Hour, NotAfter: time.Now()})
	n.Notify(ctx, acme.Event{Kind: acme.EventExpiring, CertID: "c", Threshold: 7 * 24 * time.Hour})
	n.Notify(ctx, acme.Event{Kind: acme.EventFailure, CertID: "c", Message: "rate limited"})
	n.Notify(ctx, acme.Event{Kind: acme.EventAdoptionBlocked, CertID: "c"})
	ev := r.events()
	want := []notify.Severity{notify.Critical, notify.Warning, notify.Warning, notify.Warning}
	if len(ev) != len(want) {
		t.Fatalf("events = %+v", ev)
	}
	for i, w := range want {
		if ev[i].Severity != w {
			t.Errorf("event %d (%s) severity = %v, want %v", i, ev[i].Kind, ev[i].Severity, w)
		}
	}
	if ev[0].Fields["not_after"] == "" || ev[0].DedupeKey == ev[1].DedupeKey {
		t.Fatalf("fields/dedupe: %+v", ev[:2])
	}
	if acmeNotifier(nil) != nil {
		t.Fatal("nil dispatcher should give a nil notifier")
	}
}

// /healthz shares and caches its store probe: a flood within the interval
// does not hit the store again (here: a closed store still reads healthy
// until the cached result ages out).
func TestHealthzProbeCached(t *testing.T) {
	e := newEnv(t, testYAML)
	a := e.app(func(o *Options) { o.HealthProbeInterval = time.Hour })
	get := func() int {
		rec := httptest.NewRecorder()
		a.HealthHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		return rec.Code
	}
	if c := get(); c != http.StatusOK {
		t.Fatalf("healthz = %d", c)
	}
	e.st.Close()
	for i := 0; i < 20; i++ {
		if c := get(); c != http.StatusOK {
			t.Fatalf("probe not cached: %d", c)
		}
	}
}
