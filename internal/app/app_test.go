package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/providers/fake"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/notify"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/traefik"
	"github.com/ajthom90/doorwarden/internal/web"
)

// fakeSource is a controllable discovery source.
type fakeSource struct {
	name string

	mu     sync.Mutex
	svcs   []model.Service
	err    error
	block  chan struct{} // List waits on it when non-nil
	calls  atomic.Int32
	active atomic.Int32
	maxAct atomic.Int32
	closed atomic.Int32
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) set(err error, svcs ...model.Service) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err, f.svcs = err, svcs
}

func (f *fakeSource) List(ctx context.Context) ([]model.Service, error) {
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		m := f.maxAct.Load()
		if n <= m || f.maxAct.CompareAndSwap(m, n) {
			break
		}
	}
	f.calls.Add(1)
	f.mu.Lock()
	block := f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.Service(nil), f.svcs...), f.err
}

func (f *fakeSource) Close() error { f.closed.Add(1); return nil }

func svc(src, name string) model.Service {
	return model.Service{Key: src + "/" + name, Source: src, Name: name, Zone: "example.test",
		Backend: model.Backend{Scheme: "http", Host: "198.51.100.5", Port: 8080}, State: model.StateDiscovered}
}

// recNotifier records notifications.
type recNotifier struct {
	mu  sync.Mutex
	got []notify.Event
}

func (r *recNotifier) Notify(_ context.Context, e notify.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, e)
	return nil
}

func (r *recNotifier) events() []notify.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]notify.Event(nil), r.got...)
}

type env struct {
	t       *testing.T
	cfg     *config.Config
	st      *store.Store
	fk      *fake.Fake
	src     *fakeSource
	dir     string // traefik dynamic dir
	certs   string
	dbPath  string
	notif   *recNotifier
	statErr error
}

const testYAML = `
zones:
  - name: example.test
    target_ip: 192.0.2.10
    records: {provider: fk, mode: per-host}
providers:
  fk: {type: fake}
settings: {grace_period: 1h, poll_interval: 1h}
traefik: {dynamic_dir: "@DIR@"}
acme: {certs_dir: "@CERTS@"}
`

func writeConfig(t *testing.T, yml string) (path, dir, certs string) {
	t.Helper()
	root := t.TempDir()
	dir = filepath.Join(root, "dynamic")
	certs = filepath.Join(root, "certs")
	for _, d := range []string{dir, certs} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	yml = strings.NewReplacer("@DIR@", dir, "@CERTS@", certs).Replace(yml)
	path = filepath.Join(root, "doorwarden.yaml")
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, dir, certs
}

func newEnv(t *testing.T, yml string) *env {
	t.Helper()
	path, dir, certs := writeConfig(t, yml)
	cfg, err := LoadConfig(path, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, cfg: cfg, fk: fake.New(true), src: &fakeSource{name: "docker"}, dir: dir, certs: certs,
		dbPath: filepath.Join(t.TempDir(), "dw.db"), notif: &recNotifier{}}
	e.st = e.openStore()
	return e
}

func (e *env) openStore() *store.Store {
	st, err := store.Open(e.dbPath)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { st.Close() })
	return st
}

func (e *env) app(mut ...func(*Options)) *App {
	e.t.Helper()
	o := Options{Config: e.cfg, Store: e.st,
		Sources:   []SourceSpec{{Source: e.src, Mode: approval.ModeAuto}},
		Providers: map[string]dns.Provider{"fk": e.fk},
		Notifier:  e.notif,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, m := range mut {
		m(&o)
	}
	a, err := New(o)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = a.Close(context.Background()) })
	return a
}

func writes(fk *fake.Fake) []fake.Call {
	var out []fake.Call
	for _, c := range fk.Calls() {
		if c.Op != "ListRecords" && c.Op != "Test" {
			out = append(out, c)
		}
	}
	return out
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range des {
		out = append(out, d.Name())
	}
	return out
}

func hasA(t *testing.T, fk *fake.Fake, name, value string) bool {
	t.Helper()
	recs, err := fk.ListRecords(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Type == "A" && strings.TrimSuffix(r.Name, ".") == name && r.Value == value {
			return true
		}
	}
	return false
}

// End to end: one dry-run cycle plans and records activity but writes
// nothing to the provider, the Traefik dir or the routes table; then a live
// cycle writes the route file and the DNS record through the fake.
func TestEndToEndDryRunThenLive(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.set(nil, svc("docker", "app"))
	a := e.app()
	ctx := context.Background()
	if err := a.SetDryRun(ctx, true); err != nil {
		t.Fatal(err)
	}

	res := a.RunOnce(ctx)
	if res.Err != nil || !res.DryRun {
		t.Fatalf("dry cycle: %+v", res)
	}
	var kinds []string
	for _, x := range res.Actions {
		kinds = append(kinds, string(x.Kind))
	}
	if !strings.Contains(strings.Join(kinds, ","), string(reconcile.RouteWrite)) {
		t.Fatalf("plan has no route write: %v", kinds)
	}
	if w := writes(e.fk); len(w) != 0 {
		t.Fatalf("dry run wrote to the provider: %+v", w)
	}
	if ents := dirEntries(t, e.dir); len(ents) != 0 {
		t.Fatalf("dry run wrote Traefik files: %v", ents)
	}
	if routes, _ := e.st.ListRoutes(ctx); len(routes) != 0 {
		t.Fatalf("dry run wrote routes: %+v", routes)
	}
	act, err := e.st.ListActivity(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var sawDry bool
	for _, x := range act {
		if strings.Contains(x.Message, "dry run: would") && strings.Contains(x.Message, "app.example.test") {
			sawDry = true
		}
	}
	if !sawDry {
		t.Fatalf("no dry-run activity: %+v", act)
	}

	if err := a.SetDryRun(ctx, false); err != nil {
		t.Fatal(err)
	}
	res = a.RunOnce(ctx)
	if res.Err != nil || res.DryRun || !res.Rendered {
		t.Fatalf("live cycle: %+v", res)
	}
	b, err := os.ReadFile(filepath.Join(e.dir, traefik.RoutesFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "app.example.test") || !strings.Contains(string(b), "198.51.100.5:8080") {
		t.Fatalf("routes file:\n%s", b)
	}
	if !hasA(t, e.fk, "app.example.test", "192.0.2.10") {
		recs, _ := e.fk.ListRecords(ctx, "example.test")
		t.Fatalf("no A record: %+v", recs)
	}
	if h := a.HealthStatus(); h.Degraded || !h.Sources["docker"] || h.LastReconcile == nil {
		t.Fatalf("health = %+v", h)
	}
}

// settings.dry_run in the config forces dry run whatever the toggle.
func TestConfigDryRunWins(t *testing.T) {
	e := newEnv(t, strings.Replace(testYAML, "grace_period: 1h", "dry_run: true, grace_period: 1h", 1))
	e.src.set(nil, svc("docker", "app"))
	a := e.app()
	ctx := context.Background()
	if err := a.SetDryRun(ctx, false); err != nil {
		t.Fatal(err)
	}
	if res := a.RunOnce(ctx); !res.DryRun || res.Rendered {
		t.Fatalf("res = %+v", res)
	}
	if w := writes(e.fk); len(w) != 0 {
		t.Fatalf("writes: %+v", w)
	}
}

// The global dry-run toggle is persisted in the store: a new App over the
// same database is dry.
func TestDryRunTogglePersisted(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	a := e.app()
	if on, err := a.DryRun(ctx); err != nil || on {
		t.Fatalf("default dry run = %v, %v", on, err)
	}
	if err := a.SetDryRun(ctx, true); err != nil {
		t.Fatal(err)
	}
	e.st.Close()
	e.st = e.openStore()
	b := e.app()
	if on, err := b.DryRun(ctx); err != nil || !on {
		t.Fatalf("after reopen dry run = %v, %v", on, err)
	}
	if v, ok, _ := e.st.GetSetting(ctx, DryRunKey); !ok || v != "true" {
		t.Fatalf("kv = %q %v", v, ok)
	}
	if res := b.RunOnce(ctx); !res.DryRun {
		t.Fatalf("cycle not dry: %+v", res)
	}
}

// Concurrent RunOnce calls never overlap.
func TestReconcileSerialized(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.set(nil, svc("docker", "app"))
	e.src.block = make(chan struct{})
	a := e.app()
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); a.RunOnce(context.Background()) }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.src.calls.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := e.src.calls.Load(); n != 1 {
		t.Fatalf("%d cycles listing at once", n)
	}
	close(e.src.block)
	wg.Wait()
	if m := e.src.maxAct.Load(); m != 1 {
		t.Fatalf("max concurrent cycles = %d", m)
	}
	if n := e.src.calls.Load(); n != 5 {
		t.Fatalf("cycles = %d", n)
	}
}

// Triggers that arrive while a cycle runs coalesce into one more cycle, and
// Run shuts down gracefully on cancel.
func TestRunCoalescesTriggersAndShutsDown(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.set(nil, svc("docker", "app"))
	block := make(chan struct{})
	e.src.mu.Lock()
	e.src.block = block
	e.src.mu.Unlock()
	a := e.app()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for e.src.calls.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if e.src.calls.Load() != 1 {
		t.Fatal("first cycle did not start")
	}
	for i := 0; i < 10; i++ {
		a.Trigger() // never blocks
	}
	e.src.mu.Lock()
	e.src.block = nil
	e.src.mu.Unlock()
	close(block)
	for e.src.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if n := e.src.calls.Load(); n != 2 {
		t.Fatalf("cycles = %d, want 2 (10 triggers coalesced into one)", n)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = a.Close(context.Background())
	if n := e.src.closed.Load(); n != 1 {
		t.Fatalf("source closed %d times", n)
	}
}

// Cancel during a blocked source List aborts the cycle and Run returns.
func TestRunShutdownDuringCycle(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.block = make(chan struct{})
	a := e.app()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for e.src.calls.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if ents := dirEntries(t, e.dir); len(ents) != 0 {
		t.Fatalf("aborted cycle wrote files: %v", ents)
	}
}

// The poll ticker runs cycles without triggers.
func TestRunPolls(t *testing.T) {
	e := newEnv(t, strings.Replace(testYAML, "poll_interval: 1h", "poll_interval: 20ms", 1))
	a := e.app()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for e.src.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if e.src.calls.Load() < 3 {
		t.Fatalf("polled %d times", e.src.calls.Load())
	}
}

// A source outage is unknown, never gone: routes and records stay, health
// is degraded but 200.
func TestSourceOutageKeepsRoutes(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.set(nil, svc("docker", "app"))
	a := e.app()
	ctx := context.Background()
	if res := a.RunOnce(ctx); res.Err != nil {
		t.Fatal(res.Err)
	}
	before := len(writes(e.fk))
	e.src.set(errors.New("daemon down"))
	res := a.RunOnce(ctx)
	if !res.Unavailable["docker"] {
		t.Fatalf("unavailable = %v", res.Unavailable)
	}
	for _, x := range res.Actions {
		if x.Kind == reconcile.ScheduleRemoval || x.Kind == reconcile.RouteRemove || x.Kind == reconcile.DNSDelete {
			t.Fatalf("outage planned removal: %+v", x)
		}
	}
	if len(writes(e.fk)) != before {
		t.Fatalf("outage wrote to provider: %+v", writes(e.fk)[before:])
	}
	routes, _ := e.st.ListRoutes(ctx)
	if len(routes) != 1 || routes[0].RemovedAfter != nil {
		t.Fatalf("routes = %+v", routes)
	}
	h := a.HealthStatus()
	if !h.Degraded || h.Sources["docker"] {
		t.Fatalf("health = %+v", h)
	}
	rec := httptest.NewRecorder()
	a.HealthHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
	var body web.HealthStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || !body.Degraded {
		t.Fatalf("body = %s (%v)", rec.Body, err)
	}
	if len(e.notif.events()) == 0 {
		t.Fatal("no notification for the source outage")
	}
}

// A source that failed to construct is unavailable every cycle.
func TestUnconstructedSourceUnavailable(t *testing.T) {
	e := newEnv(t, testYAML)
	a := e.app(func(o *Options) {
		o.Sources = append(o.Sources, SourceSpec{Name: "truenas", Err: errors.New("bad url")})
	})
	res := a.RunOnce(context.Background())
	if !res.Unavailable["truenas"] || res.Unavailable["docker"] {
		t.Fatalf("unavailable = %v", res.Unavailable)
	}
}

// /healthz is 503 when the store is unusable.
func TestHealthzStoreUnusable(t *testing.T) {
	e := newEnv(t, testYAML)
	a := e.app()
	rec := httptest.NewRecorder()
	a.HealthHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
	e.st.Close()
	rec = httptest.NewRecorder()
	a.HealthHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz with closed store = %d", rec.Code)
	}
}

// approval: off drops the services: they are absent, so removal is
// scheduled after the grace period.
func TestApprovalOffSchedulesRemoval(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.set(nil, svc("docker", "app"))
	a := e.app()
	ctx := context.Background()
	if res := a.RunOnce(ctx); res.Err != nil {
		t.Fatal(res.Err)
	}
	b := e.app(func(o *Options) { o.Sources = []SourceSpec{{Source: e.src, Mode: approval.ModeOff}} })
	res := b.RunOnce(ctx)
	var sched bool
	for _, x := range res.Actions {
		if x.Kind == reconcile.ScheduleRemoval {
			sched = true
		}
	}
	if !sched {
		t.Fatalf("no removal scheduled: %+v", res.Actions)
	}
}

// Duplicate service keys are deduplicated before the gate (last wins).
func TestDuplicateKeysDeduped(t *testing.T) {
	e := newEnv(t, testYAML)
	s1, s2 := svc("docker", "app"), svc("docker", "app")
	s2.Backend.Port = 9090
	e.src.set(nil, s1, s2)
	a := e.app()
	if res := a.RunOnce(context.Background()); res.Err != nil {
		t.Fatal(res.Err)
	}
	if got := a.Services(); len(got) != 1 || got[0].Backend.Port != 9090 {
		t.Fatalf("services = %+v", got)
	}
	routes, _ := e.st.ListRoutes(context.Background())
	if len(routes) != 1 || routes[0].Port != 9090 {
		t.Fatalf("routes = %+v", routes)
	}
}

// Invalid actions repeat every cycle but are recorded once (until they
// change), at warn level.
func TestInvalidActionRecordedOnce(t *testing.T) {
	e := newEnv(t, testYAML)
	bad := svc("docker", "bad")
	bad.Zone = "other.test" // not configured
	e.src.set(nil, bad)
	a := e.app()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		a.RunOnce(ctx)
	}
	act, _ := e.st.ListActivity(ctx, 100)
	n := 0
	for _, x := range act {
		if strings.Contains(x.Message, "docker/bad") {
			n++
			if x.Level != "warn" && x.Level != "error" {
				t.Fatalf("level = %s", x.Level)
			}
		}
	}
	if n != 1 {
		t.Fatalf("invalid recorded %d times: %+v", n, act)
	}
}

// The default certificate's files are checked on disk: when missing, the
// TLS file is written without the default store.
func TestDefaultCertMissingOmitsStore(t *testing.T) {
	e := newEnv(t, testYAML)
	ctx := context.Background()
	now := time.Now()
	if err := e.st.UpsertCert(ctx, store.Cert{ID: "example-test-wild", Zone: "example.test",
		DomainsJSON: `["*.example.test"]`, Issuer: "imported", Status: "imported",
		NotAfter: now.Add(48 * time.Hour), Path: "example-test-wild/v1"}); err != nil {
		t.Fatal(err)
	}
	e.src.set(nil, svc("docker", "app"))
	a := e.app()
	if res := a.RunOnce(ctx); res.Err != nil || !res.Rendered {
		t.Fatalf("res = %+v", res)
	}
	tlsFile := filepath.Join(e.dir, traefik.TLSFile)
	b, err := os.ReadFile(tlsFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "stores") {
		t.Fatalf("missing default cert still in stores:\n%s", b)
	}
	if !strings.Contains(string(b), "fullchain.pem") {
		t.Fatalf("certificate not listed:\n%s", b)
	}
	cdir := filepath.Join(e.certs, "example-test-wild", "v1")
	if err := os.MkdirAll(cdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{traefik.FullchainFile, traefik.PrivkeyFile} {
		if err := os.WriteFile(filepath.Join(cdir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a.RunOnce(ctx)
	b, _ = os.ReadFile(tlsFile)
	if !strings.Contains(string(b), "stores") {
		t.Fatalf("default store missing once files exist:\n%s", b)
	}
	if a.nextCert.IsZero() {
		t.Fatal("no re-render scheduled at the certificate expiry")
	}
}

func TestNextCertExpiry(t *testing.T) {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	rows := []store.Cert{
		{NotAfter: now.Add(-time.Hour)},
		{NotAfter: now.Add(72 * time.Hour)},
		{NotAfter: now.Add(24 * time.Hour)},
	}
	if got := NextCertExpiry(rows, now); !got.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("got %v", got)
	}
	if got := NextCertExpiry(rows[:1], now); !got.IsZero() {
		t.Fatalf("got %v", got)
	}
}

// Actions with Alert set notify an operator.
func TestAlertNotifies(t *testing.T) {
	e := newEnv(t, testYAML)
	a := e.app()
	a.countAndAlert(context.Background(), []reconcile.Action{{Kind: reconcile.Skip, Key: "docker/x",
		Alert: reconcile.AlertDNSMassMissing, Reason: "many records missing"}})
	ev := e.notif.events()
	if len(ev) != 1 || ev[0].Severity != notify.Critical {
		t.Fatalf("events = %+v", ev)
	}
}

func TestSecretStoreRoundTrip(t *testing.T) {
	e := newEnv(t, testYAML)
	box, err := secrets.NewBox(strings.Repeat("k", 32))
	if err != nil {
		box, err = secrets.NewBox("dGVzdC1tYXN0ZXIta2V5LTAxMjM0NTY3ODlhYmNkZWY=")
		if err != nil {
			t.Fatal(err)
		}
	}
	ss := &SecretStore{KV: e.st, Box: box}
	ctx := context.Background()
	if err := ss.Put(ctx, "cf-token", secrets.Secret("s3cr3t-value")); err != nil {
		t.Fatal(err)
	}
	v, err := ss.Resolve("cf-token")
	if err != nil || string(v) != "s3cr3t-value" {
		t.Fatalf("resolve = %q, %v", v, err)
	}
	if raw, ok, _ := e.st.GetSetting(ctx, SecretKVPrefix+"cf-token"); !ok || strings.Contains(raw, "s3cr3t") {
		t.Fatalf("stored in clear: %q", raw)
	}
	if v, err := ss.Value("secret:cf-token"); err != nil || string(v) != "s3cr3t-value" {
		t.Fatalf("value = %q, %v", v, err)
	}
	if v, err := ss.Value("literal"); err != nil || string(v) != "literal" {
		t.Fatalf("literal = %q, %v", v, err)
	}
	if _, err := ss.Resolve("missing"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if _, err := ss.Resolve("../bad"); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := ss.Delete(ctx, "cf-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := ss.Resolve("cf-token"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("after delete = %v", err)
	}
}

func TestLoadConfigValidates(t *testing.T) {
	yml := strings.Replace(testYAML, "type: fake", "type: no-such-provider", 1)
	path, _, _ := writeConfig(t, strings.Replace(yml, "mode: per-host", "mode: wildcard", 1))
	if _, err := LoadConfig(path, nil); err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("invalid config accepted: %v", err)
	}
	// Per-host mode with an unknown type passes Validate; building the
	// providers then fails the start.
	path, _, _ = writeConfig(t, yml)
	cfg, err := LoadConfig(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildProviders(cfg, nil); err == nil {
		t.Fatal("unknown provider type built")
	}
}

func TestParseFlags(t *testing.T) {
	f, err := ParseFlags(nil, func(k string) (string, bool) {
		if k == "DOORWARDEN_LISTEN" {
			return "127.0.0.1:0", true
		}
		return "", false
	})
	if err != nil || f.Config != "/config/doorwarden.yaml" || f.DB != "/data/doorwarden.db" || f.Listen != "127.0.0.1:0" {
		t.Fatalf("%+v %v", f, err)
	}
	f, err = ParseFlags([]string{"-config", "x.yaml", "-listen", ""}, nil)
	if err != nil || f.Config != "x.yaml" || f.Listen != "" {
		t.Fatalf("%+v %v", f, err)
	}
	if _, err := ParseFlags([]string{"extra"}, nil); err == nil {
		t.Fatal("extra args accepted")
	}
}

// RunWith composes everything from a config file (static source, fake
// provider), serves /healthz, and shuts down on cancel.
func TestRunWithServesHealthAndShutsDown(t *testing.T) {
	yml := testYAML + `
static:
  - {name: web, host: 198.51.100.7, port: 80}
`
	path, dir, _ := writeConfig(t, yml)
	db := filepath.Join(t.TempDir(), "data", "dw.db")
	ln := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunWith(ctx, Flags{Config: path, DB: db, Listen: ln},
			func(string) (string, bool) { return "", false }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	deadline := time.Now().Add(10 * time.Second)
	var code int
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + ln + "/healthz")
		if err == nil {
			code = resp.StatusCode
			resp.Body.Close()
			if _, err := os.Stat(filepath.Join(dir, traefik.RoutesFile)); err == nil && code == 200 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code != http.StatusOK {
		t.Fatalf("healthz = %d", code)
	}
	b, err := os.ReadFile(filepath.Join(dir, traefik.RoutesFile))
	if err != nil || !strings.Contains(string(b), "web.example.test") {
		t.Fatalf("routes file: %s %v", b, err)
	}
	resp, err := http.Get("http://" + ln + "/metrics")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("/metrics is exposed on the default mux")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunWith did not return")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()
	return addr
}
