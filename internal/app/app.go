// Package app wires the doorwarden control plane together: config, store,
// secrets, sources, the approval gate, reconcile.Plan, the executors (routes,
// DNS, certificates), the Traefik writer and the loop.
//
// One reconcile cycle (App.RunOnce, serialized by a mutex):
//
//  1. The effective dry run is decided once: settings.dry_run OR the
//     persisted global toggle (kv DryRunKey; SetDryRun). A store error reading
//     it makes the cycle dry (fail safe).
//  2. Every source is listed under SourceTimeout. A source that failed to
//     construct, whose List failed, or whose approvals failed to load is
//     Unavailable (keyed by its name and every Service.Source value it
//     carried), so its services are unknown, never gone. Duplicate keys are
//     dropped (the last occurrence wins, like Plan) before the approval gate.
//     Approval "off" and Skip drop services: they are absent (removal after
//     the grace period), not unavailable.
//  3. Observed: Known and LastKnown from the persisted routes, the cert rows,
//     and reconcile.GatherObservedAt (every ownership row, provider listings,
//     drift, mass-repair acknowledgements, repair backoff) filled into it.
//  4. reconcile.Runner plans and applies through one MultiExecutor holding
//     the route executor, the DNS executor (every DNSActionKinds kind, so its
//     Finish hook runs every non-dry cycle) and the ACME cert executor.
//  5. Not dry: the Traefik files are rendered from the persisted routes and
//     cert rows and written atomically. The default certificate's files are
//     checked on disk first; when either is missing only the default store
//     is left out. The next certificate expiry schedules a re-render.
//  6. Every planned action is counted in metrics; activity entries are
//     written when an action's outcome changed since the previous cycle
//     (Invalid, Conflict and Skip repeat every cycle and would flood the
//     log otherwise) and logged at warn for Invalid/Conflict/Skip; an
//     action with Alert set notifies an operator (deduplicated by the
//     dispatcher).
//
// Dry run: no provider write, no ACME order, no file write and no store
// write except activity: the plan is computed and recorded as activity
// only. Provider listings (reads) still run so the plan is accurate.
//
// The configuration is read once at start; changing it needs a restart (so
// the ACME manager is never rebuilt while an order runs).
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ajthom90/doorwarden/internal/acme"
	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/metrics"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/notify"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/source"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/web"
)

// DryRunKey is the kv key of the persisted global dry-run toggle ("true" or
// "false"; absent means off, so settings.dry_run alone decides).
const DryRunKey = "settings/dry_run"

// Defaults.
const (
	DefaultSourceTimeout = 60 * time.Second
	DefaultRenewEvery    = time.Hour
	// renderTimeout bounds the store reads of one Traefik render.
	renderTimeout = 30 * time.Second
	storeTimeout  = 10 * time.Second
)

// SourceSpec is one discovery source with its approval mode.
type SourceSpec struct {
	// Source is nil when it failed to construct (Err says why); it is then
	// Unavailable every cycle.
	Source source.Source
	// Name is the source name used when Source is nil.
	Name string
	Mode approval.Mode
	Err  error
}

func (s SourceSpec) name() string {
	if s.Source != nil {
		return s.Source.Name()
	}
	return s.Name
}

// Options configures New. Config and Store are required.
type Options struct {
	Config *config.Config
	Store  *store.Store
	// Sources are listed every cycle, in order.
	Sources []SourceSpec
	// Providers are the constructed DNS record providers by config name.
	Providers map[string]dns.Provider
	// ACME is the certificate manager (nil when no zone has an issuer).
	ACME *acme.Manager
	// Notifier receives alerts (optional).
	Notifier notify.Notifier
	// Metrics (optional; nil is a no-op sink).
	Metrics *metrics.Metrics
	// Now is the clock (default time.Now).
	Now func() time.Time
	// Log (default slog.Default()).
	Log *slog.Logger
	// SourceTimeout bounds one source List (default DefaultSourceTimeout).
	SourceTimeout time.Duration
	// DNSTimeout bounds each provider listing and call (default
	// reconcile.DefaultDNSCallTimeout).
	DNSTimeout time.Duration
	// RenewEvery is how often Run calls ACME.Renew (default
	// DefaultRenewEvery).
	RenewEvery time.Duration
	// StatFile reports whether a local file exists (default os.Stat); the
	// default certificate is checked with it before Traefik's TLS file is
	// written.
	StatFile func(path string) error
	// HealthProbeInterval is how long a /healthz store probe result is
	// reused (default web.DefaultProbeInterval).
	HealthProbeInterval time.Duration
	// LiveInit runs once, on the first cycle that is not a dry run, before
	// it plans (start-up side effects such as creating the certificate
	// directory and the ACME manager's StartupCleanup). A failure is logged
	// and retried on the next live cycle.
	LiveInit func(ctx context.Context) error
	// BeforeRenew runs before each ACME renewal round; an error skips the
	// round (e.g. RouteHosts.Load: Wanted must not see an empty host list
	// because the store could not be read, which would mark every
	// certificate unwanted).
	BeforeRenew func(ctx context.Context) error
}

// App is the control plane.
type App struct {
	cfg       *config.Config
	st        *store.Store
	sources   []SourceSpec
	providers map[string]dns.Provider
	mgr       *acme.Manager
	notifier  notify.Notifier
	met       *metrics.Metrics
	now       func() time.Time
	log       *slog.Logger
	srcTO     time.Duration
	dnsTO     time.Duration
	renewTO   time.Duration
	stat      func(string) error

	gate   *approval.Gate
	runner *reconcile.Runner
	probe  *web.CachedProbe

	liveInit    func(context.Context) error
	liveInitOK  bool // guarded by cycleMu
	beforeRenew func(context.Context) error

	cycleMu  sync.Mutex // serializes cycles (RunOnce)
	cycleDry atomic.Bool
	trigger  chan struct{}

	// Cycle-local memory (guarded by cycleMu).
	seenPrev, seenCur map[string]bool
	aliases           map[string]map[string]bool // source name -> Service.Source values
	lastLogged        map[string]string
	nextCert          time.Time
	onCertArm         func(time.Duration) // test hook: the cert timer's delay

	hmu     sync.RWMutex
	health  web.HealthStatus
	snap    []model.Service
	listing []listed // pre-gate services of the last cycle (control.go)
	plan    web.Plan
	events  func(name string, v any)

	ovMu sync.Mutex // serializes SetServiceOverride

	closeOnce sync.Once
}

// New builds the App: the approval gate, the executors and the runner. It
// fails loudly when a zone's DNS provider is missing (NewDNSExecutor).
func New(o Options) (*App, error) {
	if o.Config == nil || o.Store == nil {
		return nil, errors.New("app: Config and Store are required")
	}
	a := &App{
		cfg: o.Config, st: o.Store, sources: o.Sources, providers: o.Providers, mgr: o.ACME,
		notifier: o.Notifier, met: o.Metrics, now: o.Now, log: o.Log,
		srcTO: o.SourceTimeout, dnsTO: o.DNSTimeout, renewTO: o.RenewEvery, stat: o.StatFile,
		liveInit: o.LiveInit, beforeRenew: o.BeforeRenew,
		trigger:  make(chan struct{}, 1),
		seenPrev: map[string]bool{}, seenCur: map[string]bool{},
		aliases: map[string]map[string]bool{}, lastLogged: map[string]string{},
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.srcTO <= 0 {
		a.srcTO = DefaultSourceTimeout
	}
	if a.dnsTO <= 0 {
		a.dnsTO = reconcile.DefaultDNSCallTimeout
	}
	if a.renewTO <= 0 {
		a.renewTO = DefaultRenewEvery
	}
	if a.stat == nil {
		a.stat = statFile
	}
	// Every provider call is counted in doorwarden_dns_operations_total
	// (listings, record writes and deletes alike).
	metered := make(map[string]dns.Provider, len(a.providers))
	for n, p := range a.providers {
		if p != nil {
			p = &meteredProvider{Provider: p, met: a.met}
		}
		metered[n] = p
	}
	a.providers = metered
	a.gate = approval.NewGate(a.st)
	a.probe = web.NewCachedProbe(a.st.Ping, o.HealthProbeInterval)

	multi := reconcile.NewMultiExecutor(a.recordActivity)
	re := reconcile.NewRouteExecutor(a.st, a.now)
	for _, k := range []reconcile.ActionKind{reconcile.RouteWrite, reconcile.RouteRemove,
		reconcile.ScheduleRemoval, reconcile.CancelRemoval} {
		multi.Handle(k, re)
	}
	de, err := reconcile.NewDNSExecutor(reconcile.DNSExecutorConfig{
		Config: a.cfg, Providers: a.providers, Store: a.st, Activity: a.st,
		Log: a.log, Now: a.now, CallTimeout: a.dnsTO, RepairState: a.st,
	})
	if err != nil {
		return nil, err
	}
	reconcile.RegisterDNSExecutor(multi, de)
	if a.mgr != nil {
		multi.Handle(reconcile.CertEnsure, acme.NewCertExecutor(a.mgr).OnResult(func(r acme.Result) { a.countRenewal(r) }))
	}
	a.runner = &reconcile.Runner{Exec: multi, Config: a.cfg, DryRun: a.cycleDry.Load}

	srcNames := make([]string, 0, len(a.sources))
	for _, s := range a.sources {
		srcNames = append(srcNames, s.name())
	}
	a.met.AllowSources(srcNames...)
	zones := make([]string, 0, len(a.cfg.Zones))
	for _, z := range a.cfg.Zones {
		zones = append(zones, normZone(z.Name))
	}
	a.met.AllowZones(zones...)
	types := []string{}
	for _, p := range a.providers {
		if p != nil {
			types = append(types, p.Type())
		}
	}
	a.met.AllowProviderTypes(types...)
	a.health = web.HealthStatus{Sources: map[string]bool{}}
	return a, nil
}

// Trigger asks for a reconcile soon. Triggers that arrive while a cycle is
// pending or running coalesce into one more cycle. It never blocks.
func (a *App) Trigger() {
	select {
	case a.trigger <- struct{}{}:
	default:
	}
}

// DryRun reports the effective global dry-run state: settings.dry_run OR the
// persisted toggle. On a store error it reports true (fail safe) with the
// error.
func (a *App) DryRun(ctx context.Context) (bool, error) {
	if a.cfg.Settings.DryRun {
		return true, nil
	}
	v, ok, err := a.st.GetSetting(ctx, DryRunKey)
	if err != nil {
		return true, err
	}
	return ok && v == "true", nil
}

// SetDryRun persists the global dry-run toggle and triggers a cycle. With
// settings.dry_run set in the config the run stays dry whatever the toggle.
func (a *App) SetDryRun(ctx context.Context, on bool) error {
	v := "false"
	if on {
		v = "true"
	}
	if err := a.st.SetSetting(ctx, DryRunKey, v); err != nil {
		return fmt.Errorf("persisting dry-run toggle: %w", err)
	}
	a.appendActivity(ctx, "info", "settings", "global dry run set to "+v)
	a.Trigger()
	return nil
}

// HealthHandler returns the /healthz handler. Its store probe is shared
// and cached (HealthProbeInterval), so a request flood cannot starve the
// store.
func (a *App) HealthHandler() http.Handler {
	return web.Health{Probe: a.probe.Probe, Status: a.HealthStatus}
}

// HealthStatus returns a copy of the last cycle's health snapshot.
func (a *App) HealthStatus() web.HealthStatus {
	a.hmu.RLock()
	defer a.hmu.RUnlock()
	h := a.health
	h.Sources = make(map[string]bool, len(a.health.Sources))
	for k, v := range a.health.Sources {
		h.Sources[k] = v
	}
	if a.health.LastReconcile != nil {
		t := *a.health.LastReconcile
		h.LastReconcile = &t
	}
	return h
}

// MetricsHandler returns the Prometheus handler (served by the API server,
// behind authentication).
func (a *App) MetricsHandler() http.Handler { return a.met.Handler() }

// Services returns the services of the last cycle after the approval gate
// (dry run included), for the API.
func (a *App) Services() []model.Service {
	a.hmu.RLock()
	defer a.hmu.RUnlock()
	return append([]model.Service(nil), a.snap...)
}

// Gate returns the approval gate (the API approves through it).
func (a *App) Gate() *approval.Gate { return a.gate }

// Close releases the sources (truenas.Source.Close and any other io.Closer)
// and drains the notifier (when it has Close(ctx)) within ctx. It does not
// close the store. Safe to call more than once.
func (a *App) Close(ctx context.Context) error {
	var errs []error
	a.closeOnce.Do(func() {
		for _, s := range a.sources {
			if s.Source == nil {
				continue
			}
			if c, ok := s.Source.(io.Closer); ok {
				if err := c.Close(); err != nil {
					errs = append(errs, fmt.Errorf("closing source %s: %w", s.name(), err))
				}
			}
		}
		if c, ok := a.notifier.(interface{ Close(context.Context) error }); ok {
			if err := c.Close(ctx); err != nil {
				errs = append(errs, fmt.Errorf("closing notifier: %w", err))
			}
		}
	})
	return errors.Join(errs...)
}
