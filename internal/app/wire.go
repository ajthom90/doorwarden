package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ajthom90/doorwarden/internal/acme"
	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers" // register every provider
	"github.com/ajthom90/doorwarden/internal/metrics"
	"github.com/ajthom90/doorwarden/internal/notify"
	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/ajthom90/doorwarden/internal/source/docker"
	"github.com/ajthom90/doorwarden/internal/source/static"
	"github.com/ajthom90/doorwarden/internal/source/truenas"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/web"
)

// Version is reported in doorwarden_build_info (set by main).
var Version = "dev"

// Flags are the command-line settings of Run.
type Flags struct {
	Config string
	DB     string
	Listen string
}

// ParseFlags parses args; env DOORWARDEN_CONFIG, DOORWARDEN_DB and
// DOORWARDEN_LISTEN supply the defaults.
func ParseFlags(args []string, env func(string) (string, bool)) (Flags, error) {
	if env == nil {
		env = os.LookupEnv
	}
	def := func(k, d string) string {
		if v, ok := env(k); ok && v != "" {
			return v
		}
		return d
	}
	fs := flag.NewFlagSet("doorwarden", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var f Flags
	fs.StringVar(&f.Config, "config", def("DOORWARDEN_CONFIG", "/config/doorwarden.yaml"), "config file (env DOORWARDEN_CONFIG)")
	fs.StringVar(&f.DB, "db", def("DOORWARDEN_DB", "/data/doorwarden.db"), "SQLite database (env DOORWARDEN_DB)")
	fs.StringVar(&f.Listen, "listen", def("DOORWARDEN_LISTEN", ":8080"), "HTTP listen address, empty to disable (env DOORWARDEN_LISTEN)")
	if err := fs.Parse(args); err != nil {
		return Flags{}, err
	}
	if fs.NArg() > 0 {
		return Flags{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	return f, nil
}

// Run starts the control plane and blocks until ctx is cancelled: load
// config, validate it, open the store and secrets, build sources, providers,
// ACME, notifications and metrics, serve /healthz, and run the loop. On
// cancellation it shuts down gracefully: the running cycle is aborted
// through ctx, the HTTP server drains, sources and the notifier are closed,
// then the store. Shutdown deletes nothing: no route, DNS record,
// certificate or Traefik file is removed (the next start resumes from the
// persisted state; see docs/rollback.md).
func Run(ctx context.Context, args []string) error {
	f, err := ParseFlags(args, nil)
	if err != nil {
		return err
	}
	return RunWith(ctx, f, os.LookupEnv, slog.Default())
}

// RunWith is Run with explicit flags, environment and logger.
func RunWith(ctx context.Context, f Flags, env func(string) (string, bool), log *slog.Logger) error {
	if env == nil {
		env = os.LookupEnv
	}
	if log == nil {
		log = slog.Default()
	}
	cfg, err := LoadConfig(f.Config, env)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(f.DB); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating the database directory: %w", err)
		}
	}
	st, err := store.Open(f.DB)
	if err != nil {
		return err
	}
	defer st.Close()

	var box *secrets.Box
	if mk, ok := env("DOORWARDEN_MASTER_KEY"); ok && mk != "" {
		if box, err = secrets.NewBox(mk); err != nil {
			return err
		}
	}
	sec := &SecretStore{KV: st, Box: box}
	if box == nil && needsMasterKey(cfg) {
		return errors.New("DOORWARDEN_MASTER_KEY is required: the config uses secret: references or ACME issuers")
	}

	met := metrics.New(Version)
	disp, err := notify.FromConfig(cfg.Notifications, notify.Options{Observe: met.Notification, Logger: log})
	if err != nil {
		return fmt.Errorf("notifications: %w", err)
	}
	built := false
	defer func() {
		if !built {
			cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = disp.Close(cctx)
			cancel()
		}
	}()

	providers, err := BuildProviders(cfg, sec)
	if err != nil {
		return err
	}
	srcs := BuildSources(cfg, sec)
	defer func() {
		if !built {
			closeSources(srcs)
		}
	}()

	var appRef atomic.Pointer[App]
	var mgr *acme.Manager
	var liveInit, beforeRenew func(context.Context) error
	if hasIssuer(cfg) {
		hosts := NewRouteHosts(st, log)
		// Start-up housekeeping (cert dir creation and cleanup, stale issuer
		// switches) waits for the first cycle that is not a dry run.
		mgr, err = acme.NewManager(acme.ManagerConfig{
			Config: cfg, Store: st, Box: box, CertsDir: cfg.CertsRoot(), Logger: log,
			SettingValue: sec.SettingValue,
			Notifier:     acmeNotifier(disp),
			OnChange: func() {
				if a := appRef.Load(); a != nil {
					a.Trigger()
				}
			},
			Wanted:              hosts.Wanted,
			DeferStartupCleanup: true,
		})
		if err != nil {
			return err
		}
		m := mgr
		liveInit = func(ctx context.Context) error {
			if err := os.MkdirAll(cfg.CertsRoot(), 0o700); err != nil {
				return fmt.Errorf("creating the certificate directory: %w", err)
			}
			m.StartupCleanup(ctx)
			return nil
		}
		beforeRenew = hosts.Load
	}
	if fi, err := os.Stat(cfg.Traefik.DynamicDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("traefik.dynamic_dir %q must be an existing directory", cfg.Traefik.DynamicDir)
	}

	a, err := New(Options{Config: cfg, Store: st, Sources: srcs, Providers: providers, ACME: mgr,
		Notifier: disp, Metrics: met, Log: log, LiveInit: liveInit, BeforeRenew: beforeRenew})
	if err != nil {
		return err
	}
	built = true
	appRef.Store(a)

	var srv *http.Server
	srvErr := make(chan error, 1)
	if f.Listen != "" {
		ln, err := net.Listen("tcp", f.Listen)
		if err != nil {
			_ = a.Close(context.Background())
			return fmt.Errorf("listen %s: %w", f.Listen, err)
		}
		api, err := web.NewServer(ctx, web.Options{
			Store: st, Control: a, Config: cfg, ConfigPath: f.Config,
			ValidateConfig: func(raw []byte) error { return validateConfigBytes(raw, env, box != nil) },
			Health:         a.HealthHandler(), Metrics: a.MetricsHandler(), Log: log,
		})
		if err != nil {
			_ = ln.Close()
			_ = a.Close(context.Background())
			return fmt.Errorf("http api: %w", err)
		}
		defer api.Close()
		a.SetEventSink(api.Events().Publish)
		// WriteTimeout bounds every response except the SSE stream, which
		// lifts it per response (web/sse.go).
		srv = &http.Server{Handler: api, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
			ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
		go func() { srvErr <- srv.Serve(ln) }()
	}
	dry, dryErr := a.DryRun(ctx)
	log.InfoContext(ctx, "doorwarden started", "version", Version, "sources", len(srcs), "dns_providers", len(providers), "dry_run", dry)
	if dry {
		why := "the dry-run toggle (UI/API) is on"
		switch {
		case cfg.Settings.DryRun:
			why = "settings.dry_run is true in the config"
		case dryErr != nil:
			why = "the dry-run toggle could not be read: " + dryErr.Error()
		}
		log.WarnContext(ctx, "DRY RUN: no DNS record, certificate, Traefik file or route is changed; the plan is only recorded as activity", "reason", why)
	}

	loopCtx, stopLoop := context.WithCancel(ctx)
	loopDone := make(chan error, 1)
	go func() { loopDone <- a.Run(loopCtx) }()
	var runErr error
	select {
	case <-ctx.Done():
	case err := <-srvErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("http server: %w", err)
		}
	}
	stopLoop()
	if err := <-loopDone; err != nil && runErr == nil {
		runErr = err
	}
	log.Info("doorwarden shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if srv != nil {
		_ = srv.Shutdown(sctx)
	}
	if err := a.Close(sctx); err != nil {
		log.Warn("shutdown", "error", err)
	}
	return runErr
}

// LoadConfig loads the config and runs config.Validate with the DNS
// registry's capabilities; any problem fails.
func LoadConfig(path string, env func(string) (string, bool)) (*config.Config, error) {
	cfg, err := config.Load(path, env)
	if err != nil {
		return nil, err
	}
	if errs := cfg.Validate(dns.ConfigCaps()); len(errs) > 0 {
		return nil, fmt.Errorf("invalid config %s: %w", path, errors.Join(errs...))
	}
	return cfg, nil
}

// validateConfigBytes checks a config document as LoadConfig would at the
// next start (PUT /api/v1/config): parse, Validate with the DNS registry's
// capabilities, and the master-key requirement.
//
// The document comes from an API client, so it is never expanded with the
// real environment: a client could reference any variable (e.g.
// ${DOORWARDEN_MASTER_KEY}) in a field that fails validation and read the
// value back from the error. Variables are checked for presence only and
// expand to envPlaceholder (an empty variable stays empty, so ":-"
// defaults behave as at start-up). Errors are additionally scrubbed of the
// real values of every variable the document names.
func validateConfigBytes(raw []byte, env func(string) (string, bool), haveMasterKey bool) error {
	cfg, err := config.Parse(raw, placeholderEnv(env))
	if err != nil {
		return scrubEnvValues(err, raw, env)
	}
	if errs := cfg.Validate(dns.ConfigCaps()); len(errs) > 0 {
		return scrubEnvValues(errors.Join(errs...), raw, env)
	}
	if !haveMasterKey && needsMasterKey(cfg) {
		return errors.New("the config uses secret: references or ACME issuers, which need DOORWARDEN_MASTER_KEY (not set)")
	}
	return nil
}

// envPlaceholder is what every set variable expands to when a client's
// config document is validated.
const envPlaceholder = "doorwarden-env-placeholder"

var envRefRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)`)

// placeholderEnv reports env's variables as set (or empty) without their
// values.
func placeholderEnv(env func(string) (string, bool)) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env(k)
		if !ok {
			return "", false
		}
		if v == "" {
			return "", true
		}
		return envPlaceholder, true
	}
}

// scrubEnvValues replaces the values of the variables raw references in
// err's text.
func scrubEnvValues(err error, raw []byte, env func(string) (string, bool)) error {
	msg := err.Error()
	for _, m := range envRefRe.FindAllSubmatch(raw, -1) {
		if v, ok := env(string(m[1])); ok && len(v) >= 3 {
			msg = strings.ReplaceAll(msg, v, "[redacted]")
		}
	}
	return errors.New(msg)
}

func hasIssuer(cfg *config.Config) bool {
	for _, z := range cfg.Zones {
		if z.Certificate.Issuer != "" {
			return true
		}
	}
	return false
}

func needsMasterKey(cfg *config.Config) bool {
	if hasIssuer(cfg) {
		return true // ACME account keys are sealed at rest
	}
	isRef := func(v any) bool {
		s, ok := v.(string)
		return ok && len(s) > len(dns.SecretPrefix) && s[:len(dns.SecretPrefix)] == dns.SecretPrefix
	}
	for _, p := range cfg.Providers {
		for _, v := range p.Extra {
			if isRef(v) {
				return true
			}
		}
	}
	return cfg.Sources.TrueNAS != nil && isRef(cfg.Sources.TrueNAS.APIKey)
}

// recordProviders are the config provider names used by a zone's records
// (mode wildcard or per-host); certificate.dns_provider entries are lego
// challenge providers and are built by the ACME manager instead.
func recordProviders(cfg *config.Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, z := range reconcileZoneRefs(cfg) {
		if !seen[z] {
			seen[z] = true
			out = append(out, z)
		}
	}
	sort.Strings(out)
	return out
}

func reconcileZoneRefs(cfg *config.Config) []string {
	var out []string
	for _, z := range cfg.Zones {
		if (z.Records.Mode == "wildcard" || z.Records.Mode == "per-host") && z.Records.Provider != "" {
			out = append(out, z.Records.Provider)
		}
	}
	return out
}

// BuildProviders constructs every DNS record provider a zone uses, resolving
// "secret:" settings through sr. A provider that cannot be built fails the
// start (a zone would otherwise silently stop being managed).
func BuildProviders(cfg *config.Config, sr dns.SecretResolver) (map[string]dns.Provider, error) {
	out := map[string]dns.Provider{}
	var errs []error
	for _, name := range recordProviders(cfg) {
		pc, ok := cfg.Providers[name]
		if !ok {
			errs = append(errs, fmt.Errorf("dns provider %q is not defined", name))
			continue
		}
		p, err := dns.New(pc.Type, pc.Extra, sr)
		if err != nil {
			errs = append(errs, fmt.Errorf("dns provider %q: %w", name, err))
			continue
		}
		out[name] = p
	}
	return out, errors.Join(errs...)
}

// approvalMode is the configured mode, or def when unset (config.Load sets
// truenas's default to approve; def repeats it for hand-built configs).
func approvalMode(v string, def approval.Mode) approval.Mode {
	if v == "" {
		return def
	}
	return approval.Mode(v)
}

// sourceTargetIP is the host discovered backends use with published ports:
// the target_ip of the default zone (settings.default_zone, else the only
// zone). Empty when there is none.
func sourceTargetIP(cfg *config.Config) string {
	dz := cfg.DefaultCertZone()
	for _, z := range cfg.Zones {
		if normZone(z.Name) == dz && dz != "" {
			return z.TargetIP
		}
	}
	return ""
}

// BuildSources builds the static source (always) and the configured docker
// and truenas sources. A source that fails to construct is returned with
// its error and is Unavailable every cycle (its services stay as they are).
func BuildSources(cfg *config.Config, sec *SecretStore) []SourceSpec {
	out := []SourceSpec{{Source: static.New(static.Config{Services: cfg.Static}), Mode: approval.ModeAuto}}
	tip := sourceTargetIP(cfg)
	if d := cfg.Sources.Docker; d != nil {
		s, err := docker.New(docker.Config{Endpoint: d.Host, TargetIP: tip})
		sp := SourceSpec{Name: "docker", Mode: approvalMode(d.Approval, approval.ModeAuto), Err: err}
		if err == nil {
			sp.Source = s
		}
		out = append(out, sp)
	}
	if t := cfg.Sources.TrueNAS; t != nil {
		sp := SourceSpec{Name: "truenas", Mode: approvalMode(t.Approval, approval.ModeApprove)}
		key, err := sec.Value(t.APIKey)
		if err == nil {
			var s *truenas.Source
			if s, err = truenas.New(truenas.Config{URL: t.URL, APIKey: key, TargetIP: tip}, nil); err == nil {
				sp.Source = s
			}
		}
		if err != nil && tip == "" {
			err = fmt.Errorf("%w (the backend host is the default zone's target_ip: set settings.default_zone)", err)
		}
		sp.Err = err
		out = append(out, sp)
	}
	return out
}

func closeSources(srcs []SourceSpec) {
	for _, s := range srcs {
		if c, ok := s.Source.(io.Closer); ok && s.Source != nil {
			_ = c.Close()
		}
	}
}

// RouteHosts is the ACME Wanted callback over the persisted routes. Load
// snapshots the routes before a renewal round (App's BeforeRenew): when the
// store cannot be read the round is skipped, so Wanted never reports a zone
// as empty because of a read error (that would mark every certificate in it
// unwanted).
type RouteHosts struct {
	st   *store.Store
	snap atomic.Pointer[[]store.Route]
	log  *slog.Logger
}

// NewRouteHosts returns the Wanted source over st.
func NewRouteHosts(st *store.Store, log *slog.Logger) *RouteHosts {
	if log == nil {
		log = slog.Default()
	}
	return &RouteHosts{st: st, log: log}
}

// Load snapshots the persisted routes.
func (r *RouteHosts) Load(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	routes, err := r.st.ListRoutes(ctx)
	if err != nil {
		return fmt.Errorf("reading routes for certificate renewal: %w", err)
	}
	r.snap.Store(&routes)
	return nil
}

// Wanted returns the hostnames of zone's routes in the last snapshot.
// Without one it loads it; if that fails it fails open and reports the
// zone's apex and wildcard as wanted (a read error must never make
// certificates unwanted).
func (r *RouteHosts) Wanted(zone string) []string {
	p := r.snap.Load()
	if p == nil {
		if err := r.Load(context.Background()); err != nil {
			r.log.Warn("acme wanted hosts unavailable; treating the zone as wanted", "zone", zone, "error", err)
			z := normZone(zone)
			return []string{z, "*." + z}
		}
		p = r.snap.Load()
	}
	z := normZone(zone)
	var out []string
	for _, rt := range *p {
		if normZone(rt.Zone) == z {
			out = append(out, rt.Hostname)
		}
	}
	return out
}

// acmeNotifier adapts certificate events to the notification dispatcher.
func acmeNotifier(d notify.Notifier) acme.Notifier {
	if d == nil {
		return nil
	}
	return acme.NotifierFunc(func(ctx context.Context, e acme.Event) {
		sev := notify.Warning
		switch {
		case e.Kind == acme.EventExpiring && e.Threshold <= 24*time.Hour:
			sev = notify.Critical
		case e.Kind == acme.EventFailure:
			sev = notify.Warning
		}
		fields := map[string]string{"cert": e.CertID, "zone": e.Zone}
		if !e.NotAfter.IsZero() {
			fields["not_after"] = e.NotAfter.UTC().Format(time.RFC3339)
		}
		_ = d.Notify(ctx, notify.Event{Kind: string(e.Kind), Severity: sev,
			Subject: "doorwarden: certificate " + e.CertID + " (" + string(e.Kind) + ")",
			Message: e.Message, Fields: fields, At: time.Now(),
			DedupeKey: string(e.Kind) + "/" + e.CertID + "/" + e.Threshold.String()})
	})
}
