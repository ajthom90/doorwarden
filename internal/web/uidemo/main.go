// Command uidemo serves the real web UI and API (internal/web) on localhost
// against seeded fake data, for looking at and clicking through the UI.
// Nothing here talks to a NAS, Docker, a DNS provider or a CA: the control
// plane is an in-memory fake and the store is a throwaway SQLite file.
//
//	go run ./internal/web/uidemo                  # admin / doorwarden-demo-pass
//	go run ./internal/web/uidemo -fresh           # no admin: first-run wizard
//	go run ./internal/web/uidemo -listen 127.0.0.1:8099 -dry-run
//
// It is not part of the doorwarden binary.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	_ "github.com/ajthom90/doorwarden/internal/dns/providers" // provider capabilities and config schemas (registration only)
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/store"
	"github.com/ajthom90/doorwarden/internal/web"
)

const (
	demoUser     = "admin"
	demoPassword = "doorwarden-demo-pass"
	demoToken    = "demo-setup-token-0000"
)

// demoConfig uses documentation names and addresses only.
const demoConfig = `zones:
  - name: home.example.test
    target_ip: 192.0.2.10
    records: {provider: cloudflare, mode: per-host}
    certificate: {issuer: le, strategy: wildcard, challenge: dns-01, dns_provider: cloudflare}
  - name: lab.example.test
    target_ip: 192.0.2.11
    records: {provider: cf-lab, mode: wildcard}
    certificate: {issuer: le-staging, strategy: per-host, challenge: dns-01, dns_provider: cf-lab}
  - name: internal.example.test
    target_ip: 192.0.2.12
    records: {mode: off}
    certificate: {issuer: le-staging, strategy: san, challenge: dns-01, dns_provider: r53}
providers:
  cloudflare: {type: cloudflare, api_token: "demo-not-a-real-token"}
  cf-lab: {type: cloudflare, api_token: "secret:cf-lab-token"}
  r53: {type: route53, access_key_id: "AKIADEMO", secret_access_key: "demo-not-a-real-secret"}
issuers:
  le: {directory: production, email: ops@example.test}
  le-staging: {directory: staging, email: ops@example.test}
settings:
  default_zone: home.example.test
web:
  cookie_insecure: true
`

func main() {
	listen := flag.String("listen", "127.0.0.1:8099", "address to serve on (keep it on localhost)")
	fresh := flag.Bool("fresh", false, "start without an administrator (shows the first-run wizard)")
	dry := flag.Bool("dry-run", true, "start with the global dry run on")
	flag.Parse()
	if err := run(*listen, *fresh, *dry); err != nil {
		fmt.Fprintln(os.Stderr, "uidemo:", err)
		os.Exit(1)
	}
}

func run(listen string, fresh, dry bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dir, err := os.MkdirTemp("", "doorwarden-uidemo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(demoConfig), 0o600); err != nil {
		return err
	}
	noEnv := func(string) (string, bool) { return "", false }
	cfg, err := config.Parse([]byte(demoConfig), noEnv)
	if err != nil {
		return fmt.Errorf("demo config: %w", err)
	}
	st, err := store.Open(filepath.Join(dir, "demo.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	now := time.Now()
	hasher := web.NewHasher(web.DefaultArgon2Params, 2)
	if !fresh {
		h, err := hasher.Hash(demoPassword)
		if err != nil {
			return err
		}
		if err := st.CreateAdmin(ctx, demoUser, h, now); err != nil {
			return err
		}
	}
	if err := seed(ctx, st, now); err != nil {
		return err
	}
	ctl := newFake(st, now, dry)
	srv, err := web.NewServer(ctx, web.Options{
		Store: st, Control: ctl, Config: cfg, ConfigPath: cfgPath,
		ValidateConfig: func(raw []byte) error {
			c, err := config.Parse(raw, noEnv)
			if err != nil {
				return err
			}
			if errs := c.Validate(dns.ConfigCaps()); len(errs) > 0 {
				return errs[0]
			}
			return nil
		},
		Health: web.Health{Probe: st.Ping, Status: ctl.health},
		Log:    slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		SetupToken: func() string {
			if fresh {
				return demoToken
			}
			return ""
		}(),
		Hasher: hasher,
	})
	if err != nil {
		return err
	}
	defer srv.Close()
	ctl.events = srv.Events()

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	go ctl.ticker(ctx)

	fmt.Printf("doorwarden UI demo (fake data, no real services): http://%s/\n", ln.Addr())
	if fresh {
		fmt.Printf("first-run wizard: setup token %s\n", demoToken)
	} else {
		fmt.Printf("sign in as %s / %s\n", demoUser, demoPassword)
	}
	fmt.Println("press Ctrl-C to stop; the demo data is deleted on exit")
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}

func seed(ctx context.Context, st *store.Store, now time.Time) error {
	day := 24 * time.Hour
	certs := []store.Cert{
		{ID: "home-wildcard", Zone: "home.example.test", DomainsJSON: `["*.home.example.test","home.example.test"]`, Issuer: "le",
			NotAfter: now.Add(61 * day), Status: "valid", LastResult: "ok", Managed: true},
		{ID: "lab-grafana", Zone: "lab.example.test", DomainsJSON: `["grafana.lab.example.test"]`, Issuer: "le-staging", Staging: true,
			NotAfter: now.Add(9 * day), Status: "valid", LastResult: "ok", Managed: true},
		{ID: "lab-paperless", Zone: "lab.example.test", DomainsJSON: `["paperless.lab.example.test"]`, Issuer: "le-staging", Staging: true,
			Status: "failed", LastResult: "error", LastError: "DNS-01 challenge: the TXT record was not visible at the authoritative servers after 2m", Managed: true},
		{ID: "internal-san", Zone: "internal.example.test", DomainsJSON: `["router.internal.example.test","nas.internal.example.test"]`, Issuer: "le-staging", Staging: true,
			NotAfter: now.Add(80 * day), Status: "valid", LastResult: "ok", Managed: true},
		{ID: "npm-legacy", Zone: "home.example.test", DomainsJSON: `["old.home.example.test"]`,
			NotAfter: now.Add(4 * day), Status: "imported", LastResult: "imported", Managed: false},
	}
	for _, c := range certs {
		if err := st.UpsertCert(ctx, c); err != nil {
			return err
		}
	}
	gone := now.Add(20 * time.Hour)
	recs := []store.DNSRecord{
		{Provider: "cloudflare", Zone: "home.example.test", Name: "nextcloud.home.example.test", Type: "A", Value: "192.0.2.10", ProviderRecordID: "r1", OwnerKey: "truenas:nextcloud", CreatedAt: now.Add(-30 * day)},
		{Provider: "cloudflare", Zone: "home.example.test", Name: "jellyfin.home.example.test", Type: "A", Value: "192.0.2.10", ProviderRecordID: "r2", OwnerKey: "truenas:jellyfin", CreatedAt: now.Add(-12 * day)},
		{Provider: "cloudflare", Zone: "home.example.test", Name: "sync.home.example.test", Type: "A", Value: "192.0.2.10", ProviderRecordID: "r3", OwnerKey: "truenas:syncthing", CreatedAt: now.Add(-3 * day)},
		{Provider: "cloudflare", Zone: "home.example.test", Name: "whoami.home.example.test", Type: "A", Value: "192.0.2.10", ProviderRecordID: "r4", OwnerKey: "docker:whoami", CreatedAt: now.Add(-40 * day), RemovedAfter: &gone},
	}
	for _, r := range recs {
		if err := st.AddOwnedRecord(ctx, r); err != nil {
			return err
		}
	}
	acts := []store.ActivityEntry{
		{TS: now.Add(-50 * time.Minute), Level: "info", Kind: "cycle", Message: "cycle: 9 services, 3 actions planned (dry run)"},
		{TS: now.Add(-42 * time.Minute), Level: "warn", Kind: "dns", Message: "DNS conflict: photos.home.example.test A exists at cloudflare and was not created by doorwarden"},
		{TS: now.Add(-30 * time.Minute), Level: "error", Kind: "acme", Message: "certificate lab-paperless: issue failed: DNS-01 challenge timed out"},
		{TS: now.Add(-20 * time.Minute), Level: "warn", Kind: "dns", Message: "DNS repair paused for cf-lab/lab.example.test: 5 of 6 owned records missing"},
		{TS: now.Add(-5 * time.Minute), Level: "info", Kind: "audit", Message: "local:admin set the port override of truenas:syncthing to 8384"},
		{TS: now.Add(-time.Minute), Level: "info", Kind: "audit", Message: "<script>alert('not markup')</script> is shown as text"},
	}
	for _, a := range acts {
		if err := st.AppendActivity(ctx, a); err != nil {
			return err
		}
	}
	return nil
}

// ---- the fake control plane

type svc struct {
	info      web.ServiceInfo
	staleOnce bool
}

type fake struct {
	mu     sync.Mutex
	st     *store.Store
	svcs   []*svc
	ovs    map[string]model.UIOverrides
	dry    bool
	cycles int
	events *web.Broker
	now    time.Time
}

func be(scheme, host string, port int, skip bool) model.Backend {
	return model.Backend{Scheme: scheme, Host: host, Port: port, SkipVerify: skip}
}

func newFake(st *store.Store, now time.Time, dry bool) *fake {
	f := &fake{st: st, dry: dry, now: now, ovs: map[string]model.UIOverrides{}}
	add := func(key, source, name, zone, state string, b model.Backend, mws ...string) *svc {
		s := &svc{info: web.ServiceInfo{Key: key, Source: source, Name: name, Zone: zone, Backend: b, State: state, Middlewares: mws}}
		f.svcs = append(f.svcs, s)
		return s
	}
	port := 8384
	rn := "sync"
	add("truenas:nextcloud", "truenas", "nextcloud", "home.example.test", "published", be("https", "192.0.2.10", 9001, true))
	add("truenas:jellyfin", "truenas", "jellyfin", "home.example.test", "published", be("http", "192.0.2.10", 8096, false)).info.Websockets = true
	add("docker:grafana", "docker", "grafana", "lab.example.test", "pending", be("http", "grafana", 3000, false), "authentik@file")
	add("docker:paperless", "docker", "paperless", "lab.example.test", "pending", be("http", "paperless", 8000, false)).staleOnce = true
	add("truenas:immich", "truenas", "photos", "home.example.test", "conflict", be("http", "192.0.2.10", 2283, false))
	add("static:router", "static", "router", "internal.example.test", "published", be("https", "192.0.2.1", 443, true))
	add("docker:whoami", "docker", "whoami", "home.example.test", "skipped", be("http", "whoami", 80, false))
	add("docker:bad-label", "docker", "bad-label", "lab.example.test", "error", be("http", "bad-label", 0, false))
	add("truenas:syncthing", "truenas", "syncthing", "home.example.test", "published", be("http", "192.0.2.10", 20910, false))
	f.ovs["truenas:syncthing"] = model.UIOverrides{Rename: &rn, Port: &port}
	return f
}

func (f *fake) fingerprint(s *svc) string {
	b, _ := json.Marshal([]any{s.info.Key, f.hostname(s), s.info.Backend, s.info.Middlewares})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

func (f *fake) hostname(s *svc) string {
	n := s.info.Name
	if o := f.ovs[s.info.Key]; o.Rename != nil {
		n = *o.Rename
	}
	return n + "." + s.info.Zone
}

func (f *fake) ServiceList() []web.ServiceInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]web.ServiceInfo, 0, len(f.svcs))
	for _, s := range f.svcs {
		v := s.info
		v.Middlewares = append([]string{}, v.Middlewares...)
		v.Overrides = f.ovs[v.Key]
		v.Hostname = f.hostname(s)
		if o := v.Overrides; o.Port != nil {
			v.Backend.Port = *o.Port
		}
		if o := v.Overrides; o.SkipVerify != nil && v.Backend.Scheme == "https" {
			v.Backend.SkipVerify = *o.SkipVerify
		}
		if o := v.Overrides; o.Skip != nil && *o.Skip {
			v.State = "skipped"
		} else if o.Skip != nil && !*o.Skip && v.State == "skipped" {
			v.State = "published"
		}
		if v.State == "pending" || v.State == "published" {
			v.Fingerprint = f.fingerprint(s)
		}
		out = append(out, v)
	}
	return out
}

func (f *fake) find(key string) *svc {
	for _, s := range f.svcs {
		if s.info.Key == key {
			return s
		}
	}
	return nil
}

func (f *fake) SetServiceOverride(_ context.Context, key string, edit func(*model.UIOverrides) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.find(key)
	if s == nil {
		return web.ErrUnknownService
	}
	o := f.ovs[key]
	if err := edit(&o); err != nil {
		return err
	}
	if o.Rename != nil && !validLabel(*o.Rename) {
		return &model.OverrideError{Msg: "rename must be a lowercase DNS label"}
	}
	if o.Port != nil && (*o.Port < 1 || *o.Port > 65535) {
		return &model.OverrideError{Msg: "port must be 1-65535"}
	}
	if o.SkipVerify != nil && s.info.Backend.Scheme != "https" {
		return &model.OverrideError{Msg: "skip_verify applies only to https backends"}
	}
	old := f.ovs[key]
	f.ovs[key] = o
	// A rename or TLS change sends a published service back for approval.
	if s.info.State == "published" && (!eqStr(old.Rename, o.Rename) || !eqBool(old.SkipVerify, o.SkipVerify)) && s.info.Source != "static" {
		s.info.State = "pending"
	}
	go f.cycle()
	return nil
}

func validLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func eqStr(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
func eqBool(a, b *bool) bool  { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func (f *fake) Approve(_ context.Context, key, fp string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.find(key)
	if s == nil || s.info.State != "pending" {
		return approval.ErrUnknownService
	}
	if s.staleOnce {
		// Simulates a label change between display and click.
		s.staleOnce = false
		s.info.Backend.Port = 8010
		s.info.Middlewares = append(s.info.Middlewares, "lan-only@file")
		return approval.ErrStale
	}
	if f.fingerprint(s) != fp {
		return approval.ErrStale
	}
	s.info.State = "published"
	go f.cycle()
	return nil
}

func (f *fake) LastPlan() web.Plan {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := func(k reconcile.ActionKind, key, zone, host, prov, reason string) reconcile.Action {
		return reconcile.Action{Kind: k, Key: key, Zone: zone, Host: host, Provider: prov, Reason: reason}
	}
	conflict := a(reconcile.Conflict, "truenas:immich", "home.example.test", "photos.home.example.test", "cloudflare",
		"an A record for photos.home.example.test exists at cloudflare that doorwarden did not create")
	conflict.Record = &dns.Record{ID: "ext-1", Name: "photos.home.example.test", Type: "A", Value: "198.51.100.7"}
	conflict.Owner = "truenas:immich"
	txt := a(reconcile.Conflict, "", "home.example.test", "mail.home.example.test", "cloudflare", "a TXT record holds the name")
	txt.Record = &dns.Record{ID: "ext-2", Name: "mail.home.example.test", Type: "TXT", Value: "v=spf1 -all"}
	breaker := a(reconcile.Skip, reconcile.RepairBreakerKey("cf-lab", "lab.example.test"), "lab.example.test", "lab.example.test", "cf-lab",
		"5 of 6 owned records are missing at the provider")
	breaker.Alert = reconcile.AlertDNSMassMissing
	acts := []reconcile.Action{
		conflict, txt, breaker,
		a(reconcile.Invalid, "docker:bad-label", "lab.example.test", "", "", `label doorwarden.port: "http" is not a port number`),
		a(reconcile.Skip, "docker:whoami", "home.example.test", "whoami.home.example.test", "", "label doorwarden.skip=true"),
		a(reconcile.RouteWrite, "truenas:syncthing", "home.example.test", "sync.home.example.test", "", ""),
		a(reconcile.DNSEnsure, "truenas:syncthing", "home.example.test", "sync.home.example.test", "cloudflare", ""),
		a(reconcile.CertEnsure, "", "lab.example.test", "grafana.lab.example.test", "", ""),
	}
	return web.Plan{At: f.now.Add(time.Duration(f.cycles) * 30 * time.Second), DryRun: f.dry, Actions: acts}
}

func (f *fake) DryRun(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dry, nil
}

func (f *fake) SetDryRun(_ context.Context, on bool) error {
	f.mu.Lock()
	f.dry = on
	f.mu.Unlock()
	go f.cycle()
	return nil
}

func (f *fake) Trigger() { go f.cycle() }

func (f *fake) TestProvider(ctx context.Context, name string) error {
	select {
	case <-time.After(700 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	if name == "cf-lab" {
		return errors.New("fake: authentication failed")
	}
	return nil
}

func (f *fake) RenewCert(ctx context.Context, id string) error {
	select {
	case <-time.After(3 * time.Second):
	case <-ctx.Done():
		return ctx.Err()
	}
	if id == "lab-paperless" {
		return errors.New("fake: challenge failed again")
	}
	return f.updateCerts(ctx, func(c *store.Cert) bool {
		if c.ID != id {
			return false
		}
		c.NotAfter, c.Status, c.LastResult, c.LastError = time.Now().Add(90*24*time.Hour), "valid", "ok", ""
		return true
	})
}

func (f *fake) SwitchProduction(ctx context.Context, issuer string) error {
	select {
	case <-time.After(3 * time.Second):
	case <-ctx.Done():
		return ctx.Err()
	}
	return f.updateCerts(ctx, func(c *store.Cert) bool {
		if c.Issuer != issuer || !c.Staging {
			return false
		}
		c.Staging, c.NotAfter, c.Status, c.LastResult, c.LastError = false, time.Now().Add(90*24*time.Hour), "valid", "ok", ""
		return true
	})
}

func (f *fake) updateCerts(ctx context.Context, edit func(*store.Cert) bool) error {
	cs, err := f.st.ListCerts(ctx)
	if err != nil {
		return err
	}
	for _, c := range cs {
		if edit(&c) {
			if err := f.st.UpsertCert(ctx, c); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *fake) health() web.HealthStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.now.Add(time.Duration(f.cycles) * 30 * time.Second)
	res := "ok"
	if f.dry {
		res = "dry_run"
	}
	return web.HealthStatus{DryRun: f.dry, Sources: map[string]bool{"docker": true, "truenas": f.cycles%6 != 5, "static": true},
		LastReconcile: &t, LastResult: res}
}

// cycle stands in for a reconcile cycle: it tells the UI to refresh.
func (f *fake) cycle() {
	time.Sleep(300 * time.Millisecond)
	f.mu.Lock()
	f.cycles++
	n, ev := f.cycles, f.events
	f.mu.Unlock()
	if ev != nil {
		ev.Publish("cycle", map[string]any{"n": n})
	}
}

// ticker runs a cycle every 30s and posts an activity line every 12s.
func (f *fake) ticker(ctx context.Context) {
	c := time.NewTicker(30 * time.Second)
	a := time.NewTicker(12 * time.Second)
	defer c.Stop()
	defer a.Stop()
	i := 0
	msgs := []string{
		"cycle: no changes",
		"docker: container grafana restarted; backend unchanged",
		"truenas: listed 5 apps",
		"dns: cloudflare home.example.test in sync (4 owned records)",
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.C:
			f.cycle()
		case <-a.C:
			m := msgs[i%len(msgs)]
			i++
			kind := strings.SplitN(m, ":", 2)[0]
			_ = f.st.AppendActivity(ctx, store.ActivityEntry{TS: time.Now(), Level: "info", Kind: kind, Message: m})
			if f.events != nil {
				f.events.Publish("activity", map[string]string{"kind": kind, "message": m})
			}
		}
	}
}
