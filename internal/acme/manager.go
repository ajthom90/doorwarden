// Package acme issues, renews and imports TLS certificates with lego.
//
// Certificates live on disk as <certs dir>/<id>/{fullchain,privkey}.pem
// (directories 0700, files 0600, replaced atomically) and as rows in the
// store's certs table (no key material). A managed certificate's id is
// derived from its zone and names, so renewals and re-issues overwrite the
// same files. Imported certificates (ImportPEM, ImportNPMDir) are rows with
// managed=false and are never renewed automatically; RenewNow turns one into
// a managed certificate on explicit request once its zone has an issuer.
//
// Reliability: every certificate set has persistent exponential backoff
// (1m, 2m, 4m, ... capped at 6h, with jitter). A failed attempt never
// touches the files or the expiry of the previous certificate, which keeps
// serving. A Let's Encrypt rateLimited problem parks the set until its
// Retry-After (1h when absent). Failed validations per issuer and hostname
// are counted and the set is refused after maxFailedValidations within an
// hour (Let's Encrypt allows 5). Orders per issuer account are counted for
// 7 days; identical sets are refused after maxDuplicateOrders successful
// orders in 7 days and accounts after maxOrdersPer3h orders in 3 hours.
//
// lego is not context-aware and keeps some DNS-01 settings in package
// globals, so the process runs one ACME order at a time (issueSem). When a
// caller's context ends first the order finishes in the background and its
// result is still persisted.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	legodns "github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/ajthom90/doorwarden/internal/store"
)

// Limits (conservative relative to Let's Encrypt's published limits).
const (
	maxFailedValidations = 3 // per issuer, hostname and hour (LE: 5)
	maxDuplicateOrders   = 4 // successful orders of one exact set per 7 days (LE: 5)
	maxOrdersPer3h       = 250
	defaultRateLimitPark = time.Hour
	maxRateLimitPark     = 7 * 24 * time.Hour
	defaultIssueTimeout  = 5 * time.Minute
	defaultRenewBefore   = 30 * 24 * time.Hour
	maxErrorLen          = 1500
)

// Cert row Status values.
const (
	StatusValid    = "valid"    // issued by doorwarden
	StatusImported = "imported" // imported, not managed
	StatusFailed   = "failed"   // never issued successfully
)

// Errors.
var (
	// ErrDeferred matches every *DeferredError (backoff, rate-limit park,
	// failed-validation and order guards).
	ErrDeferred = errors.New("acme: attempt deferred")
	// ErrInFlight: an order for the same certificate is already running.
	ErrInFlight = errors.New("acme: an order for this certificate is already in progress")
	// ErrNoIssuer: the zone has no certificate issuer.
	ErrNoIssuer = errors.New("acme: zone has no certificate issuer")
	// ErrImported: imported certificates are not renewed automatically.
	ErrImported = errors.New("acme: imported certificate is not renewed automatically (use RenewNow)")
	// ErrNeedsSwitch: the certificate's staging flag differs from its issuer's
	// current directory; re-issue it explicitly (SwitchIssuer / RenewNow).
	ErrNeedsSwitch = errors.New("acme: issuer directory changed between staging and production; re-issue explicitly")
	// ErrNotFound: no certificate with that id.
	ErrNotFound = errors.New("acme: certificate not found")
)

// DeferredError reports an attempt that was not made.
type DeferredError struct {
	Until     time.Time
	Reason    string
	LastError string
}

func (e *DeferredError) Error() string {
	s := fmt.Sprintf("acme: %s; next attempt after %s", e.Reason, e.Until.UTC().Format(time.RFC3339))
	if e.LastError != "" {
		s += " (last error: " + e.LastError + ")"
	}
	return s
}

// Is makes errors.Is(err, ErrDeferred) true.
func (e *DeferredError) Is(target error) bool { return target == ErrDeferred }

// ManagerConfig configures a Manager. Config, Store, Box and a certs
// directory (CertsDir or Config.ACME.CertsDir) are required.
type ManagerConfig struct {
	Config *config.Config
	Store  *store.Store
	// Box seals ACME account keys at rest.
	Box *secrets.Box
	// CertsDir overrides Config.ACME.CertsDir.
	CertsDir string
	// Now is the clock (default time.Now).
	Now func() time.Time
	// Jitter returns a value in [0,1) for backoff jitter (default random).
	Jitter func() float64
	// HTTPClient talks to the ACME directory (default: lego's client).
	HTTPClient *http.Client
	// ProviderByName builds a lego DNS provider by code. It runs while the
	// provider's settings are in the process environment (default: lego's
	// registry, providers/dns.NewDNSChallengeProviderByName).
	ProviderByName func(name string) (challenge.Provider, error)
	// HTTP01Provider builds the HTTP-01 solver (default: lego's server on
	// Config.ACME.HTTP01Listen).
	HTTP01Provider func() (challenge.Provider, error)
	// DNS01Options are extra lego DNS-01 options (tests use them to relax the
	// client-side propagation check).
	DNS01Options []dns01.ChallengeOption
	// SettingValue turns a raw providers: setting value into the string
	// handed to lego (default: strings as is, other scalars via fmt). The
	// orchestrator plugs secret references in here.
	SettingValue func(raw any) (string, error)
	// Notifier receives failure and expiry events (optional).
	Notifier Notifier
	// OnChange is called after certificate files or rows changed (issue,
	// renewal, import), e.g. to re-render Traefik's TLS file (optional).
	OnChange func()
	// IssueTimeout overrides Config.ACME.IssueTimeout (default 5m).
	IssueTimeout time.Duration
	Logger       *slog.Logger
}

// Manager issues and renews certificates. It is safe for concurrent use.
type Manager struct {
	cfg            *config.Config
	st             *store.Store
	kv             kvStore
	box            *secrets.Box
	certsDir       string
	now            func() time.Time
	jitter         func() float64
	httpClient     *http.Client
	providerByName func(string) (challenge.Provider, error)
	http01         func() (challenge.Provider, error)
	dnsOpts        []dns01.ChallengeOption
	settingValue   func(any) (string, error)
	notifier       Notifier
	onChange       func()
	issueTimeout   time.Duration
	renewBefore    time.Duration
	log            *slog.Logger
	red            *redactor

	// obtain places one ACME order (lego by default; replaced in tests).
	obtain func(ctx context.Context, o order) (obtained, error)

	stateMu   sync.Mutex // kv read-modify-write
	accountMu sync.Mutex // account key creation / registration
	flightMu  sync.Mutex
	inflight  map[string]bool
}

// order is one ACME order request.
type order struct {
	Issuer    string
	IssuerCfg config.Issuer
	Dir       directory
	Names     []string
	Challenge string
	Provider  challenge.Provider
}

type obtained struct {
	ChainPEM []byte
	KeyPEM   []byte
}

// issueSem allows one ACME order per process (lego's DNS-01 settings are
// package globals and lego is not context-aware).
var issueSem = make(chan struct{}, 1)

var legoLogOnce sync.Once

// NewManager validates the configuration and returns a Manager.
func NewManager(mc ManagerConfig) (*Manager, error) {
	if mc.Config == nil || mc.Store == nil || mc.Box == nil {
		return nil, errors.New("acme: Config, Store and Box are required")
	}
	dir := mc.CertsDir
	if dir == "" {
		dir = mc.Config.ACME.CertsDir
	}
	if dir == "" {
		return nil, errors.New("acme: certs directory is not set (acme.certs_dir)")
	}
	m := &Manager{
		cfg: mc.Config, st: mc.Store, kv: kvStore{mc.Store}, box: mc.Box, certsDir: dir,
		now: mc.Now, jitter: mc.Jitter, httpClient: mc.HTTPClient, providerByName: mc.ProviderByName,
		http01: mc.HTTP01Provider, dnsOpts: mc.DNS01Options, settingValue: mc.SettingValue,
		notifier: mc.Notifier, onChange: mc.OnChange, issueTimeout: mc.IssueTimeout, log: mc.Logger,
		inflight: map[string]bool{},
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.jitter == nil {
		m.jitter = mrand.Float64
	}
	if m.providerByName == nil {
		m.providerByName = legodns.NewDNSChallengeProviderByName
	}
	if m.http01 == nil {
		listen := mc.Config.ACME.HTTP01Listen
		m.http01 = func() (challenge.Provider, error) {
			if listen == "" {
				return nil, errors.New("acme: http-01 needs acme.http01_listen")
			}
			host, port, err := net.SplitHostPort(listen)
			if err != nil {
				return nil, fmt.Errorf("acme: acme.http01_listen: %w", err)
			}
			return http01.NewProviderServer(host, port), nil
		}
	}
	if m.settingValue == nil {
		m.settingValue = func(raw any) (string, error) {
			switch v := raw.(type) {
			case string:
				return v, nil
			case nil:
				return "", nil
			case bool, int, int64, float64, uint64:
				return fmt.Sprint(v), nil
			}
			return "", fmt.Errorf("unsupported value type %T", raw)
		}
	}
	if m.issueTimeout <= 0 {
		m.issueTimeout = mc.Config.ACME.IssueTimeout
	}
	if m.issueTimeout <= 0 {
		m.issueTimeout = defaultIssueTimeout
	}
	m.renewBefore = mc.Config.Settings.RenewBefore
	if m.renewBefore <= 0 {
		m.renewBefore = defaultRenewBefore
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	m.red = newRedactor()
	m.red.parent = globalRedactor
	m.log = slog.New(redactHandler{inner: m.log.Handler(), r: m.red})
	if m.notifier != nil {
		m.notifier = redactNotifier{inner: m.notifier, r: m.red}
	}
	m.registerConfigSecrets()
	m.obtain = m.legoObtain
	if err := errors.Join(ValidateConfig(mc.Config, mc.HTTP01Provider != nil)...); err != nil {
		return nil, err
	}
	legoLogOnce.Do(func() {
		legolog.Logger = slog.NewLogLogger(redactHandler{inner: slog.Default().Handler(), r: globalRedactor}, slog.LevelDebug)
	})
	return m, nil
}

// ValidateConfig checks everything certificate-related that needs the lego
// catalog: issuers, and for each zone with an issuer its strategy,
// challenge and challenge provider. haveHTTP01 reports a custom HTTP-01
// solver (otherwise http-01 needs acme.http01_listen).
func ValidateConfig(c *config.Config, haveHTTP01 bool) []error {
	var errs []error
	names := make([]string, 0, len(c.Issuers))
	for n := range c.Issuers {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if err := validateIssuer(n, c.Issuers[n]); err != nil {
			errs = append(errs, err)
		}
	}
	for i, z := range c.Zones {
		cert := z.Certificate
		if cert.Issuer == "" {
			continue
		}
		id := fmt.Sprintf("zone[%d] %q", i, z.Name)
		if _, ok := c.Issuers[cert.Issuer]; !ok {
			errs = append(errs, fmt.Errorf("%s: certificate.issuer %q is not defined", id, cert.Issuer))
		}
		strategy, ch := zoneStrategy(z), zoneChallenge(z)
		switch strategy {
		case StrategyWildcard, StrategyPerHost, StrategySAN:
		default:
			errs = append(errs, fmt.Errorf("%s: unknown certificate.strategy %q", id, strategy))
		}
		switch ch {
		case ChallengeDNS01:
			if err := checkChallengeProvider(c, cert.DNSProvider); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", id, err))
			}
		case ChallengeHTTP01:
			if strategy == StrategyWildcard {
				errs = append(errs, fmt.Errorf("%s: %w (strategy wildcard)", id, ErrWildcardNeedsDNS01))
			}
			if !haveHTTP01 && c.ACME.HTTP01Listen == "" {
				errs = append(errs, fmt.Errorf("%s: challenge http-01 requires acme.http01_listen", id))
			}
		default:
			errs = append(errs, fmt.Errorf("%s: unknown certificate.challenge %q", id, ch))
		}
	}
	return errs
}

func checkChallengeProvider(c *config.Config, name string) error {
	if name == "" {
		return errors.New("certificate.dns_provider is required for dns-01")
	}
	p, ok := c.Providers[name]
	if !ok {
		return fmt.Errorf("certificate.dns_provider %q is not defined", name)
	}
	if p.Type == "unifi" {
		return fmt.Errorf("certificate.dns_provider %q is of type unifi, which cannot solve ACME challenges", name)
	}
	if _, ok := LookupChallengeProvider(p.Type); !ok {
		return fmt.Errorf("certificate.dns_provider %q has type %q, which is not a lego DNS provider", name, p.Type)
	}
	return nil
}

func zoneStrategy(z config.Zone) string {
	if z.Certificate.Strategy == "" {
		return StrategyWildcard
	}
	return z.Certificate.Strategy
}

func zoneChallenge(z config.Zone) string {
	if z.Certificate.Challenge == "" {
		return ChallengeDNS01
	}
	return z.Certificate.Challenge
}

func (m *Manager) zone(name string) (config.Zone, bool) {
	n := normName(name)
	for _, z := range m.cfg.Zones {
		if normName(z.Name) == n {
			return z, true
		}
	}
	return config.Zone{}, false
}

// IssueRequest asks for certificates of one zone. Strategy empty means the
// zone's configured strategy.
type IssueRequest struct {
	Zone     string
	Names    []string
	Strategy string
}

// Result is the outcome for one certificate (set).
type Result struct {
	CertID string
	Zone   string
	Names  []string
	// Bundle is set on success.
	Bundle *Bundle
	// Err is nil on success. errors.Is(Err, ErrDeferred) means no attempt was
	// made (see NextAttempt).
	Err error
	// NextAttempt is the earliest time another attempt will be made after a
	// failure or deferral.
	NextAttempt time.Time
	// Skipped is true when the certificate was intentionally not renewed
	// (imported, staging/production mismatch, zone without issuer).
	Skipped bool
}

// Issue orders the certificate for req, which must resolve to exactly one
// order (use IssueAll for per-host lists and san sets above 100 names).
func (m *Manager) Issue(ctx context.Context, req IssueRequest) (*Bundle, error) {
	b, err := m.issue(ctx, req)
	return b, m.red.safeErr(err)
}

func (m *Manager) issue(ctx context.Context, req IssueRequest) (*Bundle, error) {
	z, sets, err := m.resolveRequest(req)
	if err != nil {
		return nil, err
	}
	if len(sets) != 1 {
		return nil, fmt.Errorf("acme: request resolves to %d orders; use IssueAll", len(sets))
	}
	r := m.issueSet(ctx, z, sets[0], certID(z.Name, sets[0]), false)
	return r.Bundle, r.Err
}

// IssueAll orders every certificate req resolves to, one after another.
func (m *Manager) IssueAll(ctx context.Context, req IssueRequest) []Result {
	return m.safeResults(m.issueAll(ctx, req))
}

func (m *Manager) issueAll(ctx context.Context, req IssueRequest) []Result {
	z, sets, err := m.resolveRequest(req)
	if err != nil {
		return []Result{{Zone: normName(req.Zone), Names: req.Names, Err: err}}
	}
	out := make([]Result, 0, len(sets))
	for _, s := range sets {
		out = append(out, m.issueSet(ctx, z, s, certID(z.Name, s), false))
	}
	return out
}

func (m *Manager) resolveRequest(req IssueRequest) (config.Zone, [][]string, error) {
	z, ok := m.zone(req.Zone)
	if !ok {
		return z, nil, fmt.Errorf("acme: zone %q is not configured", req.Zone)
	}
	if z.Certificate.Issuer == "" {
		return z, nil, ErrNoIssuer
	}
	strategy := req.Strategy
	if strategy == "" {
		strategy = zoneStrategy(z)
	}
	sets, err := planSets(z.Name, req.Names, strategy, zoneChallenge(z))
	return z, sets, err
}

// effectiveDirectory resolves an issuer's directory, honoring an explicit
// staging->production switch (SwitchIssuer).
func (m *Manager) effectiveDirectory(ctx context.Context, issuer string) (directory, config.Issuer, error) {
	is, ok := m.cfg.Issuers[issuer]
	if !ok {
		return directory{}, is, fmt.Errorf("acme: issuer %q is not defined", issuer)
	}
	d, err := resolveDirectory(is.Directory)
	if err != nil {
		return d, is, fmt.Errorf("acme: issuer %q: %w", issuer, err)
	}
	if d.Staging {
		v, ok, err := m.st.GetSetting(ctx, overrideKey(issuer))
		if err != nil {
			return d, is, err
		}
		if ok && v == "production" {
			d, _ = resolveDirectory("production")
		}
	}
	return d, is, nil
}

func (m *Manager) markInFlight(id string) bool {
	m.flightMu.Lock()
	defer m.flightMu.Unlock()
	if m.inflight[id] {
		return false
	}
	m.inflight[id] = true
	return true
}

func (m *Manager) clearInFlight(id string) {
	m.flightMu.Lock()
	delete(m.inflight, id)
	m.flightMu.Unlock()
}

// issueSet orders one certificate into id. force skips the ordinary backoff
// (explicit user action) but never a rate-limit park or the order guards.
func (m *Manager) issueSet(ctx context.Context, z config.Zone, names []string, id string, force bool) Result {
	res := Result{CertID: id, Zone: normName(z.Name), Names: append([]string(nil), names...)}
	issuer := z.Certificate.Issuer
	if issuer == "" {
		res.Err = ErrNoIssuer
		return res
	}
	ch := zoneChallenge(z)
	if ch != ChallengeDNS01 && hasWildcard(names) {
		res.Err = ErrWildcardNeedsDNS01
		return res
	}
	dir, isCfg, err := m.effectiveDirectory(ctx, issuer)
	if err != nil {
		res.Err = err
		return res
	}
	if !m.markInFlight(id) {
		res.Err = ErrInFlight
		return res
	}
	handedOff := false
	defer func() {
		if !handedOff {
			m.clearInFlight(id)
		}
	}()
	if derr := m.guard(ctx, issuer, id, names, force); derr != nil {
		res.Err = derr
		res.NextAttempt = derr.Until
		return res
	}

	var prov challenge.Provider
	if ch == ChallengeDNS01 {
		prov, err = m.dnsChallengeProvider(z.Certificate.DNSProvider)
	} else {
		prov, err = m.http01()
	}
	if err != nil {
		return m.recordFailure(context.WithoutCancel(ctx), z, issuer, dir, id, names, err)
	}

	select {
	case issueSem <- struct{}{}:
	case <-ctx.Done():
		res.Err = fmt.Errorf("acme: waiting for another order: %w", ctx.Err())
		return res
	}
	o := order{Issuer: issuer, IssuerCfg: isCfg, Dir: dir, Names: names, Challenge: ch, Provider: prov}
	done := make(chan Result, 1)
	handedOff = true
	go func() {
		defer func() { <-issueSem }()
		defer m.clearInFlight(id)
		bg := context.WithoutCancel(ctx)
		var r Result
		func() {
			defer func() {
				if p := recover(); p != nil {
					r = m.recordFailure(bg, z, issuer, dir, id, names, fmt.Errorf("acme: order panicked: %v", p))
				}
			}()
			ob, err := m.obtain(ctx, o)
			m.recordOrder(bg, issuer, id, err == nil)
			if err != nil {
				r = m.recordFailure(bg, z, issuer, dir, id, names, err)
				return
			}
			r = m.recordSuccess(bg, z, issuer, dir, id, names, ob)
		}()
		done <- r
	}()
	select {
	case r := <-done:
		return r
	case <-ctx.Done():
		res.Err = fmt.Errorf("acme: order still running in the background; its result will be stored: %w", ctx.Err())
		return res
	}
}

// guard returns a DeferredError when no attempt may be made now.
func (m *Manager) guard(ctx context.Context, issuer, id string, names []string, force bool) *DeferredError {
	now := m.now()
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	var a attemptState
	if _, err := m.kv.getJSON(ctx, attemptKey(id), &a); err != nil {
		return &DeferredError{Until: now.Add(backoffBase), Reason: "state unreadable: " + err.Error()}
	}
	if a.ParkedUntil.After(now) {
		return &DeferredError{Until: a.ParkedUntil, Reason: "rate limited by the CA", LastError: a.LastError}
	}
	if !force && a.NextAttempt.After(now) {
		return &DeferredError{Until: a.NextAttempt, Reason: fmt.Sprintf("backing off after %d failure(s)", a.Failures), LastError: a.LastError}
	}
	for _, n := range names {
		var ts []int64
		_, _ = m.kv.getJSON(ctx, fvKey(issuer, n), &ts)
		ts = within(ts, now, time.Hour)
		if len(ts) >= maxFailedValidations {
			return &DeferredError{Until: time.Unix(ts[0], 0).Add(time.Hour), Reason: fmt.Sprintf("%d failed validations for %s in the last hour", len(ts), n), LastError: a.LastError}
		}
	}
	var evs []orderEvent
	_, _ = m.kv.getJSON(ctx, ordersKey(issuer), &evs)
	var dup, recent []int64
	for _, e := range evs {
		t := time.Unix(e.T, 0)
		if e.Set == id && e.OK && now.Sub(t) < 7*24*time.Hour {
			dup = append(dup, e.T)
		}
		if now.Sub(t) < 3*time.Hour {
			recent = append(recent, e.T)
		}
	}
	if len(dup) >= maxDuplicateOrders {
		return &DeferredError{Until: time.Unix(dup[0], 0).Add(7 * 24 * time.Hour), Reason: fmt.Sprintf("%d certificates for this exact name set in 7 days", len(dup))}
	}
	if len(recent) >= maxOrdersPer3h {
		return &DeferredError{Until: time.Unix(recent[0], 0).Add(3 * time.Hour), Reason: fmt.Sprintf("%d orders by issuer %s in 3 hours", len(recent), issuer)}
	}
	return nil
}

// within keeps the (sorted) unix times newer than now-d.
func within(ts []int64, now time.Time, d time.Duration) []int64 {
	cut := now.Add(-d).Unix()
	out := ts[:0:0]
	for _, t := range ts {
		if t > cut {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}

func (m *Manager) recordOrder(ctx context.Context, issuer, id string, ok bool) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	now := m.now()
	var evs []orderEvent
	_, _ = m.kv.getJSON(ctx, ordersKey(issuer), &evs)
	keep := evs[:0]
	for _, e := range evs {
		if now.Sub(time.Unix(e.T, 0)) < 7*24*time.Hour {
			keep = append(keep, e)
		}
	}
	keep = append(keep, orderEvent{T: now.Unix(), Set: id, OK: ok})
	if err := m.kv.putJSON(ctx, ordersKey(issuer), keep); err != nil {
		m.log.Warn("acme: record order", "issuer", issuer, "err", err)
	}
}

// OrdersLastWeek returns how many orders the issuer's account placed in the
// last 7 days (best effort; for the UI).
func (m *Manager) OrdersLastWeek(ctx context.Context, issuer string) (int, error) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	var evs []orderEvent
	if _, err := m.kv.getJSON(ctx, ordersKey(issuer), &evs); err != nil {
		return 0, err
	}
	n := 0
	for _, e := range evs {
		if m.now().Sub(time.Unix(e.T, 0)) < 7*24*time.Hour {
			n++
		}
	}
	return n, nil
}

// safeResults redacts the error text of every result.
func (m *Manager) safeResults(rs []Result) []Result {
	for i := range rs {
		rs[i].Err = m.red.safeErr(rs[i].Err)
	}
	return rs
}

// rateLimitPark returns how long to park after err, or 0 when err is not a
// rateLimited problem.
func rateLimitPark(err error, now time.Time) time.Duration {
	var rl *acme.RateLimitedError
	if errors.As(err, &rl) {
		if d := parseRetryAfter(rl.RetryAfter, now); d > 0 {
			return min(d, maxRateLimitPark)
		}
		return defaultRateLimitPark
	}
	var pd *acme.ProblemDetails
	if errors.As(err, &pd) && pd.Type == acme.RateLimitedErr {
		return defaultRateLimitPark
	}
	return 0
}

// parseRetryAfter reads a Retry-After value (delay-seconds or HTTP-date,
// RFC 9110) relative to now; 0 when absent, invalid or in the past.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n <= 0 || n > int64(maxRateLimitPark/time.Second) {
			return min(time.Duration(max(n, 0))*time.Second, maxRateLimitPark)
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// validationFailure reports whether err carries a CA validation problem (a
// failed challenge counts against Let's Encrypt's failed-validation limit).
func validationFailure(err error) bool {
	types := map[string]bool{"unauthorized": true, "dns": true, "connection": true, "incorrectResponse": true,
		"caa": true, "tls": true, "rejectedIdentifier": true}
	var found bool
	var walk func(error)
	walk = func(e error) {
		if e == nil || found {
			return
		}
		if pd, ok := e.(*acme.ProblemDetails); ok {
			if types[strings.TrimPrefix(pd.Type, "urn:ietf:params:acme:error:")] {
				found = true
			}
			for _, sp := range pd.SubProblems {
				if types[strings.TrimPrefix(sp.Type, "urn:ietf:params:acme:error:")] {
					found = true
				}
			}
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, x := range u.Unwrap() {
				walk(x)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		}
	}
	walk(err)
	return found
}

// recordFailure persists a failed attempt: backoff (and rate-limit park),
// failed validations, and the row's last_result/last_error. The previous
// certificate's files, expiry and path are left untouched.
func (m *Manager) recordFailure(ctx context.Context, z config.Zone, issuer string, dir directory, id string, names []string, cause error) Result {
	now := m.now()
	msg := m.red.errText(cause)
	park := rateLimitPark(cause, now)
	m.stateMu.Lock()
	var a attemptState
	_, _ = m.kv.getJSON(ctx, attemptKey(id), &a)
	a.Failures++
	a.LastError = msg
	a.NextAttempt = now.Add(backoffDelay(a.Failures, m.jitter()))
	if park > 0 {
		a.ParkedUntil = now.Add(park)
		if a.ParkedUntil.After(a.NextAttempt) {
			a.NextAttempt = a.ParkedUntil
		}
	}
	if err := m.kv.putJSON(ctx, attemptKey(id), a); err != nil {
		m.log.Warn("acme: persist backoff", "cert", id, "err", err)
	}
	if validationFailure(cause) {
		for _, n := range names {
			var ts []int64
			_, _ = m.kv.getJSON(ctx, fvKey(issuer, n), &ts)
			ts = append(within(ts, now, time.Hour), now.Unix())
			_ = m.kv.putJSON(ctx, fvKey(issuer, n), ts)
		}
	}
	m.stateMu.Unlock()

	result := "error"
	if park > 0 {
		result = "rate-limited"
	}
	row, found, err := m.certRow(ctx, id)
	if err != nil {
		m.log.Warn("acme: read cert row", "cert", id, "err", err)
	}
	if !found {
		dj, _ := json.Marshal(names)
		row = store.Cert{ID: id, Zone: normName(z.Name), DomainsJSON: string(dj), Issuer: issuer, Staging: dir.Staging,
			Status: StatusFailed, Managed: true}
	}
	row.LastResult, row.LastError = result, msg
	if err := m.st.UpsertCert(ctx, row); err != nil {
		m.log.Warn("acme: persist cert row", "cert", id, "err", err)
	}
	m.log.Warn("acme: certificate order failed", "cert", id, "zone", row.Zone, "names", strings.Join(names, ","),
		"failures", a.Failures, "next_attempt", a.NextAttempt, "err", msg)
	if m.notifier != nil {
		m.notifier.Notify(ctx, Event{Kind: EventFailure, CertID: id, Zone: row.Zone, Names: append([]string(nil), names...),
			NotAfter: row.NotAfter, Message: msg, NextAttempt: a.NextAttempt})
	}
	return Result{CertID: id, Zone: row.Zone, Names: append([]string(nil), names...),
		Err:         &redactedError{msg: truncate(m.red.redact(fmt.Sprintf("acme: order for %s failed: %s", strings.Join(names, ","), msg))), cause: cause},
		NextAttempt: a.NextAttempt}
}

func (m *Manager) recordSuccess(ctx context.Context, z config.Zone, issuer string, dir directory, id string, names []string, ob obtained) Result {
	leaf, err := leafCert(ob.ChainPEM)
	if err == nil {
		err = coversAll(leaf, names)
	}
	if err == nil {
		err = writeCertFiles(m.certsDir, id, ob.ChainPEM, ob.KeyPEM)
	}
	if err != nil {
		return m.recordFailure(ctx, z, issuer, dir, id, names, err)
	}
	dj, _ := json.Marshal(names)
	row := store.Cert{ID: id, Zone: normName(z.Name), DomainsJSON: string(dj), Issuer: issuer, Staging: dir.Staging,
		NotAfter: leaf.NotAfter, Status: StatusValid, LastResult: "ok", Path: id, Managed: true}
	if err := m.st.UpsertCert(ctx, row); err != nil {
		m.log.Error("acme: certificate written but its row was not stored", "cert", id, "err", err)
	}
	m.stateMu.Lock()
	if err := m.kv.putJSON(ctx, attemptKey(id), attemptState{}); err != nil {
		m.log.Warn("acme: reset backoff", "cert", id, "err", err)
	}
	m.stateMu.Unlock()
	m.log.Info("acme: certificate issued", "cert", id, "zone", row.Zone, "names", strings.Join(names, ","),
		"not_after", leaf.NotAfter, "staging", dir.Staging)
	m.changed()
	return Result{CertID: id, Zone: row.Zone, Names: append([]string(nil), names...), Bundle: &Bundle{
		ID: id, Zone: row.Zone, Names: append([]string(nil), names...), Issuer: issuer, Staging: dir.Staging, Managed: true,
		NotAfter: leaf.NotAfter, Dir: id, ChainPEM: append([]byte(nil), ob.ChainPEM...), Key: secrets.Secret(ob.KeyPEM),
	}}
}

func (m *Manager) changed() {
	if m.onChange != nil {
		m.onChange()
	}
}

func leafCert(chainPEM []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(chainPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("acme: certificate chain has no PEM certificate")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, errors.New("acme: certificate does not parse")
	}
	return c, nil
}

func coversAll(leaf *x509.Certificate, names []string) error {
	for _, n := range names {
		if !slices.Contains(leaf.DNSNames, n) {
			return fmt.Errorf("acme: issued certificate does not list %s", n)
		}
	}
	return nil
}

func (m *Manager) certRow(ctx context.Context, id string) (store.Cert, bool, error) {
	rows, err := m.st.ListCerts(ctx)
	if err != nil {
		return store.Cert{}, false, err
	}
	for _, r := range rows {
		if r.ID == id {
			return r, true, nil
		}
	}
	return store.Cert{}, false, nil
}

func rowNames(r store.Cert) []string {
	var ns []string
	_ = json.Unmarshal([]byte(r.DomainsJSON), &ns)
	return ns
}

// Renew renews every managed certificate whose remaining lifetime is at most
// settings.renew_before (default 30 days), sends expiry notifications for
// all certificates, and returns one Result per certificate it considered
// (due ones, renewed or not). Imported certificates are never renewed here.
func (m *Manager) Renew(ctx context.Context) []Result {
	return m.safeResults(m.renew(ctx))
}

func (m *Manager) renew(ctx context.Context) []Result {
	rows, err := m.st.ListCerts(ctx)
	if err != nil {
		return []Result{{Err: fmt.Errorf("acme: list certs: %w", err)}}
	}
	now := m.now()
	var out []Result
	for _, r := range rows {
		m.notifyExpiry(ctx, r, now)
		if !r.NotAfter.IsZero() && r.NotAfter.Sub(now) > m.renewBefore {
			continue
		}
		res := Result{CertID: r.ID, Zone: r.Zone, Names: rowNames(r)}
		if !r.Managed {
			res.Err, res.Skipped = ErrImported, true
			out = append(out, res)
			continue
		}
		z, ok := m.zone(r.Zone)
		if !ok || z.Certificate.Issuer == "" {
			res.Err, res.Skipped = ErrNoIssuer, true
			out = append(out, res)
			continue
		}
		if r.NotAfter.IsZero() {
			// Never issued: the reconcile loop's CertEnsure owns first issuance.
			continue
		}
		d, _, err := m.effectiveDirectory(ctx, z.Certificate.Issuer)
		if err != nil {
			res.Err = err
			out = append(out, res)
			continue
		}
		if d.Staging != r.Staging {
			res.Err, res.Skipped = ErrNeedsSwitch, true
			out = append(out, res)
			continue
		}
		ictx, cancel := context.WithTimeout(ctx, m.issueTimeout)
		out = append(out, m.issueSet(ictx, z, res.Names, r.ID, false))
		cancel()
	}
	return out
}

// notifyExpiry sends one EventExpiring for the tightest threshold crossed,
// once per certificate, threshold and expiry date.
func (m *Manager) notifyExpiry(ctx context.Context, r store.Cert, now time.Time) {
	if m.notifier == nil || r.NotAfter.IsZero() {
		return
	}
	left := r.NotAfter.Sub(now)
	var hit time.Duration
	for _, th := range ExpiryThresholds {
		if left < th {
			hit = th
		}
	}
	if hit == 0 {
		return
	}
	key := notifiedKey(r.ID, hit, r.NotAfter)
	m.stateMu.Lock()
	_, seen, err := m.st.GetSetting(ctx, key)
	if err == nil && !seen {
		err = m.st.SetSetting(ctx, key, now.UTC().Format(time.RFC3339))
	}
	m.stateMu.Unlock()
	if err != nil || seen {
		return
	}
	msg := fmt.Sprintf("certificate %s expires %s", r.ID, r.NotAfter.UTC().Format(time.RFC3339))
	if left <= 0 {
		msg = fmt.Sprintf("certificate %s expired %s", r.ID, r.NotAfter.UTC().Format(time.RFC3339))
	}
	m.notifier.Notify(ctx, Event{Kind: EventExpiring, CertID: r.ID, Zone: r.Zone, Names: rowNames(r),
		NotAfter: r.NotAfter, Threshold: hit, Message: msg})
}

// RenewNow re-issues one certificate now, skipping the ordinary backoff
// (never a rate-limit park). For an imported certificate this is the
// explicit switch to managed: its zone must have an issuer, and on success
// the row becomes managed=true with the same id.
func (m *Manager) RenewNow(ctx context.Context, certID string) Result {
	return m.safeResults([]Result{m.renewNow(ctx, certID)})[0]
}

func (m *Manager) renewNow(ctx context.Context, certID string) Result {
	r, ok, err := m.certRow(ctx, certID)
	if err != nil {
		return Result{CertID: certID, Err: err}
	}
	if !ok {
		return Result{CertID: certID, Err: ErrNotFound}
	}
	z, ok := m.zone(r.Zone)
	if !ok || z.Certificate.Issuer == "" {
		return Result{CertID: certID, Zone: r.Zone, Names: rowNames(r), Err: ErrNoIssuer}
	}
	names := rowNames(r)
	if _, err := planSets(z.Name, names, StrategySAN, zoneChallenge(z)); err != nil {
		return Result{CertID: certID, Zone: r.Zone, Names: names, Err: err}
	}
	if r.Managed && !r.NotAfter.IsZero() {
		d, _, err := m.effectiveDirectory(ctx, z.Certificate.Issuer)
		if err != nil {
			return Result{CertID: certID, Zone: r.Zone, Names: names, Err: err}
		}
		if d.Staging != r.Staging {
			return Result{CertID: certID, Zone: r.Zone, Names: names, Err: ErrNeedsSwitch}
		}
	}
	return m.issueSet(ctx, z, names, certID, true)
}

// SwitchIssuer is the explicit staging->production flow: after the caller
// has confirmed, it records that the Let's Encrypt issuer now uses the
// production directory and re-issues every staging certificate of that
// issuer (same ids, so Traefik's paths do not change). It never runs on its
// own. to must be "production".
func (m *Manager) SwitchIssuer(ctx context.Context, issuer, to string) ([]Result, error) {
	out, err := m.switchIssuer(ctx, issuer, to)
	return m.safeResults(out), m.red.safeErr(err)
}

func (m *Manager) switchIssuer(ctx context.Context, issuer, to string) ([]Result, error) {
	if to != "production" {
		return nil, fmt.Errorf("acme: can only switch to production, not %q", to)
	}
	is, ok := m.cfg.Issuers[issuer]
	if !ok {
		return nil, fmt.Errorf("acme: issuer %q is not defined", issuer)
	}
	d, err := resolveDirectory(is.Directory)
	if err != nil {
		return nil, err
	}
	if !d.LetsEncrypt {
		return nil, fmt.Errorf("acme: issuer %q uses a custom directory; edit its configuration instead", issuer)
	}
	if d.Staging {
		if err := m.st.SetSetting(ctx, overrideKey(issuer), "production"); err != nil {
			return nil, err
		}
	}
	rows, err := m.st.ListCerts(ctx)
	if err != nil {
		return nil, err
	}
	var out []Result
	for _, r := range rows {
		if !r.Managed || !r.Staging || r.Issuer != issuer {
			continue
		}
		z, ok := m.zone(r.Zone)
		if !ok || z.Certificate.Issuer != issuer {
			out = append(out, Result{CertID: r.ID, Zone: r.Zone, Names: rowNames(r), Err: ErrNoIssuer, Skipped: true})
			continue
		}
		ictx, cancel := context.WithTimeout(ctx, m.issueTimeout)
		out = append(out, m.issueSet(ictx, z, rowNames(r), r.ID, true))
		cancel()
	}
	return out, nil
}

// dnsChallengeProvider builds the lego DNS provider named by a providers:
// entry, mapping its settings to lego's environment variables under envMu
// and restoring the environment afterwards.
func (m *Manager) dnsChallengeProvider(name string) (challenge.Provider, error) {
	if err := checkChallengeProvider(m.cfg, name); err != nil {
		return nil, fmt.Errorf("acme: %w", err)
	}
	pc := m.cfg.Providers[name]
	cat, _ := LookupChallengeProvider(pc.Type)
	settings := make(map[string]string, len(pc.Extra))
	for k, raw := range pc.Extra {
		v, err := m.settingValue(raw)
		if err != nil {
			return nil, fmt.Errorf("acme: provider %q setting %s: %w", name, k, err)
		}
		settings[k] = v
	}
	env, ignored := envForSettings(cat, settings)
	if len(ignored) > 0 {
		m.log.Debug("acme: provider settings not used by the lego provider", "provider", name, "type", pc.Type, "keys", strings.Join(ignored, ","))
	}
	for _, v := range env {
		m.red.add(v)
	}
	p, err := withEnv(env, func() (challenge.Provider, error) { return m.providerByName(pc.Type) })
	if err != nil {
		return nil, fmt.Errorf("acme: challenge provider %q (%s): %w", name, pc.Type, err)
	}
	return withPropagationTimeout(p, m.cfg.ACME.DNSPropagationTimeout), nil
}

// acmeUser implements registration.User.
type acmeUser struct {
	email string
	reg   *registration.Resource
	key   *ecdsa.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// accountKey returns the issuer's account key, generating and storing it
// (sealed with the secrets box) on first use.
func (m *Manager) accountKey(ctx context.Context, issuer string) (*ecdsa.PrivateKey, error) {
	m.accountMu.Lock()
	defer m.accountMu.Unlock()
	s, ok, err := m.st.GetSetting(ctx, accountKeyKey(issuer))
	if err != nil {
		return nil, err
	}
	if ok && s != "" {
		sealed, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, errors.New("acme: stored account key is corrupt")
		}
		plain, err := m.box.Open(sealed)
		if err != nil {
			return nil, errors.New("acme: stored account key cannot be decrypted (master key changed?)")
		}
		b, _ := pem.Decode(plain)
		if b == nil {
			return nil, errors.New("acme: stored account key is corrupt")
		}
		k, err := x509.ParseECPrivateKey(b.Bytes)
		if err != nil {
			return nil, errors.New("acme: stored account key is corrupt")
		}
		m.red.addPEM(plain)
		return k, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	m.red.addPEM(keyPEM)
	sealed, err := m.box.Seal(keyPEM)
	if err != nil {
		return nil, err
	}
	if err := m.st.SetSetting(ctx, accountKeyKey(issuer), base64.StdEncoding.EncodeToString(sealed)); err != nil {
		return nil, err
	}
	return k, nil
}

// storedRegistration returns the stored account registration for the
// issuer at the order's directory, or nil.
func (m *Manager) storedRegistration(ctx context.Context, o order) *registration.Resource {
	m.accountMu.Lock()
	defer m.accountMu.Unlock()
	var reg registration.Resource
	if ok, err := m.kv.getJSON(ctx, regKey(o.Issuer, o.Dir.URL), &reg); err == nil && ok && reg.URI != "" {
		return &reg
	}
	return nil
}

// register creates the account (with EAB when configured) and stores the
// registration. lego signs later requests with the account URL as kid.
func (m *Manager) register(ctx context.Context, client *lego.Client, o order) (*registration.Resource, error) {
	m.accountMu.Lock()
	defer m.accountMu.Unlock()
	var r *registration.Resource
	var err error
	if o.IssuerCfg.EABKid != "" {
		r, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true, Kid: o.IssuerCfg.EABKid, HmacEncoded: o.IssuerCfg.EABHMAC})
	} else {
		r, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return nil, fmt.Errorf("acme: register account for issuer %s: %w", o.Issuer, err)
	}
	if err := m.kv.putJSON(ctx, regKey(o.Issuer, o.Dir.URL), r); err != nil {
		return nil, err
	}
	return r, nil
}

func (m *Manager) forgetRegistration(ctx context.Context, o order) {
	m.accountMu.Lock()
	defer m.accountMu.Unlock()
	_ = m.st.SetSetting(ctx, regKey(o.Issuer, o.Dir.URL), "")
}

// legoObtain places one order with lego. It is called with issueSem held.
func (m *Manager) legoObtain(ctx context.Context, o order) (obtained, error) {
	key, err := m.accountKey(ctx, o.Issuer)
	if err != nil {
		return obtained{}, err
	}
	u := &acmeUser{email: o.IssuerCfg.Email, key: key}
	lc := lego.NewConfig(u)
	lc.CADirURL = o.Dir.URL
	lc.UserAgent = "doorwarden"
	lc.Certificate.KeyType = certcrypto.EC256
	if m.httpClient != nil {
		lc.HTTPClient = m.httpClient
	}
	// A stored registration must be on the user before NewClient: lego
	// takes the account URL (JWS kid) from it only at construction.
	u.reg = m.storedRegistration(ctx, o)
	client, err := lego.NewClient(lc)
	if err != nil {
		return obtained{}, fmt.Errorf("acme: directory %s: %w", o.Dir.URL, err)
	}
	if u.reg == nil {
		if u.reg, err = m.register(ctx, client, o); err != nil {
			return obtained{}, err
		}
	}
	switch o.Challenge {
	case ChallengeDNS01:
		opts := []dns01.ChallengeOption{}
		if rs := m.cfg.ACME.Resolvers; len(rs) > 0 {
			opts = append(opts, dns01.AddRecursiveNameservers(rs))
		}
		opts = append(opts, m.dnsOpts...)
		err = client.Challenge.SetDNS01Provider(o.Provider, opts...)
	case ChallengeHTTP01:
		err = client.Challenge.SetHTTP01Provider(o.Provider)
	default:
		err = fmt.Errorf("acme: unknown challenge %q", o.Challenge)
	}
	if err != nil {
		return obtained{}, err
	}
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: o.Names, Bundle: true})
	if err != nil {
		var pd *acme.ProblemDetails
		if errors.As(err, &pd) && pd.Type == "urn:ietf:params:acme:error:accountDoesNotExist" {
			m.forgetRegistration(context.WithoutCancel(ctx), o)
		}
		return obtained{}, err
	}
	return obtained{ChainPEM: res.Certificate, KeyPEM: res.PrivateKey}, nil
}
