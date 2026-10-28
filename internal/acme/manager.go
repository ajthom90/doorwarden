// Package acme issues, renews and imports TLS certificates with lego.
//
// Certificates live on disk as <certs dir>/<id>/v<N>/{fullchain,privkey}.pem
// (directories 0700, files 0600, each version published atomically; see
// writeCertVersion) and as rows in the store's certs table (no key
// material) whose Path is "<id>/v<N>". A managed certificate's id is
// derived from its zone and names, so renewals and re-issues of the same
// set keep the id and add a version. Imported certificates (ImportPEM, ImportNPMDir) are rows with
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
	"os"
	"path/filepath"
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
	// StatusUnwanted: managed, but no longer wanted (ManagerConfig.Wanted);
	// not renewed and no notifications. Restored once wanted again.
	StatusUnwanted = "unwanted"
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
	// ErrImported: an imported certificate whose zone has no issuer is not
	// renewed (with an issuer, Renew adopts it once it is due).
	ErrImported = errors.New("acme: imported certificate is not renewed: its zone has no certificate issuer")
	// ErrNeedsSwitch: the certificate's staging flag differs from its issuer's
	// current directory. Renew never re-issues across that change.
	ErrNeedsSwitch = errors.New("acme: the issuer directory changed since this certificate was issued (staging vs production); automatic renewal will not switch it, re-issue it with RenewNow (or SwitchIssuer for Let's Encrypt staging to production)")
	// ErrDowngrade: RenewNow would replace a production certificate with one
	// from a staging directory (untrusted by browsers); pass AllowDowngrade
	// to do it anyway.
	ErrDowngrade = errors.New("acme: the issuer now uses a staging directory; re-issuing would replace this production certificate with an untrusted staging one (pass AllowDowngrade to do it anyway)")
	// ErrUnwanted: the certificate's names are no longer wanted
	// (ManagerConfig.Wanted); it is not renewed.
	ErrUnwanted = errors.New("acme: certificate is no longer wanted; not renewed")
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
	// Wanted, when set, returns the host names currently wanted in a zone
	// (e.g. the routes' hosts; "*.<zone>" covers its one-label children).
	// Renew then renews a managed certificate only while every name on it
	// is wanted; a wildcard certificate is wanted while its zone is
	// configured with an issuer and the wildcard strategy. An unwanted
	// certificate gets StatusUnwanted, is not renewed and sends no
	// notifications. nil: every managed certificate is wanted.
	Wanted func(zone string) []string
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
	wanted         func(zone string) []string
	log            *slog.Logger
	red            *redactor

	// obtain places one ACME order (lego by default; replaced in tests).
	obtain func(ctx context.Context, o order) (obtained, error)

	stateMu sync.Mutex // kv read-modify-write; also guards memNext
	// memNext is this process's fallback backoff for sets whose attempt
	// record could not be persisted (unwritable store): it keeps the
	// process from re-ordering in a loop when nothing can be stored.
	memNext   map[string]time.Time
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
		wanted: mc.Wanted, inflight: map[string]bool{}, memNext: map[string]time.Time{},
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
		legolog.Logger = slog.NewLogLogger(redactHandler{inner: defaultHandler{}, r: globalRedactor}, slog.LevelDebug)
	})
	m.cleanupCertDirs(context.Background())
	m.clearStaleOverrides(context.Background())
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
	// Dropped lists requested names that were not valid host names (see
	// canonName) and were left out of the request; the rest proceeded. A
	// warning is logged for each.
	Dropped []string
}

// Issue orders the certificate for req, which must resolve to exactly one
// order (use IssueAll for per-host lists and san sets above 100 names).
func (m *Manager) Issue(ctx context.Context, req IssueRequest) (*Bundle, error) {
	b, err := m.issue(ctx, req)
	return b, m.red.safeErr(err)
}

func (m *Manager) issue(ctx context.Context, req IssueRequest) (*Bundle, error) {
	z, sets, dropped, err := m.resolveRequest(req)
	if err == nil && len(sets) != 1 {
		err = fmt.Errorf("acme: request resolves to %d orders; use IssueAll", len(sets))
	}
	if err != nil {
		return nil, withDropped(err, dropped)
	}
	r := m.issueSet(ctx, z, sets[0], certID(z.Name, sets[0]), false)
	if r.Bundle != nil {
		r.Bundle.Dropped = dropped
	}
	return r.Bundle, withDropped(r.Err, dropped)
}

// withDropped appends the dropped (invalid) request names to err's text.
func withDropped(err error, dropped []string) error {
	if err == nil || len(dropped) == 0 {
		return err
	}
	return fmt.Errorf("%w (invalid names dropped from the request: %q)", err, dropped)
}

// IssueAll orders every certificate req resolves to, one after another.
func (m *Manager) IssueAll(ctx context.Context, req IssueRequest) []Result {
	return m.safeResults(m.issueAll(ctx, req))
}

func (m *Manager) issueAll(ctx context.Context, req IssueRequest) []Result {
	z, sets, dropped, err := m.resolveRequest(req)
	if err != nil {
		return []Result{{Zone: normName(req.Zone), Names: req.Names, Err: err, Dropped: dropped}}
	}
	out := make([]Result, 0, len(sets))
	for _, s := range sets {
		r := m.issueSet(ctx, z, s, certID(z.Name, s), false)
		r.Dropped = dropped
		out = append(out, r)
	}
	return out
}

// resolveRequest plans req's name sets. Invalid names are dropped (and
// logged as a warning); they are returned so callers can report them.
func (m *Manager) resolveRequest(req IssueRequest) (config.Zone, [][]string, []string, error) {
	z, ok := m.zone(req.Zone)
	if !ok {
		return z, nil, nil, fmt.Errorf("acme: zone %q is not configured", req.Zone)
	}
	if z.Certificate.Issuer == "" {
		return z, nil, nil, ErrNoIssuer
	}
	strategy := req.Strategy
	if strategy == "" {
		strategy = zoneStrategy(z)
	}
	sets, dropped, err := planSets(z.Name, req.Names, strategy, zoneChallenge(z))
	for _, d := range dropped {
		m.log.Warn("acme: invalid certificate name dropped", "zone", normName(z.Name), "name", fmt.Sprintf("%q", d))
	}
	return z, sets, dropped, err
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
		if ok && v == overrideValue(d) {
			d, _ = resolveDirectory("production")
		}
	}
	return d, is, nil
}

// overrideValue is the stored staging->production switch for an issuer whose
// configured directory resolves to d: the switch only applies while the
// configuration still names that directory.
func overrideValue(d directory) string { return "production from " + d.URL }

// clearStaleOverrides deletes switches (SwitchIssuer) whose issuer is gone
// or whose configured directory changed since.
func (m *Manager) clearStaleOverrides(ctx context.Context) {
	keys, err := m.st.ListSettingKeys(ctx, overrideKeyPrefix)
	if err != nil {
		m.log.Warn("acme: list issuer switches", "err", err)
		return
	}
	for _, k := range keys {
		issuer, ok := strings.CutSuffix(strings.TrimPrefix(k, overrideKeyPrefix), overrideKeySuffix)
		if !ok {
			continue
		}
		v, _, err := m.st.GetSetting(ctx, k)
		if err != nil {
			continue
		}
		if is, defined := m.cfg.Issuers[issuer]; defined {
			if d, err := resolveDirectory(is.Directory); err == nil && d.Staging && v == overrideValue(d) {
				continue
			}
		}
		if err := m.st.DeleteSetting(ctx, k); err != nil {
			m.log.Warn("acme: delete stale issuer switch", "issuer", issuer, "err", err)
		}
	}
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
	if !validID(id) {
		res.Err = fmt.Errorf("acme: certificate id %q cannot be stored (at most 200 of a-z, 0-9, '-', '_'); use a shorter zone name", id)
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

	select {
	case issueSem <- struct{}{}:
	case <-ctx.Done():
		res.Err = fmt.Errorf("acme: waiting for another order: %w", ctx.Err())
		return res
	}
	o := order{Issuer: issuer, IssuerCfg: isCfg, Dir: dir, Names: names, Challenge: ch}
	done := make(chan Result, 1)
	handedOff = true
	go func() {
		bg := context.WithoutCancel(ctx)
		released := false
		release := func() {
			if !released {
				released = true
				<-issueSem
			}
		}
		defer release()
		defer m.clearInFlight(id)
		var r Result
		var ev *Event
		func() {
			started := false
			defer func() {
				if p := recover(); p != nil {
					if started {
						m.endAttempt(bg, issuer, id, false)
					}
					r, ev = m.recordFailure(bg, z, issuer, dir, id, names, fmt.Errorf("acme: order panicked: %v", p), started)
				}
			}()
			// The provider is built only now, with the order slot held: no
			// other order's settings are in the environment, and a lazy
			// provider keeps its settings there for the whole order.
			cerr := m.withChallengeProvider(z, ch, func(prov challenge.Provider) {
				o.Provider = prov
				if derr := m.beginAttempt(bg, issuer, id); derr != nil {
					// Nothing could be persisted: never contact the CA.
					r = Result{CertID: id, Zone: normName(z.Name), Names: append([]string(nil), names...), Err: derr, NextAttempt: derr.Until}
					return
				}
				started = true
				ob, err := m.obtain(ctx, o)
				m.endAttempt(bg, issuer, id, err == nil)
				if err != nil {
					r, ev = m.recordFailure(bg, z, issuer, dir, id, names, err, true)
					return
				}
				r, ev = m.recordSuccess(bg, z, issuer, dir, id, names, ob)
			})
			if cerr != nil {
				r, ev = m.recordFailure(bg, z, issuer, dir, id, names, cerr, false)
			}
		}()
		// Notifications go out only after the process-wide slot is free.
		release()
		m.notify(bg, ev)
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

func (m *Manager) notify(ctx context.Context, ev *Event) {
	if ev != nil && m.notifier != nil {
		m.notifier.Notify(ctx, *ev)
	}
}

// beginAttempt persists, before an order is placed, that it is being
// attempted: the set's failure count and backoff advance as if it failed,
// and a pending order event is appended. A crash mid-order thus leaves a
// deferred set and an order that counts toward the guards; endAttempt and
// recordSuccess resolve both when the order returns.
//
// If the attempt record cannot be stored the order must not be placed
// (nothing would remember it after a crash): beginAttempt then returns a
// DeferredError and sets this process's in-memory backoff for the set.
func (m *Manager) beginAttempt(ctx context.Context, issuer, id string) *DeferredError {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	now := m.now()
	var a attemptState
	_, _ = m.kv.getJSON(ctx, attemptKey(id), &a)
	a.Failures++
	a.NextAttempt = now.Add(backoffDelay(a.Failures, m.jitter()))
	if a.ParkedUntil.After(a.NextAttempt) {
		a.NextAttempt = a.ParkedUntil
	}
	if err := m.kv.putJSON(ctx, attemptKey(id), a); err != nil {
		m.memNext[id] = a.NextAttempt
		m.log.Error("acme: state store unwritable; order not placed", "cert", id, "err", err)
		return &DeferredError{Until: a.NextAttempt, Reason: m.red.redact("state store unwritable: " + err.Error())}
	}
	delete(m.memNext, id)
	evs := m.loadOrders(ctx, issuer, now)
	evs = append(evs, orderEvent{T: now.Unix(), Set: id, Pending: true})
	if err := m.kv.putJSON(ctx, ordersKey(issuer), evs); err != nil {
		m.log.Warn("acme: record order", "issuer", issuer, "err", err)
	}
	return nil
}

// endAttempt resolves id's pending order event. Older pending events of
// the same set (left by a crash) are resolved too, as OK: such an order may
// have produced a certificate, so it keeps counting toward the duplicate
// guard, but it no longer reads as running.
func (m *Manager) endAttempt(ctx context.Context, issuer, id string, ok bool) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	evs := m.loadOrders(ctx, issuer, m.now())
	latest := true
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Set == id && evs[i].Pending {
			evs[i].Pending, evs[i].OK = false, ok || !latest
			latest = false
		}
	}
	if err := m.kv.putJSON(ctx, ordersKey(issuer), evs); err != nil {
		m.log.Warn("acme: record order", "issuer", issuer, "err", err)
	}
}

// loadOrders returns the issuer's order events of the last 7 days.
// Callers hold stateMu.
func (m *Manager) loadOrders(ctx context.Context, issuer string, now time.Time) []orderEvent {
	var evs []orderEvent
	_, _ = m.kv.getJSON(ctx, ordersKey(issuer), &evs)
	keep := evs[:0]
	for _, e := range evs {
		if now.Sub(time.Unix(e.T, 0)) < 7*24*time.Hour {
			keep = append(keep, e)
		}
	}
	return keep
}

// guard returns a DeferredError when no attempt may be made now.
func (m *Manager) guard(ctx context.Context, issuer, id string, names []string, force bool) *DeferredError {
	now := m.now()
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	var a attemptState
	if _, err := m.kv.getJSON(ctx, attemptKey(id), &a); err != nil {
		return &DeferredError{Until: now.Add(backoffBase), Reason: m.red.redact("state unreadable: " + err.Error())}
	}
	if t := m.memNext[id]; !force && t.After(now) {
		return &DeferredError{Until: t, Reason: "backing off: the state store was not writable at the last attempt", LastError: a.LastError}
	}
	if a.ParkedUntil.After(now) {
		return &DeferredError{Until: a.ParkedUntil, Reason: "rate limited by the CA", LastError: a.LastError}
	}
	var acct time.Time
	_, _ = m.kv.getJSON(ctx, accountParkKey(issuer), &acct)
	if acct.After(now) {
		return &DeferredError{Until: acct, Reason: fmt.Sprintf("issuer %s account rate limited by the CA", issuer)}
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
		if e.Set == id && (e.OK || e.Pending) && now.Sub(t) < 7*24*time.Hour {
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

// recordFailure persists a failed attempt: backoff (and rate-limit park,
// also for the issuer account), failed validations, and the row's
// last_result/last_error. The previous certificate's files, expiry and path
// are left untouched. started means beginAttempt already counted this
// attempt (it is not counted again). The failure event is returned, not
// sent: callers send it once the issue slot is released.
func (m *Manager) recordFailure(ctx context.Context, z config.Zone, issuer string, dir directory, id string, names []string, cause error, started bool) (Result, *Event) {
	now := m.now()
	msg := m.red.errText(cause)
	park := rateLimitPark(cause, now)
	m.stateMu.Lock()
	var a attemptState
	_, _ = m.kv.getJSON(ctx, attemptKey(id), &a)
	if !started || a.Failures == 0 {
		a.Failures++
	}
	// Backoff runs from the failure, not from the order start: an order
	// slower than its backoff step (DNS propagation, a hanging API) must
	// still be followed by the full wait.
	a.NextAttempt = now.Add(backoffDelay(a.Failures, m.jitter()))
	a.LastError = msg
	if park > 0 {
		a.ParkedUntil = now.Add(park)
	}
	if a.ParkedUntil.After(a.NextAttempt) {
		a.NextAttempt = a.ParkedUntil
	}
	if park > 0 {
		var acct time.Time
		_, _ = m.kv.getJSON(ctx, accountParkKey(issuer), &acct)
		if a.ParkedUntil.After(acct) {
			if err := m.kv.putJSON(ctx, accountParkKey(issuer), a.ParkedUntil); err != nil {
				m.log.Warn("acme: persist account park", "issuer", issuer, "err", err)
			}
		}
	}
	if err := m.kv.putJSON(ctx, attemptKey(id), a); err != nil {
		m.memNext[id] = a.NextAttempt
		m.log.Error("acme: persist backoff; backing off in memory only", "cert", id, "err", err)
	} else {
		delete(m.memNext, id)
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
	ev := &Event{Kind: EventFailure, CertID: id, Zone: row.Zone, Names: append([]string(nil), names...),
		NotAfter: row.NotAfter, Message: msg, NextAttempt: a.NextAttempt}
	return Result{CertID: id, Zone: row.Zone, Names: append([]string(nil), names...),
		Err:         &redactedError{msg: truncate(m.red.redact(fmt.Sprintf("acme: order for %s failed: %s", strings.Join(names, ","), msg))), cause: cause},
		NextAttempt: a.NextAttempt}, ev
}

func (m *Manager) recordSuccess(ctx context.Context, z config.Zone, issuer string, dir directory, id string, names []string, ob obtained) (Result, *Event) {
	leaf, err := leafCert(ob.ChainPEM)
	if err == nil {
		err = coversAll(leaf, names)
	}
	dj, _ := json.Marshal(names)
	row := store.Cert{ID: id, Zone: normName(z.Name), DomainsJSON: string(dj), Issuer: issuer, Staging: dir.Staging,
		Status: StatusValid, LastResult: "ok", Managed: true}
	if err == nil {
		row.NotAfter = leaf.NotAfter
		row, err = m.storeVersion(ctx, row, ob.ChainPEM, ob.KeyPEM)
	}
	if err != nil {
		return m.recordFailure(ctx, z, issuer, dir, id, names, err, true)
	}
	m.stateMu.Lock()
	if err := m.kv.putJSON(ctx, attemptKey(id), attemptState{}); err != nil {
		m.log.Warn("acme: reset backoff", "cert", id, "err", err)
	}
	delete(m.memNext, id)
	m.stateMu.Unlock()
	m.log.Info("acme: certificate issued", "cert", id, "zone", row.Zone, "names", strings.Join(names, ","),
		"not_after", leaf.NotAfter, "staging", dir.Staging)
	m.changed()
	return Result{CertID: id, Zone: row.Zone, Names: append([]string(nil), names...), Bundle: &Bundle{
		ID: id, Zone: row.Zone, Names: append([]string(nil), names...), Issuer: issuer, Staging: dir.Staging, Managed: true,
		NotAfter: leaf.NotAfter, Dir: row.Path, ChainPEM: append([]byte(nil), ob.ChainPEM...), Key: secrets.Secret(ob.KeyPEM),
	}}, nil
}

// storeVersion writes chain and key as a new version of row.ID, points
// row.Path at it and stores the row. If the row cannot be stored the new
// version is removed again (the previous version and row stay in effect);
// after the row is stored, versions older than the previous one are pruned.
func (m *Manager) storeVersion(ctx context.Context, row store.Cert, chainPEM, keyPEM []byte) (store.Cert, error) {
	p, err := writeCertVersion(m.certsDir, row.ID, chainPEM, keyPEM)
	if err != nil {
		return row, err
	}
	n, _ := pathVersion(row.ID, p)
	row.Path = p
	if err := m.st.UpsertCert(ctx, row); err != nil {
		if rerr := removeVersionsAbove(m.certsDir, row.ID, n-1); rerr != nil {
			m.log.Warn("acme: remove unrecorded certificate version", "cert", row.ID, "err", rerr)
		}
		return row, fmt.Errorf("acme: store certificate row: %w", err)
	}
	if err := pruneCertVersions(m.certsDir, row.ID, n); err != nil {
		m.log.Warn("acme: prune old certificate versions", "cert", row.ID, "err", err)
	}
	return row, nil
}

// cleanupCertDirs removes certificate versions the store does not know
// about: versions newer than a row's Path (written, then the process died
// before the row was updated), every version of an id without a row or
// without a path, and staging leftovers. Rows whose Path is not "<id>/v<N>"
// are left alone.
func (m *Manager) cleanupCertDirs(ctx context.Context) {
	rows, err := m.st.ListCerts(ctx)
	if err != nil {
		m.log.Warn("acme: certificate directory cleanup skipped", "err", err)
		return
	}
	known := map[string]bool{}
	removeAbove := func(id string, cur int) {
		err := removeVersionsAboveLogged(m.certsDir, id, cur, func(name string) {
			m.log.Info("acme: removed unrecorded certificate version directory", "cert", id, "dir", name)
		})
		if err != nil {
			m.log.Warn("acme: certificate directory cleanup", "cert", id, "err", err)
		}
	}
	for _, r := range rows {
		known[r.ID] = true
		cur := 0
		if r.Path != "" {
			n, ok := pathVersion(r.ID, r.Path)
			if !ok {
				continue
			}
			cur = n
		}
		removeAbove(r.ID, cur)
	}
	ents, err := os.ReadDir(m.certsDir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() || known[e.Name()] || !validID(e.Name()) {
			continue
		}
		removeAbove(e.Name(), 0)
		_ = os.Remove(filepath.Join(m.certsDir, e.Name())) // only if now empty
	}
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
// settings.renew_before (default 30 days), sends expiry notifications, and
// returns one Result per certificate it considered (due ones, renewed or
// not). With ManagerConfig.Wanted set, unwanted certificates are marked
// StatusUnwanted and skipped (ErrUnwanted) without notifications.
//
// An imported certificate is adopted (re-issued under the same id, becoming
// managed) only once it is due and its zone has an issuer; otherwise it is
// left alone (ErrImported when due). A certificate issued by the other
// Let's Encrypt directory than its issuer's current one is never re-issued
// here (ErrNeedsSwitch; use RenewNow or SwitchIssuer).
func (m *Manager) Renew(ctx context.Context) []Result {
	return m.safeResults(m.renew(ctx))
}

func (m *Manager) renew(ctx context.Context) []Result {
	rows, err := m.st.ListCerts(ctx)
	if err != nil {
		return []Result{{Err: fmt.Errorf("acme: list certs: %w", err)}}
	}
	now := m.now()
	m.pruneState(ctx, rows, now)
	var out []Result
	for _, r := range rows {
		due := r.NotAfter.IsZero() || r.NotAfter.Sub(now) <= m.renewBefore
		res := Result{CertID: r.ID, Zone: r.Zone, Names: rowNames(r)}
		if m.wanted != nil {
			wanted := m.rowWanted(r)
			if r.Managed {
				m.setUnwanted(ctx, r, !wanted)
			}
			if !wanted {
				if due && (r.Managed || !r.NotAfter.IsZero()) {
					res.Err, res.Skipped = ErrUnwanted, true
					out = append(out, res)
				}
				if r.Managed {
					continue
				}
				// An unwanted imported certificate keeps its notifications
				// but is never adopted.
				m.notifyExpiry(ctx, r, now)
				continue
			}
		}
		m.notifyExpiry(ctx, r, now)
		if !due {
			continue
		}
		z, ok := m.zone(r.Zone)
		if !r.Managed {
			if !ok || z.Certificate.Issuer == "" {
				res.Err, res.Skipped = ErrImported, true
				out = append(out, res)
				continue
			}
			ictx, cancel := context.WithTimeout(ctx, m.issueTimeout)
			out = append(out, m.issueSet(ictx, z, res.Names, r.ID, false))
			cancel()
			continue
		}
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

// pruneState deletes kv bookkeeping that can no longer matter: attempt
// state of certificate ids with no row, unless an order for that id is
// running here, its issuer still has a pending order event for it, or it
// still defers (backoff or park; a first issuance that crashed has no row
// yet); expiry notices of ids with no row, expiry notices
// for an earlier expiry date of a certificate, and failed-validation
// counters with nothing in the last hour.
func (m *Manager) pruneState(ctx context.Context, rows []store.Cert, now time.Time) {
	notAfter := make(map[string]int64, len(rows))
	for _, r := range rows {
		notAfter[r.ID] = r.NotAfter.Unix()
	}
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	del := func(k string) {
		if err := m.st.DeleteSetting(ctx, k); err != nil {
			m.log.Warn("acme: prune state", "key", k, "err", err)
		}
	}
	list := func(prefix string) []string {
		ks, err := m.st.ListSettingKeys(ctx, prefix)
		if err != nil {
			m.log.Warn("acme: prune state", "prefix", prefix, "err", err)
		}
		return ks
	}
	pending := map[string]bool{}
	ordersReadable := true
	for _, k := range list("acme/orders/") {
		var evs []orderEvent
		if _, err := m.kv.getJSON(ctx, k, &evs); err != nil {
			ordersReadable = false // keep every attempt record rather than guess
		}
		for _, e := range evs {
			if e.Pending {
				pending[e.Set] = true
			}
		}
	}
	for _, k := range list("acme/attempt/") {
		id := strings.TrimPrefix(k, "acme/attempt/")
		if _, ok := notAfter[id]; ok || m.isInFlight(id) || pending[id] || !ordersReadable {
			continue
		}
		// A record still deferring (backoff or park) is kept: after a crash
		// during a first issuance (no row yet) it is the only thing that
		// stops an immediate re-order.
		var a attemptState
		if _, err := m.kv.getJSON(ctx, k, &a); err != nil || a.NextAttempt.After(now) || a.ParkedUntil.After(now) {
			continue
		}
		del(k)
	}
	for _, k := range list("acme/notified/") {
		// acme/notified/<id>/<threshold>/<not after>
		parts := strings.Split(strings.TrimPrefix(k, "acme/notified/"), "/")
		if len(parts) == 3 {
			if na, ok := notAfter[parts[0]]; ok && strconv.FormatInt(na, 10) == parts[2] {
				continue
			}
		}
		del(k)
	}
	for _, k := range list("acme/fv/") {
		var ts []int64
		if _, err := m.kv.getJSON(ctx, k, &ts); err == nil && len(within(ts, now, time.Hour)) > 0 {
			continue
		}
		del(k)
	}
}

func (m *Manager) isInFlight(id string) bool {
	m.flightMu.Lock()
	defer m.flightMu.Unlock()
	return m.inflight[id]
}

// rowWanted applies ManagerConfig.Wanted to a certificate row.
func (m *Manager) rowWanted(r store.Cert) bool {
	z, ok := m.zone(r.Zone)
	if !ok || z.Certificate.Issuer == "" {
		return false
	}
	names := rowNames(r)
	if len(names) == 0 {
		return false
	}
	if hasWildcard(names) {
		return zoneStrategy(z) == StrategyWildcard
	}
	zone := normName(z.Name)
	want := map[string]bool{}
	for _, n := range m.wanted(zone) {
		if c, err := checkName(zone, n); err == nil {
			want[c] = true
		}
	}
	for _, n := range names {
		c, err := canonName(n)
		if err != nil {
			return false
		}
		if want[c] {
			continue
		}
		if _, parent, ok := strings.Cut(c, "."); ok && want["*."+parent] {
			continue
		}
		return false
	}
	return true
}

// setUnwanted moves a managed row into or out of StatusUnwanted.
func (m *Manager) setUnwanted(ctx context.Context, r store.Cert, unwanted bool) {
	switch {
	case unwanted && r.Status != StatusUnwanted:
		r.Status = StatusUnwanted
	case !unwanted && r.Status == StatusUnwanted:
		r.Status = StatusValid
		if r.NotAfter.IsZero() {
			r.Status = StatusFailed
		}
	default:
		return
	}
	if err := m.st.UpsertCert(ctx, r); err != nil {
		m.log.Warn("acme: update certificate status", "id", r.ID, "err", err)
		return
	}
	m.changed()
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
// (never a rate-limit park), from the issuer's current directory (this is
// how a certificate left on staging by a failed SwitchIssuer is retried),
// but it refuses (ErrDowngrade) to replace a managed production
// certificate with a staging one unless AllowDowngrade is passed. For an
// imported certificate this is the explicit switch to managed: its zone
// must have an issuer, and on success the row becomes managed=true with
// the same id.
func (m *Manager) RenewNow(ctx context.Context, certID string, opts ...RenewNowOption) Result {
	var o renewNowOpts
	for _, f := range opts {
		f(&o)
	}
	return m.safeResults([]Result{m.renewNow(ctx, certID, o)})[0]
}

// RenewNowOption modifies RenewNow.
type RenewNowOption func(*renewNowOpts)

type renewNowOpts struct{ allowDowngrade bool }

// AllowDowngrade lets RenewNow replace a production certificate with one
// from the issuer's (now) staging directory; without it RenewNow refuses
// with ErrDowngrade.
func AllowDowngrade() RenewNowOption { return func(o *renewNowOpts) { o.allowDowngrade = true } }

func (m *Manager) renewNow(ctx context.Context, certID string, o renewNowOpts) Result {
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
	if _, dropped, err := planSets(z.Name, names, StrategySAN, zoneChallenge(z)); err != nil || len(dropped) > 0 {
		if err == nil {
			err = &nameError{name: dropped[0], why: "stored certificate name is no longer valid"}
		}
		return Result{CertID: certID, Zone: r.Zone, Names: names, Err: err}
	}
	// A certificate from the issuer's other directory (ErrNeedsSwitch in
	// Renew) is re-issued from the current one here, except that a
	// production certificate is not replaced by a staging one unasked.
	d, _, err := m.effectiveDirectory(ctx, z.Certificate.Issuer)
	if err != nil {
		return Result{CertID: certID, Zone: r.Zone, Names: names, Err: err}
	}
	if r.Managed && !r.Staging && !r.NotAfter.IsZero() && d.Staging && !o.allowDowngrade {
		return Result{CertID: certID, Zone: r.Zone, Names: names, Err: ErrDowngrade}
	}
	return m.issueSet(ctx, z, names, certID, true)
}

// SwitchIssuer is the explicit staging->production flow: after the caller
// has confirmed, it records that the Let's Encrypt issuer now uses the
// production directory and re-issues every staging certificate of that
// issuer (same ids), each independently: the result has one entry per
// certificate, and one that failed stays on staging and can be retried
// with RenewNow. It never runs on its own. to must be "production". The
// switch is tied to the issuer's configured directory: once the
// configuration names another directory it no longer applies (and is
// deleted at the next start).
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
		if err := m.st.SetSetting(ctx, overrideKey(issuer), overrideValue(d)); err != nil {
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
// entry (see withDNSProvider). For a lazyEnvProviders type the environment
// is already restored when it returns; orders use withDNSProvider.
func (m *Manager) dnsChallengeProvider(name string) (challenge.Provider, error) {
	var p challenge.Provider
	err := m.withDNSProvider(name, func(prov challenge.Provider) { p = prov })
	return p, err
}

// withChallengeProvider builds the zone's challenge provider and calls run
// with it. It returns only a construction error; run reports its own.
func (m *Manager) withChallengeProvider(z config.Zone, ch string, run func(challenge.Provider)) error {
	if ch != ChallengeDNS01 {
		p, err := m.http01()
		if err != nil {
			return err
		}
		run(p)
		return nil
	}
	return m.withDNSProvider(z.Certificate.DNSProvider, run)
}

// withDNSProvider builds the lego DNS provider named by a providers: entry,
// mapping its settings to lego's environment variables under envMu, and
// calls run with it. The environment is restored once the provider is
// built, or, for a lazyEnvProviders type, once run returns (run then holds
// envMu and must not build another provider).
func (m *Manager) withDNSProvider(name string, run func(challenge.Provider)) error {
	if err := checkChallengeProvider(m.cfg, name); err != nil {
		return fmt.Errorf("acme: %w", err)
	}
	pc := m.cfg.Providers[name]
	cat, _ := LookupChallengeProvider(pc.Type)
	settings := make(map[string]string, len(pc.Extra))
	for k, raw := range pc.Extra {
		v, err := m.settingValue(raw)
		if err != nil {
			return fmt.Errorf("acme: provider %q setting %s: %w", name, k, err)
		}
		settings[k] = v
	}
	env, ignored := envForSettings(cat, settings)
	if len(ignored) > 0 {
		m.log.Debug("acme: provider settings not used by the lego provider", "provider", name, "type", pc.Type, "keys", strings.Join(ignored, ","))
	}
	for k, v := range settings {
		m.registerSetting(cat, k, settingEnvName(cat, k), v)
	}
	m.registerBasicPairs(cat, settings)
	build := func() (challenge.Provider, error) {
		p, err := m.providerByName(pc.Type)
		if err != nil {
			return nil, fmt.Errorf("acme: challenge provider %q (%s): %w", name, pc.Type, err)
		}
		return withPropagationTimeout(p, m.cfg.ACME.DNSPropagationTimeout), nil
	}
	if lazyEnvProviders[strings.ToLower(pc.Type)] {
		return envDo(env, func() error {
			p, err := build()
			if err != nil {
				return err
			}
			run(p)
			return nil
		})
	}
	p, err := withEnv(env, build)
	if err != nil {
		return err
	}
	run(p)
	return nil
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
	// Store bookkeeping (account key, registration) must complete even when
	// the caller's context ends mid-order: a half-written account would
	// orphan the CA account.
	bk := context.WithoutCancel(ctx)
	key, err := m.accountKey(bk, o.Issuer)
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
	u.reg = m.storedRegistration(bk, o)
	client, err := lego.NewClient(lc)
	if err != nil {
		return obtained{}, fmt.Errorf("acme: directory %s: %w", o.Dir.URL, err)
	}
	if u.reg == nil {
		if u.reg, err = m.register(bk, client, o); err != nil {
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
			m.forgetRegistration(bk, o)
		}
		return obtained{}, err
	}
	return obtained{ChainPEM: res.Certificate, KeyPEM: res.PrivateKey}, nil
}
