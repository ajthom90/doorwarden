package web

// The JSON API under /api/v1 (all behind auth.go's policy):
//
//	GET  /services                         services (pre-gate, overrides applied) with fingerprint, overrides, plan issues
//	POST /services/{key}/publish|unpublish clear/set the UI skip override
//	POST /services/{key}/approve           {fingerprint} -> 409 + fresh service when stale
//	POST /services/{key}/rename            {name}  ("" clears)
//	POST /services/{key}/port              {port}  (0 clears)
//	POST /services/{key}/skip-verify       {skip_verify: true|false|null}
//	GET  /plan                             the last reconcile plan
//	GET  /dns/providers                    configured providers (no settings)
//	POST /dns/providers/{name}/test        credential test (record providers; rate limited)
//	GET  /dns/records                      owned records and current DNS conflicts
//	GET  /dns/conflicts                    current DNS conflicts
//	POST /dns/conflicts/{id}/adopt|skip    adopt the foreign record / stop reporting it
//	POST /dns/repair/ack                   {provider, zone}: acknowledge a mass DNS repair
//	GET  /certs                            certificates (no paths, no key material)
//	POST /certs/{id}/renew                 re-issue now (async, 202)
//	POST /certs/switch-production          {issuer, confirm: true} (async, 202)
//	GET  /zones                            configured zones
//	GET  /activity?limit=N                 activity log (N <= 500)
//	GET|POST /settings/dry-run             {enabled}
//	GET|PUT  /config                       {yaml}: the config file, secrets masked (admin only; PUT needs a restart)
//	GET  /events                           SSE (sse.go)
//	auth: /auth/status, /auth/setup, /auth/login, /auth/logout, /auth/me, /auth/password
//
// Every state-changing call is written to the activity log as
// "<actor> <action>" with validated identifiers only, never request
// bodies or secrets. Requests: bodies limited (MaxBytesReader), strict
// JSON (unknown fields and trailing data refused), error bodies are short
// fixed texts; internal errors are logged and answered "internal error".

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/store"
)

const (
	smallBody  = 64 << 10
	configBody = 1 << 20
	// maxBody caps every request body (the config document is the largest).
	maxBody = configBody

	defaultProviderTestTimeout = 10 * time.Second
	providerTestEvery          = 10 * time.Second
	asyncTimeout               = 15 * time.Minute
)

// ConflictSkipPrefix is the kv prefix of skipped DNS conflicts
// (<prefix><conflict id> = RFC3339 time).
const ConflictSkipPrefix = "dns/conflict-skip/"

// ErrUnknownService is returned by Control for a key it does not know.
var ErrUnknownService = errors.New("unknown service")

// ErrNotFound is returned by Control for an unknown provider or cert.
var ErrNotFound = errors.New("not found")

// ServiceInfo is one service as the API shows it.
type ServiceInfo struct {
	Key         string            `json:"key"`
	Source      string            `json:"source"`
	Name        string            `json:"name"`
	Zone        string            `json:"zone"`
	Hostname    string            `json:"hostname,omitempty"`
	Backend     model.Backend     `json:"backend"`
	Websockets  bool              `json:"websockets"`
	Middlewares []string          `json:"middlewares"`
	State       string            `json:"state"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Overrides   model.UIOverrides `json:"overrides"`
	Issues      []PlanAction      `json:"issues,omitempty"`
}

// Plan is the last reconcile plan.
type Plan struct {
	At      time.Time
	DryRun  bool
	Actions []reconcile.Action
}

// Control is what the API needs from the orchestrator (internal/app).
type Control interface {
	// ServiceList returns the discovered services (overrides applied)
	// with their state, fingerprint and overrides.
	ServiceList() []ServiceInfo
	// SetServiceOverride edits key's UI overrides (validated, persisted,
	// and a cycle triggered). ErrUnknownService or *model.OverrideError.
	SetServiceOverride(ctx context.Context, key string, edit func(*model.UIOverrides) error) error
	// Approve approves key's displayed fingerprint (approval.ErrStale,
	// approval.ErrUnknownService) and triggers a cycle.
	Approve(ctx context.Context, key, fingerprint string) error
	LastPlan() Plan
	DryRun(ctx context.Context) (bool, error)
	SetDryRun(ctx context.Context, on bool) error
	Trigger()
	// TestProvider runs a record provider's credential test (ErrNotFound).
	TestProvider(ctx context.Context, name string) error
	// RenewCert re-issues a certificate now (blocks for the order).
	RenewCert(ctx context.Context, id string) error
	// SwitchProduction moves a Let's Encrypt issuer to production and
	// re-issues its staging certificates (blocks).
	SwitchProduction(ctx context.Context, issuer string) error
}

// Options configures NewServer.
type Options struct {
	Store   *store.Store
	Control Control
	// Config is the running configuration (zones, providers, web auth).
	Config *config.Config
	// ConfigPath is the config file GET/PUT /config read and write.
	ConfigPath string
	// ValidateConfig checks a whole config document (parse + Validate).
	ValidateConfig func(raw []byte) error
	// Health is /healthz (public); Metrics is /metrics (authenticated).
	Health  http.Handler
	Metrics http.Handler
	// Events is the SSE broker (nil: a new one).
	Events *Broker
	Log    *slog.Logger
	Now    func() time.Time
	// SetupToken is the first-run token; "" generates and logs one when no
	// administrator exists.
	SetupToken string
	// Hasher (nil: DefaultArgon2Params, 2 at a time).
	Hasher *Hasher
	// ProviderTestTimeout bounds a credential test (default 10s).
	ProviderTestTimeout time.Duration
}

// Server is the HTTP handler: policy, API, health and metrics.
type Server struct {
	st       *store.Store
	ctl      Control
	cfg      *config.Config
	cfgPath  string
	validate func([]byte) error
	log      *slog.Logger
	now      func() time.Time
	auth     *auth
	events   *Broker
	handler  http.Handler
	testTO   time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	lastTest map[string]time.Time
	inflight map[string]bool
	configMu sync.Mutex
}

// NewServer builds the handler. ctx bounds background work (renewals);
// Close cancels and waits for it.
func NewServer(ctx context.Context, o Options) (*Server, error) {
	if o.Store == nil || o.Control == nil || o.Config == nil {
		return nil, errors.New("web: Store, Control and Config are required")
	}
	s := &Server{st: o.Store, ctl: o.Control, cfg: o.Config, cfgPath: o.ConfigPath, validate: o.ValidateConfig,
		log: o.Log, now: o.Now, events: o.Events, testTO: o.ProviderTestTimeout,
		lastTest: map[string]time.Time{}, inflight: map[string]bool{}}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.events == nil {
		s.events = NewBroker()
	}
	if s.testTO <= 0 {
		s.testTO = defaultProviderTestTimeout
	}
	h := o.Hasher
	if h == nil {
		h = NewHasher(DefaultArgon2Params, 2)
	}
	a, err := newAuth(ctx, s.st, o.Config.Web, h, s.now, s.log, o.SetupToken)
	if err != nil {
		return nil, err
	}
	s.auth = a
	s.ctx, s.cancel = context.WithCancel(context.WithoutCancel(ctx))

	mux := http.NewServeMux()
	if o.Health != nil {
		mux.Handle("GET /healthz", o.Health)
	}
	if o.Metrics != nil {
		mux.Handle("GET /metrics", o.Metrics)
	}
	route := func(pattern string, f http.HandlerFunc) { mux.HandleFunc(pattern, f) }
	route("GET /api/v1/auth/status", s.handleStatus)
	route("POST /api/v1/auth/setup", s.handleSetup)
	route("POST /api/v1/auth/login", s.handleLogin)
	route("POST /api/v1/auth/logout", s.handleLogout)
	route("GET /api/v1/auth/me", s.handleMe)
	route("POST /api/v1/auth/password", s.handlePassword)

	route("GET /api/v1/services", s.handleServices)
	route("POST /api/v1/services/{key}/{action}", s.handleServiceAction)
	route("GET /api/v1/plan", s.handlePlan)
	route("GET /api/v1/dns/providers", s.handleProviders)
	route("POST /api/v1/dns/providers/{name}/test", s.handleProviderTest)
	route("GET /api/v1/dns/records", s.handleRecords)
	route("GET /api/v1/dns/conflicts", s.handleConflicts)
	route("POST /api/v1/dns/conflicts/{id}/{action}", s.handleConflictAction)
	route("POST /api/v1/dns/repair/ack", s.handleRepairAck)
	route("GET /api/v1/certs", s.handleCerts)
	route("POST /api/v1/certs/switch-production", s.handleSwitchProduction)
	route("POST /api/v1/certs/{id}/renew", s.handleRenew)
	route("GET /api/v1/zones", s.handleZones)
	route("GET /api/v1/activity", s.handleActivity)
	route("GET /api/v1/settings/dry-run", s.handleGetDryRun)
	route("POST /api/v1/settings/dry-run", s.handleSetDryRun)
	route("GET /api/v1/config", s.adminOnly(s.handleGetConfig))
	route("PUT /api/v1/config", s.adminOnly(s.handlePutConfig))
	route("GET /api/v1/events", s.handleEvents)
	mountUI(mux)

	s.handler = recoverer(s.log, securityHeaders(limitBody(a.middleware(mux))))
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// Events returns the SSE broker (the orchestrator publishes to it).
func (s *Server) Events() *Broker { return s.events }

// Close stops background work (renewals) and waits for it.
func (s *Server) Close() {
	s.cancel()
	s.wg.Wait()
	s.events.Close()
}

// ---- middleware and helpers

func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Error("http handler panic", "path", r.URL.Path, "panic", fmt.Sprint(v))
				writeErr(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) adminOnly(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p := principalFrom(r.Context()); p == nil || p.Role != RoleAdmin {
			writeErr(w, http.StatusForbidden, "administrators only")
			return
		}
		f(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) internal(w http.ResponseWriter, what string, err error) {
	s.log.Error("api: "+what+" failed", "error", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

// decodeJSON decodes exactly one JSON value into v, refusing unknown fields
// and trailing data. It writes the error response and returns false on
// failure. An empty body decodes as {}.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	body := http.MaxBytesReader(w, r.Body, limit)
	b, err := io.ReadAll(body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeErr(w, http.StatusBadRequest, "could not read the request body")
		return false
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		b = []byte("{}")
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		msg := "invalid JSON body"
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			msg = "unknown field " + strings.TrimPrefix(err.Error(), "json: unknown field ")
		}
		writeErr(w, http.StatusBadRequest, truncate(msg, 200))
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "trailing data after the JSON body")
		return false
	}
	return true
}

// audit records a state change by the request's principal.
func (s *Server) audit(r *http.Request, msg string) {
	actor := "unknown"
	if p := principalFrom(r.Context()); p != nil {
		actor = p.Actor()
	}
	s.auditAs(r.Context(), actor, msg)
}

func (s *Server) auditAs(ctx context.Context, actor, msg string) {
	line := actor + " " + msg
	s.log.Info("audit: "+line, "kind", "audit")
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.st.AppendActivity(ctx, store.ActivityEntry{TS: s.now(), Level: "info", Kind: "audit", Message: line}); err != nil {
		s.log.Warn("audit: recording failed", "error", err)
	}
	s.events.Publish("activity", map[string]string{"kind": "audit", "message": line})
}

// validKey accepts a service key: 1-256 printable ASCII characters, no
// path tricks.
func validKey(k string) bool {
	if k == "" || len(k) > 256 || k == "." || k == ".." || strings.Contains(k, "..") {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x21 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

// validName accepts config names and cert ids: [A-Za-z0-9._-], 1-128.
func validName(n string) bool {
	if n == "" || len(n) > 128 || strings.Contains(n, "..") {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func normZone(z string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(z)), ".") }

// ---- plan view

// PlanAction is one plan action as the API shows it.
type PlanAction struct {
	Kind       string      `json:"kind"`
	Key        string      `json:"key,omitempty"`
	Zone       string      `json:"zone,omitempty"`
	Host       string      `json:"host,omitempty"`
	Provider   string      `json:"provider,omitempty"`
	Reason     string      `json:"reason,omitempty"`
	Alert      string      `json:"alert,omitempty"`
	Record     *RecordView `json:"record,omitempty"`
	Owner      string      `json:"owner,omitempty"`
	ConflictID string      `json:"conflict_id,omitempty"`
}

// RecordView is a DNS record (no provider internals beyond the ID).
type RecordView struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ConflictID identifies a DNS conflict across cycles: a hash of provider,
// zone, record name, type and value. "" for actions that are not DNS
// conflicts.
func ConflictID(x reconcile.Action) string {
	if x.Kind != reconcile.Conflict || x.Record == nil || x.Provider == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{x.Provider, normZone(x.Zone),
		normZone(x.Record.Name), strings.ToUpper(x.Record.Type), x.Record.Value}, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func viewAction(x reconcile.Action) PlanAction {
	v := PlanAction{Kind: string(x.Kind), Key: x.Key, Zone: x.Zone, Host: x.Host, Provider: x.Provider,
		Reason: x.Reason, Alert: x.Alert, Owner: x.Owner, ConflictID: ConflictID(x)}
	if x.Record != nil {
		v.Record = &RecordView{Name: x.Record.Name, Type: x.Record.Type, Value: x.Record.Value}
	}
	return v
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	p := s.ctl.LastPlan()
	acts := make([]PlanAction, 0, len(p.Actions))
	for _, x := range p.Actions {
		acts = append(acts, viewAction(x))
	}
	var at *time.Time
	if !p.At.IsZero() {
		at = &p.At
	}
	writeJSON(w, http.StatusOK, map[string]any{"at": at, "dry_run": p.DryRun, "actions": acts})
}

// ---- services

func (s *Server) services() []ServiceInfo {
	list := s.ctl.ServiceList()
	issues := map[string][]PlanAction{}
	for _, x := range s.ctl.LastPlan().Actions {
		if reconcile.Informational(x.Kind) && x.Key != "" {
			issues[x.Key] = append(issues[x.Key], viewAction(x))
		}
	}
	for i := range list {
		list[i].Issues = issues[list[i].Key]
		if list[i].Middlewares == nil {
			list[i].Middlewares = []string{}
		}
	}
	return list
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"services": s.services()})
}

func (s *Server) service(key string) (ServiceInfo, bool) {
	for _, v := range s.services() {
		if v.Key == key {
			return v, true
		}
	}
	return ServiceInfo{}, false
}

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	key, action := r.PathValue("key"), r.PathValue("action")
	if !validKey(key) {
		writeErr(w, http.StatusBadRequest, "invalid service key")
		return
	}
	var edit func(*model.UIOverrides) error
	var desc string
	switch action {
	case "approve":
		s.approve(w, r, key)
		return
	case "publish", "unpublish":
		if !decodeJSON(w, r, &struct{}{}, smallBody) {
			return
		}
		skip := action == "unpublish"
		edit = func(o *model.UIOverrides) error { o.Skip = &skip; return nil }
		desc = action + "ed"
	case "rename":
		var req struct {
			Name *string `json:"name"`
		}
		if !decodeJSON(w, r, &req, smallBody) {
			return
		}
		if req.Name == nil {
			writeErr(w, http.StatusBadRequest, "name is required (\"\" clears the rename)")
			return
		}
		n := *req.Name
		edit = func(o *model.UIOverrides) error {
			if n == "" {
				o.Rename = nil
			} else {
				o.Rename = &n
			}
			return nil
		}
		desc = "renamed"
		if n != "" && validKey(n) {
			desc += " to " + n
		}
	case "port":
		var req struct {
			Port *int `json:"port"`
		}
		if !decodeJSON(w, r, &req, smallBody) {
			return
		}
		if req.Port == nil {
			writeErr(w, http.StatusBadRequest, "port is required (0 clears the override)")
			return
		}
		p := *req.Port
		edit = func(o *model.UIOverrides) error {
			if p == 0 {
				o.Port = nil
			} else {
				o.Port = &p
			}
			return nil
		}
		desc = "set the port override to " + strconv.Itoa(p)
	case "skip-verify":
		var req struct {
			SkipVerify *bool `json:"skip_verify"`
		}
		if !decodeJSON(w, r, &req, smallBody) {
			return
		}
		sv := req.SkipVerify
		edit = func(o *model.UIOverrides) error { o.SkipVerify = sv; return nil }
		desc = "set skip-verify to " + map[bool]string{true: "true", false: "false"}[sv != nil && *sv]
		if sv == nil {
			desc = "cleared the skip-verify override"
		}
	default:
		writeErr(w, http.StatusNotFound, "unknown action")
		return
	}
	if err := s.ctl.SetServiceOverride(r.Context(), key, edit); err != nil {
		var oe *model.OverrideError
		switch {
		case errors.Is(err, ErrUnknownService):
			writeErr(w, http.StatusNotFound, "unknown service")
		case errors.As(err, &oe):
			writeErr(w, http.StatusBadRequest, truncate(oe.Error(), 300))
		default:
			s.internal(w, "service override", err)
		}
		return
	}
	s.audit(r, "service "+key+": "+desc)
	v, _ := s.service(key)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request, key string) {
	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if !decodeJSON(w, r, &req, smallBody) {
		return
	}
	if req.Fingerprint == "" {
		writeErr(w, http.StatusBadRequest, "fingerprint is required")
		return
	}
	err := s.ctl.Approve(r.Context(), key, req.Fingerprint)
	switch {
	case err == nil:
	case errors.Is(err, approval.ErrStale):
		v, _ := s.service(key)
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the service changed since it was displayed; review and approve again", "service": v})
		return
	case errors.Is(err, approval.ErrUnknownService):
		writeErr(w, http.StatusNotFound, "unknown or unapprovable service")
		return
	default:
		s.internal(w, "approve", err)
		return
	}
	s.audit(r, "service "+key+": approved")
	v, _ := s.service(key)
	writeJSON(w, http.StatusOK, v)
}

// ---- DNS

type providerView struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	RecordZones    []string `json:"record_zones"`
	ChallengeZones []string `json:"challenge_zones"`
	Testable       bool     `json:"testable"`
	WildcardA      bool     `json:"wildcard_a"`
}

func (s *Server) recordProvider(name string) bool {
	for _, z := range s.cfg.Zones {
		if z.Records.Provider == name && (z.Records.Mode == "wildcard" || z.Records.Mode == "per-host") {
			return true
		}
	}
	return false
}

func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(s.cfg.Providers))
	for n := range s.cfg.Providers {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []providerView{}
	for _, n := range names {
		p := s.cfg.Providers[n]
		v := providerView{Name: n, Type: p.Type, RecordZones: []string{}, ChallengeZones: []string{}, Testable: s.recordProvider(n)}
		if c, ok := dns.CapsFor(p.Type); ok {
			v.WildcardA = c.WildcardA
		}
		for _, z := range s.cfg.Zones {
			if z.Records.Provider == n && z.Records.Mode != "off" && z.Records.Mode != "" {
				v.RecordZones = append(v.RecordZones, normZone(z.Name))
			}
			if z.Certificate.DNSProvider == n {
				v.ChallengeZones = append(v.ChallengeZones, normZone(z.Name))
			}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

func (s *Server) handleProviderTest(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName(name) {
		writeErr(w, http.StatusBadRequest, "invalid provider name")
		return
	}
	if _, ok := s.cfg.Providers[name]; !ok || !s.recordProvider(name) {
		writeErr(w, http.StatusNotFound, "no record provider with that name (challenge-only providers have no credential test)")
		return
	}
	if !decodeJSON(w, r, &struct{}{}, smallBody) {
		return
	}
	s.mu.Lock()
	if last, ok := s.lastTest[name]; ok && s.now().Sub(last) < providerTestEvery {
		s.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(int(providerTestEvery/time.Second)))
		writeErr(w, http.StatusTooManyRequests, "a test of this provider ran moments ago; try again shortly")
		return
	}
	s.lastTest[name] = s.now()
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), s.testTO)
	defer cancel()
	err := s.ctl.TestProvider(ctx, name)
	s.audit(r, "tested DNS provider "+name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "provider not found")
			return
		}
		msg := "credential test failed; see the server log"
		if errors.Is(err, context.DeadlineExceeded) {
			msg = "credential test timed out"
		}
		// Provider errors are redacted by the providers themselves.
		s.log.Warn("dns provider credential test failed", "provider", name, "error", err)
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": msg})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type conflictView struct {
	PlanAction
	ID      string `json:"id"`
	Skipped bool   `json:"skipped"`
}

func (s *Server) conflicts(ctx context.Context) ([]conflictView, error) {
	skipped, err := s.st.ListSettingsWithPrefix(ctx, ConflictSkipPrefix)
	if err != nil {
		return nil, err
	}
	out := []conflictView{}
	seen := map[string]bool{}
	for _, x := range s.ctl.LastPlan().Actions {
		id := ConflictID(x)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		_, sk := skipped[ConflictSkipPrefix+id]
		out = append(out, conflictView{PlanAction: viewAction(x), ID: id, Skipped: sk})
	}
	return out, nil
}

func (s *Server) handleConflicts(w http.ResponseWriter, r *http.Request) {
	cs, err := s.conflicts(r.Context())
	if err != nil {
		s.internal(w, "conflicts", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"conflicts": cs})
}

type ownedView struct {
	Provider     string     `json:"provider"`
	Zone         string     `json:"zone"`
	Name         string     `json:"name"`
	Type         string     `json:"type"`
	Value        string     `json:"value"`
	Owner        string     `json:"owner"`
	CreatedAt    time.Time  `json:"created_at"`
	RemovedAfter *time.Time `json:"removed_after,omitempty"`
}

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	rows, err := s.st.ListAllOwnedRecords(r.Context())
	if err != nil {
		s.internal(w, "records", err)
		return
	}
	owned := make([]ownedView, 0, len(rows))
	for _, x := range rows {
		owned = append(owned, ownedView{Provider: x.Provider, Zone: x.Zone, Name: x.Name, Type: x.Type, Value: x.Value,
			Owner: x.OwnerKey, CreatedAt: x.CreatedAt, RemovedAfter: x.RemovedAfter})
	}
	cs, err := s.conflicts(r.Context())
	if err != nil {
		s.internal(w, "conflicts", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"owned": owned, "conflicts": cs})
}

func validConflictID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

func (s *Server) handleConflictAction(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	if !validConflictID(id) {
		writeErr(w, http.StatusBadRequest, "invalid conflict id")
		return
	}
	if action != "adopt" && action != "skip" {
		writeErr(w, http.StatusNotFound, "unknown action")
		return
	}
	if !decodeJSON(w, r, &struct{}{}, smallBody) {
		return
	}
	var x *reconcile.Action
	for _, a := range s.ctl.LastPlan().Actions {
		if ConflictID(a) == id {
			a := a
			x = &a
			break
		}
	}
	if x == nil {
		writeErr(w, http.StatusConflict, "that conflict is not in the current plan (it may be resolved); reload")
		return
	}
	switch action {
	case "skip":
		if err := s.st.SetSetting(r.Context(), ConflictSkipPrefix+id, s.now().UTC().Format(time.RFC3339)); err != nil {
			s.internal(w, "conflict skip", err)
			return
		}
		s.audit(r, fmt.Sprintf("skipped DNS conflict %s (%s %s at %s/%s)", id, x.Record.Name, x.Record.Type, x.Provider, x.Zone))
	case "adopt":
		if _, ok := s.cfg.Providers[x.Provider]; !ok || x.Owner == "" {
			writeErr(w, http.StatusConflict, "this conflict cannot be adopted")
			return
		}
		t := strings.ToUpper(x.Record.Type)
		if t != "A" && t != "AAAA" {
			writeErr(w, http.StatusConflict, "only A and AAAA records can be adopted; remove the "+t+" record at the provider instead")
			return
		}
		err := s.st.AddOwnedRecord(r.Context(), store.DNSRecord{Provider: x.Provider, Zone: normZone(x.Zone), Name: x.Record.Name,
			Type: t, Value: x.Record.Value, ProviderRecordID: x.Record.ID, OwnerKey: x.Owner, CreatedAt: s.now()})
		if errors.Is(err, store.ErrOwnerConflict) {
			writeErr(w, http.StatusConflict, "the record is already owned by another service")
			return
		}
		if err != nil {
			s.internal(w, "conflict adopt", err)
			return
		}
		s.audit(r, fmt.Sprintf("adopted DNS record %s %s at %s/%s for %s", x.Record.Name, t, x.Provider, x.Zone, x.Owner))
		s.ctl.Trigger()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRepairAck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
		Zone     string `json:"zone"`
	}
	if !decodeJSON(w, r, &req, smallBody) {
		return
	}
	z := normZone(req.Zone)
	if !validName(req.Provider) || !validName(z) {
		writeErr(w, http.StatusBadRequest, "provider and zone are required")
		return
	}
	found := false
	for _, cz := range s.cfg.Zones {
		if normZone(cz.Name) == z && cz.Records.Provider == req.Provider && (cz.Records.Mode == "wildcard" || cz.Records.Mode == "per-host") {
			found = true
		}
	}
	if _, ok := s.cfg.Providers[req.Provider]; !ok || !found {
		writeErr(w, http.StatusNotFound, "no zone uses that records provider")
		return
	}
	if err := s.st.AcknowledgeMassRepair(r.Context(), req.Provider, z); err != nil {
		s.internal(w, "repair ack", err)
		return
	}
	s.audit(r, "acknowledged the mass DNS repair of "+req.Provider+"/"+z)
	s.ctl.Trigger()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- certificates

type certView struct {
	ID         string    `json:"id"`
	Zone       string    `json:"zone"`
	Domains    []string  `json:"domains"`
	Issuer     string    `json:"issuer"`
	Staging    bool      `json:"staging"`
	NotAfter   time.Time `json:"not_after"`
	Status     string    `json:"status"`
	LastResult string    `json:"last_result"`
	LastError  string    `json:"last_error,omitempty"`
	Managed    bool      `json:"managed"`
	Renewing   bool      `json:"renewing"`
}

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.st.ListCerts(r.Context())
	if err != nil {
		s.internal(w, "certs", err)
		return
	}
	out := make([]certView, 0, len(rows))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range rows {
		var doms []string
		_ = json.Unmarshal([]byte(c.DomainsJSON), &doms)
		if doms == nil {
			doms = []string{}
		}
		out = append(out, certView{ID: c.ID, Zone: c.Zone, Domains: doms, Issuer: c.Issuer, Staging: c.Staging, NotAfter: c.NotAfter,
			Status: c.Status, LastResult: c.LastResult, LastError: c.LastError, Managed: c.Managed, Renewing: s.inflight["cert/"+c.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"certs": out})
}

// runAsync runs f in the background under key (one at a time per key),
// recording the outcome in the activity log.
func (s *Server) runAsync(key, actor, what string, f func(context.Context) error) bool {
	s.mu.Lock()
	if s.inflight[key] {
		s.mu.Unlock()
		return false
	}
	s.inflight[key] = true
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.inflight, key)
			s.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(s.ctx, asyncTimeout)
		defer cancel()
		err := f(ctx)
		msg := what + ": done"
		if err != nil {
			s.log.Warn("api: "+what+" failed", "error", err)
			msg = what + ": failed (see the certificate's last error and the server log)"
		}
		s.auditAs(context.Background(), actor, msg)
		s.ctl.Trigger()
	}()
	return true
}

func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validName(id) {
		writeErr(w, http.StatusBadRequest, "invalid certificate id")
		return
	}
	if !decodeJSON(w, r, &struct{}{}, smallBody) {
		return
	}
	rows, err := s.st.ListCerts(r.Context())
	if err != nil {
		s.internal(w, "certs", err)
		return
	}
	found := false
	for _, c := range rows {
		found = found || c.ID == id
	}
	if !found {
		writeErr(w, http.StatusNotFound, "unknown certificate")
		return
	}
	actor := principalFrom(r.Context()).Actor()
	if !s.runAsync("cert/"+id, actor, "renewal of certificate "+id, func(ctx context.Context) error { return s.ctl.RenewCert(ctx, id) }) {
		writeErr(w, http.StatusConflict, "a renewal of this certificate is already running")
		return
	}
	s.audit(r, "requested renewal of certificate "+id)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "status": "renewal started"})
}

func (s *Server) handleSwitchProduction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Issuer  string `json:"issuer"`
		Confirm bool   `json:"confirm"`
	}
	if !decodeJSON(w, r, &req, smallBody) {
		return
	}
	if !validName(req.Issuer) {
		writeErr(w, http.StatusBadRequest, "issuer is required")
		return
	}
	if _, ok := s.cfg.Issuers[req.Issuer]; !ok {
		writeErr(w, http.StatusNotFound, "unknown issuer")
		return
	}
	if !req.Confirm {
		writeErr(w, http.StatusBadRequest, "set confirm: true: every staging certificate of the issuer is re-issued from production")
		return
	}
	actor := principalFrom(r.Context()).Actor()
	if !s.runAsync("issuer/"+req.Issuer, actor, "switch of issuer "+req.Issuer+" to production", func(ctx context.Context) error {
		return s.ctl.SwitchProduction(ctx, req.Issuer)
	}) {
		writeErr(w, http.StatusConflict, "a switch of this issuer is already running")
		return
	}
	s.audit(r, "requested the switch of issuer "+req.Issuer+" to production")
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "status": "switch started"})
}

// ---- zones, activity, settings

func (s *Server) handleZones(w http.ResponseWriter, r *http.Request) {
	type zoneView struct {
		Name          string `json:"name"`
		TargetIP      string `json:"target_ip"`
		RecordsMode   string `json:"records_mode"`
		RecordsProv   string `json:"records_provider,omitempty"`
		Issuer        string `json:"issuer,omitempty"`
		CertStrategy  string `json:"cert_strategy,omitempty"`
		Challenge     string `json:"challenge,omitempty"`
		ChallengeProv string `json:"challenge_provider,omitempty"`
		Default       bool   `json:"default"`
	}
	dz := s.cfg.DefaultCertZone()
	out := []zoneView{}
	for _, z := range s.cfg.Zones {
		mode := z.Records.Mode
		if mode == "" {
			mode = "off"
		}
		out = append(out, zoneView{Name: normZone(z.Name), TargetIP: z.TargetIP, RecordsMode: mode, RecordsProv: z.Records.Provider,
			Issuer: z.Certificate.Issuer, CertStrategy: z.Certificate.Strategy, Challenge: z.Certificate.Challenge,
			ChallengeProv: z.Certificate.DNSProvider, Default: normZone(z.Name) == dz})
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": out})
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeErr(w, http.StatusBadRequest, "limit must be 1..500")
			return
		}
		limit = n
	}
	rows, err := s.st.ListActivity(r.Context(), limit)
	if err != nil {
		s.internal(w, "activity", err)
		return
	}
	type entry struct {
		TS      time.Time `json:"ts"`
		Level   string    `json:"level"`
		Kind    string    `json:"kind"`
		Message string    `json:"message"`
	}
	out := make([]entry, 0, len(rows))
	for _, e := range rows {
		out = append(out, entry{e.TS, e.Level, e.Kind, e.Message})
	}
	writeJSON(w, http.StatusOK, map[string]any{"activity": out})
}

func (s *Server) handleGetDryRun(w http.ResponseWriter, r *http.Request) {
	on, err := s.ctl.DryRun(r.Context())
	if err != nil {
		s.internal(w, "dry run", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": on, "forced_by_config": s.cfg.Settings.DryRun})
}

func (s *Server) handleSetDryRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &req, smallBody) {
		return
	}
	if req.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "enabled is required")
		return
	}
	if err := s.ctl.SetDryRun(r.Context(), *req.Enabled); err != nil {
		s.internal(w, "set dry run", err)
		return
	}
	s.audit(r, fmt.Sprintf("set the global dry run to %t", *req.Enabled))
	writeJSON(w, http.StatusOK, map[string]any{"enabled": *req.Enabled || s.cfg.Settings.DryRun, "forced_by_config": s.cfg.Settings.DryRun})
}

// ---- config

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	raw, err := os.ReadFile(s.cfgPath)
	if err != nil {
		s.internal(w, "config read", err)
		return
	}
	masked, err := MaskConfig(raw)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "the config file could not be parsed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"yaml": string(masked), "masked_placeholder": Masked,
		"note": "secrets are masked; send the placeholder back unchanged to keep a value. Changes apply after a restart."})
}

func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		YAML string `json:"yaml"`
	}
	if !decodeJSON(w, r, &req, configBody) {
		return
	}
	if strings.TrimSpace(req.YAML) == "" {
		writeErr(w, http.StatusBadRequest, "yaml is required")
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	old, err := os.ReadFile(s.cfgPath)
	if err != nil {
		s.internal(w, "config read", err)
		return
	}
	secrets := append(sensitiveValues(old), sensitiveValues([]byte(req.YAML))...)
	merged, err := MergeMasked([]byte(req.YAML), old)
	if err != nil {
		writeErr(w, http.StatusBadRequest, scrubConfigError(err.Error(), secrets))
		return
	}
	if s.validate == nil {
		writeErr(w, http.StatusInternalServerError, "config validation is not available")
		return
	}
	if err := s.validate(merged); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid config: "+scrubConfigError(err.Error(), secrets))
		return
	}
	if err := writeFileAtomic(s.cfgPath, merged); err != nil {
		s.log.Error("api: writing the config file failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "the config file could not be written (is it mounted read-only?)")
		return
	}
	s.audit(r, "updated the configuration file (restart required)")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": true})
}

// writeFileAtomic writes b to path via a temp file and rename, mode 0600.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".doorwarden-config-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) //nolint:errcheck // gone after the rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
