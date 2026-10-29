package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

const testToken = "setup-token-0123456789"

const testPassword = "a-long-test-password"

// fakeControl is the control plane the API drives.
type fakeControl struct {
	mu        sync.Mutex
	services  []ServiceInfo
	fps       map[string]string
	overrides map[string]model.UIOverrides
	plan      Plan
	dry       bool
	triggers  int
	approved  map[string]string
	testErr   error
	tested    []string
	renewed   []string
	switched  []string
	renewWait chan struct{}
}

func newFakeControl() *fakeControl {
	return &fakeControl{fps: map[string]string{}, overrides: map[string]model.UIOverrides{}, approved: map[string]string{}}
}

func (f *fakeControl) ServiceList() []ServiceInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]ServiceInfo(nil), f.services...)
	for i := range out {
		out[i].Fingerprint = f.fps[out[i].Key]
		out[i].Overrides = f.overrides[out[i].Key]
	}
	return out
}

func (f *fakeControl) SetServiceOverride(_ context.Context, key string, edit func(*model.UIOverrides) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	found := false
	for _, s := range f.services {
		if s.Key == key {
			found = true
		}
	}
	if !found {
		return ErrUnknownService
	}
	o := f.overrides[key]
	if err := edit(&o); err != nil {
		return err
	}
	if o.Port != nil && (*o.Port < 1 || *o.Port > 65535) {
		return &model.OverrideError{Msg: "port out of range"}
	}
	f.overrides[key] = o
	f.triggers++
	return nil
}

func (f *fakeControl) Approve(_ context.Context, key, fp string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.fps[key]
	if !ok {
		return approval.ErrUnknownService
	}
	if cur != fp {
		return approval.ErrStale
	}
	f.approved[key] = fp
	f.triggers++
	return nil
}

func (f *fakeControl) LastPlan() Plan {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.plan
}

func (f *fakeControl) DryRun(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dry, nil
}

func (f *fakeControl) SetDryRun(_ context.Context, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dry = on
	return nil
}

func (f *fakeControl) Trigger() {
	f.mu.Lock()
	f.triggers++
	f.mu.Unlock()
}

func (f *fakeControl) TestProvider(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tested = append(f.tested, name)
	return f.testErr
}

func (f *fakeControl) RenewCert(_ context.Context, id string) error {
	if f.renewWait != nil {
		<-f.renewWait
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewed = append(f.renewed, id)
	return nil
}

func (f *fakeControl) SwitchProduction(_ context.Context, issuer string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.switched = append(f.switched, issuer)
	return nil
}

const testConfigYAML = `zones:
  - name: example.test
    target_ip: 192.0.2.10
    records: {provider: fk, mode: per-host}
providers:
  fk: {type: fake, token: "s3cr3t-provider-token"}
  ref: {type: fake, token: "secret:fk-token"}
issuers:
  le: {email: admin@example.test, eab_kid: kid1, eab_hmac: "s3cr3t-eab-hmac"}
sources:
  truenas: {url: "https://192.0.2.20", api_key: "s3cr3t-truenas-key"}
notifications:
  smtp:
    - {host: mail.example.test, username: u, password: "s3cr3t-smtp-pw", from: a@example.test, to: [b@example.test]}
web:
  trusted_header: {proxies: ["192.0.2.100/32"], user_header: X-Auth-User, role: admin}
`

type testEnv struct {
	t       *testing.T
	st      *store.Store
	ctl     *fakeControl
	srv     *Server
	h       http.Handler
	cfgPath string
	cfg     *config.Config
	now     time.Time
	nowMu   sync.Mutex
	logBuf  *syncBuf
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newTestEnv(t *testing.T, mut ...func(*Options)) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "doorwarden.yaml")
	if err := os.WriteFile(cfgPath, []byte(testConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(testConfigYAML), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "dw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &testEnv{t: t, st: st, ctl: newFakeControl(), cfgPath: cfgPath, cfg: cfg,
		now: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC), logBuf: &syncBuf{}}
	o := Options{
		Store: st, Control: e.ctl, Config: cfg, ConfigPath: cfgPath,
		ValidateConfig: func(raw []byte) error {
			c, err := config.Parse(raw, func(string) (string, bool) { return "", false })
			if err != nil {
				return err
			}
			if errs := c.Validate(nil); len(errs) > 0 {
				return errs[0]
			}
			return nil
		},
		Health:     http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }),
		Metrics:    http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "metrics") }),
		Log:        slog.New(slog.NewTextHandler(e.logBuf, nil)),
		Now:        e.clock,
		SetupToken: testToken,
		Hasher:     NewHasher(testParams, 2),
	}
	for _, m := range mut {
		m(&o)
	}
	srv, err := NewServer(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	e.srv, e.h = srv, srv
	return e
}

func (e *testEnv) clock() time.Time {
	e.nowMu.Lock()
	defer e.nowMu.Unlock()
	return e.now
}

func (e *testEnv) advance(d time.Duration) {
	e.nowMu.Lock()
	e.now = e.now.Add(d)
	e.nowMu.Unlock()
}

// client carries a session cookie and CSRF token.
type client struct {
	e      *testEnv
	cookie *http.Cookie
	csrf   string
	remote string
	origin string
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func withRemote(a string) reqOpt    { return func(r *http.Request) { r.RemoteAddr = a } }
func noCSRF() reqOpt                { return func(r *http.Request) { r.Header.Del(CSRFHeader) } }

func (c *client) do(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	c.e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			c.e.t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	r := httptest.NewRequest(method, "http://dw.example.test"+path, rd)
	r.RemoteAddr = "198.51.100.20:5555"
	if c.remote != "" {
		r.RemoteAddr = c.remote
	}
	if rd != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.origin != "" {
		r.Header.Set("Origin", c.origin)
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if c.csrf != "" {
		r.Header.Set(CSRFHeader, c.csrf)
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	c.e.h.ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == c.e.srv.auth.cookieName() {
			if ck.MaxAge < 0 {
				c.cookie = nil
			} else {
				c.cookie = ck
			}
		}
	}
	return w
}

func (e *testEnv) anon() *client { return &client{e: e} }

// setupAdmin runs first-run setup and returns a logged-in client.
func (e *testEnv) setupAdmin() *client {
	e.t.Helper()
	c := e.anon()
	w := c.do("POST", "/api/v1/auth/setup", map[string]string{"username": "admin", "password": testPassword, "token": testToken})
	if w.Code != 200 {
		e.t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	var resp struct {
		CSRF string `json:"csrf_token"`
	}
	decodeJSONT(e.t, w, &resp)
	c.csrf = resp.CSRF
	if c.cookie == nil || c.csrf == "" {
		e.t.Fatalf("setup gave no session: %v %q", c.cookie, c.csrf)
	}
	return c
}

func (e *testEnv) login(user, pw string) (*client, *httptest.ResponseRecorder) {
	c := e.anon()
	w := c.do("POST", "/api/v1/auth/login", map[string]string{"username": user, "password": pw})
	if w.Code == 200 {
		var resp struct {
			CSRF string `json:"csrf_token"`
		}
		decodeJSONT(e.t, w, &resp)
		c.csrf = resp.CSRF
	}
	return c, w
}

func decodeJSONT(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
}

func slogTo(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
