package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
)

// Everything but /healthz and the login/setup/status endpoints needs auth,
// /metrics and SSE included; unknown paths are 401, not 404.
func TestUnauthenticated401(t *testing.T) {
	e := newTestEnv(t)
	c := e.anon()
	for _, p := range []string{"/api/v1/services", "/api/v1/config", "/metrics", "/api/v1/events",
		"/api/v1/activity", "/api/v1/auth/me", "/api/v1/nope", "/", "/healthz/../api/v1/services"} {
		if w := c.do("GET", p, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s = %d", p, w.Code)
		}
	}
	if w := c.do("POST", "/api/v1/settings/dry-run", map[string]bool{"enabled": true}); w.Code != http.StatusUnauthorized {
		t.Errorf("POST dry-run = %d", w.Code)
	}
	if w := c.do("GET", "/healthz", nil); w.Code != 200 {
		t.Errorf("healthz = %d", w.Code)
	}
	w := c.do("GET", "/api/v1/auth/status", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"setup_required":true`) {
		t.Errorf("status = %d %s", w.Code, w.Body)
	}
	// Security headers on every response, even errors.
	w = c.do("GET", "/api/v1/services", nil)
	for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
		if w.Header().Get(k) != v {
			t.Errorf("%s = %q", k, w.Header().Get(k))
		}
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP = %q", csp)
	}
}

func TestFirstRunSetup(t *testing.T) {
	e := newTestEnv(t)
	c := e.anon()
	// Wrong or missing token.
	for _, tok := range []string{"", "wrong", testToken + "x"} {
		w := c.do("POST", "/api/v1/auth/setup", map[string]string{"username": "admin", "password": testPassword, "token": tok})
		if w.Code != http.StatusForbidden {
			t.Fatalf("token %q: %d %s", tok, w.Code, w.Body)
		}
	}
	// Weak password.
	if w := c.do("POST", "/api/v1/auth/setup", map[string]string{"username": "admin", "password": "short", "token": testToken}); w.Code != http.StatusBadRequest {
		t.Fatalf("short password: %d", w.Code)
	}
	admin := e.setupAdmin()
	if w := admin.do("GET", "/api/v1/auth/me", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"user":"admin"`) {
		t.Fatalf("me = %d %s", w.Code, w.Body)
	}
	// Second setup fails: an admin exists.
	w := e.anon().do("POST", "/api/v1/auth/setup", map[string]string{"username": "evil", "password": testPassword, "token": testToken})
	if w.Code != http.StatusConflict {
		t.Fatalf("second setup = %d", w.Code)
	}
	a, _, _ := e.st.GetAdmin(context.Background())
	if a.Username != "admin" || strings.Contains(a.PasswordHash, testPassword) {
		t.Fatalf("admin = %+v", a)
	}
	if strings.Contains(e.logBuf.String(), testPassword) {
		t.Fatal("password in log")
	}
}

// Two concurrent setups create exactly one admin.
func TestFirstRunRace(t *testing.T) {
	e := newTestEnv(t)
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := e.anon().do("POST", "/api/v1/auth/setup", map[string]string{"username": []string{"a", "b"}[i], "password": testPassword, "token": testToken})
			codes[i] = w.Code
		}()
	}
	wg.Wait()
	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case 200:
			ok++
		case http.StatusConflict, http.StatusForbidden:
			conflict++
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("codes = %v", codes)
	}
}

// With an admin present at start no setup token is generated and setup
// is closed.
func TestSetupTokenLoggedOnlyWithoutAdmin(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.SetupToken = "" })
	if !strings.Contains(e.logBuf.String(), "setup token") {
		t.Fatalf("no setup token logged: %s", e.logBuf)
	}
	tok := e.srv.auth.setupTokenForTest()
	if len(tok) < 20 || !strings.Contains(e.logBuf.String(), tok) {
		t.Fatalf("token %q not in log", tok)
	}
	h, _ := e.srv.auth.hasher.Hash(testPassword)
	_ = e.st.CreateAdmin(context.Background(), "admin", h, time.Now())
	buf := &syncBuf{}
	e2 := newTestEnv(t, func(o *Options) {
		o.SetupToken = ""
		o.Store = e.st
		o.Log = slogTo(buf)
	})
	if strings.Contains(buf.String(), "setup token") || e2.srv.auth.setupTokenForTest() != "" {
		t.Fatalf("setup token generated with an admin present: %s", buf)
	}
}

func TestLoginLogoutAndFixation(t *testing.T) {
	e := newTestEnv(t)
	first := e.setupAdmin()
	// Login with an existing session cookie rotates it (no fixation) and
	// the old one stops working.
	c := &client{e: e, cookie: first.cookie}
	old := first.cookie.Value
	w := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": testPassword})
	if w.Code != 200 || c.cookie == nil || c.cookie.Value == old {
		t.Fatalf("login: %d cookie=%v", w.Code, c.cookie)
	}
	ck := c.cookie
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" {
		t.Fatalf("cookie flags: %+v", ck)
	}
	if w := first.do("GET", "/api/v1/services", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("old session still valid: %d", w.Code)
	}
	var resp struct {
		CSRF string `json:"csrf_token"`
	}
	decodeJSONT(t, w, &resp)
	c.csrf = resp.CSRF
	if w := c.do("GET", "/api/v1/services", nil); w.Code != 200 {
		t.Fatalf("new session: %d", w.Code)
	}
	saved := *c.cookie
	if w := c.do("POST", "/api/v1/auth/logout", nil); w.Code != 200 {
		t.Fatalf("logout: %d %s", w.Code, w.Body)
	}
	// Replaying the old cookie after logout fails: invalidated server side.
	replay := &client{e: e, cookie: &saved, csrf: c.csrf}
	if w := replay.do("GET", "/api/v1/services", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("session valid after logout: %d", w.Code)
	}
}

func TestLoginNoEnumerationAndLockout(t *testing.T) {
	e := newTestEnv(t)
	e.setupAdmin()
	_, w1 := e.login("admin", "wrong-password-xyz")
	_, w2 := e.login("nobody", "wrong-password-xyz")
	if w1.Code != http.StatusUnauthorized || w2.Code != http.StatusUnauthorized || w1.Body.String() != w2.Body.String() {
		t.Fatalf("enumeration: %d %q vs %d %q", w1.Code, w1.Body, w2.Code, w2.Body)
	}
	for i := 0; i < throttleThreshold; i++ {
		e.login("nobody", "wrong-password-xyz")
	}
	// The address is locked: even the right password is refused.
	_, w := e.login("admin", testPassword)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("not locked out: %d", w.Code)
	}
	// The lock is per user too: failures for admin spread over addresses
	// lock admin everywhere.
	for i := 0; i < throttleThreshold; i++ {
		c := e.anon()
		c.remote = fmt.Sprintf("203.0.113.%d:1", 10+i)
		c.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "wrong-password-xyz"})
	}
	c := e.anon()
	c.remote = "203.0.113.9:1"
	if w := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": testPassword}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("user lock not applied from another IP: %d", w.Code)
	}
	// Other users from a fresh address are not affected by admin's lock.
	c.remote = "203.0.113.50:1"
	if w := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "someone", "password": "wrong-password-xyz"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("unrelated login: %d", w.Code)
	}
	e.advance(throttleMax + time.Second)
	if _, w := e.login("admin", testPassword); w.Code != 200 {
		t.Fatalf("after backoff: %d %s", w.Code, w.Body)
	}
	if strings.Contains(e.logBuf.String(), "wrong-password-xyz") || strings.Contains(e.logBuf.String(), testPassword) {
		t.Fatal("password logged")
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	e.advance(e.cfg.Web.SessionIdle - time.Minute)
	if w := c.do("GET", "/api/v1/services", nil); w.Code != 200 {
		t.Fatalf("active session: %d", w.Code)
	}
	e.advance(e.cfg.Web.SessionIdle + time.Minute)
	if w := c.do("GET", "/api/v1/services", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("idle session: %d", w.Code)
	}
	// Absolute expiry even when used.
	c2, _ := e.login("admin", testPassword)
	for i := 0; i < 30; i++ {
		e.advance(e.cfg.Web.SessionMax / 25)
		c2.do("GET", "/api/v1/services", nil)
	}
	if w := c2.do("GET", "/api/v1/services", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("session past max age: %d", w.Code)
	}
}

func TestCSRFAndOrigin(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	body := map[string]bool{"enabled": true}
	if w := c.do("POST", "/api/v1/settings/dry-run", body, noCSRF()); w.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/settings/dry-run", body, withHeader(CSRFHeader, "wrong")); w.Code != http.StatusForbidden {
		t.Fatalf("wrong CSRF: %d", w.Code)
	}
	for _, o := range []string{"https://evil.example", "null", "https://dw.example.test.evil.example"} {
		if w := c.do("POST", "/api/v1/settings/dry-run", body, withHeader("Origin", o)); w.Code != http.StatusForbidden {
			t.Fatalf("origin %s: %d", o, w.Code)
		}
	}
	if w := c.do("POST", "/api/v1/settings/dry-run", body, withHeader("Sec-Fetch-Site", "cross-site")); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site fetch: %d", w.Code)
	}
	// Login is checked for Origin too (login CSRF).
	if w := e.anon().do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": testPassword},
		withHeader("Origin", "https://evil.example")); w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login: %d", w.Code)
	}
	// A form post (not JSON) is refused.
	if w := c.do("POST", "/api/v1/settings/dry-run", "enabled=true", withHeader("Content-Type", "application/x-www-form-urlencoded")); w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("form post: %d", w.Code)
	}
	// Same origin (scheme may differ behind a TLS proxy) works.
	if w := c.do("POST", "/api/v1/settings/dry-run", body, withHeader("Origin", "https://dw.example.test")); w.Code != 200 {
		t.Fatalf("same origin: %d %s", w.Code, w.Body)
	}
	if !e.ctl.dry {
		t.Fatal("dry run not set")
	}
}

func TestAllowedOrigins(t *testing.T) {
	e := newTestEnv(t, func(o *Options) {
		o.Config.Web.AllowedOrigins = []string{"https://ui.example.test"}
	})
	c := e.setupAdmin()
	if w := c.do("POST", "/api/v1/settings/dry-run", map[string]bool{"enabled": true}, withHeader("Origin", "https://ui.example.test")); w.Code != 200 {
		t.Fatalf("allowed origin: %d", w.Code)
	}
}

func TestTrustedHeader(t *testing.T) {
	e := newTestEnv(t)
	e.setupAdmin()
	// From an untrusted peer the header is ignored (and X-Forwarded-For
	// does not make it trusted).
	c := e.anon()
	for _, opts := range [][]reqOpt{
		{withHeader("X-Auth-User", "mallory")},
		{withHeader("X-Auth-User", "mallory"), withHeader("X-Forwarded-For", "192.0.2.100")},
		{withHeader("X-Auth-User", "mallory"), withHeader("X-Real-Ip", "192.0.2.100")},
	} {
		if w := c.do("GET", "/api/v1/services", nil, opts...); w.Code != http.StatusUnauthorized {
			t.Fatalf("spoofed header accepted: %d", w.Code)
		}
	}
	// From the trusted proxy it authenticates with the configured role.
	p := e.anon()
	p.remote = "192.0.2.100:40000"
	w := p.do("GET", "/api/v1/auth/me", nil, withHeader("X-Auth-User", "alice"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"user":"alice"`) || !strings.Contains(w.Body.String(), `"role":"admin"`) {
		t.Fatalf("trusted header: %d %s", w.Code, w.Body)
	}
	var me struct {
		CSRF string `json:"csrf_token"`
	}
	decodeJSONT(t, w, &me)
	// State changes need its CSRF token like a session.
	if w := p.do("POST", "/api/v1/settings/dry-run", map[string]bool{"enabled": true}, withHeader("X-Auth-User", "alice")); w.Code != http.StatusForbidden {
		t.Fatalf("header auth without CSRF: %d", w.Code)
	}
	if w := p.do("POST", "/api/v1/settings/dry-run", map[string]bool{"enabled": true}, withHeader("X-Auth-User", "alice"), withHeader(CSRFHeader, me.CSRF)); w.Code != 200 {
		t.Fatalf("header auth with CSRF: %d %s", w.Code, w.Body)
	}
	// The audit entry names the header identity.
	act, _ := e.st.ListActivity(context.Background(), 10)
	found := false
	for _, a := range act {
		if strings.Contains(a.Message, "header:alice") && strings.Contains(a.Message, "dry") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit entry: %+v", act)
	}
	// Trusted peer without the header: no auth.
	if w := p.do("GET", "/api/v1/services", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("trusted peer without header: %d", w.Code)
	}
}

func TestTrustedHeaderViewerReadOnly(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.Config.Web.TrustedHeader.Role = "viewer" })
	p := e.anon()
	p.remote = "192.0.2.100:1"
	w := p.do("GET", "/api/v1/auth/me", nil, withHeader("X-Auth-User", "bob"))
	var me struct {
		CSRF string `json:"csrf_token"`
	}
	decodeJSONT(t, w, &me)
	if w := p.do("GET", "/api/v1/services", nil, withHeader("X-Auth-User", "bob")); w.Code != 200 {
		t.Fatalf("viewer read: %d", w.Code)
	}
	if w := p.do("POST", "/api/v1/settings/dry-run", map[string]bool{"enabled": true}, withHeader("X-Auth-User", "bob"), withHeader(CSRFHeader, me.CSRF)); w.Code != http.StatusForbidden {
		t.Fatalf("viewer write: %d", w.Code)
	}
	if w := p.do("GET", "/api/v1/config", nil, withHeader("X-Auth-User", "bob")); w.Code != http.StatusForbidden {
		t.Fatalf("viewer config read: %d", w.Code)
	}
}

// Empty proxies turns trusted-header auth off entirely.
func TestTrustedHeaderOff(t *testing.T) {
	e := newTestEnv(t, func(o *Options) {
		o.Config.Web.TrustedHeader = config.TrustedHeader{UserHeader: "X-Auth-User", Role: "admin"}
	})
	p := e.anon()
	p.remote = "192.0.2.100:1"
	if w := p.do("GET", "/api/v1/services", nil, withHeader("X-Auth-User", "alice")); w.Code != http.StatusUnauthorized {
		t.Fatalf("header honoured with no proxies: %d", w.Code)
	}
}

func TestPasswordChangeInvalidatesSessions(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	other, _ := e.login("admin", testPassword)
	if w := c.do("POST", "/api/v1/auth/password", map[string]string{"current": "nope-nope-nope", "new": "another-long-password"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/auth/password", map[string]string{"current": testPassword, "new": "another-long-password"}); w.Code != 200 {
		t.Fatalf("change: %d %s", w.Code, w.Body)
	}
	if w := other.do("GET", "/api/v1/services", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("other session survived: %d", w.Code)
	}
	if _, w := e.login("admin", "another-long-password"); w.Code != 200 {
		t.Fatalf("new password: %d", w.Code)
	}
}
