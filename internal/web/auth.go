package web

// Authentication and request policy.
//
// Default deny: Server wraps the whole mux. Only the paths in publicPaths
// (exact match: /healthz, /api/v1/auth/status, /api/v1/auth/login,
// /api/v1/auth/setup) are served without a principal; everything else,
// /metrics, SSE and unknown paths included, answers 401 first.
//
// Principals:
//   - Local admin: argon2id password, session cookie (random 256-bit ID,
//     stored as its SHA-256; HttpOnly, SameSite=Strict, Secure unless
//     web.cookie_insecure; idle and absolute expiry; a new ID on every
//     login; logout and password change delete sessions server side).
//   - Trusted header (forward-auth): web.trusted_header.user_header is read
//     only when the TCP peer (r.RemoteAddr, never X-Forwarded-For) is in
//     web.trusted_header.proxies; from any other peer the header is removed
//     before anything else sees the request. Empty proxies = off. Such a
//     principal has web.trusted_header.role (admin or viewer).
//
// State-changing requests (every method but GET/HEAD/OPTIONS):
//   - Origin, when sent, must be the request's own host (scheme ignored:
//     behind a TLS proxy the inner request is plain http) or one of
//     web.allowed_origins; "null" is refused, and so is
//     Sec-Fetch-Site: cross-site. This applies to login and setup too.
//   - A body must be application/json.
//   - Authenticated requests must carry CSRFHeader equal to the principal's
//     token (the session's random token; for header principals an HMAC of
//     the identity under a per-process key), served by /api/v1/auth/me and
//     by login/setup.
//   - Viewers get 403.
//
// First run: when no admin exists at start a random setup token is logged
// (WARN, "first-run setup token"); POST /api/v1/auth/setup must present it.
// It is single use, and the admins table holds one row, so of concurrent
// setups exactly one wins. Localhost binding was rejected: in a container
// behind Traefik every request comes from the proxy.
//
// Login throttling: per client IP and per user name (see throttle); a
// locked key answers 429 with Retry-After without checking the password.
// Unknown users cost the same argon2 work as the real one, and every
// failure has the same body.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/store"
)

// CSRFHeader carries the CSRF token on state-changing requests.
const CSRFHeader = "X-Doorwarden-CSRF"

// Roles.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

const (
	sessionIDBytes   = 32
	sessionTouchStep = time.Minute
	minPasswordLen   = 12
	maxUsernameLen   = 64
	maxIdentityLen   = 128
)

var publicPaths = map[string]bool{
	"/healthz":            true,
	"/api/v1/auth/status": true,
	"/api/v1/auth/login":  true,
	"/api/v1/auth/setup":  true,
}

// Principal is an authenticated caller.
type Principal struct {
	User   string
	Role   string
	Method string // "session" or "header"
	CSRF   string
	// sessionHash is the session's stored ID hash (session principals).
	sessionHash string
}

// Actor is the audit name: admin:<user> or header:<identity>.
func (p *Principal) Actor() string {
	if p.Method == "header" {
		return "header:" + p.User
	}
	return "local:" + p.User
}

type ctxKey struct{}

func principalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

type auth struct {
	st      *store.Store
	cfg     config.Web
	proxies []netip.Prefix
	header  string
	hasher  *Hasher
	now     func() time.Time
	log     *slog.Logger
	thr     *throttle
	hdrKey  []byte
	origins map[string]bool

	tokMu      sync.Mutex
	setupToken string
}

func newAuth(ctx context.Context, st *store.Store, cfg config.Web, hasher *Hasher, now func() time.Time, log *slog.Logger, setupToken string) (*auth, error) {
	a := &auth{st: st, cfg: cfg, hasher: hasher, now: now, log: log, thr: newThrottle(now),
		header: http.CanonicalHeaderKey(cfg.TrustedHeader.UserHeader), origins: map[string]bool{}}
	for _, p := range cfg.TrustedHeader.Proxies {
		pf, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, errors.New("web.trusted_header.proxies: invalid CIDR")
		}
		a.proxies = append(a.proxies, pf.Masked())
	}
	for _, o := range cfg.AllowedOrigins {
		a.origins[strings.ToLower(o)] = true
	}
	a.hdrKey = make([]byte, 32)
	if _, err := rand.Read(a.hdrKey); err != nil {
		return nil, err
	}
	_, exists, err := st.GetAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if !exists {
		if setupToken == "" {
			setupToken = randToken(24)
			log.Warn("no administrator yet: first-run setup token (use it once in the setup form; it changes on every restart until setup is done)",
				"setup_token", setupToken)
		}
		a.setupToken = setupToken
	}
	return a, nil
}

func (a *auth) setupTokenForTest() string {
	a.tokMu.Lock()
	defer a.tokMu.Unlock()
	return a.setupToken
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashID(id string) string {
	s := sha256.Sum256([]byte(id))
	return hex.EncodeToString(s[:])
}

func (a *auth) cookieName() string {
	if a.cfg.CookieInsecure {
		return "doorwarden_session"
	}
	return "__Host-doorwarden_session"
}

func peerAddr(r *http.Request) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

func (a *auth) trustedPeer(r *http.Request) bool {
	if len(a.proxies) == 0 {
		return false
	}
	ip, ok := peerAddr(r)
	if !ok {
		return false
	}
	for _, p := range a.proxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// clientKey is the throttling address: the peer, or, when the peer is a
// trusted proxy, the last X-Forwarded-For hop it appended.
func (a *auth) clientKey(r *http.Request) string {
	ip, _ := peerAddr(r)
	if a.trustedPeer(r) {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			hops := strings.Split(xff[len(xff)-1], ",")
			if h, err := netip.ParseAddr(strings.TrimSpace(hops[len(hops)-1])); err == nil {
				ip = h.Unmap()
			}
		}
	}
	return "ip:" + ip.String()
}

func validIdentity(s string) bool {
	if s == "" || len(s) > maxIdentityLen {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || c > 0x7e {
			return false
		}
	}
	return true
}

func (a *auth) headerCSRF(user string) string {
	m := hmac.New(sha256.New, a.hdrKey)
	m.Write([]byte("header-csrf\x00" + user))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// identify strips untrusted identity headers and returns the principal,
// if any. err is a store failure.
func (a *auth) identify(r *http.Request) (*Principal, error) {
	if a.header != "" {
		if a.trustedPeer(r) {
			if v := r.Header.Get(a.header); v != "" && validIdentity(v) {
				return &Principal{User: v, Role: a.cfg.TrustedHeader.Role, Method: "header", CSRF: a.headerCSRF(v)}, nil
			}
		} else {
			r.Header.Del(a.header)
		}
	}
	ck, err := r.Cookie(a.cookieName())
	if err != nil || !validSessionID(ck.Value) {
		return nil, nil
	}
	return a.session(r.Context(), hashID(ck.Value))
}

func validSessionID(v string) bool {
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == sessionIDBytes
}

// session loads and checks a session by its hash.
func (a *auth) session(ctx context.Context, h string) (*Principal, error) {
	s, ok, err := a.st.GetSession(ctx, h)
	if err != nil || !ok {
		return nil, err
	}
	now := a.now()
	if now.Sub(s.LastSeen) > a.cfg.SessionIdle || now.Sub(s.CreatedAt) > a.cfg.SessionMax {
		_ = a.st.DeleteSession(ctx, h)
		return nil, nil
	}
	if now.Sub(s.LastSeen) >= sessionTouchStep {
		if err := a.st.TouchSession(ctx, h, now); err != nil {
			return nil, err
		}
	}
	return &Principal{User: s.Username, Role: RoleAdmin, Method: "session", CSRF: s.CSRF, sessionHash: h}, nil
}

// stillValid re-checks p (long-lived SSE streams).
func (a *auth) stillValid(ctx context.Context, p *Principal) bool {
	if p.Method != "session" {
		return true
	}
	s, ok, err := a.st.GetSession(ctx, p.sessionHash)
	if err != nil || !ok {
		return false
	}
	now := a.now()
	return now.Sub(s.LastSeen) <= a.cfg.SessionIdle && now.Sub(s.CreatedAt) <= a.cfg.SessionMax
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// originOK applies the Origin / Sec-Fetch-Site policy.
func (a *auth) originOK(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	if a.origins[strings.ToLower(o)] {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func jsonContent(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/json")
}

// hasBody reports whether r carries a request body.
func hasBody(r *http.Request) bool {
	return r.ContentLength > 0 || (r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody)
}

// middleware enforces the policy described at the top of the file.
func (a *auth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.identify(r)
		if err != nil {
			a.log.Error("auth: session lookup failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		public := publicPaths[r.URL.Path] && r.URL.RawPath == ""
		if !safeMethod(r.Method) {
			if !a.originOK(r) {
				writeErr(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
			if hasBody(r) && !jsonContent(r) {
				writeErr(w, http.StatusUnsupportedMediaType, "request body must be application/json")
				return
			}
		}
		if p == nil && !public {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if p != nil && !safeMethod(r.Method) && !public {
			got := r.Header.Get(CSRFHeader)
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(p.CSRF)) != 1 {
				writeErr(w, http.StatusForbidden, "missing or invalid CSRF token")
				return
			}
			if p.Role != RoleAdmin {
				writeErr(w, http.StatusForbidden, "read-only access")
				return
			}
		}
		if p != nil {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, p))
		}
		next.ServeHTTP(w, r)
	})
}

// newSession creates a session for user, deleting oldHash (rotation), and
// sets the cookie. It returns the CSRF token.
func (a *auth) newSession(w http.ResponseWriter, r *http.Request, user string) (string, error) {
	if ck, err := r.Cookie(a.cookieName()); err == nil && validSessionID(ck.Value) {
		_ = a.st.DeleteSession(r.Context(), hashID(ck.Value))
	}
	id := randToken(sessionIDBytes)
	csrf := randToken(32)
	now := a.now()
	if err := a.st.CreateSession(r.Context(), store.Session{IDHash: hashID(id), Username: user, CSRF: csrf, CreatedAt: now, LastSeen: now}); err != nil {
		return "", err
	}
	// Opportunistic cleanup of expired rows.
	_, _ = a.st.DeleteExpiredSessions(r.Context(), now.Add(-a.cfg.SessionIdle), now.Add(-a.cfg.SessionMax))
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(), Value: id, Path: "/", HttpOnly: true,
		Secure: !a.cfg.CookieInsecure, SameSite: http.SameSiteStrictMode, MaxAge: int(a.cfg.SessionMax / time.Second)})
	return csrf, nil
}

func (a *auth) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(), Value: "", Path: "/", HttpOnly: true,
		Secure: !a.cfg.CookieInsecure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func validUsername(u string) bool {
	if u == "" || len(u) > maxUsernameLen {
		return false
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '@') {
			return false
		}
	}
	return true
}

func passwordProblem(pw string) string {
	switch {
	case len(pw) < minPasswordLen:
		return "password must be at least " + strconv.Itoa(minPasswordLen) + " characters"
	case len(pw) > maxPasswordLen:
		return "password is too long"
	}
	return ""
}

func (a *auth) locked(w http.ResponseWriter, keys ...string) bool {
	for _, k := range keys {
		if ok, retry := a.thr.allowed(k); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)+1))
			writeErr(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
			return true
		}
	}
	return false
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	_, exists, err := s.st.GetAdmin(r.Context())
	if err != nil {
		s.internal(w, "auth status", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"setup_required": !exists, "authenticated": principalFrom(r.Context()) != nil})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if !decodeJSON(w, r, &req, smallBody) {
		return
	}
	a := s.auth
	ipKey := a.clientKey(r)
	if a.locked(w, ipKey, "setup") {
		return
	}
	a.tokMu.Lock()
	tok := a.setupToken
	a.tokMu.Unlock()
	if tok == "" {
		writeErr(w, http.StatusConflict, "setup is already done")
		return
	}
	if req.Token == "" || subtle.ConstantTimeCompare([]byte(req.Token), []byte(tok)) != 1 {
		a.thr.fail(ipKey)
		a.thr.fail("setup")
		writeErr(w, http.StatusForbidden, "invalid setup token")
		return
	}
	if !validUsername(req.Username) {
		writeErr(w, http.StatusBadRequest, "username must be 1-64 characters of letters, digits and . _ - @")
		return
	}
	if p := passwordProblem(req.Password); p != "" {
		writeErr(w, http.StatusBadRequest, p)
		return
	}
	h, err := a.hasher.Hash(req.Password)
	if err != nil {
		s.internal(w, "setup hash", err)
		return
	}
	if err := s.st.CreateAdmin(r.Context(), req.Username, h, a.now()); err != nil {
		if errors.Is(err, store.ErrAdminExists) {
			writeErr(w, http.StatusConflict, "setup is already done")
			return
		}
		s.internal(w, "setup create", err)
		return
	}
	a.tokMu.Lock()
	a.setupToken = ""
	a.tokMu.Unlock()
	a.thr.success(ipKey)
	csrf, err := a.newSession(w, r, req.Username)
	if err != nil {
		s.internal(w, "setup session", err)
		return
	}
	s.auditAs(r.Context(), "admin:"+req.Username, "created the administrator (first-run setup)")
	writeJSON(w, http.StatusOK, map[string]any{"user": req.Username, "role": RoleAdmin, "csrf_token": csrf})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req, smallBody) {
		return
	}
	a := s.auth
	ipKey := a.clientKey(r)
	userKey := "user:" + strings.ToLower(truncate(req.Username, maxUsernameLen))
	if a.locked(w, ipKey, userKey) {
		return
	}
	adm, exists, err := s.st.GetAdmin(r.Context())
	if err != nil {
		s.internal(w, "login", err)
		return
	}
	ok := false
	if exists && len(req.Username) == len(adm.Username) &&
		subtle.ConstantTimeCompare([]byte(req.Username), []byte(adm.Username)) == 1 {
		ok = a.hasher.Verify(adm.PasswordHash, req.Password)
	} else {
		a.hasher.VerifyDummy(req.Password)
	}
	if !ok {
		a.thr.fail(ipKey)
		a.thr.fail(userKey)
		a.log.Warn("login failed", "client", ipKey)
		writeErr(w, http.StatusUnauthorized, "invalid user name or password")
		return
	}
	a.thr.success(ipKey)
	a.thr.success(userKey)
	csrf, err := a.newSession(w, r, adm.Username)
	if err != nil {
		s.internal(w, "login session", err)
		return
	}
	s.auditAs(r.Context(), "admin:"+adm.Username, "logged in")
	writeJSON(w, http.StatusOK, map[string]any{"user": adm.Username, "role": RoleAdmin, "csrf_token": csrf})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.Method == "session" {
		if err := s.st.DeleteSession(r.Context(), p.sessionHash); err != nil {
			s.internal(w, "logout", err)
			return
		}
	}
	s.auth.clearCookie(w)
	s.audit(r, "logged out")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"user": p.User, "role": p.Role, "method": p.Method, "csrf_token": p.CSRF})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decodeJSON(w, r, &req, smallBody) {
		return
	}
	p := principalFrom(r.Context())
	if p.Method != "session" {
		writeErr(w, http.StatusForbidden, "only the local administrator can change the password")
		return
	}
	a := s.auth
	userKey := "user:" + strings.ToLower(p.User)
	if a.locked(w, userKey) {
		return
	}
	adm, ok, err := s.st.GetAdmin(r.Context())
	if err != nil || !ok {
		s.internal(w, "password", err)
		return
	}
	if !a.hasher.Verify(adm.PasswordHash, req.Current) {
		a.thr.fail(userKey)
		writeErr(w, http.StatusUnauthorized, "current password is wrong")
		return
	}
	if pp := passwordProblem(req.New); pp != "" {
		writeErr(w, http.StatusBadRequest, pp)
		return
	}
	h, err := a.hasher.Hash(req.New)
	if err != nil {
		s.internal(w, "password hash", err)
		return
	}
	if err := s.st.SetAdminPassword(r.Context(), h); err != nil {
		s.internal(w, "password set", err)
		return
	}
	if err := s.st.DeleteAllSessions(r.Context()); err != nil {
		s.internal(w, "password sessions", err)
		return
	}
	csrf, err := a.newSession(w, r, adm.Username)
	if err != nil {
		s.internal(w, "password session", err)
		return
	}
	s.audit(r, "changed the administrator password (all sessions ended)")
	writeJSON(w, http.StatusOK, map[string]any{"csrf_token": csrf})
}
