package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"time"
)

// Web configures the HTTP API's authentication.
type Web struct {
	// CookieInsecure drops the Secure flag from the session cookie, for a
	// plain-http LAN setup. Default false (Secure on).
	CookieInsecure bool `yaml:"cookie_insecure"`
	// SessionIdle ends a session unused this long (default 8h).
	SessionIdle time.Duration `yaml:"session_idle"`
	// SessionMax ends a session this long after login whatever its use
	// (default 168h).
	SessionMax time.Duration `yaml:"session_max"`
	// AllowedOrigins are extra origins (scheme://host[:port]) accepted on
	// state-changing requests besides the request's own Host.
	AllowedOrigins []string `yaml:"allowed_origins"`
	// TrustedHeader is forward-auth (e.g. Authentik behind Traefik).
	TrustedHeader TrustedHeader `yaml:"trusted_header"`
	// TrustedProxies are CIDRs of reverse proxies (Traefik) whose
	// X-Forwarded-For is believed when working out the client address for
	// login throttling, audit and logs. The client is the rightmost
	// X-Forwarded-For address that is not itself a trusted proxy. Empty
	// (default): X-Forwarded-For is ignored and the TCP peer is the client;
	// behind Traefik that makes every client one address, so set it. This is
	// separate from trusted_header.proxies, which only governs identity
	// headers.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// TrustedHeader accepts an identity header, but only from the listed proxy
// networks (the TCP peer address, never X-Forwarded-For). An empty Proxies
// list turns it off.
type TrustedHeader struct {
	// Proxies are CIDRs of the proxies allowed to set UserHeader.
	Proxies []string `yaml:"proxies"`
	// UserHeader carries the authenticated user name (default Remote-User).
	UserHeader string `yaml:"user_header"`
	// Role given to header-authenticated users: admin or viewer
	// (read-only). Default viewer.
	Role string `yaml:"role"`
}

func (w *Web) applyDefaults() {
	if w.SessionIdle == 0 {
		w.SessionIdle = 8 * time.Hour
	}
	if w.SessionMax == 0 {
		w.SessionMax = 7 * 24 * time.Hour
	}
	if w.TrustedHeader.UserHeader == "" {
		w.TrustedHeader.UserHeader = "Remote-User"
	}
	if w.TrustedHeader.Role == "" {
		w.TrustedHeader.Role = "viewer"
	}
}

func validHeaderName(h string) bool {
	if h == "" || len(h) > 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ValidOrigin reports whether o is a bare origin: http or https scheme, a
// host, and nothing else (no path, query, fragment or user info).
func ValidOrigin(o string) bool {
	u, err := url.Parse(o)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" &&
		u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil && u.Opaque == ""
}

func (w *Web) validate() []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if w.SessionIdle < 0 {
		add("web.session_idle must not be negative")
	}
	if w.SessionMax < 0 {
		add("web.session_max must not be negative")
	}
	for _, o := range w.AllowedOrigins {
		if !ValidOrigin(o) {
			add("web.allowed_origins: %q must be scheme://host[:port]", o)
		}
	}
	for _, p := range w.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			add("web.trusted_proxies: %q is not a CIDR", p)
		}
	}
	th := w.TrustedHeader
	for _, p := range th.Proxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			add("web.trusted_header.proxies: %q is not a CIDR", p)
		}
	}
	if !validHeaderName(th.UserHeader) {
		add("web.trusted_header.user_header %q is not a valid header name", th.UserHeader)
	}
	if th.Role != "admin" && th.Role != "viewer" {
		add("web.trusted_header.role %q must be admin or viewer", th.Role)
	}
	return errs
}
