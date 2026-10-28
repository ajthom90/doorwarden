// Package pihole manages Local DNS A/AAAA records on a Pi-hole v6 through its
// REST API (/api/config/dns/hosts, entries of the form "ip hostname").
//
// Limitations, all inherent to Pi-hole's hosts list:
//   - no record IDs (Record.ID is always empty; a non-empty ID on Update is
//     ErrNotFound, on Delete a no-op) and no per-record TTL (TTL false);
//   - no wildcard support: hosts entries are exact names. dnsmasq can do
//     address=/.zone/ip, but Pi-hole's API does not manage such lines, so
//     WildcardA is false. Use a provider with wildcard support, or publish
//     per-app names;
//   - only A and AAAA records (the family is inferred from the IP); CNAMEs live
//     in a separate Pi-hole list and are not handled.
//
// Auth is a session: POST /api/auth with the password yields a session id sent
// as X-FTL-SID. A 401 triggers one transparent re-login. Close deletes the
// session (Pi-hole limits concurrent sessions); the registry has no Close hook
// yet, so callers that know about io.Closer should call it.
package pihole

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/httpx"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

// Type is the registry name.
const Type = "pihole"

var staticCaps = dns.Capabilities{WildcardA: false, MultiZone: true, Update: true, TTL: false}

func init() {
	dns.Register(Type, func(cfg map[string]any, sr dns.SecretResolver) (dns.Provider, error) {
		str := func(k string) string { v, _ := cfg[k].(string); return v }
		flag := func(k string) bool { v, _ := cfg[k].(bool); return v }
		pw, err := dns.ResolveField(cfg, sr, "password")
		if err != nil {
			return nil, fmt.Errorf("pihole: %w", err)
		}
		return New(Config{URL: str("url"), Password: pw,
			InsecureSkipVerify: flag("insecure_skip_verify"), AllowInsecureHTTP: flag("allow_insecure_http")})
	}, dns.ConfigSchema{Fields: []dns.Field{
		{Name: "url", Required: true, Help: "Pi-hole base URL, e.g. http://pihole.lan"},
		{Name: "password", Secret: true, Required: true, Help: "web interface or application password"},
		{Name: "insecure_skip_verify", Help: "skip TLS verification"},
		{Name: "allow_insecure_http", Help: "allow plain http to a non-private host"},
	}}, staticCaps)
}

// Config configures a Provider.
type Config struct {
	URL                string
	Password           secrets.Secret
	InsecureSkipVerify bool
	AllowInsecureHTTP  bool
}

// Provider implements dns.Provider.
type Provider struct {
	c        *httpx.Client
	password secrets.Secret

	mu  sync.Mutex
	sid string
}

// New validates cfg and builds a provider.
func New(cfg Config) (*Provider, error) {
	if err := httpx.CheckURL(cfg.URL, cfg.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("pihole: %w", err)
	}
	if cfg.Password == "" {
		return nil, errors.New("pihole: config field \"password\" is required")
	}
	c, err := httpx.New(cfg.URL, cfg.InsecureSkipVerify, 0)
	if err != nil {
		return nil, fmt.Errorf("pihole: %w", err)
	}
	c.Secrets = []string{cfg.Password.Reveal()}
	return &Provider{c: c, password: cfg.Password}, nil
}

func (p *Provider) Type() string                   { return Type }
func (p *Provider) Capabilities() dns.Capabilities { return staticCaps }

func (p *Provider) mapErr(op string, err error) error {
	var se *httpx.StatusError
	if errors.As(err, &se) {
		switch {
		case se.IsAuth():
			return fmt.Errorf("pihole: %s: authentication failed (status %d); check the password", op, se.Status)
		case se.Status == 429:
			return fmt.Errorf("pihole: %s: rate limited by Pi-hole (status 429); retry later", op)
		}
	}
	return fmt.Errorf("pihole: %s: %w", op, err)
}

func (p *Provider) login(ctx context.Context) error {
	var out struct {
		Session struct {
			Valid   bool   `json:"valid"`
			SID     string `json:"sid"`
			Message string `json:"message"`
		} `json:"session"`
	}
	if _, err := p.c.Do(ctx, "POST", "/api/auth", nil, nil, map[string]string{"password": p.password.Reveal()}, &out); err != nil {
		return p.mapErr("login", err)
	}
	if !out.Session.Valid || out.Session.SID == "" {
		return errors.New("pihole: login failed: password rejected or two-factor authentication is enabled (use an application password)")
	}
	p.mu.Lock()
	p.sid = out.Session.SID
	p.mu.Unlock()
	return nil
}

// do performs an authenticated call, logging in on demand and once more on 401.
func (p *Provider) do(ctx context.Context, op, method, path string, body, out any) error {
	for attempt := 0; ; attempt++ {
		p.mu.Lock()
		sid := p.sid
		p.mu.Unlock()
		if sid == "" {
			if err := p.login(ctx); err != nil {
				return err
			}
			p.mu.Lock()
			sid = p.sid
			p.mu.Unlock()
		}
		_, err := p.c.Do(ctx, method, path, nil, http.Header{"X-Ftl-Sid": {sid}}, body, out)
		var se *httpx.StatusError
		if errors.As(err, &se) && se.Status == 401 && attempt == 0 {
			p.mu.Lock()
			p.sid = ""
			p.mu.Unlock()
			continue
		}
		if err != nil {
			return p.mapErr(op, err)
		}
		return nil
	}
}

// Test logs in and reads the hosts list.
func (p *Provider) Test(ctx context.Context) error {
	_, err := p.hosts(ctx)
	return err
}

// Close ends the Pi-hole session, if any.
func (p *Provider) Close() error {
	p.mu.Lock()
	sid := p.sid
	p.sid = ""
	p.mu.Unlock()
	if sid == "" {
		return nil
	}
	_, err := p.c.Do(context.Background(), "DELETE", "/api/auth", nil, http.Header{"X-Ftl-Sid": {sid}}, nil, nil)
	p.c.Close()
	if err != nil {
		return p.mapErr("logout", err)
	}
	return nil
}

func (p *Provider) hosts(ctx context.Context) ([]dns.Record, error) {
	var out struct {
		Config struct {
			DNS struct {
				Hosts []string `json:"hosts"`
			} `json:"dns"`
		} `json:"config"`
	}
	if err := p.do(ctx, "list hosts", "GET", "/api/config/dns/hosts", nil, &out); err != nil {
		return nil, err
	}
	var recs []dns.Record
	for _, e := range out.Config.DNS.Hosts {
		f := strings.Fields(e)
		if len(f) < 2 {
			continue
		}
		typ := "A"
		if ip, err := netip.ParseAddr(f[0]); err == nil && !ip.Is4() && !ip.Is4In6() {
			typ = "AAAA"
		}
		for _, h := range f[1:] {
			if strings.HasPrefix(h, "#") {
				break
			}
			recs = append(recs, dns.Record{Name: strings.ToLower(h), Type: typ, Value: f[0]})
		}
	}
	return recs, nil
}

func inZone(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }

func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	all, err := p.hosts(ctx)
	if err != nil {
		return nil, err
	}
	var out []dns.Record
	for _, r := range all {
		if inZone(r.Name, zone) {
			out = append(out, r)
		}
	}
	return out, nil
}

func check(r dns.Record) error {
	if r.Type != "A" && r.Type != "AAAA" {
		return fmt.Errorf("pihole: record type %q is not supported (only A and AAAA)", r.Type)
	}
	if strings.HasPrefix(r.Name, "*") {
		return fmt.Errorf("pihole: wildcard record %q is not supported by Pi-hole's hosts list", r.Name)
	}
	if strings.ContainsAny(r.Name, " \t,#/") || r.Name == "" {
		return fmt.Errorf("pihole: invalid host name %q", r.Name)
	}
	ip, err := netip.ParseAddr(r.Value)
	if err != nil {
		return fmt.Errorf("pihole: invalid IP address %q", r.Value)
	}
	if (r.Type == "A") != (ip.Is4() || ip.Is4In6()) {
		return fmt.Errorf("pihole: value %q does not match record type %s", r.Value, r.Type)
	}
	return nil
}

func entryPath(r dns.Record) string {
	return "/api/config/dns/hosts/" + url.PathEscape(r.Value+" "+r.Name)
}

func (p *Provider) CreateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if err := check(r); err != nil {
		return dns.Record{}, err
	}
	all, err := p.hosts(ctx)
	if err != nil {
		return dns.Record{}, err
	}
	for _, e := range all {
		if e.Name == r.Name && e.Type == r.Type {
			if e.Value == r.Value {
				return e, nil
			}
			return dns.Record{}, dns.ErrRecordExists
		}
	}
	if err := p.do(ctx, "create record "+r.Name, "PUT", entryPath(r), nil, nil); err != nil {
		return dns.Record{}, err
	}
	r.TTL = 0
	return r, nil
}

func (p *Provider) UpdateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if r.ID != "" {
		return dns.Record{}, dns.ErrNotFound // pihole never issues record IDs
	}
	if err := check(r); err != nil {
		return dns.Record{}, err
	}
	all, err := p.hosts(ctx)
	if err != nil {
		return dns.Record{}, err
	}
	var old []dns.Record
	for _, e := range all {
		if e.Name == r.Name && e.Type == r.Type {
			old = append(old, e)
		}
	}
	if len(old) == 0 {
		return dns.Record{}, dns.ErrNotFound
	}
	// add the new entry first so the name never disappears, then drop the old ones
	if err := p.do(ctx, "update record "+r.Name, "PUT", entryPath(r), nil, nil); err != nil {
		return dns.Record{}, err
	}
	for _, o := range old {
		if o.Value == r.Value {
			continue
		}
		if err := p.do(ctx, "update record "+r.Name+" (remove old value)", "DELETE", entryPath(o), nil, nil); err != nil {
			return dns.Record{}, fmt.Errorf("%w (the new value was added; the old one may remain)", err)
		}
	}
	r.TTL = 0
	return r, nil
}

func (p *Provider) DeleteRecord(ctx context.Context, zone string, r dns.Record) error {
	if r.ID != "" {
		return nil // never issued: nothing can match
	}
	if err := check(r); err != nil {
		return err
	}
	all, err := p.hosts(ctx)
	if err != nil {
		return err
	}
	for _, e := range all {
		if e.Name == r.Name && e.Type == r.Type && e.Value == r.Value {
			// A 404 here means the name shares a multi-hostname hosts line
			// ("ip a b"); that surfaces as an error rather than a silent no-op.
			return p.do(ctx, "delete record "+r.Name, "DELETE", entryPath(r), nil, nil)
		}
	}
	return nil
}
