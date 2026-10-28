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
//   - only A and AAAA records are writable (the family is inferred from the IP).
//     The user's CNAMEs (dns.cnameRecords, "alias[,alias...],target[,ttl]") are
//     listed read-only and block creating an A/AAAA at the same name;
//   - a hosts line naming several hosts ("ip a b") is never modified.
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
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
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
		pw, err := dns.ResolveField(cfg, sr, "password")
		if err != nil {
			return nil, fmt.Errorf("pihole: %w", err)
		}
		c := Config{URL: str("url"), Password: pw}
		if c.InsecureSkipVerify, err = httpx.BoolOption(cfg, "insecure_skip_verify"); err != nil {
			return nil, fmt.Errorf("pihole: %w", err)
		}
		if c.AllowInsecureHTTP, err = httpx.BoolOption(cfg, "allow_insecure_http"); err != nil {
			return nil, fmt.Errorf("pihole: %w", err)
		}
		return New(c)
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
	c *httpx.Client

	// credentials are reachable only through these closures
	password func() secrets.Secret
	getSID   func() secrets.Secret
	setSID   func(secrets.Secret)
	clearSID func(stale secrets.Secret)
	loginMu  *sync.Mutex // single-flight login: no concurrent sessions leak
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
	c.AddSecret(cfg.Password)
	get, set, clr := dns.SecretCell("")
	return &Provider{c: c, password: dns.StaticSecret(cfg.Password), getSID: get, setSID: set, clearSID: clr, loginMu: &sync.Mutex{}}, nil
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

// login establishes a session unless another goroutine already did while we
// waited (stale is the session id the caller found invalid, or empty).
func (p *Provider) login(ctx context.Context, stale secrets.Secret) error {
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	if cur := p.getSID(); cur != "" && cur != stale {
		return nil
	}
	var out struct {
		Session struct {
			Valid   bool   `json:"valid"`
			SID     string `json:"sid"`
			Message string `json:"message"`
		} `json:"session"`
	}
	if _, err := p.c.Do(ctx, "POST", "/api/auth", nil, nil, map[string]string{"password": p.password().Reveal()}, &out); err != nil {
		return p.mapErr("login", err)
	}
	if !out.Session.Valid || out.Session.SID == "" {
		return errors.New("pihole: login failed: password rejected or two-factor authentication is enabled (use an application password)")
	}
	p.setSID(secrets.Secret(out.Session.SID))
	p.c.AddSecret(secrets.Secret(out.Session.SID))
	return nil
}

// do performs an authenticated call, logging in on demand and once more on 401.
func (p *Provider) do(ctx context.Context, op, method, path string, body, out any) error {
	for attempt := 0; ; attempt++ {
		sid := p.getSID()
		if sid == "" {
			if err := p.login(ctx, ""); err != nil {
				return err
			}
			sid = p.getSID()
		}
		_, err := p.c.Do(ctx, method, path, nil, http.Header{"X-Ftl-Sid": {sid.Reveal()}}, body, out)
		var se *httpx.StatusError
		if errors.As(err, &se) && se.Status == 401 && attempt == 0 {
			p.clearSID(sid)
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

var _ io.Closer = (*Provider)(nil)

// Close ends the Pi-hole session, if any. The dns registry has no lifecycle
// hook, so whoever owns the Provider should call it when it implements
// io.Closer (Pi-hole limits concurrent sessions).
func (p *Provider) Close() error {
	sid := p.getSID()
	p.clearSID(sid)
	if sid == "" {
		return nil
	}
	_, err := p.c.Do(context.Background(), "DELETE", "/api/auth", nil, http.Header{"X-Ftl-Sid": {sid.Reveal()}}, nil, nil)
	p.c.Close()
	if err != nil {
		return p.mapErr("logout", err)
	}
	return nil
}

// hostRec is a listed hosts entry; shared marks a line that names several hosts.
type hostRec struct {
	dns.Record
	shared bool
}

func (p *Provider) hosts(ctx context.Context) ([]hostRec, error) {
	var out struct {
		Config *struct {
			DNS *struct {
				Hosts *[]string `json:"hosts"`
			} `json:"dns"`
		} `json:"config"`
	}
	if err := p.do(ctx, "list hosts", "GET", "/api/config/dns/hosts", nil, &out); err != nil {
		return nil, err
	}
	if out.Config == nil || out.Config.DNS == nil || out.Config.DNS.Hosts == nil {
		return nil, errors.New("pihole: list hosts: malformed response (no config.dns.hosts)")
	}
	var recs []hostRec
	for _, e := range *out.Config.DNS.Hosts {
		f := strings.Fields(e)
		if len(f) < 2 {
			continue
		}
		typ := "A"
		if ip, err := netip.ParseAddr(f[0]); err == nil && !ip.Is4() && !ip.Is4In6() {
			typ = "AAAA"
		}
		var names []string
		for _, h := range f[1:] {
			if strings.HasPrefix(h, "#") {
				break
			}
			names = append(names, h)
		}
		for _, h := range names {
			recs = append(recs, hostRec{Record: dns.Record{Name: strings.ToLower(h), Type: typ, Value: f[0]}, shared: len(names) > 1})
		}
	}
	return recs, nil
}

// cnames reads Pi-hole's CNAME list ("alias,target[,ttl]") as read-only records.
func (p *Provider) cnames(ctx context.Context) ([]dns.Record, error) {
	var out struct {
		Config *struct {
			DNS *struct {
				CNAMEs *[]string `json:"cnameRecords"`
			} `json:"dns"`
		} `json:"config"`
	}
	if err := p.do(ctx, "list cname records", "GET", "/api/config/dns/cnameRecords", nil, &out); err != nil {
		return nil, err
	}
	if out.Config == nil || out.Config.DNS == nil || out.Config.DNS.CNAMEs == nil {
		return nil, errors.New("pihole: list cname records: malformed response (no config.dns.cnameRecords)")
	}
	var recs []dns.Record
	for _, e := range *out.Config.DNS.CNAMEs {
		rs, err := parseCNAME(e)
		if err != nil {
			return nil, fmt.Errorf("pihole: list cname records: %w", err)
		}
		recs = append(recs, rs...)
	}
	return recs, nil
}

// parseCNAME reads "alias[,alias...],target[,ttl]": a final whole-number field
// is the TTL, the field before it (or the last field when it is not numeric)
// is the target, and every earlier field is an alias; each alias is its own
// record.
func parseCNAME(entry string) ([]dns.Record, error) {
	f := strings.Split(entry, ",")
	for i := range f {
		f[i] = strings.ToLower(strings.TrimSpace(f[i]))
		if f[i] == "" {
			return nil, fmt.Errorf("unparseable entry %q (empty field)", entry)
		}
	}
	ttl := 0
	last := f[len(f)-1]
	// a final field is a TTL only when it is a plain non-negative integer and
	// something precedes the alias and target; "30s", "5m" and "3com" are valid
	// single-label host names, so they are targets
	if len(f) >= 3 && isWholeNumber(last) {
		n, err := strconv.Atoi(last)
		if err != nil {
			return nil, fmt.Errorf("unparseable entry %q (bad TTL)", entry)
		}
		ttl = n
		f = f[:len(f)-1]
	}
	if len(f) < 2 {
		return nil, fmt.Errorf("unparseable entry %q (need alias and target)", entry)
	}
	target := f[len(f)-1]
	if !validHostname(target) {
		return nil, fmt.Errorf("unparseable entry %q (target %q is not a host name; a TTL must be a plain non-negative integer)", entry, target)
	}
	var out []dns.Record
	for _, alias := range f[:len(f)-1] {
		out = append(out, dns.Record{Name: alias, Type: "CNAME", Value: target, TTL: ttl})
	}
	return out, nil
}

// validHostname reports whether s can be a DNS host name: letters, digits,
// '.', '_' and '-', not starting with '-' or '.'. Signed numbers such as "-1"
// or "+5" are therefore not host names.
func validHostname(s string) bool {
	if s == "" || s[0] == '-' || s[0] == '.' {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func isWholeNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func inZone(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }

func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	all, err := p.hosts(ctx)
	if err != nil {
		return nil, err
	}
	cn, err := p.cnames(ctx)
	if err != nil {
		return nil, err
	}
	var out []dns.Record
	for _, r := range all {
		if inZone(r.Name, zone) {
			out = append(out, r.Record)
		}
	}
	for _, r := range cn {
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
	cn, err := p.cnames(ctx)
	if err != nil {
		return dns.Record{}, err
	}
	for _, c := range cn {
		if c.Name == r.Name {
			return dns.Record{}, fmt.Errorf("pihole: %s is already a CNAME; cannot add an %s record: %w", r.Name, r.Type, dns.ErrRecordExists)
		}
	}
	exists := false
	for _, e := range all {
		if e.Name == r.Name && e.Type == r.Type {
			if e.Value == r.Value {
				return e.Record, nil
			}
			exists = true
		}
	}
	if exists {
		return dns.Record{}, dns.ErrRecordExists
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
	var old []hostRec
	for _, e := range all {
		if e.Name == r.Name && e.Type == r.Type {
			old = append(old, e)
		}
	}
	if len(old) == 0 {
		return dns.Record{}, dns.ErrNotFound
	}
	if len(old) != 1 {
		return dns.Record{}, fmt.Errorf("pihole: %s %s has %d entries; refusing to modify values doorwarden does not manage: %w", r.Name, r.Type, len(old), dns.ErrRecordExists)
	}
	if old[0].Value == r.Value {
		r.TTL = 0
		return r, nil // already the requested value: nothing to edit, even on a shared line
	}
	if old[0].shared {
		return dns.Record{}, fmt.Errorf("pihole: %s is on a hosts line naming several hosts; refusing to edit it: %w", r.Name, dns.ErrRecordExists)
	}
	// add the new entry first so the name never disappears, then drop the old ones
	if err := p.do(ctx, "update record "+r.Name, "PUT", entryPath(r), nil, nil); err != nil {
		return dns.Record{}, err
	}
	for _, o := range old {
		if o.Value == r.Value {
			continue
		}
		if err := p.do(ctx, "update record "+r.Name+" (remove old value)", "DELETE", entryPath(o.Record), nil, nil); err != nil {
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
			if e.shared {
				return fmt.Errorf("pihole: %s is on a hosts line naming several hosts; refusing to edit it: %w", r.Name, dns.ErrRecordExists)
			}
			return p.do(ctx, "delete record "+r.Name, "DELETE", entryPath(r), nil, nil)
		}
	}
	return nil
}

// String, GoString and Format print only the type: a Provider holds no
// secret-bearing value (credentials live in closures, see dns.RedactedFormat),
// and these methods keep a copy of the struct from being dumped field by field.
func (p Provider) String() string             { return "pihole.Provider <redacted>" }
func (p Provider) GoString() string           { return "pihole.Provider <redacted>" }
func (p Provider) Format(f fmt.State, _ rune) { dns.RedactedFormat(f, "pihole.Provider") }
