// Package technitium manages records in Technitium DNS Server zones through its
// HTTP API (/api/zones/records/*). There are no record IDs: records are
// addressed by (name, type[, value]). Supported types for writes: A, AAAA,
// CNAME, TXT; other record types are listed informationally (Value is the raw
// rData JSON). Credentials are either an API token or username/password, from
// which a session token is obtained (and renewed on "invalid-token"). Secrets
// are sent in the POST body, never in the URL.
package technitium

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/httpx"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

// Type is the registry name.
const Type = "technitium"

var staticCaps = dns.Capabilities{WildcardA: true, MultiZone: true, Update: true, TTL: true}

func init() {
	dns.Register(Type, func(cfg map[string]any, sr dns.SecretResolver) (dns.Provider, error) {
		str := func(k string) string { v, _ := cfg[k].(string); return v }
		flag := func(k string) bool { v, _ := cfg[k].(bool); return v }
		c := Config{URL: str("url"), Username: str("username"),
			InsecureSkipVerify: flag("insecure_skip_verify"), AllowInsecureHTTP: flag("allow_insecure_http")}
		if str("token") != "" {
			tok, err := dns.ResolveField(cfg, sr, "token")
			if err != nil {
				return nil, fmt.Errorf("technitium: %w", err)
			}
			c.Token = tok
		}
		if str("password") != "" {
			pw, err := dns.ResolveField(cfg, sr, "password")
			if err != nil {
				return nil, fmt.Errorf("technitium: %w", err)
			}
			c.Password = pw
		}
		return New(c)
	}, dns.ConfigSchema{Fields: []dns.Field{
		{Name: "url", Required: true, Help: "server base URL, e.g. http://dns.lan:5380"},
		{Name: "token", Secret: true, Help: "API token (preferred); or set username and password"},
		{Name: "username", Help: "login user (with password) when no token is set"},
		{Name: "password", Secret: true, Help: "login password"},
		{Name: "insecure_skip_verify", Help: "skip TLS verification"},
		{Name: "allow_insecure_http", Help: "allow plain http to a non-private host"},
	}}, staticCaps)
}

// Config configures a Provider.
type Config struct {
	URL                string
	Token              secrets.Secret
	Username           string
	Password           secrets.Secret
	InsecureSkipVerify bool
	AllowInsecureHTTP  bool
}

// Provider implements dns.Provider.
type Provider struct {
	c        *httpx.Client
	user     string
	password secrets.Secret

	mu    sync.Mutex
	token secrets.Secret
	fixed bool // token configured; cannot re-login
}

// New validates cfg and builds a provider.
func New(cfg Config) (*Provider, error) {
	if err := httpx.CheckURL(cfg.URL, cfg.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("technitium: %w", err)
	}
	if cfg.Token == "" && (cfg.Username == "" || cfg.Password == "") {
		return nil, errors.New("technitium: set either \"token\" or both \"username\" and \"password\"")
	}
	c, err := httpx.New(cfg.URL, cfg.InsecureSkipVerify, 0)
	if err != nil {
		return nil, fmt.Errorf("technitium: %w", err)
	}
	c.Secrets = []string{cfg.Token.Reveal(), cfg.Password.Reveal()}
	return &Provider{c: c, user: cfg.Username, password: cfg.Password, token: cfg.Token, fixed: cfg.Token != ""}, nil
}

func (p *Provider) Type() string                   { return Type }
func (p *Provider) Capabilities() dns.Capabilities { return staticCaps }

type envelope struct {
	Status       string          `json:"status"`
	ErrorMessage string          `json:"errorMessage"`
	Token        string          `json:"token"`
	Response     json.RawMessage `json:"response"`
}

var errInvalidToken = errors.New("invalid token")

func (p *Provider) post(ctx context.Context, path string, form url.Values) (*envelope, error) {
	var env envelope
	if _, err := p.c.Do(ctx, "POST", path, nil, nil, form, &env); err != nil {
		var se *httpx.StatusError
		if errors.As(err, &se) && se.IsAuth() {
			return nil, fmt.Errorf("technitium: authentication failed (status %d); check the token or credentials", se.Status)
		}
		if errors.As(err, &se) && se.Status == 429 {
			return nil, errors.New("technitium: rate limited by the server (status 429); retry later")
		}
		return nil, fmt.Errorf("technitium: %w", err)
	}
	switch env.Status {
	case "ok":
		return &env, nil
	case "invalid-token":
		return nil, errInvalidToken
	}
	msg := p.c.Scrub(env.ErrorMessage)
	if strings.Contains(strings.ToLower(msg), "no such zone") {
		return nil, fmt.Errorf("technitium: zone not found: %s", msg)
	}
	return nil, fmt.Errorf("technitium: server error: %s", msg)
}

func (p *Provider) login(ctx context.Context) error {
	env, err := p.post(ctx, "/api/user/login", url.Values{"user": {p.user}, "pass": {p.password.Reveal()}, "includeInfo": {"false"}})
	if errors.Is(err, errInvalidToken) {
		return errors.New("technitium: login failed: invalid credentials")
	}
	if err != nil {
		return fmt.Errorf("technitium: login failed: %w", err)
	}
	if env.Token == "" {
		return errors.New("technitium: login response carried no token")
	}
	p.mu.Lock()
	p.token = secrets.Secret(env.Token)
	p.mu.Unlock()
	return nil
}

// call performs an authenticated API call, logging in first or again as needed.
func (p *Provider) call(ctx context.Context, path string, form url.Values) (*envelope, error) {
	for attempt := 0; attempt < 2; attempt++ {
		p.mu.Lock()
		tok := p.token
		p.mu.Unlock()
		if tok == "" {
			if err := p.login(ctx); err != nil {
				return nil, err
			}
			p.mu.Lock()
			tok = p.token
			p.mu.Unlock()
		}
		f := url.Values{"token": {tok.Reveal()}}
		for k, v := range form {
			f[k] = v
		}
		env, err := p.post(ctx, path, f)
		if errors.Is(err, errInvalidToken) {
			if p.fixed {
				return nil, errors.New("technitium: the API token was rejected (invalid-token)")
			}
			p.mu.Lock()
			p.token = ""
			p.mu.Unlock()
			continue
		}
		return env, err
	}
	return nil, errors.New("technitium: session token rejected after re-login")
}

// Test verifies the credentials with a cheap zone listing.
func (p *Provider) Test(ctx context.Context) error {
	_, err := p.call(ctx, "/api/zones/list", url.Values{"pageNumber": {"1"}, "zonesPerPage": {"1"}})
	return err
}

type apiRecord struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	TTL      int            `json:"ttl"`
	Disabled bool           `json:"disabled"`
	RData    map[string]any `json:"rData"`
}

func (r apiRecord) record() dns.Record {
	out := dns.Record{Name: strings.ToLower(strings.TrimSuffix(r.Name, ".")), Type: r.Type, TTL: r.TTL}
	str := func(k string) string { v, _ := r.RData[k].(string); return v }
	switch r.Type {
	case "A", "AAAA":
		out.Value = str("ipAddress")
	case "CNAME":
		out.Value = strings.ToLower(strings.TrimSuffix(str("cname"), "."))
	case "TXT":
		out.Value = str("text")
	default:
		b, _ := json.Marshal(r.RData)
		out.Value = string(b)
	}
	return out
}

func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	env, err := p.call(ctx, "/api/zones/records/get", url.Values{"domain": {zone}, "zone": {zone}, "listZone": {"true"}})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Records []apiRecord `json:"records"`
	}
	if err := json.Unmarshal(env.Response, &resp); err != nil {
		return nil, fmt.Errorf("technitium: decode records: %w", err)
	}
	out := make([]dns.Record, 0, len(resp.Records))
	for _, r := range resp.Records {
		if r.Type == "SOA" {
			continue
		}
		out = append(out, r.record())
	}
	return out, nil
}

// valueParams maps a record value to the API's per-type parameter.
func valueParams(typ, val string, isNew bool) (url.Values, error) {
	v := url.Values{}
	switch typ {
	case "A", "AAAA":
		k := "ipAddress"
		if isNew {
			k = "newIpAddress"
		}
		v.Set(k, val)
	case "CNAME":
		v.Set("cname", val)
	case "TXT":
		k := "text"
		if isNew {
			k = "newText"
		}
		v.Set(k, val)
	default:
		return nil, fmt.Errorf("technitium: record type %q is not supported for writes (A, AAAA, CNAME, TXT)", typ)
	}
	return v, nil
}

func (p *Provider) find(ctx context.Context, zone, name, typ string) ([]dns.Record, error) {
	recs, err := p.ListRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []dns.Record
	for _, r := range recs {
		if r.Name == name && r.Type == typ {
			out = append(out, r)
		}
	}
	return out, nil
}

func ttlForm(r dns.Record, f url.Values) {
	if r.TTL > 0 {
		f.Set("ttl", strconv.Itoa(r.TTL))
	}
}

func (p *Provider) CreateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	vp, err := valueParams(r.Type, r.Value, false)
	if err != nil {
		return dns.Record{}, err
	}
	cur, err := p.find(ctx, zone, r.Name, r.Type)
	if err != nil {
		return dns.Record{}, err
	}
	if len(cur) > 0 {
		if len(cur) == 1 && cur[0].Value == r.Value {
			return cur[0], nil
		}
		return dns.Record{}, dns.ErrRecordExists
	}
	f := url.Values{"zone": {zone}, "domain": {r.Name}, "type": {r.Type}, "overwrite": {"false"}}
	for k, v := range vp {
		f[k] = v
	}
	ttlForm(r, f)
	if _, err := p.call(ctx, "/api/zones/records/add", f); err != nil {
		return dns.Record{}, err
	}
	return r, nil
}

func (p *Provider) UpdateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if r.ID != "" {
		return dns.Record{}, dns.ErrNotFound // technitium never issues record IDs
	}
	newP, err := valueParams(r.Type, r.Value, true)
	if err != nil {
		return dns.Record{}, err
	}
	cur, err := p.find(ctx, zone, r.Name, r.Type)
	if err != nil {
		return dns.Record{}, err
	}
	switch len(cur) {
	case 0:
		return dns.Record{}, dns.ErrNotFound
	case 1:
	default:
		return dns.Record{}, fmt.Errorf("technitium: %s %s has %d values; refusing ambiguous update", r.Name, r.Type, len(cur))
	}
	f := url.Values{"zone": {zone}, "domain": {r.Name}, "type": {r.Type}}
	oldP, _ := valueParams(r.Type, cur[0].Value, false)
	for k, v := range oldP {
		f[k] = v
	}
	for k, v := range newP {
		f[k] = v
	}
	if r.Type == "CNAME" { // single-valued: "cname" carries the new target
		f.Set("cname", r.Value)
	}
	ttlForm(r, f)
	if _, err := p.call(ctx, "/api/zones/records/update", f); err != nil {
		return dns.Record{}, err
	}
	return r, nil
}

func (p *Provider) DeleteRecord(ctx context.Context, zone string, r dns.Record) error {
	if r.ID != "" {
		return nil // never issued: nothing can match
	}
	vp, err := valueParams(r.Type, r.Value, false)
	if err != nil {
		return err
	}
	cur, err := p.find(ctx, zone, r.Name, r.Type)
	if err != nil {
		return err
	}
	match := false
	for _, c := range cur {
		if c.Value == r.Value {
			match = true
		}
	}
	if !match {
		return nil // never delete a record with a different value
	}
	f := url.Values{"zone": {zone}, "domain": {r.Name}, "type": {r.Type}}
	for k, v := range vp {
		f[k] = v
	}
	_, err = p.call(ctx, "/api/zones/records/delete", f)
	return err
}
