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
		c := Config{URL: str("url"), Username: str("username")}
		var err error
		if c.InsecureSkipVerify, err = httpx.BoolOption(cfg, "insecure_skip_verify"); err != nil {
			return nil, fmt.Errorf("technitium: %w", err)
		}
		if c.AllowInsecureHTTP, err = httpx.BoolOption(cfg, "allow_insecure_http"); err != nil {
			return nil, fmt.Errorf("technitium: %w", err)
		}
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
	c     *httpx.Client
	user  string
	fixed bool // token configured; cannot re-login

	// credentials are reachable only through these closures
	password   func() secrets.Secret
	getToken   func() secrets.Secret
	setToken   func(secrets.Secret)
	clearToken func(stale secrets.Secret)
	loginMu    *sync.Mutex // single-flight login
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
	c.AddSecret(cfg.Token, cfg.Password)
	get, set, clr := dns.SecretCell(cfg.Token)
	return &Provider{c: c, user: cfg.Username, fixed: cfg.Token != "", password: dns.StaticSecret(cfg.Password),
		getToken: get, setToken: set, clearToken: clr, loginMu: &sync.Mutex{}}, nil
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

// errAmbiguous marks a failure that does not show whether the call was applied.
// Writes turn it into dns.ErrUnconfirmed; reads just report it.
var errAmbiguous = errors.New("outcome unknown")

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
		if !httpx.IsDefinitiveRejection(err) {
			// timeout, cancellation, reset, unparseable body: the call may have been applied
			return nil, fmt.Errorf("technitium: %w: %w", errAmbiguous, err)
		}
		return nil, fmt.Errorf("technitium: %w", err)
	}
	switch env.Status {
	case "ok":
		return &env, nil
	case "invalid-token":
		return nil, errInvalidToken
	case "":
		return nil, fmt.Errorf("technitium: %w: malformed response (no status)", errAmbiguous)
	}
	msg := p.c.Scrub(env.ErrorMessage)
	if strings.Contains(strings.ToLower(msg), "no such zone") {
		return nil, fmt.Errorf("technitium: zone not found: %s", msg)
	}
	return nil, fmt.Errorf("technitium: server error: %s", msg)
}

// login obtains a session token unless another goroutine already did while we
// waited (stale is the token the caller found invalid, or empty).
func (p *Provider) login(ctx context.Context, stale secrets.Secret) error {
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	if cur := p.getToken(); cur != "" && cur != stale {
		return nil
	}
	env, err := p.post(ctx, "/api/user/login", url.Values{"user": {p.user}, "pass": {p.password().Reveal()}, "includeInfo": {"false"}})
	if errors.Is(err, errInvalidToken) {
		return errors.New("technitium: login failed: invalid credentials")
	}
	if err != nil {
		return fmt.Errorf("technitium: login failed: %v", err) // not %w: a failed login never reached the write
	}
	if env.Token == "" {
		return errors.New("technitium: login response carried no token")
	}
	p.c.AddSecret(secrets.Secret(env.Token))
	p.setToken(secrets.Secret(env.Token))
	return nil
}

// call performs an authenticated API call, logging in first or again as needed.
func (p *Provider) call(ctx context.Context, path string, form url.Values) (*envelope, error) {
	for attempt := 0; attempt < 2; attempt++ {
		tok := p.getToken()
		if tok == "" {
			if err := p.login(ctx, ""); err != nil {
				return nil, err
			}
			tok = p.getToken()
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
			p.clearToken(tok)
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
	Comments string         `json:"comments"`
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

func (p *Provider) listRaw(ctx context.Context, zone string) ([]apiRecord, error) {
	env, err := p.call(ctx, "/api/zones/records/get", url.Values{"domain": {zone}, "zone": {zone}, "listZone": {"true"}})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Records *[]apiRecord `json:"records"`
	}
	if len(env.Response) == 0 || json.Unmarshal(env.Response, &resp) != nil || resp.Records == nil {
		return nil, errors.New("technitium: list records: malformed response (no records array)")
	}
	out := make([]apiRecord, 0, len(*resp.Records))
	for _, r := range *resp.Records {
		if r.Type != "SOA" {
			out = append(out, r)
		}
	}
	return out, nil
}

func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	raw, err := p.listRaw(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]dns.Record, 0, len(raw))
	for _, r := range raw {
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

func (p *Provider) find(ctx context.Context, zone, name, typ string) ([]apiRecord, error) {
	recs, err := p.listRaw(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []apiRecord
	for _, r := range recs {
		if rec := r.record(); rec.Name == name && rec.Type == typ {
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
	for _, c := range cur {
		if rec := c.record(); rec.Value == r.Value {
			return rec, nil
		}
	}
	if len(cur) > 0 {
		return dns.Record{}, dns.ErrRecordExists
	}
	// a CNAME cannot coexist with other data at the same name
	others := []string{"CNAME"}
	if r.Type == "CNAME" {
		others = []string{"A", "AAAA", "TXT"}
	}
	for _, t := range others {
		o, err := p.find(ctx, zone, r.Name, t)
		if err != nil {
			return dns.Record{}, err
		}
		if len(o) > 0 {
			return dns.Record{}, fmt.Errorf("technitium: %s already has a %s record, which cannot coexist with %s: %w", r.Name, t, r.Type, dns.ErrRecordExists)
		}
	}
	f := url.Values{"zone": {zone}, "domain": {r.Name}, "type": {r.Type}, "overwrite": {"false"}}
	for k, v := range vp {
		f[k] = v
	}
	ttlForm(r, f)
	if _, err := p.call(ctx, "/api/zones/records/add", f); err != nil {
		if errors.Is(err, errAmbiguous) {
			return r, p.c.Ambiguous("technitium: create record "+r.Name, err)
		}
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
		return dns.Record{}, fmt.Errorf("technitium: %s %s has %d values; refusing to modify values doorwarden does not manage: %w", r.Name, r.Type, len(cur), dns.ErrRecordExists)
	}
	f := url.Values{"zone": {zone}, "domain": {r.Name}, "type": {r.Type}}
	old := cur[0]
	oldP, _ := valueParams(r.Type, old.record().Value, false)
	for k, v := range oldP {
		f[k] = v
	}
	for k, v := range newP {
		f[k] = v
	}
	if r.Type == "CNAME" { // single-valued: "cname" carries the new target
		f.Set("cname", r.Value)
	}
	// always send the ttl (the current one when unspecified) and carry over the
	// fields doorwarden does not manage, so an update resets nothing
	ttl := r.TTL
	if ttl <= 0 {
		ttl = old.TTL
	}
	if ttl > 0 {
		f.Set("ttl", strconv.Itoa(ttl))
	}
	f.Set("disable", strconv.FormatBool(old.Disabled))
	if old.Comments != "" {
		f.Set("comments", old.Comments)
	}
	r.TTL = ttl
	if _, err := p.call(ctx, "/api/zones/records/update", f); err != nil {
		if errors.Is(err, errAmbiguous) {
			return r, p.c.Ambiguous("technitium: update record "+r.Name, err)
		}
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
		if c.record().Value == r.Value {
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
	if errors.Is(err, errAmbiguous) {
		return p.c.Ambiguous("technitium: delete record "+r.Name, err) // keep the ownership row
	}
	return err
}

// String, GoString and Format print only the type: a Provider holds no
// secret-bearing value (credentials live in closures, see dns.RedactedFormat),
// and these methods keep a copy of the struct from being dumped field by field.
func (p Provider) String() string             { return "technitium.Provider <redacted>" }
func (p Provider) GoString() string           { return "technitium.Provider <redacted>" }
func (p Provider) Format(f fmt.State, _ rune) { dns.RedactedFormat(f, "technitium.Provider") }
