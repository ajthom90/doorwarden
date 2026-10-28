// Package adguard manages DNS rewrites on AdGuard Home (/control/rewrite/*),
// authenticated with HTTP basic auth.
//
// A rewrite maps a domain to an answer; the record type is inferred from the
// answer: an IPv4 address is A, an IPv6 address AAAA, anything else CNAME.
// Wildcard rewrites ("*.zone") are supported. There are no record IDs and no
// per-record TTL: records are addressed by (name, type[, value]). Update uses
// /control/rewrite/update (AdGuard Home >= 0.107.41) and falls back to
// delete-then-add on older servers.
package adguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/httpx"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

// Type is the registry name.
const Type = "adguard"

var staticCaps = dns.Capabilities{WildcardA: true, MultiZone: true, Update: true, TTL: false}

func init() {
	dns.Register(Type, func(cfg map[string]any, sr dns.SecretResolver) (dns.Provider, error) {
		str := func(k string) string { v, _ := cfg[k].(string); return v }
		pw, err := dns.ResolveField(cfg, sr, "password")
		if err != nil {
			return nil, fmt.Errorf("adguard: %w", err)
		}
		c := Config{URL: str("url"), Username: str("username"), Password: pw}
		if c.InsecureSkipVerify, err = httpx.BoolOption(cfg, "insecure_skip_verify"); err != nil {
			return nil, fmt.Errorf("adguard: %w", err)
		}
		if c.AllowInsecureHTTP, err = httpx.BoolOption(cfg, "allow_insecure_http"); err != nil {
			return nil, fmt.Errorf("adguard: %w", err)
		}
		return New(c)
	}, dns.ConfigSchema{Fields: []dns.Field{
		{Name: "url", Required: true, Help: "AdGuard Home base URL, e.g. http://adguard.lan:3000"},
		{Name: "username", Required: true, Help: "basic-auth user"},
		{Name: "password", Secret: true, Required: true, Help: "basic-auth password"},
		{Name: "insecure_skip_verify", Help: "skip TLS verification"},
		{Name: "allow_insecure_http", Help: "allow plain http to a non-private host"},
	}}, staticCaps)
}

// Config configures a Provider.
type Config struct {
	URL                string
	Username           string
	Password           secrets.Secret
	InsecureSkipVerify bool
	AllowInsecureHTTP  bool
}

// Provider implements dns.Provider.
type Provider struct {
	c    *httpx.Client
	auth secrets.Secret // base64 user:password
}

// New validates cfg and builds a provider.
func New(cfg Config) (*Provider, error) {
	if err := httpx.CheckURL(cfg.URL, cfg.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("adguard: %w", err)
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("adguard: config fields \"username\" and \"password\" are required")
	}
	c, err := httpx.New(cfg.URL, cfg.InsecureSkipVerify, 0)
	if err != nil {
		return nil, fmt.Errorf("adguard: %w", err)
	}
	tok := secrets.Secret(base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password.Reveal())))
	c.Secrets = []secrets.Secret{cfg.Password, tok}
	return &Provider{c: c, auth: tok}, nil
}

func (p *Provider) hdr() http.Header {
	return http.Header{"Authorization": {"Basic " + p.auth.Reveal()}}
}

func (p *Provider) Type() string                   { return Type }
func (p *Provider) Capabilities() dns.Capabilities { return staticCaps }

func (p *Provider) mapErr(op string, err error) error {
	var se *httpx.StatusError
	if errors.As(err, &se) {
		switch {
		case se.IsAuth():
			return fmt.Errorf("adguard: %s: authentication failed (status %d); check username and password", op, se.Status)
		case se.Status == 429:
			return fmt.Errorf("adguard: %s: rate limited (status 429); retry later", op)
		}
	}
	return fmt.Errorf("adguard: %s: %w", op, err)
}

type rewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

func typeOf(answer string) string {
	if ip, err := netip.ParseAddr(answer); err == nil {
		if ip.Is4() || ip.Is4In6() {
			return "A"
		}
		return "AAAA"
	}
	if answer == "A" || answer == "AAAA" {
		return "KEEP" // AdGuard's "pass through the real answer" markers; not a CNAME
	}
	return "CNAME"
}

// entry pairs a listed record with the exact rewrite strings the server holds;
// those raw strings (not the normalised record) are what Delete/Update send.
type entry struct {
	rec dns.Record
	raw rewrite
}

func (rw rewrite) entry() entry {
	v := rw.Answer
	t := typeOf(v)
	if t == "CNAME" {
		v = strings.ToLower(strings.TrimSuffix(v, "."))
	}
	return entry{rec: dns.Record{Name: strings.ToLower(strings.TrimSuffix(rw.Domain, ".")), Type: t, Value: v}, raw: rw}
}

func (p *Provider) Test(ctx context.Context) error {
	if _, err := p.c.Do(ctx, "GET", "/control/status", nil, p.hdr(), nil, nil); err != nil {
		return p.mapErr("verify credentials", err)
	}
	return nil
}

func (p *Provider) list(ctx context.Context) ([]entry, error) {
	var body json.RawMessage
	if _, err := p.c.Do(ctx, "GET", "/control/rewrite/list", nil, p.hdr(), nil, &body); err != nil {
		return nil, p.mapErr("list rewrites", err)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("adguard: list rewrites: empty response")
	}
	var rws []rewrite
	if err := json.Unmarshal(body, &rws); err != nil { // a JSON null is a legitimately empty list
		return nil, fmt.Errorf("adguard: list rewrites: malformed response: %w", err)
	}
	out := make([]entry, 0, len(rws))
	for _, rw := range rws {
		if rw.Domain == "" || rw.Answer == "" {
			return nil, errors.New("adguard: list rewrites: entry without domain or answer")
		}
		out = append(out, rw.entry())
	}
	return out, nil
}

func inZone(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }

func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	all, err := p.list(ctx)
	if err != nil {
		return nil, err
	}
	var out []dns.Record
	for _, e := range all {
		if inZone(e.rec.Name, zone) {
			out = append(out, e.rec)
		}
	}
	return out, nil
}

func check(r dns.Record) error {
	switch r.Type {
	case "A", "AAAA", "CNAME":
	default:
		return fmt.Errorf("adguard: record type %q is not supported for writes (A, AAAA, CNAME)", r.Type)
	}
	if r.Name == "" || strings.ContainsAny(r.Name, " \t") || r.Value == "" {
		return fmt.Errorf("adguard: invalid record %q", r.Name)
	}
	if typeOf(r.Value) != r.Type {
		return fmt.Errorf("adguard: value does not look like a %s answer", r.Type)
	}
	return nil
}

func (p *Provider) post(ctx context.Context, op, path string, body any) error {
	if _, err := p.c.Do(ctx, "POST", path, nil, p.hdr(), body, nil); err != nil {
		return p.mapErr(op, err)
	}
	return nil
}

func matching(all []entry, r dns.Record) []entry {
	var out []entry
	for _, e := range all {
		if e.rec.Name == r.Name && e.rec.Type == r.Type {
			out = append(out, e)
		}
	}
	return out
}

func (p *Provider) CreateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if err := check(r); err != nil {
		return dns.Record{}, err
	}
	all, err := p.list(ctx)
	if err != nil {
		return dns.Record{}, err
	}
	cur := matching(all, r)
	for _, e := range cur {
		if e.rec.Value == r.Value {
			return e.rec, nil
		}
	}
	if len(cur) > 0 {
		return dns.Record{}, dns.ErrRecordExists
	}
	if err := p.post(ctx, "create rewrite "+r.Name, "/control/rewrite/add", rewrite{r.Name, r.Value}); err != nil {
		return dns.Record{}, err
	}
	r.TTL = 0
	return r, nil
}

func (p *Provider) UpdateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if r.ID != "" {
		return dns.Record{}, dns.ErrNotFound // adguard never issues record IDs
	}
	if err := check(r); err != nil {
		return dns.Record{}, err
	}
	all, err := p.list(ctx)
	if err != nil {
		return dns.Record{}, err
	}
	old := matching(all, r)
	switch len(old) {
	case 0:
		return dns.Record{}, dns.ErrNotFound
	case 1:
	default:
		return dns.Record{}, fmt.Errorf("adguard: %s %s has %d values; refusing to modify values doorwarden does not manage: %w", r.Name, r.Type, len(old), dns.ErrRecordExists)
	}
	body := map[string]rewrite{"target": old[0].raw, "update": {r.Name, r.Value}}
	_, err = p.c.Do(ctx, "PUT", "/control/rewrite/update", nil, p.hdr(), body, nil)
	var se *httpx.StatusError
	if errors.As(err, &se) && (se.Status == 404 || se.Status == 405) {
		// older server without /update: add the new answer first, then drop the old
		if err := p.post(ctx, "update rewrite "+r.Name, "/control/rewrite/add", rewrite{r.Name, r.Value}); err != nil {
			return dns.Record{}, err
		}
		if err := p.post(ctx, "update rewrite "+r.Name+" (remove old)", "/control/rewrite/delete", old[0].raw); err != nil {
			return dns.Record{}, err
		}
		err = nil
	}
	if err != nil {
		return dns.Record{}, p.mapErr("update rewrite "+r.Name, err)
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
	all, err := p.list(ctx)
	if err != nil {
		return err
	}
	for _, e := range matching(all, r) {
		if e.rec.Value == r.Value {
			return p.post(ctx, "delete rewrite "+r.Name, "/control/rewrite/delete", e.raw)
		}
	}
	return nil
}

// String and GoString keep credentials out of any formatted output of the
// provider (unexported struct fields are printed raw by fmt, bypassing the
// redaction of secrets.Secret).
func (p *Provider) String() string   { return "adguard.Provider" }
func (p *Provider) GoString() string { return "adguard.Provider" }
