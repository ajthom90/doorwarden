// Package cloudflare is the Cloudflare DNS provider.
//
// It talks to the Cloudflare v4 REST API directly rather than through
// libdns/cloudflare: libdns exposes record-set semantics (SetRecords /
// DeleteRecords by value, no stable record IDs, no endpoint override), while
// the dns.Provider contract needs provider record IDs for Update/Delete and a
// test seam for the conformance suite. Records are never proxied.
package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/httpx"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

// Type is the registry name.
const Type = "cloudflare"

// DefaultAPI is the Cloudflare v4 API base URL.
const DefaultAPI = "https://api.cloudflare.com/client/v4"

var staticCaps = dns.Capabilities{WildcardA: true, MultiZone: true, Update: true, TTL: true}

func init() {
	dns.Register(Type, func(cfg map[string]any, sr dns.SecretResolver) (dns.Provider, error) {
		tok, err := dns.ResolveField(cfg, sr, "api_token")
		if err != nil {
			return nil, fmt.Errorf("cloudflare: %w", err)
		}
		// The endpoint is fixed: a user-configurable URL would let a config
		// edit send the bearer token to any host.
		if _, present := cfg["api_url"]; present {
			return nil, errors.New("cloudflare: config field \"api_url\" is not supported (the API endpoint is fixed)")
		}
		return New(Config{APIToken: tok})
	}, dns.ConfigSchema{Fields: []dns.Field{
		{Name: "api_token", Secret: true, Required: true, Help: "API token with Zone:Read and DNS:Edit on the zones"},
	}}, staticCaps)
}

// Config configures a Provider.
type Config struct {
	APIToken secrets.Secret
	// BaseURL overrides the API endpoint. Go-level test seam only; it is
	// deliberately not reachable from user config.
	BaseURL string
}

// Provider implements dns.Provider.
type Provider struct {
	c *httpx.Client
	h http.Header

	mu    sync.Mutex
	zones map[string]string // zone name -> id
}

// New builds a provider.
func New(cfg Config) (*Provider, error) {
	base := cfg.BaseURL
	if base == "" {
		base = DefaultAPI
	}
	c, err := httpx.New(base, false, 0)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: %w", err)
	}
	tok := cfg.APIToken.Reveal()
	if tok == "" {
		return nil, errors.New("cloudflare: config field \"api_token\" is required")
	}
	c.Secrets = []string{tok}
	return &Provider{c: c, h: http.Header{"Authorization": {"Bearer " + tok}}, zones: map[string]string{}}, nil
}

func (p *Provider) Type() string                   { return Type }
func (p *Provider) Capabilities() dns.Capabilities { return staticCaps }

type apiResult struct {
	Success    bool                       `json:"success"`
	Errors     []struct{ Message string } `json:"errors"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type apiRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

func (p *Provider) wrapErr(op string, err error) error {
	var se *httpx.StatusError
	if errors.As(err, &se) {
		switch {
		case se.IsAuth():
			return fmt.Errorf("cloudflare: %s: authentication failed (status %d); check that api_token is valid and has Zone:Read and DNS:Edit", op, se.Status)
		case se.Status == 429:
			return fmt.Errorf("cloudflare: %s: rate limited by the API (status 429); retry later", op)
		}
		return fmt.Errorf("cloudflare: %s: %w", op, se)
	}
	return fmt.Errorf("cloudflare: %s: %w", op, err)
}

// zoneID resolves a zone name to its ID.
func (p *Provider) zoneID(ctx context.Context, zone string) (string, error) {
	p.mu.Lock()
	id, ok := p.zones[zone]
	p.mu.Unlock()
	if ok {
		return id, nil
	}
	var out struct {
		apiResult
		Result []struct{ ID, Name string } `json:"result"`
	}
	q := url.Values{"name": {zone}}
	if _, err := p.c.Do(ctx, "GET", "/zones", q, p.h, nil, &out); err != nil {
		return "", p.wrapErr("look up zone "+zone, err)
	}
	for _, z := range out.Result {
		if strings.EqualFold(z.Name, zone) {
			p.mu.Lock()
			p.zones[zone] = z.ID
			p.mu.Unlock()
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare: zone %q not found (does the token have access to it?)", zone)
}

// Test verifies the token can read zones.
func (p *Provider) Test(ctx context.Context) error {
	var out apiResult
	if _, err := p.c.Do(ctx, "GET", "/zones", url.Values{"per_page": {"1"}}, p.h, nil, &out); err != nil {
		return p.wrapErr("verify credentials", err)
	}
	return nil
}

func fromAPI(r apiRecord) dns.Record {
	ttl := r.TTL
	if ttl == 1 { // automatic
		ttl = 0
	}
	return dns.Record{ID: r.ID, Name: strings.ToLower(strings.TrimSuffix(r.Name, ".")), Type: r.Type, Value: r.Content, TTL: ttl}
}

func apiTTL(ttl int) int {
	if ttl <= 0 {
		return 1
	}
	return ttl
}

func (p *Provider) list(ctx context.Context, zid string, q url.Values) ([]apiRecord, error) {
	var all []apiRecord
	for page := 1; ; page++ {
		qq := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		for k, v := range q {
			qq[k] = v
		}
		var out struct {
			apiResult
			Result []apiRecord `json:"result"`
		}
		if _, err := p.c.Do(ctx, "GET", "/zones/"+zid+"/dns_records", qq, p.h, nil, &out); err != nil {
			return nil, p.wrapErr("list records", err)
		}
		all = append(all, out.Result...)
		if page >= out.ResultInfo.TotalPages || len(out.Result) == 0 {
			return all, nil
		}
	}
}

func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	recs, err := p.list(ctx, zid, nil)
	if err != nil {
		return nil, err
	}
	out := make([]dns.Record, 0, len(recs))
	for _, r := range recs {
		out = append(out, fromAPI(r))
	}
	return out, nil
}

func (p *Provider) CreateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return dns.Record{}, err
	}
	existing, err := p.list(ctx, zid, url.Values{"name.exact": {r.Name}, "type": {r.Type}})
	if err != nil {
		return dns.Record{}, err
	}
	for _, e := range existing {
		if strings.EqualFold(e.Name, r.Name) && e.Type == r.Type {
			if e.Content == r.Value {
				return fromAPI(e), nil
			}
			return dns.Record{}, dns.ErrRecordExists
		}
	}
	body := map[string]any{"type": r.Type, "name": r.Name, "content": r.Value, "ttl": apiTTL(r.TTL), "proxied": false}
	var out struct {
		apiResult
		Result apiRecord `json:"result"`
	}
	if _, err := p.c.Do(ctx, "POST", "/zones/"+zid+"/dns_records", nil, p.h, body, &out); err != nil {
		return dns.Record{}, p.wrapErr("create record "+r.Name, err)
	}
	return fromAPI(out.Result), nil
}

// target finds the stored record an Update/Delete addresses.
func (p *Provider) target(ctx context.Context, zid string, r dns.Record) (apiRecord, bool, error) {
	if r.ID != "" {
		var out struct {
			apiResult
			Result apiRecord `json:"result"`
		}
		_, err := p.c.Do(ctx, "GET", "/zones/"+zid+"/dns_records/"+url.PathEscape(r.ID), nil, p.h, nil, &out)
		var se *httpx.StatusError
		if errors.As(err, &se) && (se.Status == 404 || se.Status == 400) {
			return apiRecord{}, false, nil
		}
		if err != nil {
			return apiRecord{}, false, p.wrapErr("get record", err)
		}
		return out.Result, true, nil
	}
	recs, err := p.list(ctx, zid, url.Values{"name.exact": {r.Name}, "type": {r.Type}})
	if err != nil {
		return apiRecord{}, false, err
	}
	for _, e := range recs {
		if strings.EqualFold(e.Name, r.Name) && e.Type == r.Type {
			return e, true, nil
		}
	}
	return apiRecord{}, false, nil
}

func (p *Provider) UpdateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return dns.Record{}, err
	}
	cur, ok, err := p.target(ctx, zid, r)
	if err != nil {
		return dns.Record{}, err
	}
	if !ok {
		return dns.Record{}, dns.ErrNotFound
	}
	if !strings.EqualFold(cur.Name, r.Name) || cur.Type != r.Type {
		return dns.Record{}, fmt.Errorf("cloudflare: update of record %s: name/type mismatch with stored record: %w", cur.ID, dns.ErrNotFound)
	}
	body := map[string]any{"content": r.Value, "ttl": apiTTL(r.TTL)}
	var out struct {
		apiResult
		Result apiRecord `json:"result"`
	}
	if _, err := p.c.Do(ctx, "PATCH", "/zones/"+zid+"/dns_records/"+url.PathEscape(cur.ID), nil, p.h, body, &out); err != nil {
		return dns.Record{}, p.wrapErr("update record "+r.Name, err)
	}
	return fromAPI(out.Result), nil
}

func (p *Provider) DeleteRecord(ctx context.Context, zone string, r dns.Record) error {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	cur, ok, err := p.target(ctx, zid, r)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if r.ID == "" && cur.Content != r.Value {
		return nil // never delete a record with a different value
	}
	_, err = p.c.Do(ctx, "DELETE", "/zones/"+zid+"/dns_records/"+url.PathEscape(cur.ID), nil, p.h, nil, nil)
	var se *httpx.StatusError
	if errors.As(err, &se) && se.Status == 404 {
		return nil
	}
	if err != nil {
		return p.wrapErr("delete record "+cur.Name, err)
	}
	return nil
}
