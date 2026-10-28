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
	c    *httpx.Client
	auth func() http.Header // builds the Authorization header; the token lives only in this closure

	mu    *sync.Mutex
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
	if cfg.APIToken == "" {
		return nil, errors.New("cloudflare: config field \"api_token\" is required")
	}
	c.AddSecret(cfg.APIToken)
	tok := cfg.APIToken
	return &Provider{c: c, auth: func() http.Header { return http.Header{"Authorization": {"Bearer " + tok.Reveal()}} },
		zones: map[string]string{}, mu: &sync.Mutex{}}, nil
}

func (p *Provider) hdr() http.Header { return p.auth() }

func (p *Provider) Type() string                   { return Type }
func (p *Provider) Capabilities() dns.Capabilities { return staticCaps }

type apiResult struct {
	Success    *bool                      `json:"success"`
	Errors     []struct{ Message string } `json:"errors"`
	ResultInfo *struct {
		TotalPages *int `json:"total_pages"`
	} `json:"result_info"`
}

// ok rejects a 200 that is not an explicit API success.
func (r apiResult) ok() error {
	if r.Success == nil {
		return errors.New("malformed response (no success flag)")
	}
	if !*r.Success {
		msg := "request failed"
		if len(r.Errors) > 0 && r.Errors[0].Message != "" {
			msg = r.Errors[0].Message
		}
		return errors.New(msg)
	}
	return nil
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
		Result *[]struct{ ID, Name string } `json:"result"`
	}
	q := url.Values{"name": {zone}}
	if _, err := p.c.Do(ctx, "GET", "/zones", q, p.hdr(), nil, &out); err != nil {
		return "", p.wrapErr("look up zone "+zone, err)
	}
	if err := out.ok(); err != nil || out.Result == nil {
		return "", fmt.Errorf("cloudflare: look up zone %s: %s", zone, p.c.Scrub(errText(err, out.Result == nil)))
	}
	for _, z := range *out.Result {
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
	if _, err := p.c.Do(ctx, "GET", "/zones", url.Values{"per_page": {"1"}}, p.hdr(), nil, &out); err != nil {
		return p.wrapErr("verify credentials", err)
	}
	if err := out.ok(); err != nil {
		return fmt.Errorf("cloudflare: verify credentials: %s", p.c.Scrub(err.Error()))
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

const perPage = 100

func errText(err error, missing bool) string {
	if err != nil {
		return err.Error()
	}
	if missing {
		return "malformed response (no result)"
	}
	return ""
}

func (p *Provider) list(ctx context.Context, zid string, q url.Values) ([]apiRecord, error) {
	var all []apiRecord
	for page := 1; ; page++ {
		if page > 1000 {
			return nil, errors.New("cloudflare: list records: more than 1000 pages; refusing to continue")
		}
		qq := url.Values{"per_page": {strconv.Itoa(perPage)}, "page": {strconv.Itoa(page)}}
		for k, v := range q {
			qq[k] = v
		}
		var out struct {
			apiResult
			Result *[]apiRecord `json:"result"`
		}
		if _, err := p.c.Do(ctx, "GET", "/zones/"+zid+"/dns_records", qq, p.hdr(), nil, &out); err != nil {
			return nil, p.wrapErr("list records", err)
		}
		if err := out.ok(); err != nil || out.Result == nil {
			return nil, fmt.Errorf("cloudflare: list records: %s", p.c.Scrub(errText(err, out.Result == nil)))
		}
		all = append(all, *out.Result...)
		switch {
		case out.ResultInfo != nil && out.ResultInfo.TotalPages != nil && *out.ResultInfo.TotalPages > 0:
			if page >= *out.ResultInfo.TotalPages {
				return all, nil
			}
		case len(*out.Result) < perPage:
			return all, nil // no paging info, and a short page: the only page
		default:
			return nil, errors.New("cloudflare: list records: full page without result_info.total_pages; cannot tell whether the list is complete")
		}
		if len(*out.Result) == 0 {
			return nil, errors.New("cloudflare: list records: empty page before the reported last page")
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
	found := false
	for _, e := range existing {
		if strings.EqualFold(e.Name, r.Name) && e.Type == r.Type {
			if e.Content == r.Value {
				return fromAPI(e), nil
			}
			found = true
		}
	}
	if found {
		return dns.Record{}, dns.ErrRecordExists
	}
	// a CNAME cannot coexist with other data at the same name
	others := []string{"CNAME"}
	if r.Type == "CNAME" {
		others = []string{"A", "AAAA", "TXT"}
	}
	for _, t := range others {
		o, err := p.list(ctx, zid, url.Values{"name.exact": {r.Name}, "type": {t}})
		if err != nil {
			return dns.Record{}, err
		}
		for _, e := range o {
			if strings.EqualFold(e.Name, r.Name) && e.Type == t {
				return dns.Record{}, fmt.Errorf("cloudflare: %s already has a %s record, which cannot coexist with %s: %w", r.Name, t, r.Type, dns.ErrRecordExists)
			}
		}
	}
	body := map[string]any{"type": r.Type, "name": r.Name, "content": r.Value, "ttl": apiTTL(r.TTL), "proxied": false}
	var out struct {
		apiResult
		Result apiRecord `json:"result"`
	}
	if _, err := p.c.Do(ctx, "POST", "/zones/"+zid+"/dns_records", nil, p.hdr(), body, &out); err != nil {
		return dns.Record{}, p.wrapErr("create record "+r.Name, err)
	}
	if err := out.ok(); err != nil || out.Result.ID == "" {
		return dns.Record{}, fmt.Errorf("cloudflare: create record %s: %s", r.Name, p.c.Scrub(errText(err, out.Result.ID == "")))
	}
	return fromAPI(out.Result), nil
}

// targets finds the stored records an Update/Delete addresses: the one with the
// given ID, or every record matching (name, type).
func (p *Provider) targets(ctx context.Context, zid string, r dns.Record) ([]apiRecord, error) {
	if r.ID != "" {
		var out struct {
			apiResult
			Result *apiRecord `json:"result"`
		}
		_, err := p.c.Do(ctx, "GET", "/zones/"+zid+"/dns_records/"+url.PathEscape(r.ID), nil, p.hdr(), nil, &out)
		var se *httpx.StatusError
		if errors.As(err, &se) && (se.Status == 404 || se.Status == 400) {
			return nil, nil
		}
		if err != nil {
			return nil, p.wrapErr("get record", err)
		}
		if err := out.ok(); err != nil || out.Result == nil {
			return nil, fmt.Errorf("cloudflare: get record: %s", p.c.Scrub(errText(err, out.Result == nil)))
		}
		return []apiRecord{*out.Result}, nil
	}
	recs, err := p.list(ctx, zid, url.Values{"name.exact": {r.Name}, "type": {r.Type}})
	if err != nil {
		return nil, err
	}
	var out []apiRecord
	for _, e := range recs {
		if strings.EqualFold(e.Name, r.Name) && e.Type == r.Type {
			out = append(out, e)
		}
	}
	return out, nil
}

func (p *Provider) UpdateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return dns.Record{}, err
	}
	curs, err := p.targets(ctx, zid, r)
	if err != nil {
		return dns.Record{}, err
	}
	if len(curs) == 0 {
		return dns.Record{}, dns.ErrNotFound
	}
	if len(curs) != 1 {
		return dns.Record{}, fmt.Errorf("cloudflare: %s %s has %d records; refusing to modify values doorwarden does not manage: %w", r.Name, r.Type, len(curs), dns.ErrRecordExists)
	}
	cur := curs[0]
	if !strings.EqualFold(cur.Name, r.Name) || cur.Type != r.Type {
		return dns.Record{}, fmt.Errorf("cloudflare: update of record %s: name/type mismatch with stored record: %w", cur.ID, dns.ErrNotFound)
	}
	body := map[string]any{"content": r.Value, "ttl": apiTTL(r.TTL)}
	var out struct {
		apiResult
		Result apiRecord `json:"result"`
	}
	if _, err := p.c.Do(ctx, "PATCH", "/zones/"+zid+"/dns_records/"+url.PathEscape(cur.ID), nil, p.hdr(), body, &out); err != nil {
		return dns.Record{}, p.wrapErr("update record "+r.Name, err)
	}
	if err := out.ok(); err != nil || out.Result.ID == "" {
		return dns.Record{}, fmt.Errorf("cloudflare: update record %s: %s", r.Name, p.c.Scrub(errText(err, out.Result.ID == "")))
	}
	return fromAPI(out.Result), nil
}

func (p *Provider) DeleteRecord(ctx context.Context, zone string, r dns.Record) error {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	curs, err := p.targets(ctx, zid, r)
	if err != nil {
		return err
	}
	for _, cur := range curs {
		if r.ID != "" {
			// ID wins, but a caller that also names the record must name this one
			if (r.Name != "" && !strings.EqualFold(cur.Name, r.Name)) || (r.Type != "" && cur.Type != r.Type) {
				return fmt.Errorf("cloudflare: delete of record %s: stored record is %s %s, not %s %s; refusing", r.ID, cur.Name, cur.Type, r.Name, r.Type)
			}
		} else if cur.Content != r.Value {
			continue // never delete a record with a different value
		}
		var out apiResult
		_, err := p.c.Do(ctx, "DELETE", "/zones/"+zid+"/dns_records/"+url.PathEscape(cur.ID), nil, p.hdr(), nil, &out)
		var se *httpx.StatusError
		if errors.As(err, &se) && se.Status == 404 {
			continue
		}
		if err != nil {
			return p.wrapErr("delete record "+cur.Name, err)
		}
		if err := out.ok(); err != nil {
			return fmt.Errorf("cloudflare: delete record %s: %s", cur.Name, p.c.Scrub(err.Error()))
		}
	}
	return nil
}

// String, GoString and Format print only the type: a Provider holds no
// secret-bearing value (credentials live in closures, see dns.RedactedFormat),
// and these methods keep a copy of the struct from being dumped field by field.
func (p Provider) String() string             { return "cloudflare.Provider <redacted>" }
func (p Provider) GoString() string           { return "cloudflare.Provider <redacted>" }
func (p Provider) Format(f fmt.State, _ rune) { dns.RedactedFormat(f, "cloudflare.Provider") }
