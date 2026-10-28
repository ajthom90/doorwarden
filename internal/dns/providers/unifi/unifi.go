// Package unifi manages DNS records on a UniFi gateway through the Network
// application's Integration API ("DNS policies").
//
// Records are policies of type A_RECORD (supported for writes), plus any other
// policy type, which ListRecords returns informationally with its policy type
// as Record.Type (CNAME_RECORD is reported as "CNAME", AAAA_RECORD as "AAAA",
// anything else, such as FORWARD_DOMAIN, under its raw policy type) so the
// planner sees foreign records of every kind. Ownership lives in doorwarden's
// database; the API cannot tell doorwarden's own policies from a user's, so
// nothing is filtered by metadata.origin.
//
// The policy list and the site list were checked read-only against a real
// gateway. Create/update/delete were NOT exercised live; their verbs and bodies
// follow the documented REST shape (POST collection, PUT/DELETE item).
//
// Wildcards: the controller may reject "*.zone" domains, so wildcard A records
// are off unless the admin sets "wildcard: true" after confirming their
// controller version accepts them. The static capability is therefore declared
// as an upper bound (true) and instances narrow it (see Capabilities).
package unifi

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
const Type = "unifi"

var staticCaps = dns.Capabilities{WildcardA: true, MultiZone: true, Update: true, TTL: true}

const apiRoot = "/proxy/network/integration/v1"

func init() {
	dns.Register(Type, func(cfg map[string]any, sr dns.SecretResolver) (dns.Provider, error) {
		str := func(k string) string { v, _ := cfg[k].(string); return v }
		key, err := dns.ResolveField(cfg, sr, "api_key")
		if err != nil {
			return nil, fmt.Errorf("unifi: %w", err)
		}
		c := Config{URL: str("url"), APIKey: key, SiteID: str("site_id")}
		if c.InsecureSkipVerify, err = httpx.BoolOption(cfg, "insecure_skip_verify"); err != nil {
			return nil, fmt.Errorf("unifi: %w", err)
		}
		if c.Wildcard, err = httpx.BoolOption(cfg, "wildcard"); err != nil {
			return nil, fmt.Errorf("unifi: %w", err)
		}
		if c.AllowInsecureHTTP, err = httpx.BoolOption(cfg, "allow_insecure_http"); err != nil {
			return nil, fmt.Errorf("unifi: %w", err)
		}
		return New(c)
	}, dns.ConfigSchema{Fields: []dns.Field{
		{Name: "url", Required: true, Help: "gateway base URL, e.g. https://gateway.lan"},
		{Name: "api_key", Secret: true, Required: true, Help: "Network application API key (sent as X-API-KEY)"},
		{Name: "site_id", Help: "site UUID; auto-discovered when empty (the \"default\" site, or the only site)"},
		{Name: "insecure_skip_verify", Help: "skip TLS verification (gateways use self-signed certificates)"},
		{Name: "wildcard", Help: "allow wildcard A records; enable only after verifying your controller accepts *.zone policies"},
		{Name: "allow_insecure_http", Help: "allow plain http to a non-private host"},
	}}, staticCaps)
}

// Config configures a Provider.
type Config struct {
	URL                string
	APIKey             secrets.Secret
	SiteID             string
	InsecureSkipVerify bool
	Wildcard           bool
	AllowInsecureHTTP  bool
}

// Provider implements dns.Provider.
type Provider struct {
	c        *httpx.Client
	auth     func() http.Header // builds the X-API-KEY header; the key lives only in this closure
	wildcard bool

	mu     *sync.Mutex
	siteID string
}

// New validates cfg and builds a provider.
func New(cfg Config) (*Provider, error) {
	if err := httpx.CheckURL(cfg.URL, cfg.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("unifi: %w", err)
	}
	if cfg.APIKey == "" {
		return nil, errors.New("unifi: config field \"api_key\" is required")
	}
	c, err := httpx.New(cfg.URL, cfg.InsecureSkipVerify, 0)
	if err != nil {
		return nil, fmt.Errorf("unifi: %w", err)
	}
	c.AddSecret(cfg.APIKey)
	key := cfg.APIKey
	return &Provider{c: c, auth: func() http.Header { return http.Header{"X-Api-Key": {key.Reveal()}} },
		wildcard: cfg.Wildcard, siteID: cfg.SiteID, mu: &sync.Mutex{}}, nil
}

func (p *Provider) hdr() http.Header { return p.auth() }

func (p *Provider) Type() string { return Type }

func (p *Provider) Capabilities() dns.Capabilities {
	c := staticCaps
	c.WildcardA = p.wildcard
	return c
}

func (p *Provider) wrapErr(op string, err error) error {
	var se *httpx.StatusError
	if errors.As(err, &se) {
		switch {
		case se.IsAuth():
			return fmt.Errorf("unifi: %s: authentication failed (status %d); check api_key", op, se.Status)
		case se.Status == 429:
			return fmt.Errorf("unifi: %s: rate limited by the gateway (status 429); retry later", op)
		}
	}
	return fmt.Errorf("unifi: %s: %w", op, err)
}

// maxPages bounds pagination so a server that ignores the offset cannot loop us.
const maxPages = 1000

type site struct {
	ID                string `json:"id"`
	InternalReference string `json:"internalReference"`
	Name              string `json:"name"`
}

// paginate collects every item of an offset/limit paginated list. It fails
// closed: a missing data array or totalCount, an empty page before the total
// is reached, repeated items (a server ignoring the offset), more than maxPages
// pages, or a final count differing from totalCount are all errors, never a
// short list.
func paginate[T any](ctx context.Context, p *Provider, op, path string, id func(T) string) ([]T, error) {
	// the list changing under us (totalCount differs between pages) is retried once
	all, err := paginateOnce(ctx, p, op, path, id)
	if errors.Is(err, errListChanged) {
		all, err = paginateOnce(ctx, p, op, path, id)
	}
	return all, err
}

var errListChanged = errors.New("list changed while reading")

func paginateOnce[T any](ctx context.Context, p *Provider, op, path string, id func(T) string) ([]T, error) {
	var all []T
	seen := map[string]bool{}
	total := -1
	for pages := 0; ; pages++ {
		if pages >= maxPages {
			return nil, fmt.Errorf("unifi: %s: more than %d pages; refusing to continue", op, maxPages)
		}
		var out struct {
			TotalCount *int `json:"totalCount"`
			Data       *[]T `json:"data"`
		}
		q := url.Values{"offset": {strconv.Itoa(len(all))}, "limit": {"100"}}
		if _, err := p.c.Do(ctx, "GET", path, q, p.hdr(), nil, &out); err != nil {
			return nil, p.wrapErr(op, err)
		}
		if out.Data == nil {
			return nil, fmt.Errorf("unifi: %s: malformed response (no data array)", op)
		}
		if out.TotalCount == nil {
			return nil, fmt.Errorf("unifi: %s: malformed response (no totalCount)", op)
		}
		if total >= 0 && *out.TotalCount != total {
			return nil, fmt.Errorf("unifi: %s: totalCount changed from %d to %d between pages: %w", op, total, *out.TotalCount, errListChanged)
		}
		total = *out.TotalCount
		for _, it := range *out.Data {
			k := id(it)
			if k == "" || seen[k] {
				return nil, fmt.Errorf("unifi: %s: repeated or id-less item in page %d (server ignoring offset?)", op, pages+1)
			}
			seen[k] = true
			all = append(all, it)
		}
		switch {
		case len(all) > *out.TotalCount:
			return nil, fmt.Errorf("unifi: %s: collected %d items but totalCount is %d", op, len(all), *out.TotalCount)
		case len(all) == *out.TotalCount:
			return all, nil
		case len(*out.Data) == 0:
			return nil, fmt.Errorf("unifi: %s: empty page after %d of %d items", op, len(all), *out.TotalCount)
		}
	}
}

func (p *Provider) site(ctx context.Context) (string, error) {
	p.mu.Lock()
	id := p.siteID
	p.mu.Unlock()
	if id != "" {
		return id, nil
	}
	sites, err := paginate(ctx, p, "list sites", apiRoot+"/sites", func(s site) string { return s.ID })
	if err != nil {
		return "", err
	}
	var pick *site
	switch len(sites) {
	case 0:
		return "", errors.New("unifi: the gateway reports no sites; set site_id")
	case 1:
		pick = &sites[0]
	default:
		var names []string
		for i := range sites {
			names = append(names, sites[i].InternalReference)
			if strings.EqualFold(sites[i].InternalReference, "default") {
				if pick != nil {
					return "", errors.New("unifi: several sites are named \"default\"; set site_id")
				}
				pick = &sites[i]
			}
		}
		if pick == nil {
			return "", fmt.Errorf("unifi: %d sites found (%s) and none is \"default\"; set site_id", len(sites), strings.Join(names, ", "))
		}
	}
	p.mu.Lock()
	p.siteID = pick.ID
	p.mu.Unlock()
	return pick.ID, nil
}

func (p *Provider) Test(ctx context.Context) error {
	_, err := p.site(ctx)
	return err
}

type policy struct {
	Type         string `json:"type"`
	ID           string `json:"id,omitempty"`
	Enabled      bool   `json:"enabled"`
	Domain       string `json:"domain"`
	IPv4Address  string `json:"ipv4Address,omitempty"`
	IPv6Address  string `json:"ipv6Address,omitempty"`
	TargetDomain string `json:"targetDomain,omitempty"`
	IPAddress    string `json:"ipAddress,omitempty"`
	TTLSeconds   *int   `json:"ttlSeconds,omitempty"`
}

func (po policy) record() dns.Record {
	r := dns.Record{ID: po.ID, Name: strings.ToLower(strings.TrimSuffix(po.Domain, "."))}
	if po.TTLSeconds != nil {
		r.TTL = *po.TTLSeconds
	}
	switch po.Type {
	case "A_RECORD":
		r.Type, r.Value = "A", po.IPv4Address
	case "AAAA_RECORD":
		r.Type, r.Value = "AAAA", po.IPv6Address
	case "CNAME_RECORD":
		r.Type, r.Value = "CNAME", strings.ToLower(strings.TrimSuffix(po.TargetDomain, "."))
	default:
		r.Type, r.Value = po.Type, po.IPAddress
	}
	return r
}

func (p *Provider) policies(ctx context.Context, sid string) ([]policy, error) {
	return paginate(ctx, p, "list DNS policies", apiRoot+"/sites/"+url.PathEscape(sid)+"/dns/policies", func(po policy) string { return po.ID })
}

func inZone(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }

func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	sid, err := p.site(ctx)
	if err != nil {
		return nil, err
	}
	pols, err := p.policies(ctx, sid)
	if err != nil {
		return nil, err
	}
	var out []dns.Record
	for _, po := range pols {
		if r := po.record(); inZone(r.Name, zone) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (p *Provider) checkWritable(r dns.Record) error {
	if r.Type != "A" {
		return fmt.Errorf("unifi: record type %q is not supported for writes (only A)", r.Type)
	}
	if strings.HasPrefix(r.Name, "*.") && !p.wildcard {
		return fmt.Errorf("unifi: wildcard record %q refused: set \"wildcard: true\" only after verifying your controller accepts wildcard DNS policies", r.Name)
	}
	return nil
}

func body(r dns.Record) policy {
	po := policy{Type: "A_RECORD", Enabled: true, Domain: r.Name, IPv4Address: r.Value}
	ttl := r.TTL
	po.TTLSeconds = &ttl
	return po
}

func (p *Provider) CreateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if err := p.checkWritable(r); err != nil {
		return dns.Record{}, err
	}
	sid, err := p.site(ctx)
	if err != nil {
		return dns.Record{}, err
	}
	pols, err := p.policies(ctx, sid)
	if err != nil {
		return dns.Record{}, err
	}
	for _, po := range pols {
		e := po.record()
		if e.Name == r.Name && (po.Type == "CNAME_RECORD" || po.Type == "FORWARD_DOMAIN") {
			return dns.Record{}, fmt.Errorf("unifi: %s already has a %s policy, which conflicts with an %s record: %w", r.Name, po.Type, r.Type, dns.ErrRecordExists)
		}
		if e.Name != r.Name || e.Type != r.Type {
			continue
		}
		if e.Value == r.Value && po.Enabled {
			return e, nil
		}
		state := ""
		if !po.Enabled {
			state = " (the existing policy is disabled and does not resolve)"
		}
		return dns.Record{}, fmt.Errorf("unifi: a DNS policy for %s %s already exists%s: %w", r.Name, r.Type, state, dns.ErrRecordExists)
	}
	var out policy
	path := apiRoot + "/sites/" + url.PathEscape(sid) + "/dns/policies"
	if _, err := p.c.Do(ctx, "POST", path, nil, p.hdr(), body(r), &out); err != nil {
		if !httpx.IsDefinitiveRejection(err) {
			// timeout, reset or unparseable answer: the policy may exist (without a
			// known ID; Delete matches name/type/value), so the caller must record it
			return r, p.c.Ambiguous("unifi: create DNS policy "+r.Name, err)
		}
		return dns.Record{}, p.wrapErr("create DNS policy "+r.Name, err)
	}
	if got := out.record(); out.ID != "" && got.Name == r.Name && got.Type == r.Type {
		return got, nil
	}
	// the response did not echo the policy: find it again to learn its ID
	pols, err = p.policies(ctx, sid)
	if err != nil {
		// the POST was accepted: report what was written so the caller records it
		return r, fmt.Errorf("unifi: create DNS policy %s: accepted but could not be confirmed (%v): %w", r.Name, err, dns.ErrUnconfirmed)
	}
	for _, po := range pols {
		if e := po.record(); e.Name == r.Name && e.Type == r.Type && e.Value == r.Value {
			return e, nil
		}
	}
	// accepted, but the policy cannot be found again: the record may exist without
	// an ID. Delete without an ID matches (name, type, value), so ownership is
	// still recordable.
	return r, fmt.Errorf("unifi: create DNS policy %s: the gateway accepted the request but the policy ID could not be determined: %w", r.Name, dns.ErrUnconfirmed)
}

func (p *Provider) UpdateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if err := p.checkWritable(r); err != nil {
		return dns.Record{}, err
	}
	sid, err := p.site(ctx)
	if err != nil {
		return dns.Record{}, err
	}
	pols, err := p.policies(ctx, sid)
	if err != nil {
		return dns.Record{}, err
	}
	var matches []*policy
	for i := range pols {
		e := pols[i].record()
		if (r.ID != "" && e.ID == r.ID) || (r.ID == "" && e.Name == r.Name && e.Type == r.Type) {
			matches = append(matches, &pols[i])
		}
	}
	if len(matches) == 0 {
		return dns.Record{}, dns.ErrNotFound
	}
	if len(matches) != 1 {
		return dns.Record{}, fmt.Errorf("unifi: %s %s has %d DNS policies; refusing to modify values doorwarden does not manage: %w", r.Name, r.Type, len(matches), dns.ErrRecordExists)
	}
	cur := matches[0]
	if e := cur.record(); e.Name != r.Name || e.Type != r.Type {
		return dns.Record{}, fmt.Errorf("unifi: update of policy %s: name/type mismatch with stored record: %w", cur.ID, dns.ErrNotFound)
	}
	b := body(r)
	b.Enabled = cur.Enabled
	var out policy
	if _, err := p.c.Do(ctx, "PUT", apiRoot+"/sites/"+url.PathEscape(sid)+"/dns/policies/"+url.PathEscape(cur.ID), nil, p.hdr(), b, &out); err != nil {
		if !httpx.IsDefinitiveRejection(err) {
			r.ID = cur.ID
			return r, p.c.Ambiguous("unifi: update DNS policy "+r.Name, err)
		}
		return dns.Record{}, p.wrapErr("update DNS policy "+r.Name, err)
	}
	if out.ID == "" {
		out = b
		out.ID = cur.ID
	}
	return out.record(), nil
}

func (p *Provider) DeleteRecord(ctx context.Context, zone string, r dns.Record) error {
	sid, err := p.site(ctx)
	if err != nil {
		return err
	}
	id := r.ID
	if id != "" && (r.Name != "" || r.Type != "") {
		// ID wins, but a caller that also names the record must name this one
		pols, err := p.policies(ctx, sid)
		if err != nil {
			return err
		}
		for _, po := range pols {
			if po.ID != id {
				continue
			}
			if e := po.record(); (r.Name != "" && e.Name != r.Name) || (r.Type != "" && e.Type != r.Type) {
				return fmt.Errorf("unifi: delete of policy %s: stored record is %s %s, not %s %s; refusing", id, e.Name, e.Type, r.Name, r.Type)
			}
		}
	}
	if id == "" {
		pols, err := p.policies(ctx, sid)
		if err != nil {
			return err
		}
		for _, po := range pols {
			if e := po.record(); e.Name == r.Name && e.Type == r.Type && e.Value == r.Value {
				id = po.ID
				break
			}
		}
		if id == "" {
			return nil
		}
	}
	_, err = p.c.Do(ctx, "DELETE", apiRoot+"/sites/"+url.PathEscape(sid)+"/dns/policies/"+url.PathEscape(id), nil, p.hdr(), nil, nil)
	var se *httpx.StatusError
	if errors.As(err, &se) && se.Status == 404 {
		return nil
	}
	if err != nil {
		if !httpx.IsDefinitiveRejection(err) {
			return p.c.Ambiguous("unifi: delete DNS policy", err) // keep the ownership row
		}
		return p.wrapErr("delete DNS policy", err)
	}
	return nil
}

// String, GoString and Format print only the type: a Provider holds no
// secret-bearing value (credentials live in closures, see dns.RedactedFormat),
// and these methods keep a copy of the struct from being dumped field by field.
func (p Provider) String() string             { return "unifi.Provider <redacted>" }
func (p Provider) GoString() string           { return "unifi.Provider <redacted>" }
func (p Provider) Format(f fmt.State, _ rune) { dns.RedactedFormat(f, "unifi.Provider") }
