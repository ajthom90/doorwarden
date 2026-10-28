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
		flag := func(k string) (bool, error) {
			v, ok := cfg[k]
			if !ok || v == nil {
				return false, nil
			}
			b, ok := v.(bool)
			if !ok {
				return false, fmt.Errorf("unifi: config field %q must be a bool", k)
			}
			return b, nil
		}
		key, err := dns.ResolveField(cfg, sr, "api_key")
		if err != nil {
			return nil, fmt.Errorf("unifi: %w", err)
		}
		c := Config{URL: str("url"), APIKey: key, SiteID: str("site_id")}
		if c.InsecureSkipVerify, err = flag("insecure_skip_verify"); err != nil {
			return nil, err
		}
		if c.Wildcard, err = flag("wildcard"); err != nil {
			return nil, err
		}
		if c.AllowInsecureHTTP, err = flag("allow_insecure_http"); err != nil {
			return nil, err
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
	h        http.Header
	wildcard bool

	mu     sync.Mutex
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
	c.Secrets = []string{cfg.APIKey.Reveal()}
	return &Provider{c: c, h: http.Header{"X-Api-Key": {cfg.APIKey.Reveal()}}, wildcard: cfg.Wildcard, siteID: cfg.SiteID}, nil
}

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

type page struct {
	Offset     int `json:"offset"`
	Count      int `json:"count"`
	TotalCount int `json:"totalCount"`
}

type site struct {
	ID                string `json:"id"`
	InternalReference string `json:"internalReference"`
	Name              string `json:"name"`
}

func (p *Provider) site(ctx context.Context) (string, error) {
	p.mu.Lock()
	id := p.siteID
	p.mu.Unlock()
	if id != "" {
		return id, nil
	}
	var sites []site
	for off := 0; ; {
		var out struct {
			page
			Data []site `json:"data"`
		}
		q := url.Values{"offset": {strconv.Itoa(off)}, "limit": {"100"}}
		if _, err := p.c.Do(ctx, "GET", apiRoot+"/sites", q, p.h, nil, &out); err != nil {
			return "", p.wrapErr("list sites", err)
		}
		sites = append(sites, out.Data...)
		off += out.Count
		if out.Count == 0 || off >= out.TotalCount {
			break
		}
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
	var all []policy
	for off := 0; ; {
		var out struct {
			page
			Data []policy `json:"data"`
		}
		q := url.Values{"offset": {strconv.Itoa(off)}, "limit": {"100"}}
		if _, err := p.c.Do(ctx, "GET", apiRoot+"/sites/"+url.PathEscape(sid)+"/dns/policies", q, p.h, nil, &out); err != nil {
			return nil, p.wrapErr("list DNS policies", err)
		}
		all = append(all, out.Data...)
		off += out.Count
		if out.Count == 0 || off >= out.TotalCount {
			return all, nil
		}
	}
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
		if e := po.record(); e.Name == r.Name && e.Type == r.Type {
			if e.Value == r.Value {
				return e, nil
			}
			return dns.Record{}, dns.ErrRecordExists
		}
	}
	var out policy
	if _, err := p.c.Do(ctx, "POST", apiRoot+"/sites/"+url.PathEscape(sid)+"/dns/policies", nil, p.h, body(r), &out); err != nil {
		return dns.Record{}, p.wrapErr("create DNS policy "+r.Name, err)
	}
	return out.record(), nil
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
	var cur *policy
	for i := range pols {
		e := pols[i].record()
		if (r.ID != "" && e.ID == r.ID) || (r.ID == "" && e.Name == r.Name && e.Type == r.Type) {
			cur = &pols[i]
			break
		}
	}
	if cur == nil {
		return dns.Record{}, dns.ErrNotFound
	}
	if e := cur.record(); e.Name != r.Name || e.Type != r.Type {
		return dns.Record{}, fmt.Errorf("unifi: update of policy %s: name/type mismatch with stored record: %w", cur.ID, dns.ErrNotFound)
	}
	b := body(r)
	b.Enabled = cur.Enabled
	var out policy
	if _, err := p.c.Do(ctx, "PUT", apiRoot+"/sites/"+url.PathEscape(sid)+"/dns/policies/"+url.PathEscape(cur.ID), nil, p.h, b, &out); err != nil {
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
	_, err = p.c.Do(ctx, "DELETE", apiRoot+"/sites/"+url.PathEscape(sid)+"/dns/policies/"+url.PathEscape(id), nil, p.h, nil, nil)
	var se *httpx.StatusError
	if errors.As(err, &se) && se.Status == 404 {
		return nil
	}
	if err != nil {
		return p.wrapErr("delete DNS policy", err)
	}
	return nil
}
