// Package rfc2136 is a DNS provider using RFC 2136 dynamic updates signed with
// TSIG (RFC 8945), for BIND, Knot, PowerDNS and compatible servers.
//
// It uses github.com/miekg/dns directly (the library libdns/rfc2136 is built
// on) instead of libdns/rfc2136, because the dns.Provider contract needs
// value-exact deletes, atomic RRset replacement and TSIG-verified queries,
// which libdns' record-set API does not express.
//
// There are no record IDs: Record.ID is always empty, a non-empty ID on Update
// returns dns.ErrNotFound and on Delete is a no-op. Records are addressed by
// (name, type[, value]). ListRecords uses AXFR, so the server must allow zone
// transfers to the TSIG key (BIND: allow-transfer { key doorwarden; };); if it
// does not, ListRecords returns a clear error and everything else still works.
// Supported record types: A, AAAA, CNAME, TXT.
package rfc2136

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

// Type is the registry name.
const Type = "rfc2136"

var staticCaps = dns.Capabilities{WildcardA: true, MultiZone: true, Update: true, TTL: true}

var algorithms = map[string]string{
	"hmac-sha1":   mdns.HmacSHA1,
	"hmac-sha224": mdns.HmacSHA224,
	"hmac-sha256": mdns.HmacSHA256,
	"hmac-sha384": mdns.HmacSHA384,
	"hmac-sha512": mdns.HmacSHA512,
}

func init() {
	dns.Register(Type, func(cfg map[string]any, sr dns.SecretResolver) (dns.Provider, error) {
		str := func(k string) string { v, _ := cfg[k].(string); return v }
		secret, err := dns.ResolveField(cfg, sr, "key_secret")
		if err != nil {
			return nil, fmt.Errorf("rfc2136: %w", err)
		}
		return New(Config{Server: str("server"), KeyName: str("key_name"), KeySecret: secret, Algorithm: str("algorithm")})
	}, dns.ConfigSchema{Fields: []dns.Field{
		{Name: "server", Required: true, Help: "DNS server host:port (default port 53), reached over TCP"},
		{Name: "key_name", Required: true, Help: "TSIG key name"},
		{Name: "key_secret", Secret: true, Required: true, Help: "TSIG key secret, base64"},
		{Name: "algorithm", Help: "TSIG algorithm: hmac-sha1|hmac-sha224|hmac-sha256 (default)|hmac-sha384|hmac-sha512"},
	}}, staticCaps)
}

// Config configures a Provider. TSIG is mandatory.
type Config struct {
	Server    string
	KeyName   string
	KeySecret secrets.Secret // base64
	Algorithm string
	Timeout   time.Duration
}

// Provider implements dns.Provider.
type Provider struct {
	addr    string
	keyName string
	alg     string
	secret  secrets.Secret
	timeout time.Duration
}

// New validates cfg and builds a provider.
func New(c Config) (*Provider, error) {
	if c.Server == "" {
		return nil, errors.New("rfc2136: config field \"server\" is required")
	}
	if c.KeyName == "" || c.KeySecret == "" {
		return nil, errors.New("rfc2136: TSIG is required: config fields \"key_name\" and \"key_secret\" must be set")
	}
	host, port, err := net.SplitHostPort(c.Server)
	if err != nil {
		host, port = c.Server, "53"
	}
	if host == "" || strings.ContainsAny(host, "/@ ") {
		return nil, errors.New("rfc2136: config field \"server\" must be host or host:port")
	}
	alg := strings.ToLower(c.Algorithm)
	if alg == "" {
		alg = "hmac-sha256"
	}
	full, ok := algorithms[alg]
	if !ok {
		return nil, fmt.Errorf("rfc2136: unsupported TSIG algorithm %q", c.Algorithm)
	}
	to := c.Timeout
	if to <= 0 {
		to = 10 * time.Second
	}
	return &Provider{
		addr: net.JoinHostPort(host, port), keyName: mdns.Fqdn(strings.ToLower(c.KeyName)),
		alg: full, secret: c.KeySecret, timeout: to,
	}, nil
}

func (p *Provider) Type() string                   { return Type }
func (p *Provider) Capabilities() dns.Capabilities { return staticCaps }

func (p *Provider) scrub(s string) string {
	if v := p.secret.Reveal(); v != "" {
		s = strings.ReplaceAll(s, v, "[redacted]")
	}
	return s
}

func (p *Provider) client() *mdns.Client {
	return &mdns.Client{Net: "tcp", Timeout: p.timeout, TsigSecret: map[string]string{p.keyName: p.secret.Reveal()}}
}

func (p *Provider) sign(m *mdns.Msg) *mdns.Msg {
	m.SetTsig(p.keyName, p.alg, 300, time.Now().Unix())
	return m
}

func (p *Provider) exchange(ctx context.Context, op string, m *mdns.Msg) (*mdns.Msg, error) {
	r, _, err := p.client().ExchangeContext(ctx, p.sign(m), p.addr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("rfc2136: %s: %w", op, ctx.Err())
		}
		if errors.Is(err, mdns.ErrAuth) {
			return nil, authErr(op)
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, fmt.Errorf("rfc2136: %s: %w", op, context.DeadlineExceeded)
		}
		return nil, fmt.Errorf("rfc2136: %s: %s", op, p.scrub(err.Error()))
	}
	if r.IsTsig() == nil {
		return nil, fmt.Errorf("rfc2136: %s: server response is not TSIG-signed; refusing it", op)
	}
	return r, p.rcodeErr(op, r)
}

// authErr is what a TSIG/zone authorisation failure looks like: the library
// reports a NOTAUTH response (or a TSIG that does not verify) as ErrAuth.
func authErr(op string) error {
	return fmt.Errorf("rfc2136: %s: TSIG authentication failed or zone not served (NOTAUTH/bad signature); check key_name, key_secret, algorithm and the zone", op)
}

func (p *Provider) rcodeErr(op string, r *mdns.Msg) error {
	switch r.Rcode {
	case mdns.RcodeSuccess:
		return nil
	case mdns.RcodeNotAuth:
		return authErr(op)
	case mdns.RcodeRefused:
		return fmt.Errorf("rfc2136: %s: refused by the server (REFUSED); the TSIG key may not be permitted to update this zone", op)
	case mdns.RcodeNameError:
		return nil // NXDOMAIN is an empty answer for queries
	}
	return fmt.Errorf("rfc2136: %s: server returned %s", op, mdns.RcodeToString[r.Rcode])
}

// Test sends a TSIG-signed SOA query for the root and requires the
// server to answer with a valid TSIG; it proves reachability and key
// agreement but not update permission (that is per zone).
func (p *Provider) Test(ctx context.Context) error {
	m := new(mdns.Msg)
	m.SetQuestion(".", mdns.TypeSOA)
	r, _, err := p.client().ExchangeContext(ctx, p.sign(m), p.addr)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("rfc2136: verify credentials: %w", ctx.Err())
		}
		if errors.Is(err, mdns.ErrAuth) {
			return authErr("verify credentials")
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("rfc2136: verify credentials: %w", context.DeadlineExceeded)
		}
		return fmt.Errorf("rfc2136: verify credentials: %s", p.scrub(err.Error()))
	}
	// Servers answer a signed probe for a zone they do not serve with REFUSED
	// (still signed); a wrong key yields NOTAUTH/BADKEY, surfaced above.
	if r.IsTsig() == nil {
		return errors.New("rfc2136: verify credentials: server did not sign its response with TSIG")
	}
	return nil
}

func fqdn(name string) string { return mdns.Fqdn(strings.ToLower(name)) }

func recName(rr mdns.RR) string {
	return strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
}

func toRR(r dns.Record) (mdns.RR, error) {
	ttl := uint32(r.TTL)
	if r.TTL <= 0 {
		ttl = 300
	}
	hdr := mdns.RR_Header{Name: fqdn(r.Name), Class: mdns.ClassINET, Ttl: ttl}
	switch r.Type {
	case "A":
		ip := net.ParseIP(r.Value)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("rfc2136: invalid A value %q", r.Value)
		}
		hdr.Rrtype = mdns.TypeA
		return &mdns.A{Hdr: hdr, A: ip.To4()}, nil
	case "AAAA":
		ip := net.ParseIP(r.Value)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("rfc2136: invalid AAAA value %q", r.Value)
		}
		hdr.Rrtype = mdns.TypeAAAA
		return &mdns.AAAA{Hdr: hdr, AAAA: ip}, nil
	case "CNAME":
		hdr.Rrtype = mdns.TypeCNAME
		return &mdns.CNAME{Hdr: hdr, Target: fqdn(r.Value)}, nil
	case "TXT":
		hdr.Rrtype = mdns.TypeTXT
		return &mdns.TXT{Hdr: hdr, Txt: []string{r.Value}}, nil
	}
	return nil, fmt.Errorf("rfc2136: record type %q is not supported (A, AAAA, CNAME, TXT)", r.Type)
}

func fromRR(rr mdns.RR) (dns.Record, bool) {
	rec := dns.Record{Name: recName(rr), Type: mdns.TypeToString[rr.Header().Rrtype], TTL: int(rr.Header().Ttl)}
	switch v := rr.(type) {
	case *mdns.A:
		rec.Value = v.A.String()
	case *mdns.AAAA:
		rec.Value = v.AAAA.String()
	case *mdns.CNAME:
		rec.Value = strings.ToLower(strings.TrimSuffix(v.Target, "."))
	case *mdns.TXT:
		rec.Value = strings.Join(v.Txt, "")
	case *mdns.SOA, *mdns.RRSIG, *mdns.NSEC, *mdns.NSEC3, *mdns.NSEC3PARAM, *mdns.DNSKEY:
		return rec, false // zone machinery, not user records
	default:
		rec.Value = strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
	}
	return rec, true
}

// ListRecords lists the zone by AXFR (TSIG-signed; every message must verify).
// The server must allow transfers to the key. The connection is closed when
// ctx is cancelled.
func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.Record, error) {
	m := new(mdns.Msg)
	m.SetAxfr(fqdn(zone))
	p.sign(m)
	nc, err := (&net.Dialer{Timeout: p.timeout}).DialContext(ctx, "tcp", p.addr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("rfc2136: list records: %w", ctx.Err())
		}
		return nil, fmt.Errorf("rfc2136: list records: %s", p.scrub(err.Error()))
	}
	defer nc.Close()
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	defer stop()
	t := &mdns.Transfer{Conn: &mdns.Conn{Conn: nc}, ReadTimeout: p.timeout, TsigSecret: map[string]string{p.keyName: p.secret.Reveal()}}
	ch, err := t.In(m, p.addr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("rfc2136: list records: %w", ctx.Err())
		}
		return nil, fmt.Errorf("rfc2136: list records: %s", p.scrub(err.Error()))
	}
	var recs []dns.Record
	var firstErr error
	for env := range ch {
		if env.Error != nil {
			if firstErr == nil {
				firstErr = env.Error
			}
			continue // drain
		}
		for _, rr := range env.RR {
			if r, ok := fromRR(rr); ok {
				recs = append(recs, r)
			}
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("rfc2136: list records: %w", ctx.Err())
	}
	if firstErr != nil {
		return nil, fmt.Errorf("rfc2136: list records (AXFR): %s; the server must allow zone transfers to the TSIG key (allow-transfer) and sign every response", p.scrub(firstErr.Error()))
	}
	return recs, nil
}

func (p *Provider) lookup(ctx context.Context, name, typ string) ([]dns.Record, error) {
	t, ok := mdns.StringToType[typ]
	if !ok {
		return nil, fmt.Errorf("rfc2136: unknown record type %q", typ)
	}
	m := new(mdns.Msg)
	m.SetQuestion(fqdn(name), t)
	r, err := p.exchange(ctx, "query "+name, m)
	if err != nil {
		return nil, err
	}
	var out []dns.Record
	for _, rr := range r.Answer {
		if rec, ok := fromRR(rr); ok && rec.Name == strings.ToLower(strings.TrimSuffix(name, ".")) && rec.Type == typ {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (p *Provider) update(ctx context.Context, op, zone string, f func(*mdns.Msg)) error {
	m := new(mdns.Msg)
	m.SetUpdate(fqdn(zone))
	f(m)
	_, err := p.exchange(ctx, op, m)
	return err
}

func (p *Provider) CreateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	rr, err := toRR(r)
	if err != nil {
		return dns.Record{}, err
	}
	cur, err := p.lookup(ctx, r.Name, r.Type)
	if err != nil {
		return dns.Record{}, err
	}
	for _, c := range cur {
		if c.Value == r.Value {
			return c, nil
		}
	}
	if len(cur) > 0 {
		return dns.Record{}, dns.ErrRecordExists
	}
	// a CNAME cannot coexist with other data at the same name; servers ignore
	// such updates silently, so check first
	others := []string{"CNAME"}
	if r.Type == "CNAME" {
		others = []string{"A", "AAAA", "TXT"}
	}
	for _, t := range others {
		o, err := p.lookup(ctx, r.Name, t)
		if err != nil {
			return dns.Record{}, err
		}
		if len(o) > 0 {
			return dns.Record{}, fmt.Errorf("rfc2136: %s already has a %s record, which cannot coexist with %s: %w", r.Name, t, r.Type, dns.ErrRecordExists)
		}
	}
	if err := p.update(ctx, "create record "+r.Name, zone, func(m *mdns.Msg) { m.Insert([]mdns.RR{rr}) }); err != nil {
		return dns.Record{}, err
	}
	out, _ := fromRR(rr)
	return out, nil
}

func (p *Provider) UpdateRecord(ctx context.Context, zone string, r dns.Record) (dns.Record, error) {
	if r.ID != "" {
		return dns.Record{}, dns.ErrNotFound // rfc2136 never issues record IDs
	}
	rr, err := toRR(r)
	if err != nil {
		return dns.Record{}, err
	}
	cur, err := p.lookup(ctx, r.Name, r.Type)
	if err != nil {
		return dns.Record{}, err
	}
	if len(cur) == 0 {
		return dns.Record{}, dns.ErrNotFound
	}
	if len(cur) != 1 {
		return dns.Record{}, fmt.Errorf("rfc2136: %s %s set has %d values; refusing to modify values doorwarden does not manage: %w", r.Name, r.Type, len(cur), dns.ErrRecordExists)
	}
	// one UPDATE message: replace the whole RRset atomically
	if err := p.update(ctx, "update record "+r.Name, zone, func(m *mdns.Msg) {
		m.RemoveRRset([]mdns.RR{rr})
		m.Insert([]mdns.RR{rr})
	}); err != nil {
		return dns.Record{}, err
	}
	out, _ := fromRR(rr)
	return out, nil
}

func (p *Provider) DeleteRecord(ctx context.Context, zone string, r dns.Record) error {
	if r.ID != "" {
		return nil // never issued: nothing can match
	}
	rr, err := toRR(r)
	if err != nil {
		return err
	}
	// RR-exact removal: a stored record with a different value is untouched.
	return p.update(ctx, "delete record "+r.Name, zone, func(m *mdns.Msg) { m.Remove([]mdns.RR{rr}) })
}

// String and GoString keep credentials out of any formatted output of the
// provider (unexported struct fields are printed raw by fmt, bypassing the
// redaction of secrets.Secret).
func (p *Provider) String() string   { return "rfc2136.Provider" }
func (p *Provider) GoString() string { return "rfc2136.Provider" }
