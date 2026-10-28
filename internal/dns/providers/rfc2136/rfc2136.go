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
// Writable record types: A, AAAA, CNAME (others, TXT included, are listed read-only).
package rfc2136

import (
	"context"
	"encoding/base64"
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
	// Clock overrides time.Now for TSIG timestamps (tests only).
	Clock func() time.Time
}

// Provider implements dns.Provider.
type Provider struct {
	addr    string
	keyName string
	alg     string
	secret  func() secrets.Secret // the TSIG secret lives only behind this closure
	scrubFn func(string) string
	timeout time.Duration
	now     func() time.Time
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
	if _, err := base64.StdEncoding.DecodeString(c.KeySecret.Reveal()); err != nil {
		return nil, errors.New("rfc2136: config field \"key_secret\" is not valid base64")
	}
	_, scrub := dns.Scrubber(c.KeySecret)
	now := c.Clock
	if now == nil {
		now = time.Now
	}
	return &Provider{
		addr: net.JoinHostPort(host, port), keyName: mdns.Fqdn(strings.ToLower(c.KeyName)),
		alg: full, secret: dns.StaticSecret(c.KeySecret), scrubFn: scrub, timeout: to, now: now,
	}, nil
}

func (p *Provider) Type() string                   { return Type }
func (p *Provider) Capabilities() dns.Capabilities { return staticCaps }

func (p *Provider) scrub(s string) string { return p.scrubFn(s) }

func (p *Provider) sign(m *mdns.Msg) *mdns.Msg {
	m.SetTsig(p.keyName, p.alg, 300, p.now().Unix())
	return m
}

// exchangeRaw sends one TSIG-signed message over TCP and returns the parsed,
// TSIG-verified response. Verification is done here (not by the library
// client) so a NOTAUTH answer can be told apart: BADKEY, BADSIG and BADTIME
// are reported as such when the server says so in its TSIG record.
func (p *Provider) exchangeRaw(ctx context.Context, op string, m *mdns.Msg) (*mdns.Msg, error) {
	wrap := func(err error) error {
		if ctx.Err() != nil {
			return fmt.Errorf("rfc2136: %s: %w", op, ctx.Err())
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("rfc2136: %s: %w", op, context.DeadlineExceeded)
		}
		return fmt.Errorf("rfc2136: %s: %s", op, p.scrub(err.Error()))
	}
	p.sign(m)
	out, reqMAC, err := mdns.TsigGenerate(m, p.secret().Reveal(), "", false)
	if err != nil {
		return nil, wrap(err)
	}
	nc, err := (&net.Dialer{Timeout: p.timeout}).DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return nil, wrap(err)
	}
	defer nc.Close()
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	defer stop()
	_ = nc.SetDeadline(time.Now().Add(p.timeout))
	co := &mdns.Conn{Conn: nc}
	// from here on the request may have reached the server
	if _, err := co.Write(out); err != nil {
		return nil, &ioAfterSend{wrap(err)}
	}
	raw, err := co.ReadMsgHeader(nil)
	if err != nil {
		return nil, &ioAfterSend{wrap(err)}
	}
	r := new(mdns.Msg)
	if err := r.Unpack(raw); err != nil {
		return nil, &ioAfterSend{wrap(err)}
	}
	// From here on a parsed reply exists. A reply we cannot trust (unsigned,
	// signed by another key, a MAC that does not verify) is refused, but it does
	// not prove the server refused the request: for an UPDATE the outcome is
	// unknown (ioAfterSend). Only an explicit rejection is definitive: an
	// unsigned NOTAUTH/REFUSED/FORMERR/NOTIMP/NOTZONE (servers answer unsigned
	// when they cannot verify the request), or a TSIG error the server reports.
	t := r.IsTsig()
	if t == nil {
		switch r.Rcode {
		case mdns.RcodeNotAuth:
			return nil, authErr(op, "unsigned NOTAUTH reply")
		case mdns.RcodeRefused, mdns.RcodeFormatError, mdns.RcodeNotImplemented, mdns.RcodeNotZone:
			return nil, fmt.Errorf("rfc2136: %s: server refused the request with an unsigned %s reply", op, mdns.RcodeToString[r.Rcode])
		}
		return nil, &ioAfterSend{fmt.Errorf("rfc2136: %s: server response (%s) is not TSIG-signed; refusing it", op, mdns.RcodeToString[r.Rcode])}
	}
	if e := tsigErrorFromCode(op, p.keyName, int(t.Error)); e != nil {
		return nil, e
	}
	if r.Rcode == mdns.RcodeNotAuth {
		// the TSIG library cannot verify a NOTAUTH message at all (it rejects
		// the rcode before checking the MAC); the server said no either way
		return nil, authErr(op, "signed NOTAUTH reply")
	}
	if !strings.EqualFold(t.Hdr.Name, p.keyName) {
		return nil, &ioAfterSend{fmt.Errorf("rfc2136: %s: response signed with an unexpected key %q; refusing it", op, t.Hdr.Name)}
	}
	if err := mdns.TsigVerify(raw, p.secret().Reveal(), reqMAC, false); err != nil {
		return nil, &ioAfterSend{tsigVerifyError(op, p.keyName, err)}
	}
	return r, nil
}

// tsigErrorFromCode maps a TSIG-record error code (RFC 8945 section 3.2) to a
// specific message; nil for NOERROR.
func tsigErrorFromCode(op, keyName string, code int) error {
	switch code {
	case 0:
		return nil
	case mdns.RcodeBadSig:
		return fmt.Errorf("rfc2136: %s: server reports BADSIG: the TSIG secret or algorithm does not match the server's key", op)
	case mdns.RcodeBadKey:
		return fmt.Errorf("rfc2136: %s: server reports BADKEY: it does not know the TSIG key name %q", op, keyName)
	case mdns.RcodeBadTime:
		return fmt.Errorf("rfc2136: %s: server reports BADTIME: the clocks of doorwarden and the DNS server differ by more than the TSIG fudge (300s); fix time synchronisation", op)
	}
	return fmt.Errorf("rfc2136: %s: server reports TSIG error %s", op, mdns.RcodeToString[code])
}

func tsigVerifyError(op, keyName string, err error) error {
	switch {
	case errors.Is(err, mdns.ErrTime):
		return tsigErrorFromCode(op, keyName, mdns.RcodeBadTime)
	case errors.Is(err, mdns.ErrSig):
		return fmt.Errorf("rfc2136: %s: the server's TSIG signature did not verify (BADSIG); the secret or algorithm differs", op)
	case errors.Is(err, mdns.ErrSecret):
		return tsigErrorFromCode(op, keyName, mdns.RcodeBadKey)
	}
	return fmt.Errorf("rfc2136: %s: TSIG verification failed: %v", op, err)
}

// ioAfterSend marks an I/O failure that happened after the request was written:
// the server may have applied it.
type ioAfterSend struct{ err error }

func (e *ioAfterSend) Error() string { return e.err.Error() }
func (e *ioAfterSend) Unwrap() error { return e.err }

func (p *Provider) exchange(ctx context.Context, op string, m *mdns.Msg) (*mdns.Msg, error) {
	r, err := p.exchangeRaw(ctx, op, m)
	if err != nil {
		return nil, err
	}
	return r, p.rcodeErr(op, r)
}

// authErr is what a TSIG/zone authorisation failure looks like.
func authErr(op, detail string) error {
	return fmt.Errorf("rfc2136: %s: NOTAUTH (%s): the server rejected the TSIG key or does not serve the zone; check key_name, key_secret, algorithm and the zone", op, detail)
}

func (p *Provider) rcodeErr(op string, r *mdns.Msg) error {
	switch r.Rcode {
	case mdns.RcodeSuccess:
		return nil
	case mdns.RcodeNotAuth:
		return authErr(op, "signed reply")
	case mdns.RcodeRefused:
		return fmt.Errorf("rfc2136: %s: refused by the server (REFUSED); the TSIG key may not be permitted to update this zone", op)
	case mdns.RcodeNameError:
		return nil // NXDOMAIN is an empty answer for queries
	case mdns.RcodeYXRrset, mdns.RcodeNXRrset:
		return fmt.Errorf("rfc2136: %s: the record set changed concurrently (%s); retry: %w", op, mdns.RcodeToString[r.Rcode], dns.ErrRecordExists)
	}
	return fmt.Errorf("rfc2136: %s: server returned %s", op, mdns.RcodeToString[r.Rcode])
}

// Test sends a TSIG-signed SOA query for the root and requires a correctly
// signed answer; it proves reachability and key agreement but not update
// permission (that is per zone).
func (p *Provider) Test(ctx context.Context) error {
	m := new(mdns.Msg)
	m.SetQuestion(".", mdns.TypeSOA)
	_, err := p.exchangeRaw(ctx, "verify credentials", m)
	return err
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
	}
	// TXT values can be several strings and up to 65535 bytes; rebuilding one
	// from a flat string would not match what is stored (prerequisites, exact
	// removal), and TXT is out of scope for this tool, so TXT is read-only.
	return nil, fmt.Errorf("rfc2136: record type %q is not supported for writes (A, AAAA, CNAME)", r.Type)
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
	t := &mdns.Transfer{Conn: &mdns.Conn{Conn: nc}, ReadTimeout: p.timeout, TsigSecret: map[string]string{p.keyName: p.secret().Reveal()}}
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

// update sends one UPDATE. Errors before it was written (TSIG signing, dial)
// are plain. After that, only an explicit refusal is definitive (REFUSED,
// NOTAUTH, NOTZONE, FORMERR, NOTIMP, the prerequisite failures NXRRSET/YXRRSET
// /NXDOMAIN/YXDOMAIN, or a TSIG error the server reports); SERVFAIL (a journal
// failure, or a forwarded update whose primary timed out, may still have been
// applied), an unknown rcode, an untrusted reply (unsigned, wrong key, MAC
// that does not verify), a garbled reply and an I/O failure wrap
// dns.ErrUnconfirmed.
func (p *Provider) update(ctx context.Context, op, zone string, f func(*mdns.Msg)) error {
	m := new(mdns.Msg)
	m.SetUpdate(fqdn(zone))
	f(m)
	r, err := p.exchangeRaw(ctx, op, m)
	if err == nil {
		err = updateRcodeErr(op, r)
	}
	var amb *ioAfterSend
	if errors.As(err, &amb) {
		return fmt.Errorf("rfc2136: %s: the update may have been applied but the outcome is unknown (%v): %w: %w", op, amb.err, dns.ErrUnconfirmed, amb.err) // amb.err text is already scrubbed
	}
	return err
}

// updateRcodeErr classifies the rcode of a trusted (TSIG-verified) UPDATE reply.
func updateRcodeErr(op string, r *mdns.Msg) error {
	switch r.Rcode {
	case mdns.RcodeSuccess:
		return nil
	case mdns.RcodeNotAuth:
		return authErr(op, "signed reply")
	case mdns.RcodeRefused:
		return fmt.Errorf("rfc2136: %s: refused by the server (REFUSED); the TSIG key may not be permitted to update this zone", op)
	case mdns.RcodeYXRrset, mdns.RcodeNXRrset, mdns.RcodeYXDomain, mdns.RcodeNameError:
		return fmt.Errorf("rfc2136: %s: the record set changed concurrently (prerequisite failed: %s); retry: %w", op, mdns.RcodeToString[r.Rcode], dns.ErrRecordExists)
	case mdns.RcodeNotZone, mdns.RcodeFormatError, mdns.RcodeNotImplemented:
		return fmt.Errorf("rfc2136: %s: server rejected the update (%s)", op, mdns.RcodeToString[r.Rcode])
	}
	name := mdns.RcodeToString[r.Rcode]
	if name == "" {
		name = fmt.Sprintf("rcode %d", r.Rcode)
	}
	return &ioAfterSend{fmt.Errorf("rfc2136: %s: server returned %s", op, name)}
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
	// prerequisite: no such RRset exists yet, so a concurrent writer cannot be overwritten
	if err := p.update(ctx, "create record "+r.Name, zone, func(m *mdns.Msg) {
		m.RRsetNotUsed([]mdns.RR{rr})
		m.Insert([]mdns.RR{rr})
	}); err != nil {
		if errors.Is(err, dns.ErrUnconfirmed) {
			out, _ := fromRR(rr)
			return out, err // may exist: the caller must record it
		}
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
	// prerequisite: the RRset is still exactly what was read (value dependent)
	curRR, err := toRR(dns.Record{Name: r.Name, Type: r.Type, Value: cur[0].Value, TTL: cur[0].TTL})
	if err != nil {
		return dns.Record{}, err
	}
	if err := p.update(ctx, "update record "+r.Name, zone, func(m *mdns.Msg) {
		m.Used([]mdns.RR{curRR})
		m.RemoveRRset([]mdns.RR{rr})
		m.Insert([]mdns.RR{rr})
	}); err != nil {
		if errors.Is(err, dns.ErrUnconfirmed) {
			out, _ := fromRR(rr)
			return out, err
		}
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

// String, GoString and Format print only the type: a Provider holds no
// secret-bearing value (credentials live in closures, see dns.RedactedFormat),
// and these methods keep a copy of the struct from being dumped field by field.
func (p Provider) String() string             { return "rfc2136.Provider <redacted>" }
func (p Provider) GoString() string           { return "rfc2136.Provider <redacted>" }
func (p Provider) Format(f fmt.State, _ rune) { dns.RedactedFormat(f, "rfc2136.Provider") }
