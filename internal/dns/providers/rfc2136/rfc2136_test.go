package rfc2136_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/dnstest"
	"github.com/ajthom90/doorwarden/internal/dns/providers/rfc2136"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

const (
	keyName   = "doorwarden-key."
	keySecret = "c2VjcmV0LWtleS1mb3ItdGVzdA==" // base64("secret-key-for-test")
)

type fakeServer struct {
	addr     string
	mu       sync.Mutex
	zones    map[string][]mdns.RR // zone fqdn -> records (without SOA)
	noAXFR   bool
	delay    time.Duration
	unsigned int // requests received without TSIG
	srv      *mdns.Server
}

func startServer(t *testing.T) *fakeServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{addr: l.Addr().String(), zones: map[string][]mdns.RR{"example.test.": nil, "other.test.": nil}}
	f.srv = &mdns.Server{Listener: l, Net: "tcp", Handler: f, TsigSecret: map[string]string{keyName: keySecret},
		MsgAcceptFunc: func(mdns.Header) mdns.MsgAcceptAction { return mdns.MsgAccept }}
	started := make(chan struct{})
	f.srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = f.srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = f.srv.Shutdown() })
	return f
}

func (f *fakeServer) zoneOf(name string) string {
	for z := range f.zones {
		if mdns.IsSubDomain(z, name) {
			return z
		}
	}
	return ""
}

func (f *fakeServer) soa(zone string) *mdns.SOA {
	return &mdns.SOA{Hdr: mdns.RR_Header{Name: zone, Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: 60},
		Ns: "ns." + zone, Mbox: "h." + zone, Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: 60}
}

func (f *fakeServer) ServeDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	m := new(mdns.Msg)
	m.SetReply(r)
	if t := r.IsTsig(); t != nil {
		defer func() {
			if m == nil { // AXFR wrote its own replies
				return
			}
			if w.TsigStatus() == nil {
				m.SetTsig(t.Hdr.Name, t.Algorithm, 300, time.Now().Unix())
			}
			_ = w.WriteMsg(m)
		}()
	} else {
		f.unsigned++
		m.Rcode = mdns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	if w.TsigStatus() != nil {
		m.Rcode = mdns.RcodeNotAuth
		return
	}
	q := r.Question[0]
	switch r.Opcode {
	case mdns.OpcodeUpdate:
		z := q.Name
		recs, ok := f.zones[z]
		if !ok {
			m.Rcode = mdns.RcodeNotAuth
			return
		}
		for _, rr := range r.Ns {
			h := rr.Header()
			switch h.Class {
			case mdns.ClassANY: // delete RRset
				var keep []mdns.RR
				for _, e := range recs {
					if !(strings.EqualFold(e.Header().Name, h.Name) && e.Header().Rrtype == h.Rrtype) {
						keep = append(keep, e)
					}
				}
				recs = keep
			case mdns.ClassNONE: // delete exact RR
				var keep []mdns.RR
				for _, e := range recs {
					if !(strings.EqualFold(e.Header().Name, h.Name) && e.Header().Rrtype == h.Rrtype && sameRData(e, rr)) {
						keep = append(keep, e)
					}
				}
				recs = keep
			default:
				c := mdns.Copy(rr)
				c.Header().Name = strings.ToLower(h.Name)
				recs = append(recs, c)
			}
		}
		f.zones[z] = recs
	case mdns.OpcodeQuery:
		z := f.zoneOf(q.Name)
		if z == "" {
			m.Rcode = mdns.RcodeRefused
			return
		}
		switch q.Qtype {
		case mdns.TypeSOA:
			m.Answer = append(m.Answer, f.soa(z))
		case mdns.TypeAXFR:
			if f.noAXFR {
				m.Rcode = mdns.RcodeRefused
				return
			}
			ch := make(chan *mdns.Envelope, 1)
			all := append([]mdns.RR{f.soa(z)}, f.zones[z]...)
			all = append(all, f.soa(z))
			ch <- &mdns.Envelope{RR: all}
			close(ch)
			// the deferred single reply must not also be written
			m = nil
			tr := new(mdns.Transfer)
			tr.TsigSecret = map[string]string{keyName: keySecret}
			_ = tr.Out(w, r, ch)
			return
		default:
			for _, e := range f.zones[z] {
				if strings.EqualFold(e.Header().Name, q.Name) && e.Header().Rrtype == q.Qtype {
					m.Answer = append(m.Answer, e)
				}
			}
			if len(m.Answer) == 0 {
				m.Rcode = mdns.RcodeSuccess
			}
		}
	}
}

func sameRData(a, b mdns.RR) bool {
	strip := func(r mdns.RR) string { return strings.TrimPrefix(r.String(), r.Header().String()) }
	return strip(a) == strip(b)
}

func newProvider(t *testing.T, f *fakeServer, mod func(*rfc2136.Config)) *rfc2136.Provider {
	t.Helper()
	cfg := rfc2136.Config{Server: f.addr, KeyName: keyName, KeySecret: secrets.Secret(keySecret), Timeout: 5 * time.Second}
	if mod != nil {
		mod(&cfg)
	}
	p, err := rfc2136.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConformance(t *testing.T) {
	f := startServer(t)
	p := newProvider(t, f, nil)
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test"})
	if f.unsigned != 0 {
		t.Fatalf("%d unsigned requests were sent", f.unsigned)
	}
}

func TestTSIGRequiredAndChecked(t *testing.T) {
	if _, err := rfc2136.New(rfc2136.Config{Server: "127.0.0.1:53", KeyName: "k"}); err == nil || !strings.Contains(err.Error(), "TSIG is required") {
		t.Fatalf("err = %v", err)
	}
	if _, err := dns.New("rfc2136", map[string]any{"server": "127.0.0.1", "key_name": "k"}, nil); err == nil {
		t.Fatal("registry accepted missing key_secret")
	}
	f := startServer(t)
	ctx := context.Background()
	wrong := newProvider(t, f, func(c *rfc2136.Config) { c.KeySecret = "d3Jvbmctc2VjcmV0LXdyb25n" })
	err := wrong.Test(ctx)
	if err == nil {
		t.Fatal("wrong key accepted")
	}
	for _, e := range []error{err} {
		if strings.Contains(e.Error(), keySecret) || strings.Contains(e.Error(), "d3Jvbmctc2VjcmV0LXdyb25n") {
			t.Fatalf("secret leaked: %v", e)
		}
	}
	if _, err := wrong.CreateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"}); err == nil {
		t.Fatal("create with wrong key succeeded")
	}
	if len(f.zones["example.test."]) != 0 {
		t.Fatal("record written with a wrong key")
	}
	if _, err := rfc2136.New(rfc2136.Config{Server: f.addr, KeyName: "k", KeySecret: "x", Algorithm: "md5"}); err == nil {
		t.Fatal("bad algorithm accepted")
	}
}

func TestAXFRNotAllowed(t *testing.T) {
	f := startServer(t)
	f.noAXFR = true
	p := newProvider(t, f, nil)
	_, err := p.ListRecords(context.Background(), "example.test")
	if err == nil || !strings.Contains(err.Error(), "allow-transfer") {
		t.Fatalf("err = %v", err)
	}
	// non-list operations still work
	if _, err := p.CreateRecord(context.Background(), "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownZoneRefused(t *testing.T) {
	f := startServer(t)
	p := newProvider(t, f, nil)
	_, err := p.CreateRecord(context.Background(), "nozone.test", dns.Record{Name: "a.nozone.test", Type: "A", Value: "192.0.2.1"})
	if err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("err = %v", err)
	}
}

func TestContextTimeout(t *testing.T) {
	f := startServer(t)
	f.delay = 500 * time.Millisecond
	p := newProvider(t, f, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if err := p.Test(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnsupportedType(t *testing.T) {
	f := startServer(t)
	p := newProvider(t, f, nil)
	if _, err := p.CreateRecord(context.Background(), "example.test", dns.Record{Name: "a.example.test", Type: "MX", Value: "x"}); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err = %v", err)
	}
}
