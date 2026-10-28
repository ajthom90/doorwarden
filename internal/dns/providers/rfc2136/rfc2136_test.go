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
	addr         string
	mu           sync.Mutex
	zones        map[string][]mdns.RR // zone fqdn -> records (without SOA)
	noAXFR       bool
	noSign       bool   // reply without TSIG even to signed requests
	beforeUpdate func() // runs when an UPDATE arrives, before it is evaluated (simulates a racing writer)
	delay        time.Duration
	unsigned     int // requests received without TSIG
	srv          *mdns.Server
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
			if w.TsigStatus() == nil && !f.noSign {
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
		if f.beforeUpdate != nil {
			f.beforeUpdate()
			f.beforeUpdate = nil
		}
		z := q.Name
		recs, ok := f.zones[z]
		if !ok {
			m.Rcode = mdns.RcodeNotAuth
			return
		}
		// prerequisites (RFC 2136 section 2.4)
		exists := func(name string, typ uint16) []mdns.RR {
			var out []mdns.RR
			for _, e := range recs {
				if strings.EqualFold(e.Header().Name, name) && e.Header().Rrtype == typ {
					out = append(out, e)
				}
			}
			return out
		}
		valueDep := map[string][]mdns.RR{}
		for _, pr := range r.Answer {
			h := pr.Header()
			switch h.Class {
			case mdns.ClassNONE: // NXRRSET: the RRset must not exist
				if len(exists(h.Name, h.Rrtype)) > 0 {
					m.Rcode = mdns.RcodeYXRrset
					return
				}
			case mdns.ClassANY: // YXRRSET: the RRset must exist
				if len(exists(h.Name, h.Rrtype)) == 0 {
					m.Rcode = mdns.RcodeNXRrset
					return
				}
			case mdns.ClassINET:
				k := strings.ToLower(h.Name) + "|" + mdns.TypeToString[h.Rrtype]
				valueDep[k] = append(valueDep[k], pr)
			}
		}
		for _, want := range valueDep {
			have := exists(want[0].Header().Name, want[0].Header().Rrtype)
			if len(have) != len(want) {
				m.Rcode = mdns.RcodeNXRrset
				return
			}
			for _, w := range want {
				found := false
				for _, h := range have {
					found = found || sameRData(h, w)
				}
				if !found {
					m.Rcode = mdns.RcodeNXRrset
					return
				}
			}
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
			if f.noSign {
				m.Answer = append(append([]mdns.RR{f.soa(z)}, f.zones[z]...), f.soa(z))
				_ = w.WriteMsg(m)
				m = nil
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
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test",
		SeedMultiValue: func(_ context.Context, _, name string, values ...string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, v := range values {
				rr, _ := mdns.NewRR(mdns.Fqdn(name) + " 60 IN A " + v)
				f.zones["example.test."] = append(f.zones["example.test."], rr)
			}
			return nil
		}})
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

func TestUpdateRefusesMultiValue(t *testing.T) {
	f := startServer(t)
	for _, v := range []string{"192.0.2.1", "192.0.2.2"} {
		rr, _ := mdns.NewRR("m.example.test. 60 IN A " + v)
		f.zones["example.test."] = append(f.zones["example.test."], rr)
	}
	p := newProvider(t, f, nil)
	_, err := p.UpdateRecord(context.Background(), "example.test", dns.Record{Name: "m.example.test", Type: "A", Value: "192.0.2.99"})
	if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "2 values") {
		t.Fatalf("err = %v", err)
	}
	if len(f.zones["example.test."]) != 2 {
		t.Fatal("set was modified")
	}
}

func TestCreateARefusedWhereCNAMEExists(t *testing.T) {
	f := startServer(t)
	rr, _ := mdns.NewRR("c.example.test. 60 IN CNAME target.example.test.")
	f.zones["example.test."] = append(f.zones["example.test."], rr)
	p := newProvider(t, f, nil)
	_, err := p.CreateRecord(context.Background(), "example.test", dns.Record{Name: "c.example.test", Type: "A", Value: "192.0.2.1"})
	if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "CNAME") {
		t.Fatalf("err = %v", err)
	}
	// the reverse: CNAME where an A exists
	rr, _ = mdns.NewRR("a.example.test. 60 IN A 192.0.2.5")
	f.zones["example.test."] = append(f.zones["example.test."], rr)
	if _, err := p.CreateRecord(context.Background(), "example.test", dns.Record{Name: "a.example.test", Type: "CNAME", Value: "x.example.test"}); !errors.Is(err, dns.ErrRecordExists) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnsignedResponsesRejected(t *testing.T) {
	f := startServer(t)
	f.noSign = true
	p := newProvider(t, f, nil)
	ctx := context.Background()
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"}); err == nil || !strings.Contains(err.Error(), "TSIG") {
		t.Fatalf("unsigned UPDATE/query response accepted: %v", err)
	}
	if _, err := p.ListRecords(ctx, "example.test"); err == nil {
		t.Fatal("unsigned AXFR accepted")
	}
}

func TestAXFRHonoursContext(t *testing.T) {
	f := startServer(t)
	f.delay = 2 * time.Second
	p := newProvider(t, f, func(c *rfc2136.Config) { c.Timeout = 10 * time.Second })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := p.ListRecords(ctx, "example.test")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

func TestPrerequisitesProtectAgainstConcurrentWriters(t *testing.T) {
	f := startServer(t)
	rr, _ := mdns.NewRR("c.example.test. 60 IN A 192.0.2.1")
	f.zones["example.test."] = []mdns.RR{rr}
	p := newProvider(t, f, nil)
	ctx := context.Background()
	// a competing writer changes the value between our read and our UPDATE: the
	// value-dependent prerequisite must make the server refuse our replacement
	f.beforeUpdate = func() {
		other, _ := mdns.NewRR("c.example.test. 60 IN A 192.0.2.77")
		f.zones["example.test."] = []mdns.RR{other}
	}
	_, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "c.example.test", Type: "A", Value: "192.0.2.2"})
	if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "concurrently") {
		t.Fatalf("update err = %v", err)
	}
	if got := f.zones["example.test."][0].(*mdns.A).A.String(); got != "192.0.2.77" {
		t.Fatalf("concurrent change lost: %s", got)
	}
	// create: someone else created the RRset after our existence check
	f.zones["example.test."] = nil
	f.beforeUpdate = func() {
		other, _ := mdns.NewRR("n.example.test. 60 IN A 192.0.2.88")
		f.zones["example.test."] = []mdns.RR{other}
	}
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "n.example.test", Type: "A", Value: "192.0.2.3"}); err == nil || len(f.zones["example.test."]) != 1 {
		t.Fatalf("create overwrote a concurrent RRset: err=%v", err)
	}
}

func TestTSIGErrorsAreDistinguished(t *testing.T) {
	for code, want := range map[int]string{mdns.RcodeBadSig: "BADSIG", mdns.RcodeBadKey: "BADKEY", mdns.RcodeBadTime: "BADTIME"} {
		err := rfc2136.TSIGErrorFromCode("op", "doorwarden-key.", code)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("code %d: %v", code, err)
		}
	}
	if err := rfc2136.TSIGErrorFromCode("op", "doorwarden-key.", mdns.RcodeBadKey); !strings.Contains(err.Error(), `"doorwarden-key."`) {
		t.Errorf("BADKEY must name the key: %v", err)
	}
	if rfc2136.TSIGErrorFromCode("op", "doorwarden-key.", 0) != nil {
		t.Fatal("NOERROR must map to nil")
	}
	for e, want := range map[error]string{mdns.ErrTime: "BADTIME", mdns.ErrSig: "BADSIG", mdns.ErrSecret: "BADKEY"} {
		if err := rfc2136.TSIGVerifyError("op", "doorwarden-key.", e); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: %v", e, err)
		}
	}
}

func TestClockSkewAndWrongKeyReportedClearly(t *testing.T) {
	f := startServer(t)
	ctx := context.Background()
	// wrong secret: the server answers NOTAUTH without a signature
	wrong := newProvider(t, f, func(c *rfc2136.Config) { c.KeySecret = "d3Jvbmctc2VjcmV0LXdyb25n" })
	if err := wrong.Test(ctx); err == nil || !strings.Contains(err.Error(), "NOTAUTH") || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("wrong key: err = %v", err)
	}
	// a client clock an hour off: the server rejects the timestamp
	skewed := newProvider(t, f, func(c *rfc2136.Config) { c.Clock = func() time.Time { return time.Now().Add(time.Hour) } })
	if err := skewed.Test(ctx); err == nil {
		t.Fatal("clock skew accepted")
	}
}

func TestBadBase64SecretIsAConfigError(t *testing.T) {
	_, err := rfc2136.New(rfc2136.Config{Server: "127.0.0.1", KeyName: "k", KeySecret: "not base64 !!"})
	if err == nil || !strings.Contains(err.Error(), "base64") || strings.Contains(err.Error(), "not base64") {
		t.Fatalf("err = %v", err)
	}
}

func TestTXTIsReadOnly(t *testing.T) {
	f := startServer(t)
	p := newProvider(t, f, nil)
	for _, op := range []func() error{
		func() error {
			_, err := p.CreateRecord(context.Background(), "example.test", dns.Record{Name: "t.example.test", Type: "TXT", Value: "v"})
			return err
		},
		func() error {
			_, err := p.UpdateRecord(context.Background(), "example.test", dns.Record{Name: "t.example.test", Type: "TXT", Value: "v"})
			return err
		},
	} {
		if err := op(); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("err = %v", err)
		}
	}
}
