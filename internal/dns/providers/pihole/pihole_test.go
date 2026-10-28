package pihole_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/dnstest"
	"github.com/ajthom90/doorwarden/internal/dns/providers/pihole"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

const password = "pihole-PASSWORD-do-not-leak-1"

type backend struct {
	cnames    []string
	rawHosts  string
	puts      int
	mu        sync.Mutex
	hosts     []string
	valid     map[string]bool
	n         int
	logins    int
	logouts   int
	status    int
	slow      time.Duration
	authCalls int
}

func newBackend() *backend { return &backend{valid: map[string]bool{}} }

func (b *backend) expireAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.valid = map[string]bool{}
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.slow > 0 {
		time.Sleep(b.slow)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	if b.status != 0 {
		reply(b.status, map[string]any{"error": map[string]any{"key": "x", "message": "boom " + password + r.Header.Get("X-FTL-SID")}})
		return
	}
	if r.URL.Path == "/api/auth" {
		switch r.Method {
		case "POST":
			var in struct{ Password string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Password != password {
				reply(401, map[string]any{"error": map[string]any{"key": "unauthorized", "message": "Unauthorized"}})
				return
			}
			b.logins++
			b.n++
			sid := "sid-" + strconv.Itoa(b.n)
			b.valid[sid] = true
			reply(200, map[string]any{"session": map[string]any{"valid": true, "totp": false, "sid": sid, "csrf": "c", "validity": 300}})
		case "DELETE":
			delete(b.valid, r.Header.Get("X-FTL-SID"))
			b.logouts++
			reply(204, nil)
		}
		return
	}
	if !b.valid[r.Header.Get("X-FTL-SID")] {
		reply(401, map[string]any{"error": map[string]any{"key": "unauthorized", "message": "Unauthorized"}})
		return
	}
	const base = "/api/config/dns/hosts"
	switch {
	case r.URL.Path == "/api/config/dns/cnameRecords" && r.Method == "GET":
		reply(200, map[string]any{"config": map[string]any{"dns": map[string]any{"cnameRecords": append([]string{}, b.cnames...)}}})
	case r.URL.Path == base && r.Method == "GET" && b.rawHosts != "":
		_, _ = w.Write([]byte(b.rawHosts))
	case r.URL.Path == base && r.Method == "GET":
		reply(200, map[string]any{"config": map[string]any{"dns": map[string]any{"hosts": append([]string{}, b.hosts...)}}, "took": 0.01})
	case strings.HasPrefix(r.URL.EscapedPath(), base+"/"):
		entry, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), base+"/"))
		switch r.Method {
		case "PUT":
			b.puts++
			for _, h := range b.hosts {
				if h == entry {
					reply(201, nil)
					return
				}
			}
			b.hosts = append(b.hosts, entry)
			reply(201, nil)
		case "DELETE":
			for i, h := range b.hosts {
				if h == entry {
					b.hosts = append(b.hosts[:i], b.hosts[i+1:]...)
					reply(204, nil)
					return
				}
			}
			reply(404, map[string]any{"error": map[string]any{"key": "not_found", "message": "Item not found"}})
		}
	default:
		reply(404, nil)
	}
}

func newProvider(t *testing.T, b *backend, pw string) *pihole.Provider {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	p, err := pihole.New(pihole.Config{URL: srv.URL, Password: secretOf(pw)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConformance(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, password)
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test",
		SeedMultiValue: func(_ context.Context, _, name string, values ...string) error {
			b.mu.Lock()
			defer b.mu.Unlock()
			for _, v := range values {
				b.hosts = append(b.hosts, v+" "+name)
			}
			return nil
		}})
	if p.Capabilities().WildcardA || p.Capabilities().TTL {
		t.Fatalf("caps = %+v", p.Capabilities())
	}
}

func TestReauthOn401(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	p := newProvider(t, b, password)
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	b.expireAll()
	recs, err := p.ListRecords(ctx, "example.test")
	if err != nil || len(recs) != 1 {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
	if b.logins != 2 {
		t.Fatalf("logins = %d, want 2", b.logins)
	}
}

func TestCloseDeletesSession(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, password)
	if err := p.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil || b.logouts != 1 {
		t.Fatalf("err=%v logouts=%d", err, b.logouts)
	}
	if err := p.Close(); err != nil || b.logouts != 1 {
		t.Fatal("second Close must be a no-op")
	}
}

func TestV6AndMultiHostEntries(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.hosts = []string{"2001:db8::1 six.example.test", "192.0.2.5 one.example.test two.example.test", "192.0.2.6 out.other.test"}
	p := newProvider(t, b, password)
	recs, _ := p.ListRecords(ctx, "example.test")
	if len(recs) != 3 {
		t.Fatalf("recs = %+v", recs)
	}
	for _, r := range recs {
		if r.Name == "six.example.test" && r.Type != "AAAA" {
			t.Fatalf("family not inferred: %+v", r)
		}
	}
	// deleting a name that shares a multi-hostname line must not claim success
	if err := p.DeleteRecord(ctx, "example.test", dns.Record{Name: "one.example.test", Type: "A", Value: "192.0.2.5"}); err == nil {
		t.Fatal("silent no-op on shared line")
	}
}

func TestWildcardAndTypesRefused(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, password)
	for _, r := range []dns.Record{
		{Name: "*.example.test", Type: "A", Value: "192.0.2.1"},
		{Name: "a.example.test", Type: "CNAME", Value: "b.example.test"},
		{Name: "a.example.test", Type: "A", Value: "2001:db8::1"},
		{Name: "a b.example.test", Type: "A", Value: "192.0.2.1"},
	} {
		if _, err := p.CreateRecord(context.Background(), "example.test", r); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	if len(b.hosts) != 0 {
		t.Fatal("something was written")
	}
}

func TestErrorMappingNoLeak(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	bad := newProvider(t, b, "wrong-"+password)
	if err := bad.Test(ctx); err == nil || !strings.Contains(err.Error(), "authentication failed") || strings.Contains(err.Error(), password) {
		t.Fatalf("err = %v", err)
	}
	p := newProvider(t, b, password)
	for status, want := range map[int]string{429: "rate limited", 500: "status 500"} {
		b.status = status
		err := p.Test(ctx)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), password) {
			t.Fatalf("%d: err = %v", status, err)
		}
	}
}

func TestContextAndConfig(t *testing.T) {
	b := newBackend()
	b.slow = 500 * time.Millisecond
	p := newProvider(t, b, password)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Test(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if _, err := pihole.New(pihole.Config{URL: "http://dns.example.test", Password: "x"}); err == nil {
		t.Fatal("plain http to public name accepted")
	}
	if _, err := dns.New("pihole", map[string]any{"url": "https://pi.lan"}, nil); err == nil {
		t.Fatal("missing password accepted")
	}
}

func secretOf(s string) secrets.Secret { return secrets.Secret(s) }

func TestCNAMEsListedReadOnlyAndBlockA(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.cnames = []string{"alias.example.test,app.example.test,300", "short.example.test,app.example.test"}
	p := newProvider(t, b, password)
	recs, err := p.ListRecords(ctx, "example.test")
	if err != nil || len(recs) != 2 || recs[0].Type != "CNAME" || recs[0].Value != "app.example.test" || recs[0].TTL != 300 {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
	_, err = p.CreateRecord(ctx, "example.test", dns.Record{Name: "alias.example.test", Type: "A", Value: "192.0.2.1"})
	if !errors.Is(err, dns.ErrRecordExists) || !strings.Contains(err.Error(), "CNAME") {
		t.Fatalf("err = %v", err)
	}
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "x.example.test", Type: "CNAME", Value: "y.example.test"}); err == nil {
		t.Fatal("CNAME writes must be refused")
	}
}

func TestUpdateSameValueNoOpAndMultiRefused(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.hosts = []string{"192.0.2.1 a.example.test", "192.0.2.1 m.example.test", "192.0.2.2 m.example.test"}
	p := newProvider(t, b, password)
	if _, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if b.puts != 0 || len(b.hosts) != 3 {
		t.Fatalf("same-value update wrote: puts=%d hosts=%v", b.puts, b.hosts)
	}
	_, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "m.example.test", Type: "A", Value: "192.0.2.9"})
	if !errors.Is(err, dns.ErrRecordExists) || len(b.hosts) != 3 {
		t.Fatalf("err=%v hosts=%v", err, b.hosts)
	}
}

func TestListingFailsClosedAndSIDScrubbed(t *testing.T) {
	ctx := context.Background()
	for name, raw := range map[string]string{
		"empty object": `{}`, "no config": `{"took":1}`, "no hosts": `{"config":{"dns":{}}}`, "null hosts": `{"config":{"dns":{"hosts":null}}}`,
	} {
		b := newBackend()
		b.rawHosts = raw
		p := newProvider(t, b, password)
		if recs, err := p.ListRecords(ctx, "example.test"); err == nil {
			t.Errorf("%s: accepted %v", name, recs)
		}
	}
	b := newBackend()
	p := newProvider(t, b, password)
	if err := p.Test(ctx); err != nil {
		t.Fatal(err)
	}
	b.status = 500
	if err := p.Test(ctx); err == nil || strings.Contains(err.Error(), "sid-") || strings.Contains(err.Error(), password) {
		t.Fatalf("err = %v", err)
	}
	if _, err := dns.New("pihole", map[string]any{"url": "https://pi.lan", "password": "x", "insecure_skip_verify": "maybe"}, nil); err == nil {
		t.Fatal("non-bool flag accepted")
	}
}

func TestCNAMEParsingMultipleAliasesAndTTL(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.cnames = []string{"a.example.test,b.example.test,target.example.test,300", "x.example.test,y.example.test,t2.example.test", "solo.example.test,t3.example.test,60", "p.example.test,t4.example.test", "num.example.test,123", "u1.example.test,u2.example.test,30s", "m.example.test,5m", "c.example.test,3com"}
	p := newProvider(t, b, password)
	recs, err := p.ListRecords(ctx, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]dns.Record{}
	for _, r := range recs {
		got[r.Name] = r
	}
	want := map[string][2]string{
		"a.example.test": {"target.example.test", "300"}, "b.example.test": {"target.example.test", "300"},
		"x.example.test": {"t2.example.test", "0"}, "y.example.test": {"t2.example.test", "0"},
		"solo.example.test": {"t3.example.test", "60"}, "p.example.test": {"t4.example.test", "0"},
		"num.example.test": {"123", "0"},                                  // two fields: a numeric last field is the target, not a TTL
		"u1.example.test":  {"30s", "0"}, "u2.example.test": {"30s", "0"}, // unit-suffixed: a valid single-label host name, so the target
		"m.example.test": {"5m", "0"}, "c.example.test": {"3com", "0"},
	}
	if len(got) != len(want) {
		t.Fatalf("recs = %+v", recs)
	}
	for n, w := range want {
		r := got[n]
		if r.Type != "CNAME" || r.Value != w[0] || strconv.Itoa(r.TTL) != w[1] {
			t.Errorf("%s = %+v, want %v", n, r, w)
		}
	}
	// the second alias must block an A just like the first
	if _, err := p.CreateRecord(ctx, "example.test", dns.Record{Name: "b.example.test", Type: "A", Value: "192.0.2.1"}); !errors.Is(err, dns.ErrRecordExists) {
		t.Fatalf("second alias did not block: %v", err)
	}
	for _, bad := range []string{"onlyone", "a,,b", ",a,b", "a,b,99999999999999999999", "a,b,-1", "a,b,+5", "a,-1", "a,b,+"} {
		b.cnames = []string{bad}
		if _, err := p.ListRecords(ctx, "example.test"); err == nil {
			t.Errorf("malformed %q accepted", bad)
		}
	}
}

func TestSharedHostsLineNeverEdited(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.hosts = []string{"192.0.2.5 one.example.test two.example.test"}
	p := newProvider(t, b, password)
	_, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "one.example.test", Type: "A", Value: "192.0.2.6"})
	if !errors.Is(err, dns.ErrRecordExists) || b.puts != 0 || len(b.hosts) != 1 {
		t.Fatalf("err=%v puts=%d hosts=%v", err, b.puts, b.hosts)
	}
}

func TestConcurrentFirstUseLogsInOnce(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, password)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Test(context.Background())
		}()
	}
	wg.Wait()
	if b.logins != 1 {
		t.Fatalf("logins = %d, want 1 (session leak)", b.logins)
	}
}

func TestSameValueUpdateOnSharedLineIsNoOp(t *testing.T) {
	b := newBackend()
	b.hosts = []string{"192.0.2.5 one.example.test two.example.test"}
	p := newProvider(t, b, password)
	if _, err := p.UpdateRecord(context.Background(), "example.test", dns.Record{Name: "one.example.test", Type: "A", Value: "192.0.2.5"}); err != nil {
		t.Fatalf("same-value update on a shared line: %v", err)
	}
	if b.puts != 0 || len(b.hosts) != 1 {
		t.Fatalf("puts=%d hosts=%v", b.puts, b.hosts)
	}
}
