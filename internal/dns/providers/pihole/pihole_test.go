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
		reply(b.status, map[string]any{"error": map[string]any{"key": "x", "message": "boom " + password}})
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
	case r.URL.Path == base && r.Method == "GET":
		reply(200, map[string]any{"config": map[string]any{"dns": map[string]any{"hosts": append([]string{}, b.hosts...)}}, "took": 0.01})
	case strings.HasPrefix(r.URL.EscapedPath(), base+"/"):
		entry, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), base+"/"))
		switch r.Method {
		case "PUT":
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
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test"})
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
