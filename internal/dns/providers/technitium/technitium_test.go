package technitium_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/dnstest"
	"github.com/ajthom90/doorwarden/internal/dns/providers/technitium"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

const (
	apiToken = "tech-TOKEN-do-not-leak-1"
	password = "tech-PASSWORD-do-not-leak-2"
)

type rec struct {
	name, typ, val string
	ttl            int
	disabled       bool
	comments       string
}

type backend struct {
	mu         sync.Mutex
	zones      map[string][]rec
	session    string // currently valid session token from login
	logins     int
	status     int
	slow       time.Duration
	queryToken bool // a token was seen in the URL query
	rawGet     string
}

func newBackend() *backend {
	return &backend{zones: map[string][]rec{"example.test": nil, "other.test": nil}, session: "session-1"}
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.slow > 0 {
		time.Sleep(b.slow)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	reply := func(v map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	if b.status != 0 {
		w.WriteHeader(b.status)
		reply(map[string]any{"status": "error", "errorMessage": "boom " + r.FormValue("token") + r.FormValue("pass")})
		return
	}
	_ = r.ParseForm()
	if r.URL.Query().Get("token") != "" || r.URL.Query().Get("pass") != "" {
		b.queryToken = true
	}
	f := r.PostForm
	if r.URL.Path == "/api/user/login" {
		if f.Get("user") != "admin" || f.Get("pass") != password {
			reply(map[string]any{"status": "error", "errorMessage": "Invalid username or password for user: admin"})
			return
		}
		b.logins++
		b.session = "session-" + strconv.Itoa(b.logins+1)
		reply(map[string]any{"status": "ok", "token": b.session})
		return
	}
	if f.Get("token") != apiToken && f.Get("token") != b.session {
		reply(map[string]any{"status": "invalid-token", "errorMessage": "Invalid token or session expired."})
		return
	}
	if r.URL.Path == "/api/zones/list" {
		reply(map[string]any{"status": "ok", "response": map[string]any{"zones": []any{}}})
		return
	}
	zone := f.Get("zone")
	recs, ok := b.zones[zone]
	if !ok {
		reply(map[string]any{"status": "error", "errorMessage": "No such zone was found: " + zone})
		return
	}
	typ, dom := f.Get("type"), f.Get("domain")
	valOf := func(new bool) string {
		for _, k := range []string{"ipAddress", "cname", "text"} {
			if new && (k == "ipAddress" || k == "text") {
				k = "new" + strings.ToUpper(k[:1]) + k[1:]
				k = strings.Replace(k, "NewIpAddress", "newIpAddress", 1)
			}
			if v := f.Get(k); v != "" {
				return v
			}
		}
		return ""
	}
	switch r.URL.Path {
	case "/api/zones/records/get":
		if b.rawGet != "" {
			_, _ = w.Write([]byte(b.rawGet))
			return
		}
		var out []map[string]any
		for _, e := range recs {
			rd := map[string]any{}
			switch e.typ {
			case "A", "AAAA":
				rd["ipAddress"] = e.val
			case "CNAME":
				rd["cname"] = e.val
			case "TXT":
				rd["text"] = e.val
			}
			out = append(out, map[string]any{"name": e.name, "type": e.typ, "ttl": e.ttl, "disabled": e.disabled, "comments": e.comments, "rData": rd})
		}
		out = append(out, map[string]any{"name": zone, "type": "SOA", "ttl": 60, "rData": map[string]any{"primaryNameServer": "ns"}})
		out = append(out, map[string]any{"name": zone, "type": "MX", "ttl": 60, "rData": map[string]any{"preference": 10, "exchange": "mx.example.test"}})
		reply(map[string]any{"status": "ok", "response": map[string]any{"zone": map[string]any{"name": zone}, "records": out}})
	case "/api/zones/records/add":
		ttl, _ := strconv.Atoi(f.Get("ttl"))
		b.zones[zone] = append(recs, rec{name: dom, typ: typ, val: valOf(false), ttl: ttl})
		reply(map[string]any{"status": "ok", "response": map[string]any{}})
	case "/api/zones/records/update":
		for i, e := range recs {
			if e.name == dom && e.typ == typ && (typ == "CNAME" || e.val == valOf(false)) {
				ttl, _ := strconv.Atoi(f.Get("ttl"))
				recs[i] = rec{name: dom, typ: typ, val: valOf(true), ttl: ttl, disabled: f.Get("disable") == "true", comments: f.Get("comments")}
				reply(map[string]any{"status": "ok", "response": map[string]any{}})
				return
			}
		}
		reply(map[string]any{"status": "error", "errorMessage": "Cannot update record: no such record"})
	case "/api/zones/records/delete":
		for i, e := range recs {
			if e.name == dom && e.typ == typ && e.val == valOf(false) {
				b.zones[zone] = append(recs[:i], recs[i+1:]...)
				break
			}
		}
		reply(map[string]any{"status": "ok"})
	default:
		w.WriteHeader(404)
	}
}

func newProvider(t *testing.T, b *backend, mod func(*technitium.Config)) *technitium.Provider {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	cfg := technitium.Config{URL: srv.URL, Token: secrets.Secret(apiToken)}
	if mod != nil {
		mod(&cfg)
	}
	p, err := technitium.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConformanceToken(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, nil)
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test",
		SeedMultiValue: func(_ context.Context, zone, name string, values ...string) error {
			b.mu.Lock()
			defer b.mu.Unlock()
			for _, v := range values {
				b.zones[zone] = append(b.zones[zone], rec{name: name, typ: "A", val: v, ttl: 60})
			}
			return nil
		}})
	if b.queryToken {
		t.Fatal("credentials were sent in the URL query")
	}
}

func TestConformanceLogin(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, func(c *technitium.Config) { c.Token, c.Username, c.Password = "", "admin", password })
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test"})
	if b.logins != 1 {
		t.Fatalf("logins = %d", b.logins)
	}
}

func TestSessionExpiryRelogin(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	p := newProvider(t, b, func(c *technitium.Config) { c.Token, c.Username, c.Password = "", "admin", password })
	if err := p.Test(ctx); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.session = "rotated-elsewhere"
	b.mu.Unlock()
	if err := p.Test(ctx); err != nil {
		t.Fatalf("no re-login: %v", err)
	}
	if b.logins != 2 {
		t.Fatalf("logins = %d", b.logins)
	}
}

func TestErrorMapping(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	bad := newProvider(t, b, func(c *technitium.Config) { c.Token = "wrong-" + apiToken })
	if err := bad.Test(ctx); err == nil || strings.Contains(err.Error(), apiToken) {
		t.Fatalf("err = %v", err)
	}
	badLogin := newProvider(t, b, func(c *technitium.Config) { c.Token, c.Username, c.Password = "", "admin", "nope-"+password })
	if err := badLogin.Test(ctx); err == nil || !strings.Contains(err.Error(), "login failed") || strings.Contains(err.Error(), password) {
		t.Fatalf("err = %v", err)
	}
	p := newProvider(t, b, nil)
	if _, err := p.ListRecords(ctx, "nozone.test"); err == nil || !strings.Contains(err.Error(), "zone not found") {
		t.Fatalf("err = %v", err)
	}
	for status, want := range map[int]string{401: "authentication failed", 429: "rate limited", 500: "status 500"} {
		b.status = status
		err := p.Test(ctx)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), apiToken) {
			t.Fatalf("%d: err = %v", status, err)
		}
	}
}

func TestForeignTypesListedAndSOAHidden(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, nil)
	recs, err := p.ListRecords(context.Background(), "example.test")
	if err != nil || len(recs) != 1 || recs[0].Type != "MX" {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
}

func TestContextAndConfig(t *testing.T) {
	b := newBackend()
	b.slow = 500 * time.Millisecond
	p := newProvider(t, b, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Test(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if _, err := technitium.New(technitium.Config{URL: "https://x.example.test"}); err == nil {
		t.Fatal("no credentials accepted")
	}
	if _, err := technitium.New(technitium.Config{URL: "http://dns.example.test", Token: "t"}); err == nil {
		t.Fatal("plain http to public name accepted")
	}
}

func TestUpdatePreservesUnmanagedFields(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.zones["example.test"] = []rec{{name: "a.example.test", typ: "A", val: "192.0.2.1", ttl: 777, disabled: true, comments: "keep me"}}
	p := newProvider(t, b, nil)
	if _, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "a.example.test", Type: "A", Value: "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	got := b.zones["example.test"][0]
	if got.val != "192.0.2.2" || got.ttl != 777 || !got.disabled || got.comments != "keep me" {
		t.Fatalf("update reset fields: %+v", got)
	}
}

func TestMultiValueUpdateRefusedAndDeleteExact(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	b.zones["example.test"] = []rec{{name: "m.example.test", typ: "A", val: "192.0.2.1"}, {name: "m.example.test", typ: "A", val: "192.0.2.2"}}
	p := newProvider(t, b, nil)
	if _, err := p.UpdateRecord(ctx, "example.test", dns.Record{Name: "m.example.test", Type: "A", Value: "192.0.2.9"}); err == nil || !strings.Contains(err.Error(), "2 values") {
		t.Fatalf("err = %v", err)
	}
}

func TestListingFailsClosed(t *testing.T) {
	ctx := context.Background()
	for name, raw := range map[string]string{
		"empty object": `{}`, "ok without response": `{"status":"ok"}`, "no records": `{"status":"ok","response":{"zone":{}}}`,
		"null records": `{"status":"ok","response":{"records":null}}`,
	} {
		b := newBackend()
		b.rawGet = raw
		p := newProvider(t, b, nil)
		if recs, err := p.ListRecords(ctx, "example.test"); err == nil {
			t.Errorf("%s: accepted, recs=%v", name, recs)
		}
	}
}

func TestSessionTokenScrubbedAndFlagsTyped(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	p := newProvider(t, b, func(c *technitium.Config) { c.Token, c.Username, c.Password = "", "admin", password })
	if err := p.Test(ctx); err != nil {
		t.Fatal(err)
	}
	b.status = 500
	err := p.Test(ctx)
	if err == nil || strings.Contains(err.Error(), "session-") {
		t.Fatalf("session token leaked: %v", err)
	}
	if _, err := dns.New("technitium", map[string]any{"url": "https://x.example.test", "token": "t", "allow_insecure_http": "yes"}, nil); err == nil {
		t.Fatal("non-bool flag accepted")
	}
}
