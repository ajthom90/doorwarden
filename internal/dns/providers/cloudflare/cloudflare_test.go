package cloudflare_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/dnstest"
	"github.com/ajthom90/doorwarden/internal/dns/providers/cloudflare"
	"github.com/ajthom90/doorwarden/internal/secrets"
)

const fakeToken = "cf-TOKEN-do-not-leak-123"

type rec struct {
	ID, Name, Type, Content, zone string
	TTL                           int
}

type backend struct {
	mu     sync.Mutex
	n      int
	recs   []rec
	zones  map[string]string
	status int // when non-zero, every request fails with it
	slow   time.Duration
}

func newBackend() *backend {
	return &backend{zones: map[string]string{"example.test": "zid-1", "other.test": "zid-2"}}
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.slow > 0 {
		b.mu.Unlock()
		time.Sleep(b.slow)
		b.mu.Lock()
	}
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	fail := func(code int, msg string) {
		reply(code, map[string]any{"success": false, "errors": []map[string]any{{"code": 1, "message": msg}}})
	}
	if b.status != 0 {
		fail(b.status, "forced failure "+r.Header.Get("Authorization"))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+fakeToken {
		fail(403, "invalid token")
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/client/v4")
	if p == "/zones" {
		var res []map[string]string
		for n, id := range b.zones {
			if q := r.URL.Query().Get("name"); q == "" || q == n {
				res = append(res, map[string]string{"id": id, "name": n})
			}
		}
		reply(200, map[string]any{"success": true, "result": res})
		return
	}
	parts := strings.Split(strings.TrimPrefix(p, "/zones/"), "/")
	zone := ""
	for n, id := range b.zones {
		if id == parts[0] {
			zone = n
		}
	}
	if zone == "" || len(parts) < 2 || parts[1] != "dns_records" {
		fail(404, "no route")
		return
	}
	toJSON := func(x rec) map[string]any {
		return map[string]any{"id": x.ID, "name": x.Name, "type": x.Type, "content": x.Content, "ttl": x.TTL}
	}
	find := func(id string) int {
		for i, x := range b.recs {
			if x.ID == id && x.zone == zone {
				return i
			}
		}
		return -1
	}
	if len(parts) == 2 {
		switch r.Method {
		case "GET":
			q := r.URL.Query()
			var match []rec
			for _, x := range b.recs {
				if x.zone != zone || (q.Get("name.exact") != "" && x.Name != q.Get("name.exact")) || (q.Get("type") != "" && x.Type != q.Get("type")) {
					continue
				}
				match = append(match, x)
			}
			page, _ := strconv.Atoi(q.Get("page"))
			const per = 3 // force pagination regardless of per_page
			total := (len(match) + per - 1) / per
			lo, hi := (page-1)*per, page*per
			if lo > len(match) {
				lo = len(match)
			}
			if hi > len(match) {
				hi = len(match)
			}
			res := []map[string]any{}
			for _, x := range match[lo:hi] {
				res = append(res, toJSON(x))
			}
			reply(200, map[string]any{"success": true, "result": res, "result_info": map[string]int{"page": page, "total_pages": total}})
		case "POST":
			var in struct {
				Type, Name, Content string
				TTL                 int
				Proxied             bool
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Proxied {
				fail(400, "proxied must be false")
				return
			}
			b.n++
			x := rec{ID: fmt.Sprintf("r%d", b.n), Name: in.Name, Type: in.Type, Content: in.Content, TTL: in.TTL, zone: zone}
			b.recs = append(b.recs, x)
			reply(200, map[string]any{"success": true, "result": toJSON(x)})
		}
		return
	}
	i := find(parts[2])
	if i < 0 {
		fail(404, "record not found")
		return
	}
	switch r.Method {
	case "GET":
		reply(200, map[string]any{"success": true, "result": toJSON(b.recs[i])})
	case "PATCH":
		var in struct {
			Content string
			TTL     int
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		b.recs[i].Content, b.recs[i].TTL = in.Content, in.TTL
		reply(200, map[string]any{"success": true, "result": toJSON(b.recs[i])})
	case "DELETE":
		b.recs = append(b.recs[:i], b.recs[i+1:]...)
		reply(200, map[string]any{"success": true, "result": map[string]string{"id": parts[2]}})
	}
}

func newProvider(t *testing.T, b *backend, token string) *cloudflare.Provider {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	p, err := cloudflare.New(cloudflare.Config{APIToken: secrets.Secret(token), BaseURL: srv.URL + "/client/v4"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConformance(t *testing.T) {
	b := newBackend()
	p := newProvider(t, b, fakeToken)
	dnstest.RunWith(t, func(*testing.T) dns.Provider { return p }, dnstest.Options{Zone: "example.test", OtherZone: "other.test"})
}

func TestRegisteredAndSecretResolution(t *testing.T) {
	if c, ok := dns.CapsFor("cloudflare"); !ok || !c.WildcardA || !c.TTL {
		t.Fatalf("caps %+v", c)
	}
	if _, err := dns.New("cloudflare", map[string]any{}, nil); err == nil {
		t.Fatal("missing token accepted")
	}
	p, err := dns.New("cloudflare", map[string]any{"api_token": "x"}, nil)
	if err != nil || p.Type() != "cloudflare" {
		t.Fatal(err)
	}
}

func TestErrorMappingNoSecretLeak(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	// wrong token -> 403
	p := newProvider(t, b, "wrong-"+fakeToken)
	err := p.Test(ctx)
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Fatal("secret leaked")
	}
	// rate limit, with the backend echoing the Authorization header in its body
	b.status = 429
	p = newProvider(t, b, fakeToken)
	err = p.Test(ctx)
	if err == nil || !strings.Contains(err.Error(), "rate limited") || strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("err = %v", err)
	}
	b.status = 500
	err = p.Test(ctx)
	if err == nil || strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("500 err leaked: %v", err)
	}
	// unknown zone
	b.status = 0
	_, err = p.ListRecords(ctx, "nope.test")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("zone err = %v", err)
	}
}

func TestPaginationAndForeignRecords(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	p := newProvider(t, b, fakeToken)
	for i := 0; i < 8; i++ {
		b.recs = append(b.recs, rec{ID: fmt.Sprint("f", i), Name: fmt.Sprintf("h%d.example.test", i), Type: "A", Content: "192.0.2.1", TTL: 1, zone: "example.test"})
	}
	recs, err := p.ListRecords(ctx, "example.test")
	if err != nil || len(recs) != 8 {
		t.Fatalf("recs=%d err=%v", len(recs), err)
	}
	if recs[0].TTL != 0 {
		t.Fatalf("automatic ttl should map to 0, got %d", recs[0].TTL)
	}
}

func TestContextTimeout(t *testing.T) {
	b := newBackend()
	b.slow = 500 * time.Millisecond
	p := newProvider(t, b, fakeToken)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Test(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIURLRejectedFromConfig(t *testing.T) {
	_, err := dns.New("cloudflare", map[string]any{"api_token": fakeToken, "api_url": "https://evil.example.test"}, nil)
	if err == nil || !strings.Contains(err.Error(), "api_url") || strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("err = %v", err)
	}
	sch, _ := dns.SchemaFor("cloudflare")
	for _, f := range sch.Fields {
		if f.Name == "api_url" {
			t.Fatal("api_url in schema")
		}
	}
}
